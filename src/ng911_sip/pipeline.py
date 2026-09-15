"""Capture files in, feature frame out.

Parsing keeps only decoded SIP messages, not packets. On the ESInet captures
this targets that is a reduction of roughly three hundred to one, which is what
keeps an hour of traffic in tens of megabytes instead of gigabytes.

Captures are parsed in parallel, one process per file. Measured on a production
capture, 90% of the time is CPU spent decoding rather than waiting on disk, so
this scales with cores until it runs out of files. Reassembly is already
per-file, so splitting the work this way changes no result.

Windowing then happens across every capture at once rather than per file. That
is deliberate: a ten-second window straddling an hourly rotation belongs to both
files, and only a global pass over absolute-epoch windows counts it once.
"""

from __future__ import annotations

import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

import pandas as pd

from .features import (
    CaptureSpan,
    DEFAULT_WINDOW_SECONDS,
    build_source_windows,
    build_windows,
)
from .pcap import find_captures, iter_packets
from .privacy import Pseudonymiser
from .sip import DEFAULT_SIP_PORTS, SipMessage, SipReassembler

# Parsed SIP is small, but a runaway capture should not exhaust memory silently.
_MESSAGE_WARN_THRESHOLD = 5_000_000


@dataclass(slots=True)
class ParseResult:
    """Everything a parse pass produced, plus how it went."""

    messages: list[SipMessage] = field(default_factory=list)
    spans: list[CaptureSpan] = field(default_factory=list)
    files_read: int = 0
    files_failed: list[tuple[str, str]] = field(default_factory=list)
    packets_examined: int = 0
    resyncs: int = 0
    keepalives: int = 0
    truncated_streams: int = 0

    @property
    def message_count(self) -> int:
        return len(self.messages)


@dataclass(slots=True)
class _FileResult:
    """What one worker produced from one capture. Must be picklable."""

    name: str
    messages: list[SipMessage]
    span: CaptureSpan | None
    packets: int
    resyncs: int
    keepalives: int
    truncated: int
    error: str | None = None


def _parse_one_capture(
    path_str: str,
    ports: frozenset[int],
    key: bytes,
    enabled: bool,
) -> _FileResult:
    """Parse a single capture. Runs in a worker process.

    The pseudonymisation key is passed rather than the Pseudonymiser itself, so
    every worker derives identical tokens for the same caller. Without that,
    counts of distinct callers would be wrong wherever a caller appears in two
    files handled by different workers.
    """
    path = Path(path_str)
    pseudonymiser = Pseudonymiser(key=key, enabled=enabled)
    assembler = SipReassembler(pseudonymiser)
    messages: list[SipMessage] = []
    packets = 0
    first_seen: float | None = None
    last_seen: float | None = None

    try:
        for packet in iter_packets(path, ports=ports):
            packets += 1
            if first_seen is None:
                first_seen = packet.timestamp
            last_seen = packet.timestamp
            messages.extend(assembler.feed(packet, path.name))
    except Exception as error:  # noqa: BLE001 - one bad file must not stop the run
        return _FileResult(
            path.name, [], None, packets, 0, 0, 0,
            f"{type(error).__name__}: {error}",
        )

    span = (
        CaptureSpan(path.name, first_seen, last_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return _FileResult(
        path.name,
        messages,
        span,
        packets,
        assembler.stats.resyncs,
        assembler.stats.keepalives,
        assembler.stats.truncated_streams,
    )


def default_jobs(file_count: int) -> int:
    """How many workers to use: never more than there are files to read."""
    return max(1, min(file_count, os.cpu_count() or 1))


def parse_captures(
    source: str | Path,
    ports: Iterable[int] = DEFAULT_SIP_PORTS,
    pseudonymiser: Pseudonymiser | None = None,
    progress: Callable[[str], None] | None = None,
    jobs: int | None = None,
) -> ParseResult:
    """Parse every capture under ``source`` into SIP messages.

    Files are parsed in parallel, one process each, up to ``jobs`` at a time.
    Parallelism is capped at the number of files, since a single capture is
    parsed by one worker.

    A file that cannot be read is recorded and skipped rather than aborting the
    run: a directory of hourly captures routinely contains one that is still
    being written or was interrupted mid-transfer.
    """
    pseudonymiser = pseudonymiser or Pseudonymiser()
    port_set = frozenset(ports)
    paths = find_captures(source)
    result = ParseResult()

    if not paths:
        return result

    workers = default_jobs(len(paths)) if jobs is None else max(1, min(jobs, len(paths)))
    collected: dict[str, _FileResult] = {}

    if workers == 1:
        for path in paths:
            outcome = _parse_one_capture(
                str(path), port_set, pseudonymiser.key, pseudonymiser.enabled
            )
            collected[str(path)] = outcome
            if progress:
                progress(_describe(outcome))
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _parse_one_capture,
                    str(path),
                    port_set,
                    pseudonymiser.key,
                    pseudonymiser.enabled,
                ): str(path)
                for path in paths
            }
            for future in as_completed(futures):
                outcome = future.result()
                collected[futures[future]] = outcome
                if progress:
                    progress(_describe(outcome))

    # Reassemble in filename order so a run is reproducible regardless of the
    # order workers happened to finish in.
    for path in paths:
        outcome = collected.get(str(path))
        if outcome is None:
            continue
        if outcome.error is not None:
            result.files_failed.append((outcome.name, outcome.error))
            continue

        result.files_read += 1
        result.packets_examined += outcome.packets
        result.resyncs += outcome.resyncs
        result.keepalives += outcome.keepalives
        result.truncated_streams += outcome.truncated
        result.messages.extend(outcome.messages)
        if outcome.span is not None:
            result.spans.append(outcome.span)

    if result.message_count > _MESSAGE_WARN_THRESHOLD:
        print(
            f"warning: {result.message_count:,} messages parsed; "
            "consider narrowing the capture range",
            file=sys.stderr,
        )

    return result


def _describe(outcome: _FileResult) -> str:
    if outcome.error is not None:
        return f"{outcome.name}: skipped ({outcome.error})"
    return f"{outcome.name}: {len(outcome.messages):,} SIP messages"


def build_feature_frame(
    result: ParseResult,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    per_source: bool = False,
    fill_gaps: bool = True,
) -> pd.DataFrame:
    """Aggregate parsed messages into a feature frame."""
    if not result.messages:
        return pd.DataFrame()

    if per_source:
        rows = build_source_windows(result.messages, window_seconds)
    else:
        rows = build_windows(
            result.messages,
            window_seconds=window_seconds,
            spans=result.spans,
            fill_gaps=fill_gaps,
        )

    frame = pd.DataFrame(rows)
    leading = [
        column
        for column in (
            "capture_file",
            "src_ip",
            "window_start_utc",
            "window_start_epoch",
            "window_end_epoch",
            "window_seconds",
            "is_gap_filled",
            "total_messages",
        )
        if column in frame.columns
    ]
    rest = [column for column in frame.columns if column not in leading]
    return frame[leading + rest]


def write_frame(frame: pd.DataFrame, path: str | Path) -> Path:
    """Write a feature frame as Parquet or CSV based on the file suffix."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix.lower() == ".parquet":
        frame.to_parquet(path, index=False)
    else:
        frame.to_csv(path, index=False, encoding="utf-8")
    return path


def read_frame(path: str | Path) -> pd.DataFrame:
    """Read a feature frame written by :func:`write_frame`."""
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path)


def summarise(result: ParseResult, frame: pd.DataFrame | None = None) -> list[str]:
    """Human-readable lines describing what a parse pass found."""
    lines = [
        f"capture files read     : {result.files_read}",
        f"packets examined       : {result.packets_examined:,}",
        f"SIP messages parsed    : {result.message_count:,}",
    ]
    if result.resyncs:
        lines.append(f"stream resynchronised  : {result.resyncs:,} time(s)")
    if result.truncated_streams:
        lines.append(f"streams over buffer cap: {result.truncated_streams:,}")
    if result.files_failed:
        lines.append(f"files skipped          : {len(result.files_failed)}")
        for name, reason in result.files_failed:
            lines.append(f"    {name}: {reason}")

    if frame is not None and not frame.empty:
        filled = int(frame.get("is_gap_filled", pd.Series(dtype=int)).sum())
        lines.extend(
            [
                f"feature windows        : {len(frame):,}",
                f"    with traffic       : {len(frame) - filled:,}",
                f"    silent (gap-filled): {filled:,}",
            ]
        )
        if "window_start_utc" in frame.columns:
            lines.append(
                f"time range             : {frame['window_start_utc'].min()} "
                f"to {frame['window_start_utc'].max()}"
            )
    return lines
