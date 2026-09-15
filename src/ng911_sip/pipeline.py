"""Capture files in, feature frame out.

Parsing streams one capture at a time and keeps only decoded SIP messages, not
packets. On the ESInet captures this targets that is a reduction of roughly
three hundred to one, which is what keeps an hour of traffic in tens of
megabytes instead of gigabytes.

Windowing then happens across every capture at once rather than per file. That
is deliberate: a ten-second window straddling an hourly rotation belongs to both
files, and only a global pass over absolute-epoch windows counts it once.
"""

from __future__ import annotations

import sys
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


def parse_captures(
    source: str | Path,
    ports: Iterable[int] = DEFAULT_SIP_PORTS,
    pseudonymiser: Pseudonymiser | None = None,
    progress: Callable[[str], None] | None = None,
) -> ParseResult:
    """Parse every capture under ``source`` into SIP messages.

    A file that cannot be read is recorded and skipped rather than aborting the
    run: a directory of hourly captures routinely contains one that is still
    being written or was interrupted mid-transfer.
    """
    pseudonymiser = pseudonymiser or Pseudonymiser()
    port_set = frozenset(ports)
    result = ParseResult()

    for path in find_captures(source):
        assembler = SipReassembler(pseudonymiser)
        first_seen: float | None = None
        last_seen: float | None = None
        before = result.message_count

        try:
            for packet in iter_packets(path, ports=port_set):
                result.packets_examined += 1
                if first_seen is None:
                    first_seen = packet.timestamp
                last_seen = packet.timestamp
                result.messages.extend(assembler.feed(packet, path.name))
        except Exception as error:  # noqa: BLE001 - one bad file must not stop the run
            result.files_failed.append((path.name, f"{type(error).__name__}: {error}"))
            continue

        result.files_read += 1
        result.resyncs += assembler.stats.resyncs
        result.keepalives += assembler.stats.keepalives
        result.truncated_streams += assembler.stats.truncated_streams

        if first_seen is not None and last_seen is not None:
            result.spans.append(CaptureSpan(path.name, first_seen, last_seen))

        if progress:
            progress(
                f"{path.name}: {result.message_count - before:,} SIP messages"
            )

        if result.message_count > _MESSAGE_WARN_THRESHOLD:
            print(
                f"warning: {result.message_count:,} messages parsed; "
                "consider narrowing the capture range",
                file=sys.stderr,
            )

    return result


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
