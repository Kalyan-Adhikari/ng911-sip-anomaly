"""Turn parsed SIP messages into fixed-width feature windows.

Four decisions here matter more than the individual feature list:

* **Windows are anchored to absolute epoch time**, not to the first packet of
  each file. Hourly-rotated captures otherwise produce windows that restart at
  zero and straddle different offsets per file, so no continuous timeline can be
  built and a dialog spanning a rotation is counted twice.

* **Silent windows are emitted, not dropped.** On a keepalive-driven ESInet the
  absence of traffic is the anomaly worth catching: a window with no OPTIONS
  means an element stopped answering. Gaps are filled only inside an observed
  capture span, so the hours between two non-adjacent files never masquerade as
  silence.

* **Per-source concentration is measured inside each window.** Window-wide sums
  hide a single host flooding INVITEs among legitimate traffic, which is exactly
  the NG911 TDoS shape. Source entropy and top-talker share expose it without
  needing a row per source.

* **Authentication counters follow SIP semantics.** A 401 answering a REGISTER
  is the routine digest challenge, not a failed login; only a challenge never
  followed by success, or an outright 403/404, indicates trouble.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from .sip import SipMessage

DEFAULT_WINDOW_SECONDS = 10

# Counted individually because each is a distinct ESInet behaviour.
_METHODS = (
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
    "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE", "INFO", "UPDATE", "PUBLISH", "PRACK",
)

# Specific codes worth their own column beyond the per-class rollup.
_STATUS_CODES = (401, 403, 404, 407, 408, 480, 486, 487, 500, 503)

# Identifier and bookkeeping columns that must never be fed to a model.
METADATA_COLUMNS = frozenset(
    {
        "capture_file", "window_start_epoch", "window_end_epoch",
        "window_start_utc", "window_seconds", "is_gap_filled",
        "label", "anomaly_score", "is_anomaly", "model_name",
    }
)


# A source present in at least this share of windows counts as part of the mesh.
ESTABLISHED_PRESENCE = 0.2


def _entropy(counts: Iterable[int]) -> float:
    """Shannon entropy in bits of a count distribution."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total <= 0 or len(values) <= 1:
        return 0.0
    return round(-sum((c / total) * math.log2(c / total) for c in values), 6)


def _established_sources(
    grouped: dict[int, list[SipMessage]],
    presence: float = ESTABLISHED_PRESENCE,
) -> frozenset[str]:
    """Sources that behave like members of the mesh rather than visitors.

    An ESInet talks to a small, fixed set of elements that appear in nearly
    every window. A scanner or spoofing host appears in a handful. Deriving the
    mesh from the data keeps this self-contained -- no configured allowlist to
    drift -- and makes the feature mean the same thing at training and scoring
    time, because both compute it the same way over whatever they were given.
    """
    if not grouped:
        return frozenset()

    windows_seen: Counter[str] = Counter()
    for bucket in grouped.values():
        for src_ip in {message.src_ip for message in bucket}:
            windows_seen[src_ip] += 1

    minimum = max(1, int(len(grouped) * presence))
    return frozenset(ip for ip, count in windows_seen.items() if count >= minimum)


@dataclass(slots=True)
class CaptureSpan:
    """The observed time range of one capture file."""

    capture_file: str
    first_epoch: float
    last_epoch: float


def _window_index(timestamp: float, window_seconds: int) -> int:
    """Absolute-epoch window index, identical across files and runs."""
    return int(timestamp // window_seconds)


def _empty_window(
    window_index: int,
    window_seconds: int,
    capture_file: str,
) -> dict[str, object]:
    """A window in which no SIP message was observed."""
    start = window_index * window_seconds
    row: dict[str, object] = {
        "capture_file": capture_file,
        "window_start_epoch": float(start),
        "window_end_epoch": float(start + window_seconds),
        "window_start_utc": datetime.fromtimestamp(start, tz=timezone.utc),
        "window_seconds": window_seconds,
        "is_gap_filled": 1,
        "total_messages": 0,
        "request_count": 0,
        "response_count": 0,
        "response_request_ratio": 0.0,
        "retransmission_count": 0,
        "unique_src_ips": 0,
        "unique_dst_ips": 0,
        "unique_call_ids": 0,
        "unique_from_users": 0,
        "unique_to_users": 0,
        "unique_user_agents": 0,
        "unique_peer_pairs": 0,
        "src_ip_entropy": 0.0,
        "method_entropy": 0.0,
        "top_source_share": 0.0,
        "max_messages_one_source": 0,
        "max_invites_one_source": 0,
        "offmesh_source_count": 0,
        "offmesh_message_ratio": 0.0,
        "mean_message_size": 0.0,
        "max_message_size": 0,
        "stdev_message_size": 0.0,
        "tcp_ratio": 0.0,
        "max_via_depth": 0,
        "emergency_call_count": 0,
        "geolocation_count": 0,
        "sdp_count": 0,
        "multipart_body_count": 0,
        "location_body_count": 0,
        "auth_challenge_count": 0,
        "auth_completed_count": 0,
        "auth_rejected_count": 0,
        "unanswered_challenge_count": 0,
    }
    for method in _METHODS:
        row[f"{method.lower()}_count"] = 0
    for klass in range(1, 7):
        row[f"status_{klass}xx"] = 0
    for code in _STATUS_CODES:
        row[f"status_{code}"] = 0
    row.update(_time_features(start))
    return row


def _time_features(start_epoch: float) -> dict[str, float]:
    """Cyclical time-of-day and day-of-week encodings.

    PSAP traffic is strongly diurnal. Encoding the clock as sine/cosine pairs
    lets a model learn that 03:00 and 15:00 differ without treating midnight as
    maximally distant from 23:59.
    """
    moment = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
    seconds_of_day = moment.hour * 3600 + moment.minute * 60 + moment.second
    day_fraction = seconds_of_day / 86400.0
    week_fraction = moment.weekday() / 7.0
    return {
        "hour_sin": round(math.sin(2 * math.pi * day_fraction), 6),
        "hour_cos": round(math.cos(2 * math.pi * day_fraction), 6),
        "dow_sin": round(math.sin(2 * math.pi * week_fraction), 6),
        "dow_cos": round(math.cos(2 * math.pi * week_fraction), 6),
    }


def _summarise(
    messages: Sequence[SipMessage],
    window_index: int,
    window_seconds: int,
    capture_file: str,
    established: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Build one feature row from the messages inside a window."""
    row = _empty_window(window_index, window_seconds, capture_file)
    row["is_gap_filled"] = 0

    total = len(messages)
    requests = [m for m in messages if m.is_request]
    responses = [m for m in messages if not m.is_request]

    row["total_messages"] = total
    row["request_count"] = len(requests)
    row["response_count"] = len(responses)
    row["response_request_ratio"] = (
        round(len(responses) / len(requests), 6) if requests else 0.0
    )

    method_counts = Counter(m.method for m in requests if m.method)
    for method in _METHODS:
        row[f"{method.lower()}_count"] = method_counts.get(method, 0)
    row["method_entropy"] = _entropy(method_counts.values())

    status_counts = Counter(m.status_code for m in responses if m.status_code)
    for klass in range(1, 7):
        row[f"status_{klass}xx"] = sum(
            count for code, count in status_counts.items() if code // 100 == klass
        )
    for code in _STATUS_CODES:
        row[f"status_{code}"] = status_counts.get(code, 0)

    src_counts = Counter(m.src_ip for m in messages)
    row["unique_src_ips"] = len(src_counts)
    row["unique_dst_ips"] = len({m.dst_ip for m in messages})
    row["unique_peer_pairs"] = len({(m.src_ip, m.dst_ip) for m in messages})
    row["unique_call_ids"] = len({m.call_id for m in messages if m.call_id})
    row["unique_from_users"] = len({m.from_user for m in messages if m.from_user})
    row["unique_to_users"] = len({m.to_user for m in messages if m.to_user})
    row["unique_user_agents"] = len({m.user_agent for m in messages if m.user_agent})

    # Concentration: one host dominating a window is the TDoS signature that
    # window-wide totals cannot see.
    row["src_ip_entropy"] = _entropy(src_counts.values())
    busiest = max(src_counts.values()) if src_counts else 0
    row["max_messages_one_source"] = busiest
    row["top_source_share"] = round(busiest / total, 6) if total else 0.0

    invites_by_source = Counter(
        m.src_ip for m in requests if m.method == "INVITE"
    )
    row["max_invites_one_source"] = (
        max(invites_by_source.values()) if invites_by_source else 0
    )

    # Traffic from hosts that are not part of the mesh. A low-rate scan barely
    # moves any volume feature, but it is entirely off-mesh, which this catches.
    if established:
        offmesh = {ip: n for ip, n in src_counts.items() if ip not in established}
        row["offmesh_source_count"] = len(offmesh)
        row["offmesh_message_ratio"] = (
            round(sum(offmesh.values()) / total, 6) if total else 0.0
        )

    sizes = [m.message_size for m in messages]
    mean_size = sum(sizes) / len(sizes)
    row["mean_message_size"] = round(mean_size, 3)
    row["max_message_size"] = max(sizes)
    row["stdev_message_size"] = round(
        math.sqrt(sum((s - mean_size) ** 2 for s in sizes) / len(sizes)), 3
    )

    row["tcp_ratio"] = round(
        sum(1 for m in messages if m.transport == "TCP") / total, 6
    )
    row["max_via_depth"] = max((m.via_count for m in messages), default=0)

    # A retransmission repeats the same transaction identity. On a healthy link
    # this is near zero; it rises under congestion and during floods.
    transactions = Counter(
        (m.call_id, m.cseq_number, m.method or m.status_code) for m in messages
    )
    row["retransmission_count"] = sum(c - 1 for c in transactions.values() if c > 1)

    row["emergency_call_count"] = sum(
        1 for m in requests if m.is_emergency_service and m.method == "INVITE"
    )
    row["geolocation_count"] = sum(1 for m in messages if m.has_geolocation)
    row["sdp_count"] = sum(1 for m in messages if m.has_sdp)
    row["multipart_body_count"] = sum(1 for m in messages if m.has_multipart_body)
    row["location_body_count"] = sum(1 for m in messages if m.has_location_body)

    row.update(_auth_features(requests, responses))
    return row


def _auth_features(
    requests: Sequence[SipMessage],
    responses: Sequence[SipMessage],
) -> dict[str, int]:
    """Authentication counters that respect SIP digest semantics.

    A 401/407 answering a REGISTER is the routine challenge every registration
    receives. Treating it as a failure -- as a naive counter does -- makes normal
    registration look like an attack. What matters is the challenge that is
    never completed, and the outright rejection.
    """
    challenges = 0
    completed = 0
    rejected = 0

    challenged_dialogs: set[str | None] = set()
    completed_dialogs: set[str | None] = set()

    for response in responses:
        if response.cseq_method != "REGISTER":
            continue
        # Keyed on Call-ID, not CSeq: a digest retry reuses the same Call-ID
        # with an incremented CSeq, so the 401 and the eventual 200 carry
        # different sequence numbers. Pairing them by CSeq would mark every
        # ordinary registration as an unanswered challenge.
        key = response.call_id
        code = response.status_code or 0
        if code in (401, 407):
            challenges += 1
            challenged_dialogs.add(key)
        elif code == 200:
            completed += 1
            completed_dialogs.add(key)
        elif code in (403, 404):
            rejected += 1

    return {
        "auth_challenge_count": challenges,
        "auth_completed_count": completed,
        "auth_rejected_count": rejected,
        # Challenged but never completed within this window: the shape that
        # credential stuffing produces and normal registration does not.
        "unanswered_challenge_count": len(challenged_dialogs - completed_dialogs),
    }


def build_windows(
    messages: Iterable[SipMessage],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    spans: Sequence[CaptureSpan] | None = None,
    fill_gaps: bool = True,
) -> list[dict[str, object]]:
    """Aggregate messages into absolute-epoch feature windows.

    ``spans`` bounds gap filling to time actually covered by a capture, so the
    hours between two non-adjacent files are not invented as silence.
    """
    grouped: dict[int, list[SipMessage]] = defaultdict(list)
    capture_of_window: dict[int, str] = {}

    for message in messages:
        index = _window_index(message.timestamp, window_seconds)
        grouped[index].append(message)
        capture_of_window.setdefault(index, message.capture_file)

    established = _established_sources(grouped)
    rows = [
        _summarise(bucket, index, window_seconds, capture_of_window[index], established)
        for index, bucket in sorted(grouped.items())
    ]

    if fill_gaps and spans:
        rows.extend(_fill_spans(spans, window_seconds, set(grouped)))

    rows.sort(key=lambda row: row["window_start_epoch"])
    return rows


def _fill_spans(
    spans: Sequence[CaptureSpan],
    window_seconds: int,
    observed: set[int],
) -> list[dict[str, object]]:
    """Emit empty rows for silent windows inside each observed capture span."""
    filled: list[dict[str, object]] = []
    for span in spans:
        first = _window_index(span.first_epoch, window_seconds)
        last = _window_index(span.last_epoch, window_seconds)
        for index in range(first, last + 1):
            if index not in observed:
                observed.add(index)
                filled.append(_empty_window(index, window_seconds, span.capture_file))
    return filled


def build_source_windows(
    messages: Iterable[SipMessage],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[dict[str, object]]:
    """Aggregate per (window, source IP) instead of per window.

    Window-level rows answer "is this interval unusual?". Source-level rows
    answer "which host made it unusual?", which is what an operator acts on.
    """
    grouped: dict[tuple[int, str], list[SipMessage]] = defaultdict(list)
    for message in messages:
        grouped[(_window_index(message.timestamp, window_seconds), message.src_ip)].append(
            message
        )

    rows: list[dict[str, object]] = []
    for (index, src_ip), bucket in sorted(grouped.items()):
        row = _summarise(bucket, index, window_seconds, bucket[0].capture_file)
        row["src_ip"] = src_ip
        rows.append(row)
    return rows
