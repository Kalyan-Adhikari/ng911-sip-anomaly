"""Feature tests, focused on the windowing and semantics bugs being fixed."""

from __future__ import annotations

from ng911_sip.features import CaptureSpan, build_source_windows, build_windows
from ng911_sip.sip import SipMessage


def message(
    timestamp: float,
    method: str | None = "OPTIONS",
    status: int | None = None,
    src_ip: str = "10.0.0.1",
    call_id: str = "c1",
    cseq: int = 1,
    cseq_method: str | None = None,
    capture_file: str = "a.pcap",
    size: int = 400,
    emergency: bool = False,
) -> SipMessage:
    return SipMessage(
        capture_file=capture_file,
        packet_number=1,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="10.0.0.9",
        src_port=5060,
        dst_port=5060,
        transport="TCP",
        message_size=size,
        message_type="request" if status is None else "response",
        method=method if status is None else None,
        status_code=status,
        cseq_number=cseq,
        cseq_method=cseq_method or (method if status is None else "REGISTER"),
        call_id=call_id,
        is_emergency_service=emergency,
    )


def test_windows_are_anchored_to_absolute_epoch():
    """Two captures of the same wall-clock second share a window index.

    Anchoring to each file's first packet instead makes rotated captures
    produce misaligned windows that cannot be placed on one timeline.
    """
    rows = build_windows(
        [
            message(1_700_000_003.0, capture_file="hour1.pcap"),
            message(1_700_000_007.0, capture_file="hour2.pcap"),
        ],
        window_seconds=10,
    )
    assert len(rows) == 1
    assert rows[0]["window_start_epoch"] == 1_700_000_000.0
    assert rows[0]["total_messages"] == 2


def test_window_boundaries_do_not_shift_with_the_first_packet():
    late = build_windows([message(1_700_000_009.5)], window_seconds=10)
    assert late[0]["window_start_epoch"] == 1_700_000_000.0


def test_silent_windows_are_emitted_inside_a_span():
    """No traffic is itself the signal on a keepalive-driven ESInet."""
    rows = build_windows(
        [message(1_700_000_000.0), message(1_700_000_040.0)],
        window_seconds=10,
        spans=[CaptureSpan("a.pcap", 1_700_000_000.0, 1_700_000_040.0)],
    )
    assert len(rows) == 5
    filled = [r for r in rows if r["is_gap_filled"] == 1]
    assert len(filled) == 3
    assert all(r["total_messages"] == 0 for r in filled)


def test_gaps_between_non_adjacent_captures_are_not_invented():
    """Hours with no capture file must not be fabricated as silence."""
    rows = build_windows(
        [message(1_700_000_000.0, capture_file="h08.pcap"),
         message(1_700_003_600.0, capture_file="h09.pcap")],
        window_seconds=10,
        spans=[
            CaptureSpan("h08.pcap", 1_700_000_000.0, 1_700_000_005.0),
            CaptureSpan("h09.pcap", 1_700_003_600.0, 1_700_003_605.0),
        ],
    )
    # One window per span, not the 360 windows the intervening hour would add.
    assert len(rows) == 2


def test_gap_filling_can_be_disabled():
    rows = build_windows(
        [message(1_700_000_000.0), message(1_700_000_040.0)],
        window_seconds=10,
        spans=[CaptureSpan("a.pcap", 1_700_000_000.0, 1_700_000_040.0)],
        fill_gaps=False,
    )
    assert len(rows) == 2


def test_register_challenge_is_not_counted_as_a_failure():
    """A 401 answering REGISTER is the routine digest challenge."""
    rows = build_windows(
        [
            message(1_700_000_001.0, method="REGISTER", call_id="r1", cseq=1),
            message(1_700_000_002.0, method=None, status=401, call_id="r1", cseq=1),
            message(1_700_000_003.0, method="REGISTER", call_id="r1", cseq=2),
            message(1_700_000_004.0, method=None, status=200, call_id="r1", cseq=2),
        ],
        window_seconds=10,
    )
    row = rows[0]
    assert row["auth_challenge_count"] == 1
    assert row["auth_completed_count"] == 1
    # The dialog completed, so nothing is left outstanding.
    assert row["unanswered_challenge_count"] == 0


def test_unanswered_challenges_are_counted():
    """Credential stuffing challenges repeatedly and never completes."""
    messages = []
    for i in range(20):
        messages.append(message(1_700_000_000.0 + i * 0.1, method="REGISTER",
                                call_id=f"c{i}", cseq=1))
        messages.append(message(1_700_000_000.0 + i * 0.1 + 0.01, method=None,
                                status=401, call_id=f"c{i}", cseq=1))
    row = build_windows(messages, window_seconds=10)[0]

    assert row["auth_challenge_count"] == 20
    assert row["auth_completed_count"] == 0
    assert row["unanswered_challenge_count"] == 20


def test_source_concentration_exposes_a_single_flooder():
    """Window totals alone cannot separate a flood from a busy interval."""
    spread = [message(1_700_000_000.0 + i * 0.05, src_ip=f"10.0.{i // 250}.{i % 250}")
              for i in range(100)]
    concentrated = [message(1_700_000_000.0 + i * 0.05, src_ip="10.0.0.66")
                    for i in range(100)]

    spread_row = build_windows(spread, window_seconds=10)[0]
    flood_row = build_windows(concentrated, window_seconds=10)[0]

    assert spread_row["total_messages"] == flood_row["total_messages"]
    assert flood_row["top_source_share"] == 1.0
    assert spread_row["top_source_share"] < 0.1
    assert flood_row["src_ip_entropy"] == 0.0
    assert spread_row["src_ip_entropy"] > 5.0


def test_retransmissions_are_detected():
    repeated = [message(1_700_000_000.0 + i * 0.1, call_id="same", cseq=7) for i in range(4)]
    row = build_windows(repeated, window_seconds=10)[0]
    assert row["retransmission_count"] == 3


def test_emergency_calls_are_counted_separately_from_keepalives():
    rows = build_windows(
        [
            message(1_700_000_001.0, method="OPTIONS"),
            message(1_700_000_002.0, method="INVITE", emergency=True, call_id="e1"),
        ],
        window_seconds=10,
    )
    assert rows[0]["emergency_call_count"] == 1
    assert rows[0]["options_count"] == 1


def test_time_of_day_is_encoded_cyclically():
    midnight = build_windows([message(1_700_000_000.0)], window_seconds=10)[0]
    assert -1.0 <= midnight["hour_sin"] <= 1.0
    assert -1.0 <= midnight["hour_cos"] <= 1.0
    assert {"hour_sin", "hour_cos", "dow_sin", "dow_cos"} <= set(midnight)


def test_no_duplicate_volume_columns():
    """The replaced pipeline shipped three perfectly collinear volume columns."""
    row = build_windows([message(1_700_000_000.0)], window_seconds=10)[0]
    assert "total_packets" not in row
    assert "messages_per_second" not in row
    assert "registration_attempts" not in row  # duplicated register_count


def test_per_source_rows_attribute_traffic_to_a_host():
    rows = build_source_windows(
        [
            message(1_700_000_001.0, src_ip="10.0.0.1"),
            message(1_700_000_002.0, src_ip="10.0.0.2"),
            message(1_700_000_003.0, src_ip="10.0.0.2"),
        ],
        window_seconds=10,
    )
    by_ip = {r["src_ip"]: r["total_messages"] for r in rows}
    assert by_ip == {"10.0.0.1": 1, "10.0.0.2": 2}
