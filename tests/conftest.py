"""Shared helpers: build synthetic captures in memory, no fixtures on disk."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from ng911_sip.privacy import Pseudonymiser

ETHERNET = 1


def ethernet_frame(
    payload: bytes,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 5060,
    dst_port: int = 5060,
    protocol: str = "TCP",
    vlan: int | None = None,
) -> bytes:
    """Build one Ethernet/IPv4/TCP-or-UDP frame around ``payload``."""
    if protocol == "TCP":
        # Fixed 20-byte header; data offset 5 words in the high nibble of byte 12.
        transport = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 5 << 4, 0, 0, 0, 0)
        proto_number = 6
    else:
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        proto_number = 17

    body = transport + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(body), 0, 0, 64, proto_number, 0,
        bytes(int(o) for o in src_ip.split(".")),
        bytes(int(o) for o in dst_ip.split(".")),
    )

    if vlan is None:
        link = b"\x00" * 12 + struct.pack("!H", 0x0800)
    else:
        link = b"\x00" * 12 + struct.pack("!HHH", 0x8100, vlan, 0x0800)

    return link + ip_header + body


def write_pcap(path: Path, frames: list[tuple[float, bytes]], linktype: int = ETHERNET) -> Path:
    """Write a little-endian classic pcap containing ``frames``."""
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for timestamp, frame in frames:
            seconds = int(timestamp)
            microseconds = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            handle.write(frame)
    return path


def sip_request(
    method: str = "OPTIONS",
    uri: str = "sip:psap.example",
    call_id: str = "abc123",
    cseq: int = 1,
    body: str = "",
    extra: str = "",
) -> bytes:
    """A syntactically complete SIP request with a correct Content-Length."""
    headers = (
        f"{method} {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK{cseq}\r\n"
        f"From: <sip:caller@10.0.0.1>;tag=t{cseq}\r\n"
        f"To: <{uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} {method}\r\n"
        f"Max-Forwards: 70\r\n"
        f"{extra}"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    return (headers + body).encode()


def sip_response(
    code: int = 200,
    reason: str = "OK",
    call_id: str = "abc123",
    cseq: int = 1,
    cseq_method: str = "OPTIONS",
) -> bytes:
    return (
        f"SIP/2.0 {code} {reason}\r\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK{cseq}\r\n"
        f"From: <sip:caller@10.0.0.1>;tag=t{cseq}\r\n"
        f"To: <sip:psap.example>;tag=s{cseq}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} {cseq_method}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


@pytest.fixture
def pseudonymiser() -> Pseudonymiser:
    """A deterministic pseudonymiser so tests can assert on token stability."""
    return Pseudonymiser(key=b"fixed-test-key")
