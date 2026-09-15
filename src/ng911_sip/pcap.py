"""Fast, streaming packet reader for classic pcap captures.

The captures this project targets are hourly ESInet spans in which fewer than
one packet in three hundred is SIP. Fully dissecting every frame only to discard
99.7% of them dominates runtime, so this module decodes just the fixed-offset
Ethernet/IP/TCP/UDP fields needed to answer "is this a SIP port?" and returns a
raw payload slice for the frames that survive.

Anything that is not a classic pcap file (pcapng, unusual link types) falls back
to Scapy, which is slower but understands far more formats.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# libpcap file magics mapped to (big_endian, timestamps_in_nanoseconds).
_MAGICS = {
    0xA1B2C3D4: (False, False),
    0xD4C3B2A1: (True, False),
    0xA1B23C4D: (False, True),
    0x4D3CB2A1: (True, True),
}

LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

_PROTO_TCP = 6
_PROTO_UDP = 17

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}


@dataclass(slots=True)
class Packet:
    """One transport-layer segment carrying a payload."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    payload: bytes
    frame_length: int
    packet_number: int


class CaptureFormatError(Exception):
    """Raised when a file cannot be read as a capture at all."""


def _parse_ip(buf: memoryview, offset: int) -> tuple[str, str, int, int] | None:
    """Return (src, dst, l4_protocol, l4_offset), or None if not IPv4/IPv6."""
    if offset + 20 > len(buf):
        return None

    version = buf[offset] >> 4

    if version == 4:
        ihl = (buf[offset] & 0x0F) * 4
        if ihl < 20 or offset + ihl > len(buf):
            return None
        # A non-zero fragment offset means no transport header is present here.
        frag = struct.unpack_from("!H", buf, offset + 6)[0]
        if frag & 0x1FFF:
            return None
        return (
            socket.inet_ntoa(bytes(buf[offset + 12 : offset + 16])),
            socket.inet_ntoa(bytes(buf[offset + 16 : offset + 20])),
            buf[offset + 9],
            offset + ihl,
        )

    if version == 6:
        if offset + 40 > len(buf):
            return None
        return (
            socket.inet_ntop(socket.AF_INET6, bytes(buf[offset + 8 : offset + 24])),
            socket.inet_ntop(socket.AF_INET6, bytes(buf[offset + 24 : offset + 40])),
            buf[offset + 6],
            offset + 40,
        )

    return None


def _l3_offset(buf: memoryview, linktype: int) -> int | None:
    """Skip the link layer, returning the offset of the network header."""
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            return None
        ethertype = struct.unpack_from("!H", buf, 12)[0]
        offset = 14
        while ethertype in _VLAN_TAGS:  # Walk any stack of VLAN tags.
            if offset + 4 > len(buf):
                return None
            ethertype = struct.unpack_from("!H", buf, offset + 2)[0]
            offset += 4
        if ethertype in (_ETH_IPV4, _ETH_IPV6):
            return offset
        return None  # 802.3 with LLC/SNAP rather than Ethernet II.

    if linktype == LINKTYPE_LINUX_SLL:
        return 16 if len(buf) >= 16 else None
    if linktype == LINKTYPE_RAW_IP:
        return 0
    if linktype == LINKTYPE_NULL:
        return 4 if len(buf) >= 4 else None
    return None


def _iter_pcap_fast(path: Path, ports: frozenset[int] | None) -> Iterator[Packet]:
    """Stream a classic pcap file, decoding only what the port filter needs."""
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise CaptureFormatError(f"{path.name}: file header is incomplete")

        (magic,) = struct.unpack("<I", header[:4])
        if magic not in _MAGICS:
            (magic,) = struct.unpack(">I", header[:4])
        if magic not in _MAGICS:
            raise CaptureFormatError(f"{path.name}: not a classic pcap file")

        big_endian, nanoseconds = _MAGICS[magic]
        endian = ">" if big_endian else "<"
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        record_header = struct.Struct(endian + "IIII")
        divisor = 1e9 if nanoseconds else 1e6

        number = 0
        while True:
            raw = handle.read(16)
            if len(raw) < 16:
                return  # Cut mid-record: an interrupted transfer or live rotation.

            ts_sec, ts_frac, captured_len, original_len = record_header.unpack(raw)
            data = handle.read(captured_len)
            if len(data) < captured_len:
                return

            number += 1
            if captured_len < 28:
                continue

            buf = memoryview(data)
            offset = _l3_offset(buf, linktype)
            if offset is None:
                continue

            parsed = _parse_ip(buf, offset)
            if parsed is None:
                continue
            src_ip, dst_ip, proto, l4 = parsed

            if proto == _PROTO_TCP:
                if l4 + 20 > len(buf):
                    continue
                src_port, dst_port = struct.unpack_from("!HH", buf, l4)
                if ports is not None and src_port not in ports and dst_port not in ports:
                    continue
                data_offset = (buf[l4 + 12] >> 4) * 4
                if data_offset < 20:
                    continue
                payload_at = l4 + data_offset
                transport = "TCP"
            elif proto == _PROTO_UDP:
                if l4 + 8 > len(buf):
                    continue
                src_port, dst_port = struct.unpack_from("!HH", buf, l4)
                if ports is not None and src_port not in ports and dst_port not in ports:
                    continue
                payload_at = l4 + 8
                transport = "UDP"
            else:
                continue

            yield Packet(
                timestamp=ts_sec + ts_frac / divisor,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                transport=transport,
                payload=bytes(buf[payload_at:]) if payload_at < len(buf) else b"",
                frame_length=original_len,
                packet_number=number,
            )


def _iter_pcap_scapy(path: Path, ports: frozenset[int] | None) -> Iterator[Packet]:
    """Fallback for formats the fast reader does not implement (e.g. pcapng)."""
    from scapy.all import IP, IPv6, PcapReader, Raw, TCP, UDP

    with PcapReader(str(path)) as reader:
        for number, packet in enumerate(reader, start=1):
            if packet.haslayer(IP):
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
            else:
                continue

            if packet.haslayer(TCP):
                layer, transport = packet[TCP], "TCP"
            elif packet.haslayer(UDP):
                layer, transport = packet[UDP], "UDP"
            else:
                continue

            src_port, dst_port = int(layer.sport), int(layer.dport)
            if ports is not None and src_port not in ports and dst_port not in ports:
                continue

            yield Packet(
                timestamp=float(packet.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                transport=transport,
                payload=bytes(packet[Raw].load) if packet.haslayer(Raw) else b"",
                frame_length=len(packet),
                packet_number=number,
            )


def iter_packets(
    path: str | Path,
    ports: Iterable[int] | None = None,
) -> Iterator[Packet]:
    """Yield transport segments from a capture, optionally filtered by port.

    Passing ``ports`` is what makes hour-long captures tractable: frames that
    touch none of those ports are rejected from their fixed-offset headers
    alone, without the payload ever being copied or decoded.
    """
    path = Path(path)
    port_set = frozenset(ports) if ports is not None else None

    try:
        yield from _iter_pcap_fast(path, port_set)
    except CaptureFormatError:
        yield from _iter_pcap_scapy(path, port_set)


def find_captures(root: str | Path) -> list[Path]:
    """Find capture files under ``root``.

    Partial downloads (``.crdownload``, ``.part``) and hidden files are skipped
    so a directory still being populated does not break a run.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"capture path does not exist: {root}")
    if root.is_file():
        return [root]

    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in CAPTURE_SUFFIXES
        and not path.name.startswith(".")
    )
