"""SIP message parsing with correct transport framing.

Two things distinguish this from parsing each packet in isolation:

* **TCP reassembly.** RFC 3261 §7.5 frames SIP over TCP by Content-Length, not
  by packet boundaries. A message may span several segments, and several
  messages may share one segment. The ESInet captures this targets carry SIP
  predominantly over TCP, so treating one packet as one message both loses long
  messages and miscounts pipelined ones.

* **Resynchronisation.** Captures routinely begin mid-connection. Rather than
  discarding a stream whose first bytes are a message fragment, the assembler
  scans forward to the next plausible start line and resumes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from .pcap import Packet
from .privacy import Pseudonymiser

SIP_METHODS = frozenset(
    {
        "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "SUBSCRIBE",
        "NOTIFY", "REFER", "MESSAGE", "INFO", "PRACK", "UPDATE", "PUBLISH",
    }
)

DEFAULT_SIP_PORTS = frozenset({5060, 5061, 5062})

# Compact header forms (RFC 3261 §20) seen from constrained user agents.
_COMPACT = {
    "i": "call-id", "m": "contact", "e": "content-encoding", "l": "content-length",
    "c": "content-type", "f": "from", "s": "subject", "k": "supported",
    "t": "to", "v": "via", "x": "session-expires", "o": "event", "r": "refer-to",
    "b": "referred-by", "j": "reject-contact", "d": "request-disposition",
    "a": "accept-contact", "u": "allow-events", "y": "identity",
}

_SEPARATOR = b"\r\n\r\n"
_SEPARATOR_LF = b"\n\n"
_START_LINE_RE = re.compile(
    rb"(?:^|\r\n|\n)((?:" + b"|".join(m.encode() for m in sorted(SIP_METHODS)) + rb")\s+\S+\s+SIP/2\.0|SIP/2\.0\s+\d{3})"
)

# A desynchronised stream must not grow without bound.
_MAX_BUFFER = 1 << 20


@dataclass(slots=True)
class SipMessage:
    """One parsed SIP message, with identities already pseudonymised."""

    capture_file: str
    packet_number: int
    timestamp: float

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    message_size: int

    message_type: str                 # "request" or "response"
    method: str | None = None         # request method
    status_code: int | None = None    # response status
    cseq_number: int | None = None
    cseq_method: str | None = None    # the method a response answers

    call_id: str | None = None        # pseudonymised
    from_user: str | None = None      # pseudonymised
    from_host: str | None = None
    to_user: str | None = None        # pseudonymised
    to_host: str | None = None
    request_uri_user: str | None = None
    request_uri_host: str | None = None
    contact_host: str | None = None

    user_agent: str | None = None
    via_count: int = 0
    max_forwards: int | None = None
    content_length: int | None = None
    has_sdp: bool = False
    has_geolocation: bool = False     # NG911 i3 location by reference/value
    has_auth: bool = False            # Authorization / Proxy-Authorization present
    is_emergency_service: bool = False  # addressed to urn:service:sos (RFC 5031)

    @property
    def is_request(self) -> bool:
        return self.message_type == "request"


@dataclass(slots=True)
class ParseStats:
    """Counters that make parser health visible instead of silent."""

    packets: int = 0
    messages: int = 0
    resyncs: int = 0
    keepalives: int = 0
    truncated_streams: int = 0
    undecodable: int = 0


def _split_headers(block: str) -> dict[str, list[str]]:
    """Parse a header block, unfolding continuations and keeping repeats."""
    headers: dict[str, list[str]] = {}
    current: str | None = None

    for line in block.split("\n"):
        line = line.rstrip("\r")
        if not line:
            continue
        if line[0] in " \t" and current:
            headers[current][-1] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        name = _COMPACT.get(name, name)
        current = name
        headers.setdefault(name, []).append(value.strip())

    return headers


def _first(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def _parse_start_line(line: str) -> tuple[str, str | None, int | None, str | None] | None:
    """Return (message_type, method, status_code, request_uri)."""
    parts = line.split()
    if len(parts) < 2:
        return None

    if parts[0].upper().startswith("SIP/2.0"):
        if not parts[1].isdigit():
            return None
        code = int(parts[1])
        if not 100 <= code <= 699:
            return None
        return "response", None, code, None

    method = parts[0].upper()
    if method in SIP_METHODS and len(parts) >= 3 and parts[-1].upper().startswith("SIP/2.0"):
        return "request", method, None, parts[1]

    return None


def parse_message(
    raw: bytes,
    packet: Packet,
    capture_file: str,
    pseudonymiser: Pseudonymiser,
) -> SipMessage | None:
    """Parse one complete SIP message. Returns None if it is not valid SIP."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Non-UTF-8 bodies are legal; headers are ASCII, so salvage those.
        text = raw.decode("utf-8", "replace")

    separator = text.find("\r\n\r\n")
    if separator == -1:
        separator = text.find("\n\n")
        head = text[:separator] if separator != -1 else text
    else:
        head = text[:separator]

    line_end = head.find("\n")
    start_line = (head if line_end == -1 else head[:line_end]).strip()
    parsed = _parse_start_line(start_line)
    if parsed is None:
        return None

    message_type, method, status_code, request_uri = parsed
    headers = _split_headers(head[line_end + 1 :] if line_end != -1 else "")

    cseq_number: int | None = None
    cseq_method: str | None = None
    cseq = _first(headers, "cseq")
    if cseq:
        bits = cseq.split()
        if bits and bits[0].isdigit():
            cseq_number = int(bits[0])
        if len(bits) > 1:
            cseq_method = bits[1].upper()

    content_length: int | None = None
    raw_length = _first(headers, "content-length")
    if raw_length and raw_length.strip().isdigit():
        content_length = int(raw_length.strip())

    max_forwards: int | None = None
    raw_forwards = _first(headers, "max-forwards")
    if raw_forwards and raw_forwards.strip().isdigit():
        max_forwards = int(raw_forwards.strip())

    from_user, from_host = pseudonymiser.split_uri(_first(headers, "from"))
    to_user, to_host = pseudonymiser.split_uri(_first(headers, "to"))
    uri_user, uri_host = pseudonymiser.split_uri(request_uri)
    _, contact_host = pseudonymiser.split_uri(_first(headers, "contact"))

    content_type = (_first(headers, "content-type") or "").lower()

    # An i3 emergency call is addressed to a service URN; keepalives are not.
    emergency = any(
        host is not None and host.startswith("urn:service:sos")
        for host in (uri_host, to_host)
    )

    return SipMessage(
        capture_file=capture_file,
        packet_number=packet.packet_number,
        timestamp=packet.timestamp,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        transport=packet.transport,
        message_size=len(raw),
        message_type=message_type,
        method=method,
        status_code=status_code,
        cseq_number=cseq_number,
        cseq_method=cseq_method,
        call_id=pseudonymiser.token(_first(headers, "call-id")),
        from_user=from_user,
        from_host=from_host,
        to_user=to_user,
        to_host=to_host,
        request_uri_user=uri_user,
        request_uri_host=uri_host,
        contact_host=contact_host,
        user_agent=_first(headers, "user-agent") or _first(headers, "server"),
        via_count=len(headers.get("via", [])),
        max_forwards=max_forwards,
        content_length=content_length,
        has_sdp="application/sdp" in content_type,
        has_geolocation="geolocation" in headers or "geolocation-routing" in headers,
        has_auth="authorization" in headers or "proxy-authorization" in headers,
        is_emergency_service=emergency,
    )


class SipReassembler:
    """Turns a packet stream into complete SIP messages.

    UDP datagrams are self-delimiting and parsed directly. TCP segments are
    buffered per direction and split on Content-Length, which is what makes
    segmented and pipelined messages come out correctly.
    """

    def __init__(self, pseudonymiser: Pseudonymiser) -> None:
        self._pseudonymiser = pseudonymiser
        self._buffers: dict[tuple, bytearray] = {}
        self._packets: dict[tuple, Packet] = {}
        self.stats = ParseStats()

    def feed(self, packet: Packet, capture_file: str) -> Iterator[SipMessage]:
        """Yield every complete SIP message this packet completes."""
        self.stats.packets += 1
        if not packet.payload:
            return

        if packet.transport == "UDP":
            message = parse_message(
                packet.payload, packet, capture_file, self._pseudonymiser
            )
            if message is not None:
                self.stats.messages += 1
                yield message
            return

        key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        buffer = self._buffers.get(key)
        if buffer is None:
            buffer = bytearray()
            self._buffers[key] = buffer
        buffer += packet.payload
        self._packets[key] = packet

        yield from self._drain(key, buffer, packet, capture_file)

    def _drain(
        self,
        key: tuple,
        buffer: bytearray,
        packet: Packet,
        capture_file: str,
    ) -> Iterator[SipMessage]:
        """Pull every complete message out of one direction's buffer."""
        while True:
            # SIP over TCP uses a bare CRLF (or CRLFCRLF) as a keepalive ping.
            while buffer[:2] == b"\r\n":
                del buffer[:2]
                self.stats.keepalives += 1
            if not buffer:
                return

            separator_len = 4
            end = buffer.find(_SEPARATOR)
            if end == -1:
                end = buffer.find(_SEPARATOR_LF)
                separator_len = 2
            if end == -1:
                if len(buffer) > _MAX_BUFFER:
                    self.stats.truncated_streams += 1
                    buffer.clear()
                return

            head = bytes(buffer[:end])
            if not self._looks_like_start(head):
                if not self._resync(buffer):
                    return
                continue

            body_at = end + separator_len
            length = self._content_length(head)
            if length is None:
                length = 0
            total = body_at + length
            if len(buffer) < total:
                if len(buffer) > _MAX_BUFFER:
                    self.stats.truncated_streams += 1
                    buffer.clear()
                return

            raw = bytes(buffer[:total])
            del buffer[:total]

            message = parse_message(raw, packet, capture_file, self._pseudonymiser)
            if message is not None:
                self.stats.messages += 1
                yield message
            else:
                self.stats.undecodable += 1

    @staticmethod
    def _looks_like_start(head: bytes) -> bool:
        first = head.split(b"\n", 1)[0].strip()
        if first.upper().startswith(b"SIP/2.0"):
            return True
        method = first.split(b" ", 1)[0].upper()
        return method.decode("ascii", "ignore") in SIP_METHODS

    def _resync(self, buffer: bytearray) -> bool:
        """Drop bytes up to the next plausible start line. False if none yet."""
        match = _START_LINE_RE.search(bytes(buffer), 1)
        if match is None:
            if len(buffer) > _MAX_BUFFER:
                buffer.clear()
                self.stats.truncated_streams += 1
            return False
        del buffer[: match.start(1)]
        self.stats.resyncs += 1
        return True

    @staticmethod
    def _content_length(head: bytes) -> int | None:
        for line in head.split(b"\n"):
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith(b"content-length:") or lowered.startswith(b"l:"):
                _, _, value = stripped.partition(b":")
                value = value.strip()
                if value.isdigit():
                    return int(value)
        return None
