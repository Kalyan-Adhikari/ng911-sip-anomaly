"""Parser tests, concentrating on the framing the old per-packet parser got wrong."""

from __future__ import annotations

from conftest import ethernet_frame, sip_request, sip_response

from ng911_sip.pcap import Packet
from ng911_sip.sip import SipReassembler, parse_message


def packet(payload: bytes, transport: str = "TCP", number: int = 1, timestamp: float = 100.0):
    return Packet(
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5060,
        dst_port=5060,
        transport=transport,
        payload=payload,
        frame_length=len(payload) + 54,
        packet_number=number,
    )


def test_parses_request_and_response(pseudonymiser):
    request = parse_message(sip_request("INVITE"), packet(b""), "c.pcap", pseudonymiser)
    assert request is not None
    assert request.is_request and request.method == "INVITE"

    response = parse_message(sip_response(404, "Not Found"), packet(b""), "c.pcap", pseudonymiser)
    assert response is not None
    assert not response.is_request
    assert response.status_code == 404
    assert response.cseq_method == "OPTIONS"


def test_message_split_across_tcp_segments(pseudonymiser):
    """RFC 3261 frames SIP over TCP by Content-Length, not packet boundary."""
    whole = sip_request("INVITE", body="v=0\r\n" + "a=x\r\n" * 200)
    cut = len(whole) // 2
    assembler = SipReassembler(pseudonymiser)

    assert list(assembler.feed(packet(whole[:cut], number=1), "c.pcap")) == []
    messages = list(assembler.feed(packet(whole[cut:], number=2), "c.pcap"))

    assert len(messages) == 1
    assert messages[0].method == "INVITE"
    assert messages[0].content_length == len(whole) - whole.index(b"\r\n\r\n") - 4


def test_multiple_messages_in_one_segment(pseudonymiser):
    """Pipelined messages must be counted separately, not as one."""
    payload = sip_request("OPTIONS", cseq=1) + sip_response(200, cseq=1) + sip_request(
        "OPTIONS", cseq=2
    )
    assembler = SipReassembler(pseudonymiser)
    messages = list(assembler.feed(packet(payload), "c.pcap"))

    assert len(messages) == 3
    assert [m.message_type for m in messages] == ["request", "response", "request"]


def test_resynchronises_on_a_stream_joined_mid_message(pseudonymiser):
    """Captures routinely start mid-connection; the stream must recover."""
    assembler = SipReassembler(pseudonymiser)
    garbage = b"ntent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n"
    messages = list(assembler.feed(packet(garbage + sip_request("BYE")), "c.pcap"))

    assert [m.method for m in messages] == ["BYE"]
    assert assembler.stats.resyncs == 1


def test_tcp_keepalive_pings_are_not_messages(pseudonymiser):
    assembler = SipReassembler(pseudonymiser)
    messages = list(assembler.feed(packet(b"\r\n\r\n" + sip_request("OPTIONS")), "c.pcap"))

    assert len(messages) == 1
    assert assembler.stats.keepalives == 2


def test_udp_datagram_is_parsed_directly(pseudonymiser):
    assembler = SipReassembler(pseudonymiser)
    messages = list(assembler.feed(packet(sip_request("REGISTER"), transport="UDP"), "c.pcap"))
    assert [m.method for m in messages] == ["REGISTER"]


def test_compact_header_forms(pseudonymiser):
    """Constrained user agents send single-letter header names."""
    raw = (
        b"OPTIONS sip:psap.example SIP/2.0\r\n"
        b"v: SIP/2.0/UDP 10.0.0.1\r\n"
        b"f: <sip:caller@10.0.0.1>;tag=1\r\n"
        b"t: <sip:psap.example>\r\n"
        b"i: compact-call-id\r\n"
        b"CSeq: 4 OPTIONS\r\n"
        b"l: 0\r\n\r\n"
    )
    message = parse_message(raw, packet(b""), "c.pcap", pseudonymiser)
    assert message is not None
    assert message.call_id == pseudonymiser.token("compact-call-id")
    assert message.via_count == 1
    assert message.content_length == 0


def test_folded_header_continuation(pseudonymiser):
    raw = (
        b"OPTIONS sip:psap.example SIP/2.0\r\n"
        b"Via: SIP/2.0/TCP 10.0.0.1;\r\n branch=z9hG4bKfolded\r\n"
        b"Call-ID: folded\r\n"
        b"CSeq: 1 OPTIONS\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    message = parse_message(raw, packet(b""), "c.pcap", pseudonymiser)
    assert message is not None and message.via_count == 1


def test_emergency_service_urn_is_recognised(pseudonymiser):
    """NG911 i3 addresses calls to urn:service:sos, not user@host."""
    raw = sip_request("INVITE", uri="urn:service:sos", extra="Geolocation: <cid:x@y>\r\n")
    message = parse_message(raw, packet(b""), "c.pcap", pseudonymiser)

    assert message is not None
    assert message.is_emergency_service
    assert message.request_uri_host == "urn:service:sos"
    assert message.request_uri_user is None  # a service, not a person
    assert message.has_geolocation


def test_non_sip_payload_is_rejected(pseudonymiser):
    assert parse_message(b"\x80\x00\x00\x01rtp", packet(b""), "c.pcap", pseudonymiser) is None
    assert parse_message(b"GET / HTTP/1.1\r\n\r\n", packet(b""), "c.pcap", pseudonymiser) is None


def test_invalid_status_code_is_rejected(pseudonymiser):
    raw = b"SIP/2.0 999 Nonsense\r\nCall-ID: x\r\nContent-Length: 0\r\n\r\n"
    assert parse_message(raw, packet(b""), "c.pcap", pseudonymiser) is None


def test_desynchronised_stream_does_not_grow_without_bound(pseudonymiser):
    assembler = SipReassembler(pseudonymiser)
    for i in range(40):
        list(assembler.feed(packet(b"X" * 60_000, number=i), "c.pcap"))
    assert assembler.stats.truncated_streams >= 1
