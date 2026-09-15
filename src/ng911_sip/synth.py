"""Synthetic ESInet traffic for validating the detector without real captures.

Real NG911 captures cannot be committed to a repository, which in the pipeline
this replaces meant the detection half was never exercised at all: a scoring
function existed but nothing called it, and the only "attack" fixture was three
packets that every model scored as more normal than the baseline.

This module generates traffic shaped like a real ESInet -- an OPTIONS keepalive
mesh between a handful of fixed elements, with occasional emergency INVITEs
carrying Geolocation and addressed to urn:service:sos -- plus labelled attacks
against it. That makes ``ng911-sip validate`` a self-contained proof that the
pipeline detects what it claims to, runnable by anyone who clones the repo.

The shape here was taken from measurements of a production ESInet capture: SIP
predominantly over TCP, roughly 2.4 OPTIONS exchanges per second across a small
peer mesh, and emergency calls several orders of magnitude rarer.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from pathlib import Path

# A small fixed mesh standing in for a BCF, two SBCs and an ESRP. These are
# RFC 5737 documentation addresses, not any real deployment: the shape of the
# traffic is what was measured from production, never the addressing.
ELEMENTS = ("192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40")
PSAP_HOST = "psap1-sbc.ng911.example"
BASE_EPOCH = 1_700_000_000.0


@dataclass(slots=True)
class Scenario:
    """One labelled traffic scenario."""

    name: str
    description: str
    label: int


SCENARIOS = {
    "invite_flood": Scenario(
        "invite_flood",
        "TDoS: one host drives emergency INVITEs far above the mesh rate",
        1,
    ),
    "register_brute": Scenario(
        "register_brute",
        "Credential stuffing: REGISTER storm challenged but never completed",
        1,
    ),
    "options_scan": Scenario(
        "options_scan",
        "Enumeration: an unknown host sweeps extensions with OPTIONS",
        1,
    ),
    "keepalive_blackout": Scenario(
        "keepalive_blackout",
        "Element failure: the keepalive mesh goes silent mid-capture",
        1,
    ),
    "baseline": Scenario("baseline", "Normal ESInet keepalive mesh", 0),
}


def _frame(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int = 5060,
    dst_port: int = 5060,
) -> bytes:
    """Wrap a SIP payload in Ethernet/IPv4/TCP."""
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 5 << 4, 0x18, 8192, 0, 0)
    body = tcp + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(body), 0, 0, 64, 6, 0,
        bytes(int(o) for o in src_ip.split(".")),
        bytes(int(o) for o in dst_ip.split(".")),
    )
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + ip + body


def write_pcap(path: str | Path, packets: list[tuple[float, bytes]]) -> Path:
    """Write a little-endian classic pcap with an Ethernet link type."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = sorted(packets, key=lambda item: item[0])

    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for timestamp, frame in packets:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)
    return path


def _options(src: str, dst: str, cseq: int) -> bytes:
    return (
        f"OPTIONS sip:{dst}:5060 SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP {src}:5060;branch=z9hG4bK{cseq:08x}\r\n"
        f"From: <sip:{src}>;tag=gK{cseq:08x}\r\n"
        f"To: <sip:{dst}>\r\n"
        f"Call-ID: {cseq:08x}_{src}\r\n"
        f"CSeq: {cseq} OPTIONS\r\n"
        f"Contact: <sip:{src}:5060;transport=tcp>\r\n"
        f"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def _ok(src: str, dst: str, cseq: int, method: str = "OPTIONS") -> bytes:
    return (
        f"SIP/2.0 200 OK\r\n"
        f"Via: SIP/2.0/TCP {dst}:5060;branch=z9hG4bK{cseq:08x}\r\n"
        f"From: <sip:{dst}>;tag=gK{cseq:08x}\r\n"
        f"To: <sip:{src}>;tag=as{cseq:08x}\r\n"
        f"Call-ID: {cseq:08x}_{dst}\r\n"
        f"CSeq: {cseq} {method}\r\n"
        f"Server: ExampleBCF\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def _emergency_invite(src: str, dst: str, cseq: int, caller: str) -> bytes:
    """An i3 emergency INVITE: service URN, Geolocation, SDP body."""
    body = (
        "v=0\r\no=- 1 1 IN IP4 " + src + "\r\ns=-\r\n"
        "c=IN IP4 " + src + "\r\nt=0 0\r\n"
        "m=audio 16400 RTP/AVP 0 8 101\r\na=sendrecv\r\n"
    )
    headers = (
        f"INVITE urn:service:sos SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP {src}:5060;branch=z9hG4bK{cseq:08x}\r\n"
        f"From: <sip:{caller}@{src}>;tag=t{cseq:08x}\r\n"
        f"To: <urn:service:sos>\r\n"
        f"Call-ID: call-{cseq:08x}@{src}\r\n"
        f"CSeq: {cseq} INVITE\r\n"
        f"Contact: <sip:{caller}@{src}:5060;transport=tcp>\r\n"
        f"Geolocation: <cid:target{cseq}@{PSAP_HOST}>;routing-allowed=yes\r\n"
        f"Call-Info: <urn:emergency:uid:callid:{cseq:032x}:{PSAP_HOST}>;"
        f"purpose=emergency-CallId\r\n"
        f"Max-Forwards: 69\r\nUser-Agent: ExampleESRP\r\n"
        f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n"
    )
    return (headers + body).encode()


def _register(src: str, dst: str, cseq: int, user: str) -> bytes:
    return (
        f"REGISTER sip:{dst} SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP {src}:5060;branch=z9hG4bK{cseq:08x}\r\n"
        f"From: <sip:{user}@{dst}>;tag=t{cseq:08x}\r\n"
        f"To: <sip:{user}@{dst}>\r\n"
        f"Call-ID: reg-{cseq:08x}@{src}\r\n"
        f"CSeq: {cseq} REGISTER\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def _challenge(src: str, dst: str, cseq: int) -> bytes:
    return (
        f"SIP/2.0 401 Unauthorized\r\n"
        f"Via: SIP/2.0/TCP {src}:5060;branch=z9hG4bK{cseq:08x}\r\n"
        f"From: <sip:u@{dst}>;tag=t{cseq:08x}\r\n"
        f"To: <sip:u@{dst}>;tag=s{cseq:08x}\r\n"
        f"Call-ID: reg-{cseq:08x}@{src}\r\n"
        f"CSeq: {cseq} REGISTER\r\n"
        f'WWW-Authenticate: Digest realm="{dst}",nonce="{cseq:016x}"\r\n'
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def baseline_packets(
    duration_seconds: int,
    start: float = BASE_EPOCH,
    seed: int = 7,
) -> list[tuple[float, bytes]]:
    """A steady keepalive mesh with occasional emergency calls."""
    rng = random.Random(seed)
    packets: list[tuple[float, bytes]] = []
    cseq = 1000

    # Each ordered element pair exchanges OPTIONS about every 5 seconds.
    pairs = [(a, b) for a in ELEMENTS for b in ELEMENTS if a != b]
    for pair_index, (src, dst) in enumerate(pairs):
        offset = rng.uniform(0, 5.0)
        moment = start + offset
        while moment < start + duration_seconds:
            cseq += 1
            packets.append((moment, _frame(_options(src, dst, cseq), src, dst)))
            packets.append((moment + 0.004, _frame(_ok(src, dst, cseq), dst, src)))
            moment += 5.0 + rng.uniform(-0.4, 0.4)

    # Emergency calls are rare: a handful per hour, each a full dialog.
    call_count = max(1, duration_seconds // 600)
    for index in range(call_count):
        cseq += 1
        moment = start + rng.uniform(5, max(6, duration_seconds - 20))
        src, dst = ELEMENTS[1], ELEMENTS[2]
        caller = f"+1555{rng.randint(1000, 9999)}"
        packets.append((moment, _frame(_emergency_invite(src, dst, cseq, caller), src, dst)))
        packets.append((moment + 0.02, _frame(_ok(src, dst, cseq, "INVITE"), dst, src)))
        packets.append((moment + 8.0, _frame(
            _options(src, dst, cseq + 1), src, dst)))

    return packets


def attack_packets(
    kind: str,
    start: float,
    duration_seconds: int = 60,
    intensity: int = 40,
    seed: int = 11,
) -> list[tuple[float, bytes]]:
    """Attack traffic of the requested kind, beginning at ``start``."""
    rng = random.Random(seed)
    packets: list[tuple[float, bytes]] = []
    attacker = "198.51.100.66"
    victim = ELEMENTS[0]

    if kind == "invite_flood":
        total = intensity * duration_seconds
        for index in range(total):
            moment = start + index * (duration_seconds / total)
            packets.append((
                moment,
                _frame(_emergency_invite(attacker, victim, 50_000 + index, "+15550000"),
                       attacker, victim),
            ))
        return packets

    if kind == "register_brute":
        total = intensity * duration_seconds
        for index in range(total):
            moment = start + index * (duration_seconds / total)
            cseq = 60_000 + index
            packets.append((moment, _frame(
                _register(attacker, victim, cseq, f"user{index}"), attacker, victim)))
            packets.append((moment + 0.003, _frame(
                _challenge(attacker, victim, cseq), victim, attacker)))
        return packets

    if kind == "options_scan":
        # Deliberately low volume: this must be caught by who and how, not how much.
        for index in range(duration_seconds):
            moment = start + index + rng.uniform(0, 0.4)
            packets.append((moment, _frame(
                _options(attacker, victim, 70_000 + index), attacker, victim)))
        return packets

    if kind == "keepalive_blackout":
        return []  # The absence of traffic is the attack; see build_scenario.

    raise ValueError(f"unknown scenario {kind!r}; choose from {sorted(SCENARIOS)}")


def build_scenario(
    kind: str,
    output: str | Path,
    baseline_seconds: int = 900,
    attack_seconds: int = 60,
    intensity: int = 40,
    seed: int = 7,
) -> Path:
    """Write one capture containing baseline traffic and, if any, an attack."""
    if kind not in SCENARIOS:
        raise ValueError(f"unknown scenario {kind!r}; choose from {sorted(SCENARIOS)}")

    packets = baseline_packets(baseline_seconds, seed=seed)
    attack_start = BASE_EPOCH + baseline_seconds * 0.6

    if kind == "keepalive_blackout":
        # Drop every packet in the blackout interval: the mesh stops answering.
        stop = attack_start + attack_seconds
        packets = [p for p in packets if not attack_start <= p[0] < stop]
    elif kind != "baseline":
        packets.extend(
            attack_packets(kind, attack_start, attack_seconds, intensity, seed + 1)
        )

    return write_pcap(output, packets)


def attack_window_range(
    baseline_seconds: int = 900,
    attack_seconds: int = 60,
) -> tuple[float, float]:
    """Epoch bounds of the attack, for labelling the windows it covers."""
    start = BASE_EPOCH + baseline_seconds * 0.6
    return start, start + attack_seconds
