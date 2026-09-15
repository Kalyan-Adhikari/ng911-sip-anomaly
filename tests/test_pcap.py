"""Reader tests: framing, filtering, and the failure modes real directories hit."""

from __future__ import annotations

import struct

from conftest import ethernet_frame, sip_request, write_pcap

from ng911_sip.pcap import find_captures, iter_packets


def test_reads_tcp_and_udp(tmp_path):
    path = write_pcap(
        tmp_path / "mixed.pcap",
        [
            (1000.0, ethernet_frame(b"tcp-payload", protocol="TCP")),
            (1001.5, ethernet_frame(b"udp-payload", protocol="UDP")),
        ],
    )
    packets = list(iter_packets(path))

    assert [p.transport for p in packets] == ["TCP", "UDP"]
    assert [p.payload for p in packets] == [b"tcp-payload", b"udp-payload"]
    assert packets[1].timestamp == 1001.5
    assert packets[0].src_ip == "10.0.0.1"
    assert packets[0].dst_port == 5060


def test_port_filter_rejects_before_payload():
    """The filter is the reason large captures are tractable, so it must bite."""
    frames = [
        (1.0, ethernet_frame(b"sip", src_port=5060, dst_port=5060)),
        (2.0, ethernet_frame(b"web", src_port=44321, dst_port=443)),
        (3.0, ethernet_frame(b"rtp", src_port=16384, dst_port=16385, protocol="UDP")),
    ]
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        path = write_pcap(Path(directory) / "f.pcap", frames)
        assert len(list(iter_packets(path))) == 3
        kept = list(iter_packets(path, ports={5060}))
        assert len(kept) == 1
        assert kept[0].payload == b"sip"


def test_vlan_tagged_frames_are_decoded(tmp_path):
    path = write_pcap(
        tmp_path / "vlan.pcap",
        [(1.0, ethernet_frame(sip_request(), vlan=2410))],
    )
    packets = list(iter_packets(path, ports={5060}))
    assert len(packets) == 1
    assert packets[0].payload.startswith(b"OPTIONS")


def test_truncated_file_yields_what_it_can(tmp_path):
    """An interrupted transfer must not lose the packets that did arrive."""
    path = write_pcap(
        tmp_path / "cut.pcap",
        [(1.0, ethernet_frame(b"first")), (2.0, ethernet_frame(b"second"))],
    )
    data = path.read_bytes()
    path.write_bytes(data[: len(data) - 10])  # chop the last record mid-body

    packets = list(iter_packets(path))
    assert len(packets) == 1
    assert packets[0].payload == b"first"


def test_big_endian_capture(tmp_path):
    """Captures written on a big-endian host use the swapped magic."""
    frame = ethernet_frame(b"payload")
    path = tmp_path / "be.pcap"
    with path.open("wb") as handle:
        handle.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        handle.write(struct.pack(">IIII", 7, 500_000, len(frame), len(frame)))
        handle.write(frame)

    packets = list(iter_packets(path))
    assert len(packets) == 1
    assert packets[0].timestamp == 7.5


def test_find_captures_skips_partial_downloads(tmp_path):
    (tmp_path / "a.pcap").write_bytes(b"")
    (tmp_path / "b.pcapng").write_bytes(b"")
    (tmp_path / "Unconfirmed 1234.crdownload").write_bytes(b"")
    (tmp_path / "notes.txt").write_bytes(b"")
    nested = tmp_path / "day2"
    nested.mkdir()
    (nested / "c.pcap").write_bytes(b"")

    names = [p.name for p in find_captures(tmp_path)]
    assert names == ["a.pcap", "b.pcapng", "c.pcap"]


def test_find_captures_accepts_a_single_file(tmp_path):
    path = tmp_path / "one.pcap"
    path.write_bytes(b"")
    assert find_captures(path) == [path]
