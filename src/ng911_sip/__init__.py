"""SIP anomaly detection for NG911 ESInet traffic."""

from __future__ import annotations

__version__ = "0.1.0"

from .features import CaptureSpan, build_source_windows, build_windows
from .model import AnomalyDetector, evaluate, train
from .pcap import Packet, find_captures, iter_packets
from .pipeline import build_feature_frame, parse_captures, read_frame, write_frame
from .privacy import Pseudonymiser
from .sip import SipMessage, SipReassembler, parse_message

__all__ = [
    "__version__",
    "AnomalyDetector",
    "CaptureSpan",
    "Packet",
    "Pseudonymiser",
    "SipMessage",
    "SipReassembler",
    "build_feature_frame",
    "build_source_windows",
    "build_windows",
    "evaluate",
    "find_captures",
    "iter_packets",
    "parse_captures",
    "parse_message",
    "read_frame",
    "train",
    "write_frame",
]
