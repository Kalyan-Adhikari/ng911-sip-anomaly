"""Deterministic rules for conditions a baseline model structurally cannot learn.

An unsupervised model can only flag what deviates from what it saw. Some
conditions never occur in a clean baseline at all, so the feature that would
expose them is constant during training and gets pruned -- and even if kept, a
tree has no split point to learn from a column that never varies.

A low-rate scan from a host outside the ESInet mesh is the clearest case. It
adds perhaps one message per second to a mesh already doing several, so every
volume feature stays in range, yet it is by definition traffic from somewhere
that should not be sending SIP at all. That is a fact to assert, not a
distribution to estimate.

Rules complement the model rather than replacing it: the model catches
distributional shifts, and these catch structural violations. A window flagged
by either is reported, with the reason attached so an operator knows which.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pandas as pd


@dataclass(frozen=True, slots=True)
class Rule:
    """One structural condition worth alerting on by itself."""

    name: str
    description: str
    test: Callable[[pd.DataFrame], pd.Series]
    requires: tuple[str, ...]

    def applies_to(self, frame: pd.DataFrame) -> bool:
        return all(column in frame.columns for column in self.requires)


def _offmesh_traffic(frame: pd.DataFrame) -> pd.Series:
    return frame["offmesh_source_count"] > 0


def _auth_storm(frame: pd.DataFrame) -> pd.Series:
    # Digest challenges that are never completed. Normal registration always
    # completes, so a burst of unanswered challenges is credential stuffing.
    return frame["unanswered_challenge_count"] >= 10


def _mesh_silent(frame: pd.DataFrame) -> pd.Series:
    # On a keepalive-driven ESInet, a window inside a capture with no SIP at all
    # means an element stopped answering.
    return frame["is_gap_filled"] == 1


def _single_source_domination(frame: pd.DataFrame) -> pd.Series:
    # One host responsible for nearly all traffic in a busy window is the TDoS
    # shape; the volume bar keeps ordinary quiet windows out.
    return (frame["top_source_share"] > 0.9) & (frame["total_messages"] >= 50)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        "offmesh_traffic",
        "SIP from a host that is not an established member of the mesh",
        _offmesh_traffic,
        ("offmesh_source_count",),
    ),
    Rule(
        "auth_storm",
        "10 or more digest challenges in one window with no completion",
        _auth_storm,
        ("unanswered_challenge_count",),
    ),
    Rule(
        "mesh_silent",
        "no SIP at all in a window inside an observed capture span",
        _mesh_silent,
        ("is_gap_filled",),
    ),
    Rule(
        "single_source_domination",
        "one source accounts for over 90% of a busy window",
        _single_source_domination,
        ("top_source_share", "total_messages"),
    ),
)


def apply_rules(
    frame: pd.DataFrame,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> tuple[pd.Series, pd.Series]:
    """Return (triggered, reasons) for every row.

    ``reasons`` is a comma-separated list of the rules that fired, empty where
    none did, so a flagged window always explains itself.
    """
    triggered = pd.Series(False, index=frame.index)
    collected: list[list[str]] = [[] for _ in range(len(frame))]

    for rule in rules:
        if not rule.applies_to(frame):
            continue
        hit = rule.test(frame).fillna(False).astype(bool)
        if not hit.any():
            continue
        triggered |= hit
        for position in range(len(frame)):
            if hit.iloc[position]:
                collected[position].append(rule.name)

    reasons = pd.Series(
        [",".join(names) for names in collected], index=frame.index, dtype="object"
    )
    return triggered, reasons
