"""Rule tests, including the end-to-end case the model alone cannot catch."""

from __future__ import annotations

import pandas as pd

from ng911_sip.rules import DEFAULT_RULES, apply_rules


def frame(**overrides) -> pd.DataFrame:
    base = {
        "offmesh_source_count": [0],
        "unanswered_challenge_count": [0],
        "is_gap_filled": [0],
        "top_source_share": [0.3],
        "total_messages": [48],
    }
    base.update({key: [value] for key, value in overrides.items()})
    return pd.DataFrame(base)


def test_clean_window_triggers_nothing():
    triggered, reasons = apply_rules(frame())
    assert not triggered.iloc[0]
    assert reasons.iloc[0] == ""


def test_offmesh_source_triggers():
    triggered, reasons = apply_rules(frame(offmesh_source_count=1))
    assert triggered.iloc[0]
    assert "offmesh_traffic" in reasons.iloc[0]


def test_auth_storm_needs_volume_not_a_single_challenge():
    """One unanswered challenge is ordinary; a burst of them is not."""
    assert not apply_rules(frame(unanswered_challenge_count=1))[0].iloc[0]
    assert apply_rules(frame(unanswered_challenge_count=12))[0].iloc[0]


def test_silent_window_triggers():
    triggered, reasons = apply_rules(frame(is_gap_filled=1))
    assert triggered.iloc[0]
    assert "mesh_silent" in reasons.iloc[0]


def test_domination_requires_a_busy_window():
    """A quiet window with one talker is normal; a busy one is a flood."""
    assert not apply_rules(frame(top_source_share=0.95, total_messages=4))[0].iloc[0]
    assert apply_rules(frame(top_source_share=0.95, total_messages=200))[0].iloc[0]


def test_multiple_reasons_are_reported_together():
    _, reasons = apply_rules(
        frame(offmesh_source_count=2, top_source_share=0.99, total_messages=300)
    )
    assert "offmesh_traffic" in reasons.iloc[0]
    assert "single_source_domination" in reasons.iloc[0]


def test_rules_skip_frames_missing_their_columns():
    """Per-source frames lack some columns; that must not raise."""
    partial = pd.DataFrame({"total_messages": [10]})
    triggered, reasons = apply_rules(partial)
    assert not triggered.any()
    assert (reasons == "").all()


def test_every_default_rule_declares_its_columns():
    for rule in DEFAULT_RULES:
        assert rule.requires
        assert rule.description
