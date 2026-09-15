"""Model tests: calibration honesty, feature pruning, artifact integrity."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ng911_sip.model import (
    AnomalyDetector,
    ArtifactIntegrityError,
    NotEnoughDataError,
    evaluate,
    select_features,
    train,
)


def synthetic_windows(count: int = 400, seed: int = 3) -> pd.DataFrame:
    """A plausible baseline: steady keepalives with mild natural variation."""
    rng = np.random.default_rng(seed)
    start = 1_700_000_000
    messages = rng.poisson(48, count)

    return pd.DataFrame(
        {
            "window_start_epoch": [start + i * 10 for i in range(count)],
            "window_end_epoch": [start + i * 10 + 10 for i in range(count)],
            "window_seconds": 10,
            "is_gap_filled": 0,
            "capture_file": "synthetic.pcap",
            "total_messages": messages,
            "request_count": messages // 2,
            "response_count": messages - messages // 2,
            "options_count": messages // 2,
            "invite_count": rng.poisson(0.2, count),
            "unique_src_ips": rng.integers(3, 5, count),
            "mean_message_size": rng.normal(380, 12, count),
            "method_entropy": rng.normal(0.4, 0.05, count),
            "top_source_share": rng.normal(0.3, 0.02, count),
            "unanswered_challenge_count": 0,
            "offmesh_source_count": 0,
            "hour_sin": np.sin(np.arange(count) / 50),
            "hour_cos": np.cos(np.arange(count) / 50),
        }
    )


def test_threshold_comes_from_held_out_data_not_contamination():
    """The replaced pipeline flagged 10% of training data by construction."""
    frame = synthetic_windows()
    detector = train(frame, model_name="iforest", target_fpr=0.01)

    assert detector.calibration.target_fpr == 0.01
    # Within a window or two of target on a few hundred calibration rows.
    assert detector.calibration.achieved_fpr < 0.06
    assert detector.calibration.calibration_windows > 0
    assert detector.training_windows + detector.calibration.calibration_windows == len(frame)


def test_calibration_split_is_temporal_not_random():
    """Shuffling would leak autocorrelated neighbours across the split."""
    frame = synthetic_windows(300)
    detector = train(frame, target_fpr=0.02, calibration_fraction=0.3)

    assert detector.training_windows == int(300 * 0.7)
    assert detector.calibration.calibration_windows == 300 - int(300 * 0.7)


def test_alerts_per_day_is_reported():
    detector = train(synthetic_windows(), target_fpr=0.01)
    estimate = detector.calibration.alerts_per_day_estimate
    # 8,640 ten-second windows a day at roughly the achieved rate.
    assert 0 < estimate < 8640
    assert estimate == pytest.approx(
        detector.calibration.achieved_fpr * 8640, rel=0.01
    )


def test_metadata_and_constant_columns_are_never_features():
    columns = select_features(synthetic_windows())

    assert "window_start_epoch" not in columns
    assert "window_seconds" not in columns  # constant
    assert "is_gap_filled" not in columns
    assert "capture_file" not in columns    # not numeric
    assert "total_messages" in columns


def test_collinear_duplicates_are_pruned():
    """Near-duplicate columns would multiply the weight of what they measure."""
    frame = synthetic_windows()
    frame["total_packets"] = frame["total_messages"]          # exact duplicate
    frame["messages_per_second"] = frame["total_messages"] / 10  # perfectly collinear

    columns = select_features(frame)
    volume_like = {"total_messages", "total_packets", "messages_per_second"}
    assert len(volume_like & set(columns)) == 1


def test_too_little_data_is_refused_not_guessed():
    with pytest.raises(NotEnoughDataError):
        train(synthetic_windows(20))


def test_scoring_requires_the_trained_columns():
    detector = train(synthetic_windows())
    incomplete = synthetic_windows(60).drop(columns=["mean_message_size"])
    with pytest.raises(ValueError, match="missing"):
        detector.predict(incomplete)


def test_save_and_load_round_trip(tmp_path):
    frame = synthetic_windows()
    detector = train(frame, model_name="ecod", target_fpr=0.02)
    detector.save(tmp_path / "ecod")

    reloaded = AnomalyDetector.load(tmp_path / "ecod")
    assert reloaded.feature_columns == detector.feature_columns
    assert reloaded.calibration.threshold == pytest.approx(detector.calibration.threshold)
    np.testing.assert_allclose(reloaded.score(frame), detector.score(frame))


def test_tampered_artifact_is_refused(tmp_path):
    """Loading a joblib file executes code, so a digest mismatch must stop it."""
    detector = train(synthetic_windows(), model_name="ecod")
    directory = detector.save(tmp_path / "ecod")

    (directory / "model.joblib").write_bytes(b"not the model that was trained")
    with pytest.raises(ArtifactIntegrityError):
        AnomalyDetector.load(directory)


def test_prediction_records_what_flagged_the_window():
    detector = train(synthetic_windows())
    scored = detector.predict(synthetic_windows(80, seed=9))

    assert {"anomaly_score", "is_anomaly", "detected_by"} <= set(scored.columns)
    for flagged, reason in zip(scored["is_anomaly"], scored["detected_by"]):
        assert bool(flagged) == bool(reason)


def test_evaluate_computes_recall_and_precision():
    scored = pd.DataFrame(
        {
            "label": [0, 0, 1, 1, 0, 1],
            "is_anomaly": [0, 1, 1, 1, 0, 0],
            "anomaly_score": [0.1, 0.9, 0.8, 0.7, 0.2, 0.3],
        }
    )
    metrics = evaluate(scored)

    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert metrics["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert "roc_auc" in metrics
