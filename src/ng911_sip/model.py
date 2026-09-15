"""Training, calibration, scoring and evaluation.

The central change from a naive PyOD setup is how the decision threshold is
chosen. Passing ``contamination=0.10`` makes the cutoff the 90th percentile of
the training scores, so exactly 10% of the data used to define "normal" is
labelled anomalous no matter what that data contains. At ten-second windows that
is 864 alerts a day, by construction, before a single real anomaly exists.

Here the data is split in time: the model fits on the earlier portion, and the
threshold is read off a later, held-out portion at an explicit target false
positive rate. The rate is then a stated operating point that can be verified,
not an artefact of a default argument.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from .features import METADATA_COLUMNS

ARTIFACT_VERSION = 2
SUPPORTED_MODELS = ("iforest", "lof", "ecod", "copod")

# Features correlated above this with an already-kept feature are dropped: near
# duplicates silently multiply the weight of whatever they measure.
COLLINEARITY_LIMIT = 0.995


class NotEnoughDataError(ValueError):
    """Raised when there are too few windows to fit and calibrate honestly."""


class ArtifactIntegrityError(Exception):
    """Raised when a stored model does not match its recorded digest."""


def _digest(path: Path) -> str:
    """SHA-256 of a file, read in chunks so model size does not matter."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(slots=True)
class Calibration:
    """Where the decision threshold came from."""

    target_fpr: float
    threshold: float
    achieved_fpr: float
    calibration_windows: int
    alerts_per_day_estimate: float


@dataclass(slots=True)
class AnomalyDetector:
    """A fitted model together with everything needed to score new traffic."""

    model: Any
    scaler: StandardScaler
    feature_columns: list[str]
    model_name: str
    window_seconds: int
    calibration: Calibration
    training_windows: int
    fit_seconds: float
    trained_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Share of clean calibration windows flagged by rules rather than the model.
    # Non-zero means the rules are noisy against this baseline and want tuning.
    rule_fpr: float = 0.0

    def _matrix(self, frame: pd.DataFrame) -> np.ndarray:
        """Align new data to the trained feature order, then scale."""
        missing = [c for c in self.feature_columns if c not in frame.columns]
        if missing:
            raise ValueError(
                f"{len(missing)} feature column(s) missing from input, "
                f"first few: {missing[:5]}"
            )
        ordered = frame.loc[:, self.feature_columns].apply(
            pd.to_numeric, errors="coerce"
        )
        ordered = ordered.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return self.scaler.transform(ordered.to_numpy(dtype=float))

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        """Raw anomaly scores; higher means more abnormal."""
        return self.model.decision_function(self._matrix(frame))

    def predict(self, frame: pd.DataFrame, use_rules: bool = True) -> pd.DataFrame:
        """Score the input and decide, combining the model with structural rules.

        The model supplies the distributional judgement; the rules cover
        conditions a clean baseline cannot teach it, such as traffic from a host
        outside the mesh. A window flagged by either is flagged, and
        ``detected_by`` records which.
        """
        scores = self.score(frame)
        result = frame.copy()
        result["model_name"] = self.model_name
        result["anomaly_score"] = scores

        by_model = pd.Series(
            scores > self.calibration.threshold, index=frame.index
        )
        if use_rules:
            from .rules import apply_rules

            by_rule, reasons = apply_rules(frame)
        else:
            by_rule = pd.Series(False, index=frame.index)
            reasons = pd.Series([""] * len(frame), index=frame.index, dtype="object")

        result["is_anomaly"] = (by_model | by_rule).astype(int)
        result["detected_by"] = [
            ",".join(filter(None, ["model" if m else "", r]))
            for m, r in zip(by_model, reasons)
        ]
        return result

    def save(self, directory: str | Path) -> Path:
        """Persist model, scaler, feature order and calibration together.

        The estimators are stored with joblib, which is pickle-based. Loading a
        pickle executes code, so these files are treated as build outputs of the
        machine that trained them: they are written to a gitignored directory,
        never committed, and never fetched from anywhere. ``load`` verifies the
        SHA-256 recorded here so a silently altered or truncated artifact fails
        loudly instead of being unpickled.
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        model_path = directory / "model.joblib"
        scaler_path = directory / "scaler.joblib"
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)

        (directory / "manifest.json").write_text(
            json.dumps(
                {
                    "artifact_version": ARTIFACT_VERSION,
                    "model_name": self.model_name,
                    "window_seconds": self.window_seconds,
                    "feature_columns": self.feature_columns,
                    "training_windows": self.training_windows,
                    "fit_seconds": round(self.fit_seconds, 4),
                    "trained_at": self.trained_at,
                    "digests": {
                        "model.joblib": _digest(model_path),
                        "scaler.joblib": _digest(scaler_path),
                    },
                    "calibration": {
                        "target_fpr": self.calibration.target_fpr,
                        "threshold": float(self.calibration.threshold),
                        "achieved_fpr": self.calibration.achieved_fpr,
                        "calibration_windows": self.calibration.calibration_windows,
                        "alerts_per_day_estimate": self.calibration.alerts_per_day_estimate,
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return directory

    @classmethod
    def load(cls, directory: str | Path) -> "AnomalyDetector":
        """Load a detector saved by :meth:`save`."""
        directory = Path(directory)
        manifest_path = directory / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"no manifest.json in {directory}")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = manifest.get("artifact_version")
        if version != ARTIFACT_VERSION:
            raise ValueError(
                f"artifact version {version} does not match expected "
                f"{ARTIFACT_VERSION}; retrain rather than loading this model"
            )

        # Verify before unpickling: a mismatch means the artifact is not the one
        # this manifest describes, and joblib.load would execute whatever it is.
        for filename, expected in manifest.get("digests", {}).items():
            actual = _digest(directory / filename)
            if actual != expected:
                raise ArtifactIntegrityError(
                    f"{filename} in {directory} does not match its recorded digest "
                    f"(expected {expected[:16]}..., found {actual[:16]}...); "
                    "retrain rather than loading it"
                )

        calibration = manifest["calibration"]
        return cls(
            model=joblib.load(directory / "model.joblib"),
            scaler=joblib.load(directory / "scaler.joblib"),
            feature_columns=list(manifest["feature_columns"]),
            model_name=manifest["model_name"],
            window_seconds=int(manifest["window_seconds"]),
            calibration=Calibration(
                target_fpr=calibration["target_fpr"],
                threshold=calibration["threshold"],
                achieved_fpr=calibration["achieved_fpr"],
                calibration_windows=calibration["calibration_windows"],
                alerts_per_day_estimate=calibration["alerts_per_day_estimate"],
            ),
            training_windows=int(manifest["training_windows"]),
            fit_seconds=float(manifest.get("fit_seconds", 0.0)),
            trained_at=manifest.get("trained_at", ""),
        )


def select_features(
    frame: pd.DataFrame,
    collinearity_limit: float = COLLINEARITY_LIMIT,
) -> list[str]:
    """Choose model input columns: numeric, non-constant, non-duplicated.

    Dropping near-duplicates matters because scaled distances weight every
    column equally. Three columns that all encode message volume triple the
    weight of volume relative to, say, authentication behaviour.
    """
    numeric = frame.select_dtypes(include="number").drop(
        columns=[c for c in frame.columns if c in METADATA_COLUMNS],
        errors="ignore",
    )
    numeric = numeric.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    varying = [c for c in numeric.columns if numeric[c].nunique(dropna=False) > 1]
    if not varying:
        raise NotEnoughDataError("every candidate feature is constant")
    numeric = numeric[varying]

    correlation = numeric.corr().abs()
    kept: list[str] = []
    for column in numeric.columns:
        if any(correlation.loc[column, k] > collinearity_limit for k in kept):
            continue
        kept.append(column)
    return kept


def _build_model(model_name: str, random_state: int) -> Any:
    """Instantiate a PyOD detector.

    ``contamination`` still has to be supplied because PyOD computes an internal
    label during fit, but that label is never used: the operating threshold is
    set during calibration instead.
    """
    name = model_name.strip().lower()
    placeholder = 0.05

    if name == "iforest":
        from pyod.models.iforest import IForest

        return IForest(
            contamination=placeholder,
            n_estimators=300,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,
        )
    if name == "lof":
        from pyod.models.lof import LOF

        return LOF(contamination=placeholder, n_neighbors=35, novelty=True, n_jobs=-1)
    if name == "ecod":
        from pyod.models.ecod import ECOD

        return ECOD(contamination=placeholder, n_jobs=-1)
    if name == "copod":
        from pyod.models.copod import COPOD

        return COPOD(contamination=placeholder, n_jobs=-1)

    raise ValueError(
        f"unsupported model {model_name!r}; choose one of {', '.join(SUPPORTED_MODELS)}"
    )


def train(
    windows: pd.DataFrame,
    model_name: str = "iforest",
    target_fpr: float = 0.01,
    calibration_fraction: float = 0.3,
    feature_columns: Sequence[str] | None = None,
    random_state: int = 42,
) -> AnomalyDetector:
    """Fit a detector and calibrate its threshold on held-out windows.

    The split is temporal rather than random: traffic is autocorrelated, so
    shuffling would let near-identical adjacent windows appear on both sides and
    produce a threshold that looks better than it is.
    """
    if not 0.0 < target_fpr < 0.5:
        raise ValueError("target_fpr must be between 0 and 0.5")
    if not 0.1 <= calibration_fraction <= 0.5:
        raise ValueError("calibration_fraction must be between 0.1 and 0.5")

    frame = windows.sort_values("window_start_epoch").reset_index(drop=True)
    if len(frame) < 50:
        raise NotEnoughDataError(
            f"{len(frame)} windows is too few to fit and calibrate; "
            "capture a longer baseline (at least 50 windows, ideally thousands)"
        )

    columns = list(feature_columns) if feature_columns else select_features(frame)

    split = int(len(frame) * (1.0 - calibration_fraction))
    fit_frame = frame.iloc[:split]
    calibration_frame = frame.iloc[split:]
    if len(calibration_frame) < 20:
        raise NotEnoughDataError("calibration split has fewer than 20 windows")

    fit_matrix = (
        fit_frame.loc[:, columns]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
        .to_numpy(dtype=float)
    )

    scaler = StandardScaler().fit(fit_matrix)
    model = _build_model(model_name, random_state)

    started = perf_counter()
    model.fit(scaler.transform(fit_matrix))
    fit_seconds = perf_counter() - started

    window_seconds = int(frame["window_seconds"].iloc[0])
    provisional = AnomalyDetector(
        model=model,
        scaler=scaler,
        feature_columns=columns,
        model_name=model_name.strip().lower(),
        window_seconds=window_seconds,
        calibration=Calibration(target_fpr, float("inf"), 0.0, 0, 0.0),
        training_windows=len(fit_frame),
        fit_seconds=fit_seconds,
    )

    # The baseline is assumed normal, so any calibration window scoring above
    # the threshold is a false positive by definition. Placing the threshold at
    # the (1 - target_fpr) quantile makes that rate the stated operating point.
    calibration_scores = provisional.score(calibration_frame)
    threshold = float(np.quantile(calibration_scores, 1.0 - target_fpr))
    provisional.calibration = Calibration(
        target_fpr, threshold, 0.0, len(calibration_frame), 0.0
    )

    # Report the rate the deployed detector actually produces. Rules fire
    # independently of the threshold, so measuring the model alone would
    # understate the alert volume an operator sees.
    combined = provisional.predict(calibration_frame)["is_anomaly"]
    achieved = float(combined.mean())
    rule_only = float(
        ((combined == 1) & (calibration_scores <= threshold)).mean()
    )

    provisional.calibration = Calibration(
        target_fpr=target_fpr,
        threshold=threshold,
        achieved_fpr=round(achieved, 6),
        calibration_windows=len(calibration_frame),
        alerts_per_day_estimate=round(achieved * 86400.0 / window_seconds, 1),
    )
    provisional.rule_fpr = round(rule_only, 6)
    return provisional


def evaluate(scored: pd.DataFrame, label_column: str = "label") -> dict[str, float]:
    """Score a labelled result frame (1 = attack, 0 = normal)."""
    if label_column not in scored.columns:
        raise ValueError(f"no {label_column!r} column to evaluate against")

    truth = scored[label_column].astype(int).to_numpy()
    predicted = scored["is_anomaly"].astype(int).to_numpy()

    true_positive = int(((predicted == 1) & (truth == 1)).sum())
    false_positive = int(((predicted == 1) & (truth == 0)).sum())
    false_negative = int(((predicted == 0) & (truth == 1)).sum())
    true_negative = int(((predicted == 0) & (truth == 0)).sum())

    precision = true_positive / (true_positive + false_positive) if predicted.sum() else 0.0
    recall = true_positive / (true_positive + false_negative) if truth.sum() else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    metrics = {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(
            false_positive / max(true_negative + false_positive, 1), 6
        ),
    }

    # Ranking quality is threshold-independent, so it separates "the model
    # ranks attacks highly" from "the threshold happens to sit well".
    if 0 < truth.sum() < len(truth):
        try:
            from sklearn.metrics import average_precision_score, roc_auc_score

            scores = scored["anomaly_score"].to_numpy()
            metrics["roc_auc"] = round(float(roc_auc_score(truth, scores)), 4)
            metrics["average_precision"] = round(
                float(average_precision_score(truth, scores)), 4
            )
        except Exception:  # pragma: no cover - metrics are a bonus, not required
            pass

    return metrics
