"""Command-line interface.

Five subcommands cover the whole path from capture to verdict:

    inspect   what SIP is in these captures?
    features  captures -> feature windows on disk
    train     feature windows -> a calibrated detector
    score     new feature windows -> anomaly scores and decisions
    evaluate  scored windows + labels -> precision, recall, F1

``score`` exists as a first-class command on purpose. In the pipeline this
replaces, the equivalent function was written but never called from anywhere, so
the half of the workflow that actually detects anything had never run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from .features import DEFAULT_WINDOW_SECONDS
from .model import (
    ArtifactIntegrityError,
    AnomalyDetector,
    NotEnoughDataError,
    SUPPORTED_MODELS,
    evaluate as evaluate_scores,
    train as train_detector,
)
from .pipeline import (
    build_feature_frame,
    parse_captures,
    read_frame,
    summarise,
    write_frame,
)
from .privacy import Pseudonymiser
from .sip import DEFAULT_SIP_PORTS


def _ports(raw: str | None) -> frozenset[int]:
    if not raw:
        return DEFAULT_SIP_PORTS
    return frozenset(int(part) for part in raw.split(",") if part.strip())


def _echo(lines: list[str]) -> None:
    for line in lines:
        print(line)


def cmd_inspect(args: argparse.Namespace) -> int:
    result = parse_captures(
        args.captures,
        ports=_ports(args.ports),
        pseudonymiser=Pseudonymiser(enabled=not args.no_pseudonymise),
        progress=(lambda line: print(f"  {line}")) if args.verbose else None,
        jobs=args.jobs,
    )
    if not result.messages:
        print("No SIP messages found.", file=sys.stderr)
        _echo(summarise(result))
        return 1

    frame = build_feature_frame(result, args.window_seconds)
    _echo(summarise(result, frame))

    messages = result.messages
    requests = [m for m in messages if m.is_request]
    methods = pd.Series([m.method for m in requests if m.method]).value_counts()
    statuses = pd.Series(
        [m.status_code for m in messages if not m.is_request and m.status_code]
    ).value_counts()

    print("\nRequest methods:")
    for method, count in methods.items():
        print(f"    {method:<12} {count:,}")
    print("\nResponse codes:")
    for code, count in statuses.head(12).items():
        print(f"    {code:<12} {count:,}")

    emergency = sum(1 for m in requests if m.is_emergency_service)
    print(f"\nEmergency-service (urn:service:sos) requests: {emergency:,}")
    print(f"Messages carrying Geolocation              : "
          f"{sum(1 for m in messages if m.has_geolocation):,}")
    print(f"Transport                                  : "
          f"{dict(pd.Series([m.transport for m in messages]).value_counts())}")
    return 0


def cmd_features(args: argparse.Namespace) -> int:
    result = parse_captures(
        args.captures,
        ports=_ports(args.ports),
        pseudonymiser=Pseudonymiser(enabled=not args.no_pseudonymise),
        progress=(lambda line: print(f"  {line}")) if args.verbose else None,
        jobs=args.jobs,
    )
    if not result.messages:
        print("No SIP messages found; nothing written.", file=sys.stderr)
        return 1

    frame = build_feature_frame(
        result,
        window_seconds=args.window_seconds,
        per_source=args.per_source,
        fill_gaps=not args.no_fill_gaps,
    )
    if args.label is not None:
        frame["label"] = int(args.label)

    _echo(summarise(result, frame))
    path = write_frame(frame, args.output)
    print(f"\nWrote {len(frame):,} windows x {len(frame.columns)} columns to {path}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    frame = read_frame(args.features)
    if args.exclude_gap_filled and "is_gap_filled" in frame.columns:
        frame = frame[frame["is_gap_filled"] == 0]

    model_dir = Path(args.model_dir)
    rows = []

    for name in args.models:
        try:
            detector = train_detector(
                frame,
                model_name=name,
                target_fpr=args.target_fpr,
                calibration_fraction=args.calibration_fraction,
            )
        except NotEnoughDataError as error:
            print(f"{name}: {error}", file=sys.stderr)
            return 1

        detector.save(model_dir / name)
        calibration = detector.calibration
        rows.append(
            {
                "model": name,
                "features": len(detector.feature_columns),
                "train_windows": detector.training_windows,
                "calib_windows": calibration.calibration_windows,
                "target_fpr": calibration.target_fpr,
                "achieved_fpr": calibration.achieved_fpr,
                "alerts_per_day": calibration.alerts_per_day_estimate,
                "fit_seconds": round(detector.fit_seconds, 3),
            }
        )
        print(f"trained {name}: saved to {model_dir / name}")

    summary = pd.DataFrame(rows)
    print("\n" + summary.to_string(index=False))
    print(
        f"\nFeature columns kept after removing constant and collinear inputs: "
        f"{rows[0]['features']}"
    )
    print(
        "alerts_per_day is what this threshold implies on continuous traffic "
        "at this window size."
    )
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    try:
        detector = AnomalyDetector.load(args.model)
    except ArtifactIntegrityError as error:
        print(f"refusing to load model: {error}", file=sys.stderr)
        return 1

    frame = read_frame(args.features)
    scored = detector.predict(frame)
    flagged = int(scored["is_anomaly"].sum())

    print(f"model            : {detector.model_name} (trained {detector.trained_at})")
    print(f"threshold        : {detector.calibration.threshold:.6f} "
          f"(target FPR {detector.calibration.target_fpr})")
    print(f"windows scored   : {len(scored):,}")
    print(f"windows flagged  : {flagged:,} ({flagged / max(len(scored), 1) * 100:.2f}%)")

    if flagged:
        columns = [
            c
            for c in (
                "window_start_utc", "src_ip", "total_messages", "invite_count",
                "options_count", "max_invites_one_source", "top_source_share",
                "unanswered_challenge_count", "retransmission_count", "anomaly_score",
            )
            if c in scored.columns
        ]
        print("\nHighest-scoring windows:")
        print(
            scored.nlargest(min(args.top, flagged), "anomaly_score")[columns]
            .to_string(index=False)
        )

    if args.output:
        path = write_frame(scored, args.output)
        print(f"\nWrote scored windows to {path}")

    if "label" in scored.columns:
        print("\nLabels present; evaluating:")
        for key, value in evaluate_scores(scored).items():
            print(f"    {key:<22} {value}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    scored = read_frame(args.scored)
    if "label" not in scored.columns:
        print("scored file has no 'label' column", file=sys.stderr)
        return 1
    for key, value in evaluate_scores(scored).items():
        print(f"{key:<22} {value}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Prove the pipeline end to end on synthetic ESInet traffic.

    Trains on a clean baseline, then scores each attack scenario and reports
    whether the attack windows were caught. No real capture is needed, so this
    runs anywhere and keeps the detection path continuously exercised.
    """
    import tempfile

    from .synth import SCENARIOS, attack_window_range, build_scenario

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp())
    workdir.mkdir(parents=True, exist_ok=True)
    pseudonymiser = Pseudonymiser(key=b"validate-fixed-key")

    print(f"working directory: {workdir}\n")
    print(f"building {args.baseline_seconds}s of synthetic ESInet baseline...")
    baseline_capture = build_scenario(
        "baseline", workdir / "baseline.pcap", baseline_seconds=args.baseline_seconds
    )
    baseline = parse_captures(baseline_capture, pseudonymiser=pseudonymiser)
    baseline_frame = build_feature_frame(baseline, window_seconds=args.window_seconds)
    print(f"  {baseline.message_count:,} messages -> {len(baseline_frame):,} windows")

    try:
        detector = train_detector(
            baseline_frame, model_name=args.model, target_fpr=args.target_fpr
        )
    except NotEnoughDataError as error:
        print(f"\n{error}", file=sys.stderr)
        print("increase --baseline-seconds", file=sys.stderr)
        return 1

    calibration = detector.calibration
    print(
        f"  trained {args.model}: {len(detector.feature_columns)} features, "
        f"threshold {calibration.threshold:.4f}, "
        f"achieved FPR {calibration.achieved_fpr:.4f} "
        f"({calibration.alerts_per_day_estimate:.0f} alerts/day)\n"
    )

    attack_start, attack_end = attack_window_range(
        args.baseline_seconds, args.attack_seconds
    )
    rows = []

    for name, scenario in SCENARIOS.items():
        if name == "baseline":
            continue
        capture = build_scenario(
            name,
            workdir / f"{name}.pcap",
            baseline_seconds=args.baseline_seconds,
            attack_seconds=args.attack_seconds,
            intensity=args.intensity,
        )
        parsed = parse_captures(capture, pseudonymiser=pseudonymiser)
        frame = build_feature_frame(parsed, window_seconds=args.window_seconds)

        # A window is attack-labelled when it overlaps the attack interval.
        frame["label"] = (
            (frame["window_end_epoch"] > attack_start)
            & (frame["window_start_epoch"] < attack_end)
        ).astype(int)

        scored = detector.predict(frame)
        metrics = evaluate_scores(scored)
        attack_rows = scored[scored["label"] == 1]
        caught = int(attack_rows["is_anomaly"].sum())

        rows.append(
            {
                "scenario": name,
                "attack_windows": len(attack_rows),
                "detected": caught,
                "recall": metrics["recall"],
                "precision": metrics["precision"],
                "false_positives": metrics["false_positive"],
                "roc_auc": metrics.get("roc_auc", float("nan")),
            }
        )
        verdict = "DETECTED" if caught else "MISSED"
        print(f"{scenario.description}\n    {name:<20} {verdict} "
              f"({caught}/{len(attack_rows)} attack windows flagged)")

    summary = pd.DataFrame(rows)
    print("\n" + summary.to_string(index=False))

    missed = summary[summary["detected"] == 0]["scenario"].tolist()
    if missed:
        print(f"\nscenarios not detected: {', '.join(missed)}")
        return 1
    print("\nall scenarios detected")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ng911-sip",
        description="SIP anomaly detection for NG911 ESInet traffic.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_capture_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("captures", help="capture file or directory of captures")
        p.add_argument("--ports", help="comma-separated SIP ports (default 5060,5061,5062)")
        p.add_argument(
            "--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS,
            help=f"feature window width (default {DEFAULT_WINDOW_SECONDS})",
        )
        p.add_argument(
            "--no-pseudonymise", action="store_true",
            help="keep caller identifiers in the clear (not for real 911 traffic)",
        )
        p.add_argument(
            "-j", "--jobs", type=int, default=None,
            help="parse this many captures at once (default: one per CPU core, "
                 "capped at the number of files)",
        )
        p.add_argument("-v", "--verbose", action="store_true", help="per-file progress")

    inspect = sub.add_parser("inspect", help="summarise the SIP content of captures")
    add_capture_args(inspect)
    inspect.set_defaults(func=cmd_inspect)

    features = sub.add_parser("features", help="build feature windows from captures")
    add_capture_args(features)
    features.add_argument("-o", "--output", required=True, help="output .parquet or .csv")
    features.add_argument(
        "--per-source", action="store_true",
        help="one row per (window, source IP) instead of per window",
    )
    features.add_argument(
        "--no-fill-gaps", action="store_true",
        help="omit silent windows instead of emitting them as zero rows",
    )
    features.add_argument(
        "--label", type=int, choices=(0, 1),
        help="tag every window (1 = attack, 0 = normal) for later evaluation",
    )
    features.set_defaults(func=cmd_features)

    train = sub.add_parser("train", help="fit and calibrate detectors")
    train.add_argument("features", help="feature file from the features command")
    train.add_argument("-m", "--model-dir", default="models", help="output directory")
    train.add_argument(
        "--models", nargs="+", default=["iforest", "ecod"], choices=SUPPORTED_MODELS,
        help="which detectors to train",
    )
    train.add_argument(
        "--target-fpr", type=float, default=0.01,
        help="false positive rate to calibrate the threshold to (default 0.01)",
    )
    train.add_argument(
        "--calibration-fraction", type=float, default=0.3,
        help="trailing fraction of windows held out for calibration",
    )
    train.add_argument(
        "--exclude-gap-filled", action="store_true",
        help="train only on windows that contained traffic",
    )
    train.set_defaults(func=cmd_train)

    score = sub.add_parser("score", help="score feature windows with a trained model")
    score.add_argument("model", help="a model directory, e.g. models/iforest")
    score.add_argument("features", help="feature file to score")
    score.add_argument("-o", "--output", help="write scored windows here")
    score.add_argument("--top", type=int, default=15, help="how many top windows to print")
    score.set_defaults(func=cmd_score)

    evaluate = sub.add_parser("evaluate", help="metrics for a labelled scored file")
    evaluate.add_argument("scored", help="output of score, containing a label column")
    evaluate.set_defaults(func=cmd_evaluate)

    validate = sub.add_parser(
        "validate",
        help="prove the pipeline detects attacks, using synthetic traffic only",
    )
    validate.add_argument(
        "--workdir", help="where to write synthetic captures (default: a temp dir)"
    )
    validate.add_argument("--model", default="iforest", choices=SUPPORTED_MODELS)
    validate.add_argument("--baseline-seconds", type=int, default=3600)
    validate.add_argument("--attack-seconds", type=int, default=60)
    validate.add_argument(
        "--intensity", type=int, default=40,
        help="attack messages per second for flood scenarios",
    )
    validate.add_argument("--target-fpr", type=float, default=0.01)
    validate.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    validate.set_defaults(func=cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
