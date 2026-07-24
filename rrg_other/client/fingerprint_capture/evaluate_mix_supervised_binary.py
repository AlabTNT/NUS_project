#!/usr/bin/env python3
"""Supervised six-fold evaluation using both Formal and Magic training data.

Each outer fold fits a group-and-class-balanced logistic classifier on the
concatenated AUTH A, AUTH B, and READ block-0 features from five groups.  The
decision threshold is the strictest value that keeps every one of those five
Formal groups at or below the configured false-reject rate.  The sixth group is
untouched until the final blind evaluation.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = SCRIPT_DIR.parent
for module_dir in (WORKSPACE_DIR, SCRIPT_DIR):
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))

from fingerprint_capture import fingerprint_experiment_utils as utils  # noqa: E402
import train_fingerprint_model as model_api  # noqa: E402


STAGES = utils.STAGES


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def equal_group_class_weights(
    groups: np.ndarray,
    labels: np.ndarray,
) -> np.ndarray:
    """Give every (physical group, class) cell equal total training weight."""

    cells = sorted(set(zip(groups.tolist(), labels.tolist())))
    weights = np.zeros(groups.size, dtype=np.float64)
    for group, label in cells:
        mask = (groups == group) & (labels == label)
        weights[mask] = groups.size / (
            len(cells) * int(np.count_nonzero(mask))
        )
    return weights


def fit_weighted_logistic(
    matrix: np.ndarray,
    labels: np.ndarray,
    groups: np.ndarray,
    ridge: float,
    max_iterations: int = 100,
) -> dict[str, object]:
    """Fit L2 logistic regression with equal group/class influence."""

    sample_weights = equal_group_class_weights(groups, labels)
    normalized_weights = sample_weights / sample_weights.sum()
    mean = np.sum(normalized_weights[:, np.newaxis] * matrix, axis=0)
    variance = np.sum(
        normalized_weights[:, np.newaxis] * (matrix - mean) ** 2,
        axis=0,
    )
    scale = np.sqrt(np.maximum(variance, 0.0))
    scale = np.where(scale > 1e-12, scale, 1.0)
    standardized = (matrix - mean) / scale
    design = np.column_stack([np.ones(matrix.shape[0]), standardized])
    coefficients = np.zeros(design.shape[1], dtype=np.float64)
    penalty = np.eye(design.shape[1], dtype=np.float64) * ridge
    penalty[0, 0] = 0.0

    for _ in range(max_iterations):
        probability = model_api.sigmoid(design @ coefficients)
        residual = sample_weights * (probability - labels)
        curvature = sample_weights * np.maximum(
            probability * (1.0 - probability),
            1e-8,
        )
        gradient = design.T @ residual + penalty @ coefficients
        hessian = (design.T * curvature) @ design + penalty
        update = np.linalg.solve(hessian, gradient)
        coefficients -= update
        if float(np.max(np.abs(update))) < 1e-8:
            break

    return {
        "mean": model_api.json_ready_array(mean),
        "scale": model_api.json_ready_array(scale),
        "intercept": float(coefficients[0]),
        "weights": model_api.json_ready_array(coefficients[1:]),
        "ridge": float(ridge),
        "group_class_balanced": True,
    }


def score_logistic(matrix: np.ndarray, parameters: dict[str, object]) -> np.ndarray:
    mean = np.asarray(parameters["mean"], dtype=np.float64)
    scale = np.asarray(parameters["scale"], dtype=np.float64)
    coefficients = np.asarray(parameters["weights"], dtype=np.float64)
    standardized = (matrix - mean) / scale
    return model_api.sigmoid(
        standardized @ coefficients + float(parameters["intercept"])
    )


def choose_group_safe_threshold(
    formal_scores: np.ndarray,
    formal_groups: np.ndarray,
    magic_scores: np.ndarray,
    max_group_frr: float,
) -> tuple[float, dict[str, Any]]:
    """Use Magic to choose a safe threshold with a separation-margin tie break."""

    group_names = sorted(set(formal_groups.tolist()))
    all_scores = np.sort(np.unique(np.concatenate([formal_scores, magic_scores])))
    candidates = [float(all_scores[0])]
    candidates.extend(
        float((left + right) / 2.0)
        for left, right in zip(all_scores[:-1], all_scores[1:])
    )
    candidates.append(float(all_scores[-1]))

    best_rank: tuple[float, float, float, float] | None = None
    best_threshold: float | None = None
    best_frr_by_group: dict[str, float] | None = None
    for threshold in candidates:
        frr_by_group = {
            group: float(
                np.mean(formal_scores[formal_groups == group] > threshold)
            )
            for group in group_names
        }
        if max(frr_by_group.values()) > max_group_frr + 1e-12:
            continue
        magic_far = float(np.mean(magic_scores <= threshold))
        formal_frr = float(np.mean(formal_scores > threshold))
        nearest_score_margin = float(
            np.min(np.abs(np.concatenate([formal_scores, magic_scores]) - threshold))
        )
        # Security first, then usability.  If both classifications are equal,
        # prefer the widest observed score gap rather than an arbitrary edge.
        rank = (magic_far, formal_frr, -nearest_score_margin, threshold)
        if best_rank is None or rank < best_rank:
            best_rank = rank
            best_threshold = threshold
            best_frr_by_group = frr_by_group

    if best_threshold is None or best_frr_by_group is None or best_rank is None:
        raise RuntimeError("failed to find a per-group-safe supervised threshold")
    return best_threshold, {
        "formal_frr_by_group": best_frr_by_group,
        "worst_group_formal_frr": max(best_frr_by_group.values()),
        "formal_frr": best_rank[1],
        "magic_far": best_rank[0],
        "score_gap_margin": -best_rank[2],
        "candidate_count": len(candidates),
    }


def concatenate_stages(matrices: dict[str, np.ndarray]) -> np.ndarray:
    return np.column_stack([matrices[stage] for stage in STAGES])


def write_model(
    *,
    path: Path,
    parameters: dict[str, object],
    threshold: float,
    ridge: float,
    training_groups: Sequence[str],
    formal_count: int,
    magic_count: int,
    sample_rate_hz: float,
) -> None:
    document = {
        "schema_version": 1,
        "created_utc": utc_now(),
        "model_type": "three_stage_supervised_binary_logistic",
        "required_stages": list(STAGES),
        "stage_feature_names": {
            stage: list(model_api.FEATURE_NAMES) for stage in STAGES
        },
        "concatenation_order": list(STAGES),
        "sample_rate_hz": float(sample_rate_hz),
        "training_groups": list(training_groups),
        "training_formal_count": int(formal_count),
        "training_magic_count": int(magic_count),
        "ridge": float(ridge),
        "threshold": float(threshold),
        "threshold_policy": (
            "minimize training Magic FAR, then Formal FRR, subject to every "
            "Formal group's FRR constraint; use score-gap margin as tie break"
        ),
        "parameters": parameters,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def fit_fold(
    *,
    matrix: np.ndarray,
    labels: np.ndarray,
    groups: np.ndarray,
    training_mask: np.ndarray,
    test_mask: np.ndarray,
    max_group_frr: float,
    ridge: float,
    sample_rate_hz: float,
    output_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    binary_labels = np.asarray(labels == "magic", dtype=np.float64)
    parameters = fit_weighted_logistic(
        matrix[training_mask],
        binary_labels[training_mask],
        groups[training_mask],
        ridge,
    )
    training_scores = score_logistic(matrix[training_mask], parameters)
    training_labels = labels[training_mask]
    training_groups = groups[training_mask]
    formal_training = training_labels == "formal"
    threshold, safety = choose_group_safe_threshold(
        training_scores[formal_training],
        training_groups[formal_training],
        training_scores[~formal_training],
        max_group_frr,
    )
    calibration_accepted = training_scores <= threshold
    calibration_metrics = utils.decision_metrics(
        training_labels,
        calibration_accepted,
    )
    calibration_metrics.update(safety)

    model_path = output_dir / "supervised_binary_model.json"
    write_model(
        path=model_path,
        parameters=parameters,
        threshold=threshold,
        ridge=ridge,
        training_groups=sorted(set(training_groups.tolist())),
        formal_count=int(np.count_nonzero(training_labels == "formal")),
        magic_count=int(np.count_nonzero(training_labels == "magic")),
        sample_rate_hz=sample_rate_hz,
    )

    test_scores = score_logistic(matrix[test_mask], parameters)
    accepted = test_scores <= threshold
    test_labels = labels[test_mask]
    metrics = utils.decision_metrics(test_labels, accepted)
    formal_test_scores = test_scores[test_labels == "formal"]
    magic_test_scores = test_scores[test_labels == "magic"]
    metrics.update(
        {
            "threshold": float(threshold),
            "calibration": calibration_metrics,
            "training_groups": sorted(set(training_groups.tolist())),
            "model": utils.portable_path(model_path),
            "formal_score_summary": model_api.summarize_scores(
                formal_test_scores
            ),
            "magic_score_summary": model_api.summarize_scores(magic_test_scores),
            "auc": model_api.auc_pairwise(
                formal_test_scores,
                magic_test_scores,
            ),
        }
    )

    rows: list[dict[str, Any]] = []
    for position, original_index in enumerate(np.flatnonzero(test_mask)):
        rows.append(
            {
                "index": int(original_index),
                "group": str(groups[original_index]),
                "label": str(labels[original_index]),
                "magic_probability": float(test_scores[position]),
                "threshold": float(threshold),
                "accepted_as_formal": bool(accepted[position]),
            }
        )
    return metrics, rows


def run(args: argparse.Namespace) -> int:
    data_root = args.data_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    transactions = utils.discover_transactions(data_root)
    labels = np.asarray([item.label for item in transactions], dtype=object)
    groups = np.asarray([item.group for item in transactions], dtype=object)
    stage_matrices = utils.load_or_extract_features(
        transactions,
        args.feature_cache.resolve(),
        args.sample_rate_hz,
    )
    matrix = concatenate_stages(stage_matrices)
    group_names = sorted(set(groups.tolist()))
    group_metadata = json.loads(
        args.group_metadata.read_text(encoding="utf-8")
    )["groups"]
    missing_metadata = set(group_names) - set(group_metadata)
    if missing_metadata:
        raise ValueError(
            f"missing group metadata for {sorted(missing_metadata)}"
        )

    folds: list[dict[str, Any]] = []
    predictions: list[dict[str, Any]] = []
    for held_out_group in group_names:
        print(f"Supervised fold held_out={held_out_group}", flush=True)
        training_mask = groups != held_out_group
        test_mask = groups == held_out_group
        metrics, rows = fit_fold(
            matrix=matrix,
            labels=labels,
            groups=groups,
            training_mask=training_mask,
            test_mask=test_mask,
            max_group_frr=args.max_group_frr,
            ridge=args.ridge,
            sample_rate_hz=args.sample_rate_hz,
            output_dir=output_dir / "folds" / f"held_out_{held_out_group}",
        )
        metrics["held_out_group"] = held_out_group
        metrics["held_out_magic_generation"] = group_metadata[held_out_group][
            "magic_generation"
        ]
        metrics["same_generation_training_groups"] = [
            group
            for group in group_names
            if group != held_out_group
            and group_metadata[group]["magic_generation"]
            == metrics["held_out_magic_generation"]
        ]
        folds.append(metrics)
        for row in rows:
            row["held_out_group"] = held_out_group
        predictions.extend(rows)

    pooled_labels = np.asarray([row["label"] for row in predictions], dtype=object)
    pooled_accepted = np.asarray(
        [row["accepted_as_formal"] for row in predictions],
        dtype=bool,
    )
    aggregate = utils.decision_metrics(pooled_labels, pooled_accepted)
    aggregate["macro_formal_accept_rate"] = float(
        np.mean([fold["formal_accept_rate"] for fold in folds])
    )
    aggregate["macro_magic_reject_rate"] = float(
        np.mean([fold["magic_reject_rate"] for fold in folds])
    )
    aggregate["macro_balanced_accuracy"] = float(
        np.mean([fold["balanced_accuracy"] for fold in folds])
    )
    aggregate["macro_auc"] = float(np.mean([fold["auc"] for fold in folds]))
    generation_breakdown: dict[str, dict[str, Any]] = {}
    generations = sorted(
        {
            metadata["magic_generation"]
            for metadata in group_metadata.values()
        }
    )
    for generation in generations:
        generation_rows = [
            row
            for row in predictions
            if row["label"] == "magic"
            and group_metadata[row["group"]]["magic_generation"] == generation
        ]
        scores = np.asarray(
            [row["magic_probability"] for row in generation_rows],
            dtype=np.float64,
        )
        rejected = sum(
            not row["accepted_as_formal"] for row in generation_rows
        )
        generation_breakdown[generation] = {
            "groups": sorted({row["group"] for row in generation_rows}),
            "magic_count": len(generation_rows),
            "magic_rejected": rejected,
            "magic_accepted": len(generation_rows) - rejected,
            "magic_reject_rate": utils.safe_div(
                rejected,
                len(generation_rows),
            ),
            "magic_probability_summary": model_api.summarize_scores(scores),
        }

    generation_holdout: list[dict[str, Any]] = []
    generation_holdout_predictions: list[dict[str, Any]] = []
    for held_out_generation in generations:
        held_out_groups = [
            group
            for group in group_names
            if group_metadata[group]["magic_generation"] == held_out_generation
        ]
        test_mask = np.isin(groups, held_out_groups)
        training_mask = ~test_mask
        generation_metrics, generation_rows = fit_fold(
            matrix=matrix,
            labels=labels,
            groups=groups,
            training_mask=training_mask,
            test_mask=test_mask,
            max_group_frr=args.max_group_frr,
            ridge=args.ridge,
            sample_rate_hz=args.sample_rate_hz,
            output_dir=output_dir
            / "generation_holdout"
            / f"held_out_{held_out_generation.replace(' ', '_').replace('/', '_')}",
        )
        for row in generation_rows:
            row["held_out_generation"] = held_out_generation
        generation_holdout_predictions.extend(generation_rows)
        generation_metrics.update(
            {
                "held_out_generation": held_out_generation,
                "held_out_groups": held_out_groups,
            }
        )
        generation_holdout.append(generation_metrics)
    utils.write_csv(
        output_dir / "generation_holdout_predictions.csv",
        generation_holdout_predictions,
    )

    four_two_folds: list[dict[str, Any]] = []
    four_two_predictions: list[dict[str, Any]] = []
    for held_out_pair in itertools.combinations(group_names, 2):
        split_id = "__".join(held_out_pair)
        print(f"4|2 split held_out={split_id}", flush=True)
        test_mask = np.isin(groups, held_out_pair)
        training_mask = ~test_mask
        split_metrics, split_rows = fit_fold(
            matrix=matrix,
            labels=labels,
            groups=groups,
            training_mask=training_mask,
            test_mask=test_mask,
            max_group_frr=args.max_group_frr,
            ridge=args.ridge,
            sample_rate_hz=args.sample_rate_hz,
            output_dir=output_dir / "four_train_two_test" / split_id,
        )
        split_metrics.update(
            {
                "split_id": split_id,
                "held_out_groups": list(held_out_pair),
                "held_out_magic_generations": {
                    group: group_metadata[group]["magic_generation"]
                    for group in held_out_pair
                },
            }
        )
        four_two_folds.append(split_metrics)
        for row in split_rows:
            row["split_id"] = split_id
        four_two_predictions.extend(split_rows)

    four_two_labels = np.asarray(
        [row["label"] for row in four_two_predictions],
        dtype=object,
    )
    four_two_accepted = np.asarray(
        [row["accepted_as_formal"] for row in four_two_predictions],
        dtype=bool,
    )
    four_two_aggregate = utils.decision_metrics(
        four_two_labels,
        four_two_accepted,
    )
    four_two_aggregate.update(
        {
            "prediction_count_note": (
                "Each transaction appears in five different 4|2 test folds."
            ),
            "macro_formal_accept_rate": float(
                np.mean(
                    [fold["formal_accept_rate"] for fold in four_two_folds]
                )
            ),
            "macro_magic_reject_rate": float(
                np.mean(
                    [fold["magic_reject_rate"] for fold in four_two_folds]
                )
            ),
            "macro_balanced_accuracy": float(
                np.mean(
                    [fold["balanced_accuracy"] for fold in four_two_folds]
                )
            ),
            "macro_auc": float(
                np.mean([fold["auc"] for fold in four_two_folds])
            ),
        }
    )
    four_two_rows = [
        {
            "split_id": fold["split_id"],
            "held_out_groups": "/".join(fold["held_out_groups"]),
            "formal_count": fold["formal_count"],
            "formal_accepted": fold["formal_accepted"],
            "formal_rejected": fold["formal_rejected"],
            "formal_accept_rate": fold["formal_accept_rate"],
            "magic_count": fold["magic_count"],
            "magic_rejected": fold["magic_rejected"],
            "magic_accepted": fold["magic_accepted"],
            "magic_reject_rate": fold["magic_reject_rate"],
            "accuracy": fold["accuracy"],
            "balanced_accuracy": fold["balanced_accuracy"],
            "auc": fold["auc"],
            "threshold": fold["threshold"],
            "calibration_worst_group_frr": fold["calibration"][
                "worst_group_formal_frr"
            ],
        }
        for fold in four_two_folds
    ]
    utils.write_csv(
        output_dir / "four_train_two_test_results.csv",
        four_two_rows,
    )
    utils.write_csv(
        output_dir / "four_train_two_test_predictions.csv",
        four_two_predictions,
    )

    all_mask = np.ones(labels.size, dtype=bool)
    final_metrics, _ = fit_fold(
        matrix=matrix,
        labels=labels,
        groups=groups,
        training_mask=all_mask,
        test_mask=all_mask,
        max_group_frr=args.max_group_frr,
        ridge=args.ridge,
        sample_rate_hz=args.sample_rate_hz,
        output_dir=output_dir / "final_all_groups",
    )

    fold_rows = [
        {
            "held_out_group": fold["held_out_group"],
            "held_out_magic_generation": fold["held_out_magic_generation"],
            "formal_count": fold["formal_count"],
            "formal_accepted": fold["formal_accepted"],
            "formal_rejected": fold["formal_rejected"],
            "formal_accept_rate": fold["formal_accept_rate"],
            "magic_count": fold["magic_count"],
            "magic_rejected": fold["magic_rejected"],
            "magic_accepted": fold["magic_accepted"],
            "magic_reject_rate": fold["magic_reject_rate"],
            "balanced_accuracy": fold["balanced_accuracy"],
            "auc": fold["auc"],
            "threshold": fold["threshold"],
            "calibration_formal_accept_rate": fold["calibration"][
                "formal_accept_rate"
            ],
            "calibration_magic_reject_rate": fold["calibration"][
                "magic_reject_rate"
            ],
            "calibration_worst_group_frr": fold["calibration"][
                "worst_group_formal_frr"
            ],
        }
        for fold in folds
    ]
    utils.write_csv(output_dir / "fold_results.csv", fold_rows)
    utils.write_csv(output_dir / "blind_predictions.csv", predictions)

    report = {
        "schema_version": 1,
        "created_utc": utc_now(),
        "strategy": {
            "outer_validation": "leave one complete group out",
            "training_classes": "five groups Formal and Magic",
            "features": "concatenated auth_a, auth_b and read_block0 features",
            "classifier": "L2 logistic regression",
            "sample_weighting": "equal total weight for every group/class cell",
            "threshold": (
                f"every training Formal group FRR <= {args.max_group_frr:.3f}"
            ),
            "blind_test": "held-out group's Formal and Magic only",
        },
        "data_root": utils.portable_path(data_root),
        "complete_transaction_count": len(transactions),
        "feature_count": int(matrix.shape[1]),
        "ridge": float(args.ridge),
        "folds": folds,
        "blind_aggregate": aggregate,
        "magic_generation_breakdown": generation_breakdown,
        "leave_one_magic_generation_out": generation_holdout,
        "four_train_two_test": {
            "fold_count": len(four_two_folds),
            "folds": four_two_folds,
            "aggregate_with_repeated_test_appearances": four_two_aggregate,
        },
        "group_metadata": utils.portable_path(args.group_metadata),
        "final_all_groups_model": {
            "note": (
                "Trained and calibrated on all six groups; metrics are "
                "resubstitution/calibration, not blind-test evidence."
            ),
            "model": utils.portable_path(
                output_dir
                / "final_all_groups"
                / "supervised_binary_model.json"
            ),
            "calibration_metrics": final_metrics,
        },
        "artifacts": {
            "fold_results_csv": utils.portable_path(
                output_dir / "fold_results.csv"
            ),
            "blind_predictions_csv": utils.portable_path(
                output_dir / "blind_predictions.csv"
            ),
            "generation_holdout_predictions_csv": utils.portable_path(
                output_dir / "generation_holdout_predictions.csv"
            ),
            "four_train_two_test_results_csv": utils.portable_path(
                output_dir / "four_train_two_test_results.csv"
            ),
            "four_train_two_test_predictions_csv": utils.portable_path(
                output_dir / "four_train_two_test_predictions.csv"
            ),
            "feature_cache": utils.portable_path(args.feature_cache),
        },
    }
    report_path = output_dir / "supervised_binary_report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Report: {report_path}")
    print(
        "Supervised blind aggregate: "
        f"formal_accept={aggregate['formal_accept_rate']:.3f}, "
        f"magic_reject={aggregate['magic_reject_rate']:.3f}, "
        f"balanced_accuracy={aggregate['balanced_accuracy']:.3f}, "
        f"macro_auc={aggregate['macro_auc']:.3f}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Supervised Formal/Magic six-fold Mix evaluation"
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=WORKSPACE_DIR / "fingerprint_data_mix",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=WORKSPACE_DIR
        / "fingerprint_models"
        / "mix_supervised_binary",
    )
    parser.add_argument(
        "--feature-cache",
        type=Path,
        default=WORKSPACE_DIR
        / "fingerprint_models"
        / "mix_supervised_binary"
        / "feature_cache.npz",
    )
    parser.add_argument(
        "--group-metadata",
        type=Path,
        default=WORKSPACE_DIR
        / "fingerprint_data_mix"
        / "group_metadata.json",
    )
    parser.add_argument("--sample-rate-hz", type=float, default=1_695_000.0)
    parser.add_argument("--max-group-frr", type=float, default=0.05)
    parser.add_argument("--ridge", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 <= args.max_group_frr < 0.5:
        raise ValueError("--max-group-frr must be in [0, 0.5)")
    if args.ridge <= 0 or not math.isfinite(args.ridge):
        raise ValueError("--ridge must be positive and finite")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
