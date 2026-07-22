#!/usr/bin/env python3
"""MIFARE Classic raw-envelope dataset, training, evaluation, and inference.

The model is intentionally a small one-class baseline.  It is trained only on
genuine cards and combines PCA reconstruction error with distance in the PCA
latent space.  It is useful for proving whether the acquisition contains a
repeatable physical signal before investing in a neural network.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np


GENUINE_ALIASES = {"genuine", "official", "normal", "real"}
EPSILON = 1e-9


class PipelineError(RuntimeError):
    """Raised for invalid data, model, or command configuration."""


@dataclass(frozen=True)
class Capture:
    capture_id: str
    session_id: str
    card_id: str
    label: str
    reader_id: str
    fixture_id: str
    sample_rate_hz: float
    waveform: Path
    manifest: Path


@dataclass(frozen=True)
class FeatureConfig:
    window_samples: int = 32768
    temporal_bins: int = 128
    spectral_bins: int = 24
    min_samples: int = 1000
    min_std: float = 1.0
    min_changed_fraction: float = 0.001
    max_clipped_fraction: float = 0.05


@dataclass(frozen=True)
class QualityReport:
    ok: bool
    reason: str
    sample_count: int
    sample_min: int
    sample_max: int
    sample_mean: float
    sample_std: float
    changed_fraction: float
    clipped_fraction: float
    alignment_start: int


def _normal_label(value: str) -> str:
    return value.strip().lower().replace(" ", "_")


def _resolve_waveform(manifest: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() and candidate.exists():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    for parent in (manifest.parent, *manifest.parents):
        joined = parent / candidate
        if joined.exists():
            return joined.resolve()
    return candidate


def discover_captures(data_root: Path) -> list[Capture]:
    """Load all successful capture rows below a dataset root."""

    if not data_root.exists():
        raise PipelineError(f"data root does not exist: {data_root}")
    manifests = sorted(data_root.rglob("manifest.csv"))
    if not manifests:
        raise PipelineError(f"no manifest.csv found below {data_root}")

    captures: list[Capture] = []
    seen_ids: set[str] = set()
    for manifest in manifests:
        with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"capture_id", "session_id", "card_id", "label", "file"}
            missing = required.difference(reader.fieldnames or [])
            if missing:
                raise PipelineError(
                    f"{manifest}: missing manifest columns {sorted(missing)}"
                )
            for line_number, row in enumerate(reader, start=2):
                if row.get("status", "ok").strip().lower() != "ok":
                    continue
                capture_id = row["capture_id"].strip()
                if not capture_id:
                    raise PipelineError(f"{manifest}:{line_number}: empty capture_id")
                if capture_id in seen_ids:
                    raise PipelineError(f"duplicate capture_id: {capture_id}")
                seen_ids.add(capture_id)
                try:
                    sample_rate = float(row.get("sample_rate_hz") or 1_695_000)
                except ValueError as exc:
                    raise PipelineError(
                        f"{manifest}:{line_number}: invalid sample_rate_hz"
                    ) from exc
                captures.append(
                    Capture(
                        capture_id=capture_id,
                        session_id=row["session_id"].strip(),
                        card_id=row["card_id"].strip(),
                        label=_normal_label(row["label"]),
                        reader_id=row.get("reader_id", "unknown").strip() or "unknown",
                        fixture_id=row.get("fixture_id", "unknown").strip() or "unknown",
                        sample_rate_hz=sample_rate,
                        waveform=_resolve_waveform(manifest, row["file"].strip()),
                        manifest=manifest.resolve(),
                    )
                )
    if not captures:
        raise PipelineError("manifests contain no rows with status=ok")
    return captures


def read_pm3(path: Path) -> np.ndarray:
    """Read one signed GraphBuffer value per line without normalization."""

    values: list[int] = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    value = int(text)
                except ValueError as exc:
                    raise PipelineError(
                        f"{path}:{line_number}: invalid integer {text!r}"
                    ) from exc
                if not -128 <= value <= 128:
                    raise PipelineError(
                        f"{path}:{line_number}: sample {value} outside PM3 range"
                    )
                values.append(value)
    except FileNotFoundError as exc:
        raise PipelineError(f"waveform does not exist: {path}") from exc
    if not values:
        raise PipelineError(f"waveform is empty: {path}")
    return np.asarray(values, dtype=np.float64)


def _alignment_start(centered: np.ndarray) -> int:
    """Coarsely align to the first sustained increase in envelope activity."""

    if centered.size < 128:
        return 0
    magnitude = np.abs(centered)
    width = min(64, max(8, centered.size // 200))
    activity = np.convolve(magnitude, np.ones(width) / width, mode="same")
    baseline_count = max(width * 2, centered.size // 10)
    baseline = activity[:baseline_count]
    median = float(np.median(baseline))
    mad = float(np.median(np.abs(baseline - median)))
    threshold = max(median + 6.0 * max(mad, 0.05), float(activity.max()) * 0.10)
    sustained = np.convolve(
        (activity >= threshold).astype(np.int16), np.ones(width, dtype=np.int16), mode="same"
    )
    candidates = np.flatnonzero(sustained >= max(3, width // 3))
    return max(0, int(candidates[0]) - width) if candidates.size else 0


def _quality(samples: np.ndarray, config: FeatureConfig) -> tuple[QualityReport, int]:
    centered = samples - np.median(samples)
    changed = float(np.count_nonzero(np.diff(samples))) / max(1, samples.size - 1)
    clipped = float(np.count_nonzero((samples <= -127) | (samples >= 127))) / samples.size
    start = _alignment_start(centered)
    reasons: list[str] = []
    if samples.size < config.min_samples:
        reasons.append(f"too_short<{config.min_samples}")
    if float(samples.std()) < config.min_std:
        reasons.append(f"low_std<{config.min_std}")
    if changed < config.min_changed_fraction:
        reasons.append(f"low_activity<{config.min_changed_fraction}")
    if clipped > config.max_clipped_fraction:
        reasons.append(f"clipped>{config.max_clipped_fraction}")
    report = QualityReport(
        ok=not reasons,
        reason="ok" if not reasons else ";".join(reasons),
        sample_count=int(samples.size),
        sample_min=int(samples.min()),
        sample_max=int(samples.max()),
        sample_mean=float(samples.mean()),
        sample_std=float(samples.std()),
        changed_fraction=changed,
        clipped_fraction=clipped,
        alignment_start=start,
    )
    return report, start


def _fixed_window(centered: np.ndarray, start: int, size: int) -> np.ndarray:
    window = centered[start : start + size]
    if window.size < size:
        window = np.pad(window, (0, size - window.size))
    return window


def _binned_statistics(values: np.ndarray, bins: int) -> tuple[np.ndarray, np.ndarray]:
    edges = np.linspace(0, values.size, bins + 1, dtype=np.int64)
    mean_abs = np.empty(bins, dtype=np.float64)
    rms = np.empty(bins, dtype=np.float64)
    for index in range(bins):
        part = values[edges[index] : edges[index + 1]]
        if part.size == 0:
            mean_abs[index] = 0.0
            rms[index] = 0.0
        else:
            mean_abs[index] = float(np.mean(np.abs(part)))
            rms[index] = float(np.sqrt(np.mean(part * part)))
    return mean_abs, rms


def extract_features(
    samples: np.ndarray, config: FeatureConfig
) -> tuple[np.ndarray, list[str], QualityReport]:
    """Extract amplitude-preserving temporal, spectral, and scalar features."""

    report, start = _quality(samples, config)
    centered = samples - np.median(samples)
    window = _fixed_window(centered, start, config.window_samples)
    mean_abs, rms_bins = _binned_statistics(window, config.temporal_bins)

    spectrum = np.abs(np.fft.rfft(window * np.hanning(window.size))) ** 2
    spectrum = np.log1p(spectrum)
    spectral_edges = np.linspace(1, spectrum.size, config.spectral_bins + 1, dtype=np.int64)
    spectral = np.asarray(
        [
            float(np.mean(spectrum[spectral_edges[i] : spectral_edges[i + 1]]))
            for i in range(config.spectral_bins)
        ],
        dtype=np.float64,
    )

    absolute = np.abs(window)
    std = float(window.std())
    rms = float(np.sqrt(np.mean(window * window)))
    q10, q25, q50, q75, q90, q99 = np.quantile(absolute, [0.10, 0.25, 0.50, 0.75, 0.90, 0.99])
    if std > EPSILON:
        normalized = (window - window.mean()) / std
        skew = float(np.mean(normalized**3))
        kurtosis = float(np.mean(normalized**4))
    else:
        skew = 0.0
        kurtosis = 0.0
    scalars = np.asarray(
        [
            std,
            rms,
            float(np.ptp(window)),
            float(np.max(absolute)),
            float(q10),
            float(q25),
            float(q50),
            float(q75),
            float(q90),
            float(q99),
            float(np.max(absolute) / max(rms, EPSILON)),
            skew,
            kurtosis,
            report.changed_fraction,
            report.clipped_fraction,
            float(start / max(1, samples.size)),
        ],
        dtype=np.float64,
    )
    scalar_names = [
        "std",
        "rms",
        "peak_to_peak",
        "peak_abs",
        "abs_q10",
        "abs_q25",
        "abs_q50",
        "abs_q75",
        "abs_q90",
        "abs_q99",
        "crest_factor",
        "skew",
        "kurtosis",
        "changed_fraction",
        "clipped_fraction",
        "alignment_ratio",
    ]
    names = (
        scalar_names
        + [f"mean_abs_{i:03d}" for i in range(config.temporal_bins)]
        + [f"rms_{i:03d}" for i in range(config.temporal_bins)]
        + [f"log_spectral_{i:02d}" for i in range(config.spectral_bins)]
    )
    return np.concatenate([scalars, mean_abs, rms_bins, spectral]), names, report


def build_feature_matrix(
    captures: Iterable[Capture], config: FeatureConfig
) -> tuple[np.ndarray, list[Capture], list[dict[str, Any]], list[str]]:
    features: list[np.ndarray] = []
    valid: list[Capture] = []
    rejected: list[dict[str, Any]] = []
    names: list[str] = []
    for capture in captures:
        try:
            vector, current_names, quality = extract_features(read_pm3(capture.waveform), config)
            if not quality.ok:
                rejected.append(
                    {"capture_id": capture.capture_id, "file": str(capture.waveform), **asdict(quality)}
                )
                continue
            features.append(vector)
            valid.append(capture)
            names = current_names
        except PipelineError as exc:
            rejected.append(
                {"capture_id": capture.capture_id, "file": str(capture.waveform), "ok": False, "reason": str(exc)}
            )
    if not features:
        raise PipelineError("no waveform passed quality checks")
    return np.vstack(features), valid, rejected, names


def _robust_center_scale(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    center = np.median(matrix, axis=0)
    q25, q75 = np.quantile(matrix, [0.25, 0.75], axis=0)
    scale = (q75 - q25) / 1.349
    fallback = matrix.std(axis=0)
    scale = np.where(scale > 1e-6, scale, fallback)
    scale = np.where(scale > 1e-6, scale, 1.0)
    return center, scale


def _robust_location_scale(values: np.ndarray) -> tuple[float, float]:
    center = float(np.median(values))
    mad = float(np.median(np.abs(values - center))) * 1.4826
    if mad < 1e-6:
        mad = max(float(values.std()), 1e-6)
    return center, mad


def _raw_components(
    standardized: np.ndarray, max_components: int, variance_target: float
) -> np.ndarray:
    _, singular, vt = np.linalg.svd(standardized, full_matrices=False)
    variances = singular * singular
    if float(variances.sum()) <= EPSILON:
        raise PipelineError("genuine training features have no variance")
    cumulative = np.cumsum(variances) / variances.sum()
    needed = int(np.searchsorted(cumulative, variance_target) + 1)
    upper = min(max_components, standardized.shape[0] - 1, standardized.shape[1])
    count = max(1, min(needed, upper))
    return vt[:count]


def _metrics_for(
    standardized: np.ndarray,
    components: np.ndarray,
    latent_center: np.ndarray,
    latent_scale: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    latent = standardized @ components.T
    reconstructed = latent @ components
    reconstruction = np.mean((standardized - reconstructed) ** 2, axis=1)
    latent_distance = np.mean(
        ((latent - latent_center) / np.maximum(latent_scale, 1e-6)) ** 2,
        axis=1,
    )
    return reconstruction, latent_distance


def _combined_score(
    reconstruction: np.ndarray,
    latent_distance: np.ndarray,
    metric_center: np.ndarray,
    metric_scale: np.ndarray,
) -> np.ndarray:
    metrics = np.column_stack([reconstruction, latent_distance])
    robust = (metrics - metric_center) / np.maximum(metric_scale, 1e-6)
    return np.mean(np.maximum(robust, 0.0), axis=1)


def _group_split(
    captures: list[Capture], calibration_fraction: float, seed: int
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    cards = sorted({capture.card_id for capture in captures})
    if len(cards) < 3:
        raise PipelineError(
            "training requires at least 3 different genuine card_id values so calibration "
            "can use an unseen physical card"
        )
    rng = np.random.default_rng(seed)
    shuffled = list(cards)
    rng.shuffle(shuffled)
    calibration_count = max(1, min(len(cards) - 2, int(round(len(cards) * calibration_fraction))))
    calibration_cards = set(shuffled[:calibration_count])
    calibration = np.asarray(
        [i for i, capture in enumerate(captures) if capture.card_id in calibration_cards],
        dtype=np.int64,
    )
    training = np.asarray(
        [i for i, capture in enumerate(captures) if capture.card_id not in calibration_cards],
        dtype=np.int64,
    )
    return training, calibration, sorted(calibration_cards)


def save_model(path: Path, arrays: dict[str, np.ndarray], metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(arrays)
    payload["metadata_json"] = np.asarray(json.dumps(metadata, ensure_ascii=False))
    with path.open("wb") as handle:
        np.savez_compressed(handle, **payload)


def load_model(path: Path) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    try:
        with np.load(path, allow_pickle=False) as loaded:
            arrays = {key: loaded[key] for key in loaded.files if key != "metadata_json"}
            metadata = json.loads(str(loaded["metadata_json"].item()))
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot load model {path}: {exc}") from exc
    if metadata.get("model_type") != "pca_oneclass_v1":
        raise PipelineError(f"unsupported model type in {path}")
    return arrays, metadata


def score_matrix(matrix: np.ndarray, arrays: dict[str, np.ndarray]) -> np.ndarray:
    standardized = (matrix - arrays["feature_center"]) / arrays["feature_scale"]
    reconstruction, latent_distance = _metrics_for(
        standardized,
        arrays["components"],
        arrays["latent_center"],
        arrays["latent_scale"],
    )
    return _combined_score(
        reconstruction,
        latent_distance,
        arrays["metric_center"],
        arrays["metric_scale"],
    )


def _feature_config_from_args(args: argparse.Namespace) -> FeatureConfig:
    config = FeatureConfig(
        window_samples=args.window_samples,
        temporal_bins=args.temporal_bins,
        spectral_bins=args.spectral_bins,
        min_samples=args.min_samples,
        min_std=args.min_std,
        min_changed_fraction=args.min_changed_fraction,
        max_clipped_fraction=args.max_clipped_fraction,
    )
    if config.window_samples < 256:
        raise PipelineError("window_samples must be at least 256")
    if config.temporal_bins < 4 or config.spectral_bins < 4:
        raise PipelineError("temporal_bins and spectral_bins must each be at least 4")
    if config.temporal_bins > config.window_samples:
        raise PipelineError("temporal_bins cannot exceed window_samples")
    if config.min_samples < 1 or config.min_std < 0:
        raise PipelineError("min_samples must be positive and min_std cannot be negative")
    if not 0 <= config.min_changed_fraction <= 1:
        raise PipelineError("min_changed_fraction must be between 0 and 1")
    if not 0 <= config.max_clipped_fraction <= 1:
        raise PipelineError("max_clipped_fraction must be between 0 and 1")
    return config


def _feature_config_from_metadata(metadata: dict[str, Any]) -> FeatureConfig:
    return FeatureConfig(**metadata["feature_config"])


def command_inspect(args: argparse.Namespace) -> int:
    config = _feature_config_from_args(args)
    captures = discover_captures(args.data_root)
    matrix, valid, rejected, _ = build_feature_matrix(captures, config)
    by_label: dict[str, int] = {}
    cards_by_label: dict[str, set[str]] = {}
    for capture in valid:
        by_label[capture.label] = by_label.get(capture.label, 0) + 1
        cards_by_label.setdefault(capture.label, set()).add(capture.card_id)
    result = {
        "data_root": str(args.data_root.resolve()),
        "manifest_rows": len(captures),
        "valid_captures": len(valid),
        "rejected_captures": len(rejected),
        "feature_count": int(matrix.shape[1]),
        "captures_by_label": by_label,
        "physical_cards_by_label": {key: len(value) for key, value in cards_by_label.items()},
        "rejected": rejected[:20],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def command_train(args: argparse.Namespace) -> int:
    config = _feature_config_from_args(args)
    if not 0 < args.calibration_fraction < 0.5:
        raise PipelineError("calibration_fraction must be between 0 and 0.5")
    if not 0.5 <= args.threshold_quantile < 1:
        raise PipelineError("threshold_quantile must be at least 0.5 and less than 1")
    if args.max_components < 1:
        raise PipelineError("max_components must be positive")
    if not 0 < args.variance_target <= 1:
        raise PipelineError("variance_target must be between 0 and 1")
    captures = discover_captures(args.data_root)
    genuine_labels = {_normal_label(args.genuine_label), *GENUINE_ALIASES}
    genuine = [capture for capture in captures if capture.label in genuine_labels]
    if len(genuine) < 20:
        raise PipelineError("training requires at least 20 valid genuine captures")
    matrix, valid, rejected, feature_names = build_feature_matrix(genuine, config)
    training_indices, calibration_indices, calibration_cards = _group_split(
        valid, args.calibration_fraction, args.seed
    )
    training = matrix[training_indices]
    calibration = matrix[calibration_indices]
    center, scale = _robust_center_scale(training)
    standardized = (training - center) / scale
    components = _raw_components(standardized, args.max_components, args.variance_target)
    latent = standardized @ components.T
    latent_center, latent_scale = _robust_center_scale(latent)
    reconstruction, latent_distance = _metrics_for(
        standardized, components, latent_center, latent_scale
    )
    metric_centers: list[float] = []
    metric_scales: list[float] = []
    for values in (reconstruction, latent_distance):
        metric_center, metric_scale = _robust_location_scale(values)
        metric_centers.append(metric_center)
        metric_scales.append(metric_scale)
    metric_center_array = np.asarray(metric_centers)
    metric_scale_array = np.asarray(metric_scales)

    calibration_standardized = (calibration - center) / scale
    calibration_reconstruction, calibration_latent = _metrics_for(
        calibration_standardized, components, latent_center, latent_scale
    )
    calibration_scores = _combined_score(
        calibration_reconstruction,
        calibration_latent,
        metric_center_array,
        metric_scale_array,
    )
    threshold = float(np.quantile(calibration_scores, args.threshold_quantile))
    arrays = {
        "feature_center": center,
        "feature_scale": scale,
        "components": components,
        "latent_center": latent_center,
        "latent_scale": latent_scale,
        "metric_center": metric_center_array,
        "metric_scale": metric_scale_array,
        "threshold": np.asarray(threshold),
    }
    metadata = {
        "model_type": "pca_oneclass_v1",
        "feature_config": asdict(config),
        "feature_names": feature_names,
        "genuine_label": _normal_label(args.genuine_label),
        "training_capture_count": int(training.shape[0]),
        "calibration_capture_count": int(calibration.shape[0]),
        "training_card_ids": sorted({valid[i].card_id for i in training_indices}),
        "calibration_card_ids": calibration_cards,
        "pca_components": int(components.shape[0]),
        "variance_target": args.variance_target,
        "threshold_quantile": args.threshold_quantile,
        "threshold": threshold,
        "rejected_genuine_captures": len(rejected),
        "dataset_root_sha256": hashlib.sha256(str(args.data_root.resolve()).encode()).hexdigest(),
    }
    save_model(args.model_out, arrays, metadata)
    summary_path = args.model_out.with_suffix(".json")
    summary_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"model": str(args.model_out.resolve()), **metadata}, ensure_ascii=False, indent=2))
    return 0


def _rank_auc(labels: np.ndarray, scores: np.ndarray) -> float | None:
    positives = int(labels.sum())
    negatives = int(labels.size - positives)
    if positives == 0 or negatives == 0:
        return None
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(scores.size, dtype=np.float64)
    index = 0
    while index < scores.size:
        end = index + 1
        while end < scores.size and scores[order[end]] == scores[order[index]]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        ranks[order[index:end]] = average_rank
        index = end
    positive_ranks = float(ranks[labels].sum())
    return (positive_ranks - positives * (positives + 1) / 2) / (positives * negatives)


def _average_precision(labels: np.ndarray, scores: np.ndarray) -> float | None:
    positives = int(labels.sum())
    if positives == 0:
        return None
    order = np.argsort(-scores, kind="mergesort")
    ordered = labels[order].astype(np.int64)
    true_positives = np.cumsum(ordered)
    precision = true_positives / np.arange(1, ordered.size + 1)
    return float(precision[ordered.astype(bool)].sum() / positives)


def command_evaluate(args: argparse.Namespace) -> int:
    arrays, metadata = load_model(args.model)
    config = _feature_config_from_metadata(metadata)
    captures = discover_captures(args.data_root)
    matrix, valid, rejected, _ = build_feature_matrix(captures, config)
    seen_card_ids = set(metadata.get("training_card_ids", [])) | set(
        metadata.get("calibration_card_ids", [])
    )
    overlap = sorted({capture.card_id for capture in valid} & seen_card_ids)
    excluded_seen_captures = 0
    if overlap and not args.include_seen_genuine:
        keep = np.asarray(
            [capture.card_id not in seen_card_ids for capture in valid], dtype=bool
        )
        excluded_seen_captures = int((~keep).sum())
        matrix = matrix[keep]
        valid = [capture for capture, include in zip(valid, keep) if include]
    if not valid:
        raise PipelineError(
            "evaluation contains no unseen cards after excluding training/calibration card_id values"
        )
    scores = score_matrix(matrix, arrays)
    threshold = float(arrays["threshold"])
    genuine_label = _normal_label(args.genuine_label or metadata["genuine_label"])
    is_anomaly = np.asarray([capture.label != genuine_label for capture in valid], dtype=bool)
    predicted_anomaly = scores > threshold
    genuine_count = int((~is_anomaly).sum())
    anomaly_count = int(is_anomaly.sum())
    if genuine_count == 0 or anomaly_count == 0:
        raise PipelineError(
            "evaluation requires both unseen genuine captures and labeled anomalous captures"
        )
    false_rejects = int((predicted_anomaly & ~is_anomaly).sum())
    false_accepts = int((~predicted_anomaly & is_anomaly).sum())
    breakdown: dict[str, dict[str, Any]] = {}
    for label in sorted({capture.label for capture in valid}):
        indices = np.asarray([i for i, capture in enumerate(valid) if capture.label == label])
        decisions = predicted_anomaly[indices]
        breakdown[label] = {
            "captures": int(indices.size),
            "physical_cards": len({valid[i].card_id for i in indices}),
            "mean_score": float(scores[indices].mean()),
            "median_score": float(np.median(scores[indices])),
            "predicted_anomalous": int(decisions.sum()),
            "predicted_genuine": int((~decisions).sum()),
        }
    result = {
        "model": str(args.model.resolve()),
        "data_root": str(args.data_root.resolve()),
        "threshold": threshold,
        "valid_captures": len(valid),
        "rejected_captures": len(rejected),
        "overlapping_card_ids": overlap,
        "excluded_seen_captures": excluded_seen_captures,
        "genuine_captures": genuine_count,
        "anomaly_captures": anomaly_count,
        "false_reject_rate": false_rejects / genuine_count if genuine_count else None,
        "false_accept_rate": false_accepts / anomaly_count if anomaly_count else None,
        "auroc": _rank_auc(is_anomaly, scores),
        "average_precision": _average_precision(is_anomaly, scores),
        "breakdown": breakdown,
        "rejected": rejected[:20],
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


def command_predict(args: argparse.Namespace) -> int:
    arrays, metadata = load_model(args.model)
    config = _feature_config_from_metadata(metadata)
    vector, _, quality = extract_features(read_pm3(args.waveform), config)
    threshold = float(arrays["threshold"])
    if quality.ok:
        score = float(score_matrix(vector.reshape(1, -1), arrays)[0])
        decision = "anomalous" if score > threshold else "genuine"
    else:
        score = math.inf
        decision = "invalid_capture"
    result = {
        "waveform": str(args.waveform.resolve()),
        "score": score,
        "threshold": threshold,
        "decision": decision,
        "quality": asdict(quality),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if quality.ok else 3


def _add_feature_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--window-samples", type=int, default=32768)
    parser.add_argument("--temporal-bins", type=int, default=128)
    parser.add_argument("--spectral-bins", type=int, default=24)
    parser.add_argument("--min-samples", type=int, default=1000)
    parser.add_argument("--min-std", type=float, default=1.0)
    parser.add_argument("--min-changed-fraction", type=float, default=0.001)
    parser.add_argument("--max-clipped-fraction", type=float, default=0.05)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect PM3 waveforms and train/evaluate a genuine-card one-class model"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="validate manifests and waveforms")
    inspect_parser.add_argument("--data-root", type=Path, required=True)
    _add_feature_arguments(inspect_parser)
    inspect_parser.set_defaults(function=command_inspect)

    train_parser = subparsers.add_parser("train", help="train only on genuine cards")
    train_parser.add_argument("--data-root", type=Path, required=True)
    train_parser.add_argument("--model-out", type=Path, required=True)
    train_parser.add_argument("--genuine-label", default="genuine")
    train_parser.add_argument("--calibration-fraction", type=float, default=0.25)
    train_parser.add_argument("--threshold-quantile", type=float, default=0.99)
    train_parser.add_argument("--max-components", type=int, default=24)
    train_parser.add_argument("--variance-target", type=float, default=0.95)
    train_parser.add_argument("--seed", type=int, default=20260722)
    _add_feature_arguments(train_parser)
    train_parser.set_defaults(function=command_train)

    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate a labeled dataset")
    evaluate_parser.add_argument("--data-root", type=Path, required=True)
    evaluate_parser.add_argument("--model", type=Path, required=True)
    evaluate_parser.add_argument("--genuine-label")
    evaluate_parser.add_argument("--output", type=Path)
    evaluate_parser.add_argument(
        "--include-seen-genuine",
        action="store_true",
        help="debug only: include card_id values used for training/calibration",
    )
    evaluate_parser.set_defaults(function=command_evaluate)

    predict_parser = subparsers.add_parser("predict", help="classify one new PM3 waveform")
    predict_parser.add_argument("--model", type=Path, required=True)
    predict_parser.add_argument("--waveform", type=Path, required=True)
    predict_parser.set_defaults(function=command_predict)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.function(args))
    except (PipelineError, ValueError, np.linalg.LinAlgError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
