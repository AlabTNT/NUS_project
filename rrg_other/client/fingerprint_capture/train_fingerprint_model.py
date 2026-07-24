"""Train and apply a waveform-feature model for MIFARE card screening.

The default ``oneclass`` mode learns only from formal/genuine cards.  Captures
whose feature vectors are far from the learned formal-card distribution receive
larger anomaly scores.  Magic-card captures, when present, are used only for
evaluation and never for fitting or threshold calibration.

The optional ``binary`` mode is an exploratory regularized logistic classifier
that uses both labels.  It should not be used as evidence of unseen-card
generalization unless validation is grouped by physical card.

Only NumPy is required.  Models are stored as readable JSON files.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np


MODEL_SCHEMA_VERSION = 2
DEFAULT_SAMPLE_RATE_HZ = 1_695_000.0

# Families receive equal weight in the one-class score.  This prevents a large
# set of mutually correlated amplitude features from overwhelming frequency or
# transition information merely because that family contains more columns.
FEATURE_FAMILIES: dict[str, tuple[str, ...]] = {
    "amplitude": (
        "mean",
        "std",
        "rms",
        "mean_abs",
        "centered_mean_abs",
        "median",
        "mad_median",
        "q05",
        "q25",
        "q75",
        "q95",
        "iqr",
        "skewness",
        "kurtosis_excess",
        "amplitude_entropy",
    ),
    "occupancy": (
        "clip_pos_frac",
        "clip_neg_frac",
        "clip_total_frac",
        "near_zero_frac",
        "abs_gt_32_frac",
        "abs_gt_64_frac",
        "abs_gt_96_frac",
        "active_frac_0_5std",
        "active_frac_1std",
        "active_frac_2std",
    ),
    "transition": (
        "d1_rms",
        "d1_mean_abs",
        "norm_d1_rms",
        "norm_d1_mean_abs",
        "norm_d2_rms",
        "d1_abs_q50",
        "d1_abs_q90",
        "d1_abs_q95",
        "d1_zero_frac",
        "d1_gt_16_frac",
        "d1_gt_32_frac",
        "d1_gt_64_frac",
        "zcr_centered",
        "slope_change_rate",
        "lagdiff_norm_2",
        "lagdiff_norm_4",
        "lagdiff_norm_8",
        "lagdiff_norm_16",
        "lagdiff_norm_32",
    ),
    "correlation": (
        "autocorr_1",
        "autocorr_2",
        "autocorr_4",
        "autocorr_8",
        "autocorr_16",
        "autocorr_32",
        "autocorr_64",
        "autocorr_128",
    ),
    "temporal": (
        "local_rms_cv",
        "local_abs_cv",
        "energy_time_center",
        "energy_time_spread",
        "energy_first_half_frac",
        "active_runs_per_ksample",
        "active_longest_frac",
    ),
    "spectrum": (
        "spec_centroid_norm",
        "spec_bandwidth_norm",
        "spec_entropy",
        "spec_flatness",
        "spec_rolloff50_norm",
        "spec_rolloff85_norm",
        "spec_rolloff95_norm",
        "spec_peak_norm",
        "band_000_010k_frac",
        "band_010_030k_frac",
        "band_030_060k_frac",
        "band_060_090k_frac",
        "band_090_130k_frac",
        "band_130_200k_frac",
        "band_200_350k_frac",
        "band_350_600k_frac",
        "band_600_nyquist_frac",
        "spec_low_mid_log_ratio",
        "spec_high_low_log_ratio",
    ),
}

FEATURE_NAMES = tuple(
    feature
    for family_features in FEATURE_FAMILIES.values()
    for feature in family_features
)


@dataclass(frozen=True)
class Capture:
    """One waveform and the metadata required for leakage-safe evaluation."""

    path: Path
    label: str
    card_id: str
    batch_id: str


def safe_div(numerator: float, denominator: float) -> float:
    """Return a finite quotient, using zero when the denominator is tiny."""
    if abs(denominator) <= 1e-15:
        return 0.0
    return float(numerator / denominator)


def read_pm3(path: Path) -> np.ndarray:
    """Read a PM3 one-signed-sample-per-line GraphBuffer file."""
    values: list[int] = []
    with path.open("r", encoding="ascii") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                value = int(text)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_number}: invalid integer sample {text!r}"
                ) from exc
            if not -128 <= value <= 128:
                raise ValueError(
                    f"{path}:{line_number}: sample {value} is outside [-128, 128]"
                )
            values.append(value)

    if len(values) < 4096:
        raise ValueError(f"{path}: only {len(values)} samples; at least 4096 required")
    return np.asarray(values, dtype=np.float64)


def normalize_label(value: str) -> str:
    """Normalize common dataset labels to ``formal`` or ``magic``."""
    text = value.strip().lower()
    aliases = {
        "formal": "formal",
        "genuine": "formal",
        "normal": "formal",
        "magic": "magic",
        "clone": "magic",
        "anomaly": "magic",
    }
    if text not in aliases:
        raise ValueError(f"unsupported label {value!r}; expected formal or magic")
    return aliases[text]


def discover_captures(data_root: Path, card_id_mode: str) -> list[Capture]:
    """Discover the current ``capture/<batch>/<label>*.pm3`` layout.

    ``prefix`` mode treats all captures with one label in a directory as
    repetitions of one physical card.  ``file`` mode treats every PM3 file as
    a different physical card.  An explicit manifest remains preferable when
    cards have multiple captures or a more complex directory structure.
    """
    captures: list[Capture] = []
    for path in sorted(data_root.rglob("*.pm3")):
        stem = path.stem.lower()
        if stem.startswith("formal"):
            label = "formal"
        elif stem.startswith("magic"):
            label = "magic"
        else:
            continue
        relative_parent = path.parent.relative_to(data_root).as_posix() or "."
        if card_id_mode == "file":
            card_id = path.relative_to(data_root).with_suffix("").as_posix()
        else:
            card_id = f"{relative_parent}::{label}"
        captures.append(
            Capture(
                path=path.resolve(),
                label=label,
                card_id=card_id,
                batch_id=relative_parent,
            )
        )
    if not captures:
        raise ValueError(f"{data_root}: no formal*.pm3 or magic*.pm3 files found")
    return captures


def load_manifest(manifest: Path) -> list[Capture]:
    """Load an explicit CSV containing file, label, card_id and optional batch_id."""
    captures: list[Capture] = []
    with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"file", "label", "card_id"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{manifest}: missing columns {sorted(missing)}")
        for row_number, row in enumerate(reader, start=2):
            path = Path(row["file"])
            if not path.is_absolute():
                path = manifest.parent / path
            if not path.exists():
                raise FileNotFoundError(f"{manifest}:{row_number}: {path} not found")
            card_id = row["card_id"].strip()
            if not card_id:
                raise ValueError(f"{manifest}:{row_number}: card_id is empty")
            captures.append(
                Capture(
                    path=path.resolve(),
                    label=normalize_label(row["label"]),
                    card_id=card_id,
                    batch_id=(row.get("batch_id") or card_id).strip(),
                )
            )
    if not captures:
        raise ValueError(f"{manifest}: manifest contains no captures")
    return captures


def autocorrelation(centered: np.ndarray, lag: int) -> float:
    """Normalized autocorrelation at one sample lag."""
    left = centered[:-lag]
    right = centered[lag:]
    denominator = math.sqrt(float(np.dot(left, left) * np.dot(right, right)))
    return safe_div(float(np.dot(left, right)), denominator)


def run_statistics(mask: np.ndarray) -> tuple[int, int]:
    """Return the number of true runs and the longest true-run length."""
    starts = np.flatnonzero(mask & np.r_[True, ~mask[:-1]])
    ends = np.flatnonzero(mask & np.r_[~mask[1:], True])
    if starts.size == 0:
        return 0, 0
    lengths = ends - starts + 1
    return int(lengths.size), int(lengths.max())


def welch_features(centered: np.ndarray, sample_rate_hz: float) -> dict[str, float]:
    """Return normalized Welch-spectrum descriptors using 4096-sample windows."""
    nfft = 4096
    hop = nfft // 2
    window = np.hanning(nfft)
    window_power = float(np.dot(window, window))
    spectra: list[np.ndarray] = []

    for start in range(0, centered.size - nfft + 1, hop):
        segment = centered[start : start + nfft]
        segment = segment - segment.mean()
        fft_values = np.fft.rfft(segment * window)
        spectra.append((np.abs(fft_values) ** 2) / window_power)

    power = np.mean(spectra, axis=0)
    frequencies = np.fft.rfftfreq(nfft, d=1.0 / sample_rate_hz)
    power[0] = 0.0
    total_power = float(power.sum())
    if total_power <= 0.0:
        raise ValueError("waveform has no non-DC spectral energy")
    probability = power / total_power

    centroid = float(np.sum(frequencies * probability))
    bandwidth = math.sqrt(
        float(np.sum(((frequencies - centroid) ** 2) * probability))
    )
    nonzero_probability = probability[probability > 0.0]
    entropy = float(
        -np.sum(nonzero_probability * np.log2(nonzero_probability))
        / math.log2(probability.size)
    )
    flatness = safe_div(
        float(np.exp(np.mean(np.log(power + 1e-30)))),
        float(np.mean(power)),
    )
    cumulative = np.cumsum(probability)

    def rolloff(fraction: float) -> float:
        index = min(
            int(np.searchsorted(cumulative, fraction)), frequencies.size - 1
        )
        return float(frequencies[index] / nyquist)

    nyquist = sample_rate_hz / 2.0
    peak_frequency = float(frequencies[1 + int(np.argmax(power[1:]))])

    result = {
        "spec_centroid_norm": centroid / nyquist,
        "spec_bandwidth_norm": bandwidth / nyquist,
        "spec_entropy": entropy,
        "spec_flatness": flatness,
        "spec_rolloff50_norm": rolloff(0.50),
        "spec_rolloff85_norm": rolloff(0.85),
        "spec_rolloff95_norm": rolloff(0.95),
        "spec_peak_norm": peak_frequency / nyquist,
    }

    bands = (
        (0.0, 10_000.0, "band_000_010k_frac"),
        (10_000.0, 30_000.0, "band_010_030k_frac"),
        (30_000.0, 60_000.0, "band_030_060k_frac"),
        (60_000.0, 90_000.0, "band_060_090k_frac"),
        (90_000.0, 130_000.0, "band_090_130k_frac"),
        (130_000.0, 200_000.0, "band_130_200k_frac"),
        (200_000.0, 350_000.0, "band_200_350k_frac"),
        (350_000.0, 600_000.0, "band_350_600k_frac"),
        (600_000.0, nyquist + 1.0, "band_600_nyquist_frac"),
    )
    for low, high, name in bands:
        mask = (frequencies >= low) & (frequencies < high)
        result[name] = float(power[mask].sum() / total_power)
    low_power = sum(
        result[name]
        for name in (
            "band_000_010k_frac",
            "band_010_030k_frac",
            "band_030_060k_frac",
            "band_060_090k_frac",
        )
    )
    mid_power = sum(
        result[name]
        for name in (
            "band_090_130k_frac",
            "band_130_200k_frac",
            "band_200_350k_frac",
        )
    )
    high_power = result["band_350_600k_frac"] + result["band_600_nyquist_frac"]
    result["spec_low_mid_log_ratio"] = float(
        np.log((low_power + 1e-12) / (mid_power + 1e-12))
    )
    result["spec_high_low_log_ratio"] = float(
        np.log((high_power + 1e-12) / (low_power + 1e-12))
    )
    return result


def extract_features(samples: np.ndarray, sample_rate_hz: float) -> dict[str, float]:
    """Extract complementary amplitude, transition and frequency features."""
    mean = float(samples.mean())
    centered = samples - mean
    standard_deviation = float(centered.std())
    absolute = np.abs(samples)
    difference = np.diff(samples)
    second_difference = np.diff(samples, n=2)
    absolute_difference = np.abs(difference)
    variance = float(np.mean(centered * centered))
    rms = float(np.sqrt(np.mean(samples * samples)))
    q05, q25, q75, q95 = np.quantile(samples, (0.05, 0.25, 0.75, 0.95))

    third_moment = float(np.mean(centered**3))
    fourth_moment = float(np.mean(centered**4))
    histogram, _ = np.histogram(samples, bins=np.arange(-128.5, 128.6, 1.0))
    histogram_probability = histogram[histogram > 0] / samples.size
    amplitude_entropy = float(
        -np.sum(histogram_probability * np.log2(histogram_probability)) / 8.0
    )
    d1_rms = float(np.sqrt(np.mean(difference * difference)))
    d1_mean_abs = float(absolute_difference.mean())
    features = {
        "mean": mean,
        "std": standard_deviation,
        "rms": rms,
        "mean_abs": float(absolute.mean()),
        "centered_mean_abs": float(np.mean(np.abs(centered))),
        "median": float(np.median(samples)),
        "mad_median": float(np.median(np.abs(samples - np.median(samples)))),
        "q05": float(q05),
        "q25": float(q25),
        "q75": float(q75),
        "q95": float(q95),
        "iqr": float(q75 - q25),
        "skewness": safe_div(third_moment, variance**1.5),
        "kurtosis_excess": safe_div(fourth_moment, variance**2) - 3.0,
        "amplitude_entropy": amplitude_entropy,
        "clip_pos_frac": float(np.mean(samples >= 126)),
        "clip_neg_frac": float(np.mean(samples <= -126)),
        "clip_total_frac": float(np.mean(absolute >= 126)),
        "near_zero_frac": float(np.mean(absolute <= 5)),
        "abs_gt_32_frac": float(np.mean(absolute > 32)),
        "abs_gt_64_frac": float(np.mean(absolute > 64)),
        "abs_gt_96_frac": float(np.mean(absolute > 96)),
        "active_frac_0_5std": float(
            np.mean(np.abs(centered) > 0.5 * standard_deviation)
        ),
        "active_frac_1std": float(
            np.mean(np.abs(centered) > standard_deviation)
        ),
        "active_frac_2std": float(
            np.mean(np.abs(centered) > 2.0 * standard_deviation)
        ),
        "d1_rms": d1_rms,
        "d1_mean_abs": d1_mean_abs,
        "norm_d1_rms": safe_div(d1_rms, standard_deviation),
        "norm_d1_mean_abs": safe_div(d1_mean_abs, standard_deviation),
        "norm_d2_rms": safe_div(
            float(np.sqrt(np.mean(second_difference * second_difference))),
            standard_deviation,
        ),
        "d1_abs_q50": float(np.quantile(absolute_difference, 0.50)),
        "d1_abs_q90": float(np.quantile(absolute_difference, 0.90)),
        "d1_abs_q95": float(np.quantile(absolute_difference, 0.95)),
        "d1_zero_frac": float(np.mean(difference == 0)),
        "d1_gt_16_frac": float(np.mean(absolute_difference > 16)),
        "d1_gt_32_frac": float(np.mean(absolute_difference > 32)),
        "d1_gt_64_frac": float(np.mean(absolute_difference > 64)),
        "zcr_centered": float(np.mean(centered[:-1] * centered[1:] < 0)),
        "slope_change_rate": float(np.mean(difference[:-1] * difference[1:] < 0)),
        "autocorr_1": autocorrelation(centered, 1),
        "autocorr_2": autocorrelation(centered, 2),
        "autocorr_4": autocorrelation(centered, 4),
        "autocorr_8": autocorrelation(centered, 8),
        "autocorr_16": autocorrelation(centered, 16),
        "autocorr_32": autocorrelation(centered, 32),
        "autocorr_64": autocorrelation(centered, 64),
        "autocorr_128": autocorrelation(centered, 128),
    }

    for lag in (2, 4, 8, 16, 32):
        lag_difference = samples[lag:] - samples[:-lag]
        features[f"lagdiff_norm_{lag}"] = safe_div(
            float(np.sqrt(np.mean(lag_difference * lag_difference))),
            standard_deviation,
        )

    chunks = np.array_split(centered, 16)
    local_rms = np.asarray(
        [float(np.sqrt(np.mean(chunk * chunk))) for chunk in chunks]
    )
    local_abs = np.asarray([float(np.mean(np.abs(chunk))) for chunk in chunks])
    energy = centered * centered
    normalized_time = np.linspace(0.0, 1.0, samples.size)
    energy_sum = float(energy.sum())
    energy_center = safe_div(float(np.sum(normalized_time * energy)), energy_sum)
    active_mask = np.abs(centered) > standard_deviation
    active_runs, active_longest = run_statistics(active_mask)
    features.update(
        {
            "local_rms_cv": safe_div(float(local_rms.std()), float(local_rms.mean())),
            "local_abs_cv": safe_div(float(local_abs.std()), float(local_abs.mean())),
            "energy_time_center": energy_center,
            "energy_time_spread": math.sqrt(
                safe_div(
                    float(np.sum(((normalized_time - energy_center) ** 2) * energy)),
                    energy_sum,
                )
            ),
            "energy_first_half_frac": safe_div(
                float(energy[: samples.size // 2].sum()), energy_sum
            ),
            "active_runs_per_ksample": active_runs / samples.size * 1000.0,
            "active_longest_frac": active_longest / samples.size,
        }
    )
    features.update(welch_features(centered, sample_rate_hz))

    nonfinite = [name for name, value in features.items() if not math.isfinite(value)]
    if nonfinite:
        raise ValueError(f"non-finite features: {nonfinite}")
    return features


def build_feature_table(
    captures: Sequence[Capture], sample_rate_hz: float
) -> tuple[np.ndarray, list[dict[str, object]]]:
    """Read all captures and return the model matrix plus auditable CSV rows."""
    matrix: list[list[float]] = []
    rows: list[dict[str, object]] = []
    for index, capture in enumerate(captures, start=1):
        samples = read_pm3(capture.path)
        features = extract_features(samples, sample_rate_hz)
        matrix.append([features[name] for name in FEATURE_NAMES])
        rows.append(
            {
                "file": str(capture.path),
                "label": capture.label,
                "card_id": capture.card_id,
                "batch_id": capture.batch_id,
                "sample_count": int(samples.size),
                **features,
            }
        )
        print(
            f"[{index:03d}/{len(captures):03d}] "
            f"{capture.label:6s} {capture.card_id}: {capture.path.name}"
        )
    return np.asarray(matrix, dtype=np.float64), rows


def write_csv(path: Path, rows: Sequence[dict[str, object]]) -> None:
    """Write a list of uniform dictionaries as UTF-8 CSV."""
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def json_ready_array(values: np.ndarray) -> list[float]:
    """Convert a NumPy array to ordinary finite JSON numbers."""
    return [float(value) for value in values]


def quantile_higher(values: np.ndarray, quantile: float) -> float:
    """An empirical upper quantile that never interpolates below an observation."""
    ordered = np.sort(np.asarray(values, dtype=np.float64))
    index = math.ceil(quantile * ordered.size) - 1
    return float(ordered[min(max(index, 0), ordered.size - 1)])


def fit_oneclass(
    formal_matrix: np.ndarray,
    target_false_reject_rate: float,
    z_clip: float,
) -> dict[str, object]:
    """Fit a robust, family-balanced one-class feature-distance model."""
    center = np.median(formal_matrix, axis=0)
    mad = np.median(np.abs(formal_matrix - center), axis=0)
    robust_scale = 1.4826 * mad
    standard_scale = formal_matrix.std(axis=0, ddof=1)
    scale = np.where(robust_scale > 1e-12, robust_scale, standard_scale)
    scale = np.where(scale > 1e-12, scale, 1.0)

    model: dict[str, object] = {
        "center": json_ready_array(center),
        "scale": json_ready_array(scale),
        "z_clip": float(z_clip),
    }
    training_scores, family_scores = score_oneclass(formal_matrix, model)
    threshold = quantile_higher(training_scores, 1.0 - target_false_reject_rate)
    # A tiny margin prevents a value equal up to JSON roundoff from being rejected.
    model["threshold"] = float(threshold + max(1e-12, abs(threshold) * 1e-12))
    model["training_score_summary"] = summarize_scores(training_scores)
    model["training_family_score_mean"] = {
        family: float(values.mean()) for family, values in family_scores.items()
    }
    return model


def score_oneclass(
    matrix: np.ndarray, model: dict[str, object]
) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    """Score samples; larger values mean less similar to learned formal cards."""
    center = np.asarray(model["center"], dtype=np.float64)
    scale = np.asarray(model["scale"], dtype=np.float64)
    z_clip = float(model["z_clip"])
    clipped_squared_z = np.minimum(((matrix - center) / scale) ** 2, z_clip**2)

    family_scores: dict[str, np.ndarray] = {}
    offset = 0
    for family, names in FEATURE_FAMILIES.items():
        width = len(names)
        family_scores[family] = clipped_squared_z[:, offset : offset + width].mean(
            axis=1
        )
        offset += width
    combined = np.mean(np.column_stack(list(family_scores.values())), axis=1)
    return combined, family_scores


def sigmoid(values: np.ndarray) -> np.ndarray:
    """Numerically stable logistic sigmoid."""
    clipped = np.clip(values, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def fit_binary(
    matrix: np.ndarray,
    labels: np.ndarray,
    ridge: float,
    max_iterations: int = 100,
) -> dict[str, object]:
    """Fit a small L2-regularized logistic model using Newton updates."""
    mean = matrix.mean(axis=0)
    scale = matrix.std(axis=0, ddof=1)
    scale = np.where(scale > 1e-12, scale, 1.0)
    standardized = (matrix - mean) / scale
    design = np.column_stack([np.ones(matrix.shape[0]), standardized])
    weights = np.zeros(design.shape[1], dtype=np.float64)
    penalty = np.eye(design.shape[1], dtype=np.float64) * ridge
    penalty[0, 0] = 0.0

    for _ in range(max_iterations):
        probability = sigmoid(design @ weights)
        curvature = np.maximum(probability * (1.0 - probability), 1e-8)
        gradient = design.T @ (probability - labels) + penalty @ weights
        hessian = (design.T * curvature) @ design + penalty
        update = np.linalg.solve(hessian, gradient)
        weights -= update
        if float(np.max(np.abs(update))) < 1e-8:
            break

    return {
        "mean": json_ready_array(mean),
        "scale": json_ready_array(scale),
        "intercept": float(weights[0]),
        "weights": json_ready_array(weights[1:]),
        "threshold": 0.5,
        "ridge": float(ridge),
    }


def score_binary(matrix: np.ndarray, model: dict[str, object]) -> np.ndarray:
    """Return estimated Magic-card probability for a binary model."""
    mean = np.asarray(model["mean"], dtype=np.float64)
    scale = np.asarray(model["scale"], dtype=np.float64)
    weights = np.asarray(model["weights"], dtype=np.float64)
    standardized = (matrix - mean) / scale
    return sigmoid(standardized @ weights + float(model["intercept"]))


def auc_pairwise(formal_scores: np.ndarray, magic_scores: np.ndarray) -> float | None:
    """Probability that a random Magic score exceeds a random formal score."""
    if formal_scores.size == 0 or magic_scores.size == 0:
        return None
    comparisons = [
        1.0 if magic > formal else 0.5 if magic == formal else 0.0
        for formal in formal_scores
        for magic in magic_scores
    ]
    return float(np.mean(comparisons))


def summarize_scores(scores: np.ndarray) -> dict[str, float]:
    """Compact numeric summary used in the JSON report."""
    return {
        "minimum": float(np.min(scores)),
        "median": float(np.median(scores)),
        "mean": float(np.mean(scores)),
        "maximum": float(np.max(scores)),
    }


def classification_metrics(
    labels: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, object]:
    """Evaluate scores where Magic is the positive/rejected class."""
    formal = labels == 0
    magic = labels == 1
    predicted_magic = scores > threshold
    metrics: dict[str, object] = {
        "sample_count": int(labels.size),
        "threshold": float(threshold),
        "accuracy": float(np.mean(predicted_magic == magic)),
        "formal_accept_rate": (
            float(np.mean(~predicted_magic[formal])) if np.any(formal) else None
        ),
        "magic_reject_rate": (
            float(np.mean(predicted_magic[magic])) if np.any(magic) else None
        ),
        "auc": auc_pairwise(scores[formal], scores[magic]),
        "formal_scores": summarize_scores(scores[formal]) if np.any(formal) else None,
        "magic_scores": summarize_scores(scores[magic]) if np.any(magic) else None,
    }
    return metrics


def grouped_binary_validation(
    matrix: np.ndarray,
    labels: np.ndarray,
    batch_ids: np.ndarray,
    ridge: float,
) -> dict[str, object]:
    """Leave one entire acquisition batch out at a time."""
    folds: list[dict[str, object]] = []
    all_labels: list[int] = []
    all_scores: list[float] = []
    for held_out in sorted(set(batch_ids.tolist())):
        test = batch_ids == held_out
        train = ~test
        if len(set(labels[train].tolist())) < 2:
            continue
        model = fit_binary(matrix[train], labels[train], ridge)
        scores = score_binary(matrix[test], model)
        fold_metrics = classification_metrics(labels[test], scores, 0.5)
        folds.append({"held_out_batch": held_out, **fold_metrics})
        all_labels.extend(labels[test].tolist())
        all_scores.extend(scores.tolist())
    if not folds:
        return {"status": "unavailable", "reason": "need at least two usable batches"}
    aggregate = classification_metrics(
        np.asarray(all_labels, dtype=int),
        np.asarray(all_scores, dtype=float),
        0.5,
    )
    return {"status": "ok", "folds": folds, "aggregate": aggregate}


def grouped_oneclass_formal_validation(
    matrix: np.ndarray,
    labels: np.ndarray,
    card_ids: np.ndarray,
    target_false_reject_rate: float,
    z_clip: float,
) -> dict[str, object]:
    """Hold out each complete formal physical card and score it as unseen."""
    formal_indices = np.flatnonzero(labels == 0)
    formal_cards = sorted(set(card_ids[formal_indices].tolist()))
    folds: list[dict[str, object]] = []
    all_scores: list[float] = []

    for held_out_card in formal_cards:
        test = (labels == 0) & (card_ids == held_out_card)
        train = (labels == 0) & ~test
        if np.count_nonzero(train) < 2:
            continue
        model = fit_oneclass(matrix[train], target_false_reject_rate, z_clip)
        scores, _ = score_oneclass(matrix[test], model)
        threshold = float(model["threshold"])
        folds.append(
            {
                "held_out_card": held_out_card,
                "capture_count": int(scores.size),
                "accept_rate": float(np.mean(scores <= threshold)),
                "threshold": threshold,
                "scores": summarize_scores(scores),
            }
        )
        all_scores.extend(scores.tolist())
    if not folds:
        return {
            "status": "unavailable",
            "reason": "need at least two formal physical-card groups",
        }
    return {
        "status": "ok",
        "folds": folds,
        "aggregate_unseen_formal_accept_rate": float(
            np.average(
                [fold["accept_rate"] for fold in folds],
                weights=[fold["capture_count"] for fold in folds],
            )
        ),
        "unseen_formal_scores": summarize_scores(np.asarray(all_scores)),
    }


def grouped_oneclass_batch_validation(
    matrix: np.ndarray,
    labels: np.ndarray,
    batch_ids: np.ndarray,
    target_false_reject_rate: float,
    z_clip: float,
) -> dict[str, object]:
    """Train without one complete batch, then score both classes in that batch."""
    folds: list[dict[str, object]] = []
    pooled_labels: list[int] = []
    pooled_relative_scores: list[float] = []

    for held_out_batch in sorted(set(batch_ids.tolist())):
        test = batch_ids == held_out_batch
        train_formal = (labels == 0) & ~test
        if np.count_nonzero(train_formal) < 2:
            continue
        model = fit_oneclass(
            matrix[train_formal],
            target_false_reject_rate=target_false_reject_rate,
            z_clip=z_clip,
        )
        scores, _ = score_oneclass(matrix[test], model)
        threshold = float(model["threshold"])
        relative_scores = scores / threshold
        fold_metrics = classification_metrics(labels[test], relative_scores, 1.0)
        folds.append(
            {
                "held_out_batch": held_out_batch,
                "raw_threshold": threshold,
                **fold_metrics,
            }
        )
        pooled_labels.extend(labels[test].tolist())
        pooled_relative_scores.extend(relative_scores.tolist())

    if not folds:
        return {"status": "unavailable", "reason": "need at least two usable batches"}
    aggregate = classification_metrics(
        np.asarray(pooled_labels, dtype=int),
        np.asarray(pooled_relative_scores, dtype=float),
        1.0,
    )
    return {
        "status": "ok",
        "score_definition": "fold anomaly score divided by that fold threshold",
        "folds": folds,
        "aggregate": aggregate,
    }


def train_command(args: argparse.Namespace) -> int:
    """Extract features, train the requested model and write its artifacts."""
    captures = (
        load_manifest(args.manifest.resolve())
        if args.manifest
        else discover_captures(args.data_root.resolve(), args.card_id_mode)
    )
    formal_count = sum(capture.label == "formal" for capture in captures)
    magic_count = sum(capture.label == "magic" for capture in captures)
    if formal_count < 2:
        raise ValueError("at least two formal captures are required")
    if args.mode == "binary" and magic_count < 2:
        raise ValueError("binary mode requires at least two Magic captures")

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    matrix, rows = build_feature_table(captures, args.sample_rate_hz)
    labels = np.asarray([capture.label == "magic" for capture in captures], dtype=int)
    card_ids = np.asarray([capture.card_id for capture in captures], dtype=object)
    batch_ids = np.asarray([capture.batch_id for capture in captures], dtype=object)

    feature_csv = output_dir / "features.csv"
    model_path = output_dir / f"{args.mode}_model.json"
    report_path = output_dir / f"{args.mode}_training_report.json"
    write_csv(feature_csv, rows)

    common_model: dict[str, object] = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model_type": args.mode,
        "sample_rate_hz": float(args.sample_rate_hz),
        "feature_names": list(FEATURE_NAMES),
        "feature_families": {
            family: list(names) for family, names in FEATURE_FAMILIES.items()
        },
        "formal_label": "formal",
        "anomaly_label": "magic",
        "training_capture_count": len(captures),
        "training_formal_count": formal_count,
        "evaluation_magic_count": magic_count,
    }

    if args.mode == "oneclass":
        fitted = fit_oneclass(
            matrix[labels == 0],
            target_false_reject_rate=args.target_frr,
            z_clip=args.z_clip,
        )
        scores, family_scores = score_oneclass(matrix, fitted)
        threshold = float(fitted["threshold"])
        report = {
            "mode": "oneclass",
            "important_note": (
                "Magic samples were used only for evaluation, never for fitting "
                "or threshold calibration."
            ),
            "all_available_data_evaluation": classification_metrics(
                labels, scores, threshold
            ),
            "leave_one_formal_card_out": grouped_oneclass_formal_validation(
                matrix,
                labels,
                card_ids,
                target_false_reject_rate=args.target_frr,
                z_clip=args.z_clip,
            ),
            "leave_one_batch_out": grouped_oneclass_batch_validation(
                matrix,
                labels,
                batch_ids,
                target_false_reject_rate=args.target_frr,
                z_clip=args.z_clip,
            ),
            "mean_family_scores_by_label": {
                label_name: {
                    family: float(values[labels == label_value].mean())
                    for family, values in family_scores.items()
                }
                for label_name, label_value in (("formal", 0), ("magic", 1))
                if np.any(labels == label_value)
            },
        }
    else:
        fitted = fit_binary(matrix, labels, ridge=args.ridge)
        scores = score_binary(matrix, fitted)
        threshold = float(fitted["threshold"])
        report = {
            "mode": "binary",
            "important_note": (
                "Both formal and Magic samples were used for fitting. Treat this "
                "as an exploratory classifier, not one-class OOD validation."
            ),
            "all_available_data_evaluation": classification_metrics(
                labels, scores, threshold
            ),
            "leave_one_batch_out": grouped_binary_validation(
                matrix, labels, batch_ids, ridge=args.ridge
            ),
        }

    common_model["parameters"] = fitted
    model_path.write_text(
        json.dumps(common_model, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report.update(
        {
            "model_file": str(model_path),
            "feature_file": str(feature_csv),
            "capture_count": len(captures),
            "formal_card_groups": sorted(set(card_ids[labels == 0].tolist())),
            "magic_card_groups": sorted(set(card_ids[labels == 1].tolist())),
        }
    )
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    evaluation = report["all_available_data_evaluation"]
    print(f"\nModel:   {model_path}")
    print(f"Features:{feature_csv}")
    print(f"Report:  {report_path}")
    print(
        "Available-data evaluation: "
        f"accuracy={evaluation['accuracy']:.3f}, "
        f"formal_accept={evaluation['formal_accept_rate']:.3f}, "
        f"magic_reject={evaluation['magic_reject_rate']}"
    )
    return 0


def predict_command(args: argparse.Namespace) -> int:
    """Load a JSON model and score one or more PM3 waveform files."""
    model = json.loads(args.model.read_text(encoding="utf-8"))
    if model.get("schema_version") != MODEL_SCHEMA_VERSION:
        raise ValueError("unsupported model schema version")
    if tuple(model.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("model feature list does not match this script")

    sample_rate_hz = float(model["sample_rate_hz"])
    parameters = model["parameters"]
    rows: list[dict[str, object]] = []
    for path in args.files:
        samples = read_pm3(path.resolve())
        extracted = extract_features(samples, sample_rate_hz)
        matrix = np.asarray([[extracted[name] for name in FEATURE_NAMES]])
        if model["model_type"] == "oneclass":
            score = float(score_oneclass(matrix, parameters)[0][0])
            threshold = float(parameters["threshold"])
            confidence = safe_div(score, threshold)
            decision = "reject_anomaly" if score > threshold else "accept_formal"
        elif model["model_type"] == "binary":
            score = float(score_binary(matrix, parameters)[0])
            threshold = float(parameters["threshold"])
            confidence = score
            decision = "reject_magic" if score > threshold else "accept_formal"
        else:
            raise ValueError(f"unsupported model type {model['model_type']!r}")
        rows.append(
            {
                "file": str(path),
                "score": score,
                "threshold": threshold,
                "relative_score": confidence,
                "decision": decision,
            }
        )

    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line interface."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train", help="extract features and train a model")
    source = train.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--data-root",
        type=Path,
        help="Recursively discover capture/<batch>/{formal,magic}*.pm3",
    )
    source.add_argument(
        "--manifest",
        type=Path,
        help="CSV with file,label,card_id and optional batch_id columns",
    )
    train.add_argument(
        "--mode",
        choices=("oneclass", "binary"),
        default="oneclass",
        help="Training objective (default: oneclass)",
    )
    train.add_argument(
        "--card-id-mode",
        choices=("prefix", "file"),
        default="prefix",
        help=(
            "In discovered data, treat one directory/label prefix as one card "
            "or treat every PM3 file as a distinct card (default: prefix)"
        ),
    )
    train.add_argument(
        "--output-dir",
        type=Path,
        default=Path("fingerprint_capture/model_output"),
        help="Artifact directory",
    )
    train.add_argument(
        "--sample-rate-hz",
        type=float,
        default=DEFAULT_SAMPLE_RATE_HZ,
        help="PM3 waveform sample rate (default: 1695000)",
    )
    train.add_argument(
        "--target-frr",
        type=float,
        default=0.05,
        help="One-class training false-reject target (default: 0.05)",
    )
    train.add_argument(
        "--z-clip",
        type=float,
        default=6.0,
        help="Limit each standardized feature contribution (default: 6)",
    )
    train.add_argument(
        "--ridge",
        type=float,
        default=1.0,
        help="Binary logistic L2 penalty (default: 1)",
    )
    train.set_defaults(function=train_command)

    predict = subparsers.add_parser("predict", help="score PM3 files")
    predict.add_argument("--model", type=Path, required=True, help="Model JSON")
    predict.add_argument("files", type=Path, nargs="+", help="PM3 files to score")
    predict.set_defaults(function=predict_command)
    return parser


def main() -> int:
    """CLI entry point with concise user-facing failures."""
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "target_frr") and not 0.0 < args.target_frr < 0.5:
        parser.error("--target-frr must be between 0 and 0.5")
    if hasattr(args, "z_clip") and args.z_clip <= 0.0:
        parser.error("--z-clip must be positive")
    if hasattr(args, "sample_rate_hz") and args.sample_rate_hz <= 0.0:
        parser.error("--sample-rate-hz must be positive")
    try:
        return int(args.function(args))
    except (OSError, ValueError, np.linalg.LinAlgError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
