"""Shared dataset, feature-cache, metric, and artifact helpers."""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from fingerprint_capture import train_fingerprint_model as model_api


SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = SCRIPT_DIR.parent
STAGES = ("auth_a", "auth_b", "read_block0")
LABELS = ("formal", "magic")


@dataclass(frozen=True)
class Transaction:
    """One complete transaction with all required stage waveforms."""

    group: str
    label: str
    capture_name: str
    stage_files: dict[str, Path]


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def portable_path(path: Path) -> str:
    """Prefer a workspace-relative path, avoiding Windows locale corruption."""

    try:
        return path.resolve().relative_to(WORKSPACE_DIR.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def discover_transactions(data_root: Path) -> list[Transaction]:
    """Discover only labeled captures present in all three stage directories."""

    group_dirs = sorted(path for path in data_root.iterdir() if path.is_dir())
    if not group_dirs:
        raise ValueError(f"no group directories found under {data_root}")

    transactions: list[Transaction] = []
    for group_dir in group_dirs:
        for label in LABELS:
            files_by_stage: dict[str, dict[str, Path]] = {}
            for stage in STAGES:
                stage_dir = group_dir / "stages" / stage
                if not stage_dir.is_dir():
                    raise ValueError(f"missing stage directory: {stage_dir}")
                files_by_stage[stage] = {
                    path.name: path.resolve()
                    for path in sorted(stage_dir.glob(f"{label}-*.pm3"))
                }
            complete_names = set.intersection(
                *(set(files_by_stage[stage]) for stage in STAGES)
            )
            for capture_name in sorted(complete_names):
                transactions.append(
                    Transaction(
                        group=group_dir.name,
                        label=label,
                        capture_name=capture_name,
                        stage_files={
                            stage: files_by_stage[stage][capture_name]
                            for stage in STAGES
                        },
                    )
                )

    groups = sorted({item.group for item in transactions})
    if len(groups) < 2:
        raise ValueError("training requires at least two complete groups")
    for group in groups:
        for label in LABELS:
            if not any(
                item.group == group and item.label == label
                for item in transactions
            ):
                raise ValueError(f"group {group} has no complete {label} captures")
    return transactions


def load_or_extract_features(
    transactions: Sequence[Transaction],
    cache_path: Path,
    sample_rate_hz: float,
) -> dict[str, np.ndarray]:
    """Extract each waveform once and reuse a content-indexed feature cache."""

    expected_keys = [
        f"{item.group}|{item.label}|{item.capture_name}"
        for item in transactions
    ]
    if cache_path.exists():
        with np.load(cache_path, allow_pickle=False) as cached:
            cached_rate = float(cached["sample_rate_hz"][0])
            if (
                math.isclose(cached_rate, sample_rate_hz)
                and cached["keys"].tolist() == expected_keys
                and all(stage in cached for stage in STAGES)
            ):
                return {
                    stage: np.asarray(cached[stage], dtype=np.float64)
                    for stage in STAGES
                }

    matrices: dict[str, np.ndarray] = {}
    total = len(transactions) * len(STAGES)
    completed = 0
    for stage in STAGES:
        rows: list[list[float]] = []
        for item in transactions:
            samples = model_api.read_pm3(item.stage_files[stage])
            features = model_api.extract_features(samples, sample_rate_hz)
            rows.append([features[name] for name in model_api.FEATURE_NAMES])
            completed += 1
            if completed % 100 == 0 or completed == total:
                print(f"Feature extraction: {completed}/{total}", flush=True)
        matrices[stage] = np.asarray(rows, dtype=np.float64)

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        cache_path,
        sample_rate_hz=np.asarray([sample_rate_hz], dtype=np.float64),
        keys=np.asarray(expected_keys),
        **matrices,
    )
    return matrices


def decision_metrics(labels: np.ndarray, accepted: np.ndarray) -> dict[str, Any]:
    """Compute metrics where Magic is the rejected/positive class."""

    formal = labels == "formal"
    magic = labels == "magic"
    formal_accepted = int(np.count_nonzero(formal & accepted))
    formal_rejected = int(np.count_nonzero(formal & ~accepted))
    magic_rejected = int(np.count_nonzero(magic & ~accepted))
    magic_accepted = int(np.count_nonzero(magic & accepted))
    formal_count = int(np.count_nonzero(formal))
    magic_count = int(np.count_nonzero(magic))
    formal_accept_rate = safe_div(formal_accepted, formal_count)
    magic_reject_rate = safe_div(magic_rejected, magic_count)
    return {
        "formal_count": formal_count,
        "magic_count": magic_count,
        "formal_accepted": formal_accepted,
        "formal_rejected": formal_rejected,
        "magic_rejected": magic_rejected,
        "magic_accepted": magic_accepted,
        "formal_accept_rate": formal_accept_rate,
        "formal_frr": 1.0 - formal_accept_rate,
        "magic_reject_rate": magic_reject_rate,
        "magic_far": 1.0 - magic_reject_rate,
        "accuracy": safe_div(
            formal_accepted + magic_rejected,
            formal_count + magic_count,
        ),
        "balanced_accuracy": (formal_accept_rate + magic_reject_rate) / 2.0,
    }


def write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
