"""Validate PM3 text waveforms and convert them to NumPy arrays.

The PM3 `data save` format contains one signed GraphBuffer sample per line.
This converter preserves those integer values exactly as int16 `.npy` files and
creates an enriched manifest with basic quality-control statistics.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable

import numpy as np


def read_pm3(path: Path) -> np.ndarray:
    """Read one-number-per-line PM3 GraphBuffer data without normalization."""
    values: list[int] = []
    with path.open("r", encoding="ascii") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                value = int(text)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: invalid integer {text!r}") from exc
            if not -128 <= value <= 128:
                raise ValueError(
                    f"{path}:{line_number}: sample {value} is outside expected PM3 range"
                )
            values.append(value)

    if not values:
        raise ValueError(f"{path}: waveform is empty")
    return np.asarray(values, dtype=np.int16)


def waveform_stats(samples: np.ndarray) -> dict[str, str | int | float]:
    """Return inexpensive checks useful for rejecting broken acquisitions."""
    samples_f = samples.astype(np.float64, copy=False)
    edge_count = int(np.count_nonzero(np.diff(samples_f)))
    clipped = np.count_nonzero((samples <= -127) | (samples >= 127))
    return {
        "sample_count": int(samples.size),
        "sample_min": int(samples.min()),
        "sample_max": int(samples.max()),
        "sample_mean": float(samples_f.mean()),
        "sample_std": float(samples_f.std()),
        "changed_sample_fraction": edge_count / max(1, samples.size - 1),
        "clipped_fraction": int(clipped) / samples.size,
    }


def iter_manifest_rows(manifest: Path) -> Iterable[dict[str, str]]:
    with manifest.open("r", encoding="utf-8", newline="") as handle:
        yield from csv.DictReader(handle)


def resolve_waveform(manifest: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate

    # Lua stores paths relative to the PM3 client working directory. First try
    # the current process directory, then the session manifest's ancestors.
    if candidate.exists():
        return candidate.resolve()
    for parent in (manifest.parent, *manifest.parents):
        joined = parent / candidate
        if joined.exists():
            return joined.resolve()
    return candidate


def convert_manifest(manifest: Path, output_dir: Path | None) -> Path:
    rows = list(iter_manifest_rows(manifest))
    if not rows:
        raise ValueError(f"{manifest}: manifest has no capture rows")

    target_root = output_dir or (manifest.parent / "npy")
    target_root.mkdir(parents=True, exist_ok=True)
    enriched_path = manifest.with_name("manifest_enriched.csv")
    enriched_rows: list[dict[str, object]] = []

    for row in rows:
        enriched: dict[str, object] = dict(row)
        source = resolve_waveform(manifest, row["file"])
        try:
            samples = read_pm3(source)
            target = target_root / f"{row['capture_id']}.npy"
            np.save(target, samples, allow_pickle=False)
            stats = waveform_stats(samples)
            enriched.update(stats)
            enriched["npy_file"] = str(target.resolve())
            enriched["qc_status"] = (
                "ok"
                if stats["sample_std"] >= 1.0
                and stats["changed_sample_fraction"] >= 0.001
                else "low_information"
            )
            enriched["qc_error"] = ""
        except Exception as exc:  # Keep a complete audit row for failed captures.
            enriched.update(
                {
                    "sample_count": 0,
                    "sample_min": "",
                    "sample_max": "",
                    "sample_mean": "",
                    "sample_std": "",
                    "changed_sample_fraction": "",
                    "clipped_fraction": "",
                    "npy_file": "",
                    "qc_status": "error",
                    "qc_error": str(exc),
                }
            )
        enriched_rows.append(enriched)

    fieldnames = list(enriched_rows[0].keys())
    with enriched_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched_rows)
    return enriched_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="Session manifest.csv")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for .npy files (default: <session>/npy)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    enriched = convert_manifest(args.manifest.resolve(), args.output_dir)
    print(f"Wrote {enriched}")


if __name__ == "__main__":
    main()
