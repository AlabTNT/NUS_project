"""Temporary timing-profile analysis for the six PM3 capture groups."""

from pathlib import Path

import numpy as np


ROOT = Path("capture")
BIN_SIZE = 128
SAMPLE_RATE = 1_695_000.0


def load_profile(path: Path) -> tuple[np.ndarray, np.ndarray]:
    samples = np.loadtxt(path, dtype=np.float64)
    usable = (samples.size // BIN_SIZE) * BIN_SIZE
    blocks = samples[:usable].reshape(-1, BIN_SIZE)
    centered = blocks - blocks.mean(axis=1, keepdims=True)
    local_std = centered.std(axis=1)
    difference = np.abs(np.diff(samples[:usable], prepend=samples[0]))
    diff_activity = difference.reshape(-1, BIN_SIZE).mean(axis=1)
    return local_std, diff_activity


records = []
for group_dir in sorted(path for path in ROOT.iterdir() if path.is_dir()):
    for path in sorted(group_dir.glob("*.pm3")):
        if path.stem.startswith("formal"):
            label = "formal"
        elif path.stem.startswith("magic"):
            label = "magic"
        else:
            continue
        local_std, diff_activity = load_profile(path)
        records.append(
            {
                "group": group_dir.name,
                "label": label,
                "std": local_std,
                "diff": diff_activity,
            }
        )


def stack(group: str, metric: str) -> np.ndarray:
    return np.stack([r[metric] for r in records if r["group"] == group])


groups = sorted({r["group"] for r in records})
reference_groups = [group for group in groups if group != "zxh"]
zxh_diff = stack("zxh", "diff")
other_diff = np.concatenate([stack(group, "diff") for group in reference_groups])
zxh_std = stack("zxh", "std")
other_std = np.concatenate([stack(group, "std") for group in reference_groups])

time_ms = (np.arange(zxh_diff.shape[1]) * BIN_SIZE + BIN_SIZE / 2) / SAMPLE_RATE * 1000
diff_delta = other_diff.mean(axis=0) - zxh_diff.mean(axis=0)
std_delta = other_std.mean(axis=0) - zxh_std.mean(axis=0)

# Rank bins by a pooled standardized group difference.
pooled_diff_sd = np.sqrt(
    (other_diff.var(axis=0, ddof=1) + zxh_diff.var(axis=0, ddof=1)) / 2
)
effect = np.divide(
    diff_delta,
    pooled_diff_sd,
    out=np.zeros_like(diff_delta),
    where=pooled_diff_sd > 1e-9,
)

print(f"records={len(records)} bins={len(time_ms)} duration_ms={time_ms[-1]:.3f}")
print("group mean_diff mean_std first_half_diff second_half_diff")
half = zxh_diff.shape[1] // 2
for group in groups:
    diff = stack(group, "diff")
    std = stack(group, "std")
    print(
        group,
        f"{diff.mean():.6f}",
        f"{std.mean():.6f}",
        f"{diff[:, :half].mean():.6f}",
        f"{diff[:, half:].mean():.6f}",
    )

print("\ntop positive other-minus-zxh diff-activity bins")
for index in np.argsort(effect)[-30:][::-1]:
    print(
        f"{time_ms[index]:.4f}ms effect={effect[index]:.3f} "
        f"other={other_diff[:, index].mean():.3f} "
        f"zxh={zxh_diff[:, index].mean():.3f} "
        f"std_delta={std_delta[index]:.3f}"
    )

# Print coarse 0.5 ms averages so transaction phases are visible numerically.
print("\ncoarse_0.5ms time other_diff zxh_diff delta effect")
coarse_bins = max(1, round(0.5e-3 * SAMPLE_RATE / BIN_SIZE))
for start in range(0, len(time_ms), coarse_bins):
    stop = min(start + coarse_bins, len(time_ms))
    print(
        f"{time_ms[start]:.3f}-{time_ms[stop-1]:.3f}",
        f"{other_diff[:, start:stop].mean():.4f}",
        f"{zxh_diff[:, start:stop].mean():.4f}",
        f"{diff_delta[start:stop].mean():.4f}",
        f"{effect[start:stop].mean():.3f}",
    )


def intervals(activity: np.ndarray, threshold: float = 5.0) -> list[tuple[int, int]]:
    """Merge active bins separated by at most two inactive bins."""
    active = activity > threshold
    active_indices = np.flatnonzero(active)
    if active_indices.size == 0:
        return []
    merged: list[tuple[int, int]] = []
    start = previous = int(active_indices[0])
    for index in active_indices[1:]:
        index = int(index)
        if index - previous > 3:
            merged.append((start, previous))
            start = index
        previous = index
    merged.append((start, previous))
    return merged


print("\nindividual merged activity intervals (>5 mean abs diff)")
for group in ("lxj", "zxh"):
    selected = [r for r in records if r["group"] == group]
    for number, record in enumerate(selected[:4]):
        readable = [
            (
                round(time_ms[start] - BIN_SIZE / 2 / SAMPLE_RATE * 1000, 3),
                round(time_ms[stop] + BIN_SIZE / 2 / SAMPLE_RATE * 1000, 3),
            )
            for start, stop in intervals(record["diff"])
        ]
        print(group, record["label"], number, readable)

print("\ninterval count and last-active time by group")
for group in groups:
    selected = [r for r in records if r["group"] == group]
    counts = np.asarray([len(intervals(r["diff"])) for r in selected])
    ends = np.asarray(
        [
            time_ms[intervals(r["diff"])[-1][1]]
            if intervals(r["diff"])
            else float("nan")
            for r in selected
        ]
    )
    print(
        group,
        "counts",
        sorted(set(counts.tolist())),
        "median_count",
        float(np.median(counts)),
        "end_ms",
        f"{np.nanmin(ends):.3f}..{np.nanmax(ends):.3f}",
        "median",
        f"{np.nanmedian(ends):.3f}",
    )
