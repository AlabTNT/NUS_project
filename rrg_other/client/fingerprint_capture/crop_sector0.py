"""Extract the sector-0 authentication/read transaction from PM3 waveforms.

The copied ``lock/door_lock_sim.py`` performs MIFARE Classic operations in this
order for the current capture configurations:

1. authenticate sector 0 with each configured key type;
2. read each selected sector-0 data block;
3. optionally continue with later sectors.

At the RF level, one successful Crypto1 authentication contains four frames and
one successful block read contains two frames.  This script detects modulation
bursts, groups nearby bursts into RF frames, locates the first sector operation
after the initial card-selection traffic, and preserves the number of frames
implied by the matching lock configuration.

This is waveform-based segmentation, not an ISO14443-A decoder.  Originals are
never overwritten and every decision is recorded in a CSV manifest for review.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

try:
    from .convert_pm3 import read_pm3
except ImportError:  # Allow direct execution from the script path.
    from convert_pm3 import read_pm3


DEFAULT_SAMPLE_RATE = 1_695_000.0
DEFAULT_BIN_SIZE = 32
DEFAULT_ACTIVITY_THRESHOLD = 3.0
DEFAULT_FRAME_MERGE_MS = 0.30
DEFAULT_TRANSACTION_GAP_MS = 1.80
DEFAULT_PREROLL_MS = 0.20
DEFAULT_POSTROLL_MS = 0.20


@dataclass(frozen=True)
class Interval:
    """Half-open sample interval."""

    start: int
    end: int


@dataclass(frozen=True)
class SectorPlan:
    """RF-frame expectation derived from one lock configuration."""

    auth_types: tuple[str, ...]
    read_blocks: tuple[int, ...]

    @property
    def expected_frames(self) -> int:
        # Successful MIFARE Classic authentication: AUTH, NT, NR||AR, AT.
        authentication_frames = 4 * len(self.auth_types)
        # Successful MIFARE Classic read: READ command and 16-byte response.
        read_frames = 2 * len(self.read_blocks)
        return authentication_frames + read_frames


def milliseconds_to_samples(milliseconds: float, sample_rate: float) -> int:
    """Convert a duration to the nearest whole sample."""
    return int(round(milliseconds * sample_rate / 1000.0))


def load_sector0_plan(config_path: Path) -> SectorPlan:
    """Read the sector-0 operation sequence from a door-lock JSON config."""
    raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
    sectors = raw.get("sectors")
    if not isinstance(sectors, list):
        raise ValueError(f"{config_path}: sectors must be an array")

    sector0 = next(
        (item for item in sectors if isinstance(item, dict) and item.get("sector") == 0),
        None,
    )
    if sector0 is None:
        raise ValueError(f"{config_path}: sector 0 is not configured")

    auth = str(sector0.get("auth", "")).lower()
    if auth == "a":
        auth_types = ("A",)
    elif auth == "b":
        auth_types = ("B",)
    elif auth == "both":
        # SectorConfig.required_key_types in door_lock_sim.py returns A then B.
        auth_types = ("A", "B")
    else:
        raise ValueError(f"{config_path}: unsupported sector-0 auth policy {auth!r}")

    read_blocks = tuple(
        relative_block
        for relative_block in range(3)
        if sector0.get(f"block{relative_block}") is True
    )
    if not read_blocks:
        raise ValueError(f"{config_path}: sector 0 has no selected data block")

    return SectorPlan(auth_types=auth_types, read_blocks=read_blocks)


def detect_activity_intervals(
    samples: np.ndarray,
    *,
    bin_size: int,
    threshold: float,
) -> list[Interval]:
    """Detect short modulation-active regions using mean absolute differences."""
    usable_count = samples.size // bin_size * bin_size
    if usable_count < bin_size:
        return []

    waveform = samples[:usable_count].astype(np.float64, copy=False)
    difference = np.abs(np.diff(waveform, prepend=waveform[0]))
    activity = difference.reshape(-1, bin_size).mean(axis=1)
    active_bins = np.flatnonzero(activity > threshold)
    if active_bins.size == 0:
        return []

    # Bridge one inactive bin. This prevents a single quiet modulation symbol
    # from fragmenting a burst without joining separate reader/card frames.
    intervals: list[Interval] = []
    start_bin = previous_bin = int(active_bins[0])
    for active_bin_value in active_bins[1:]:
        active_bin = int(active_bin_value)
        if active_bin - previous_bin > 2:
            intervals.append(
                Interval(start_bin * bin_size, (previous_bin + 1) * bin_size)
            )
            start_bin = active_bin
        previous_bin = active_bin
    intervals.append(Interval(start_bin * bin_size, (previous_bin + 1) * bin_size))
    return intervals


def group_intervals_into_frames(
    intervals: list[Interval],
    *,
    merge_gap_samples: int,
) -> list[Interval]:
    """Join fragments separated by an intra-frame modulation gap."""
    if not intervals:
        return []

    frames: list[Interval] = []
    current_start = intervals[0].start
    current_end = intervals[0].end
    for interval in intervals[1:]:
        if interval.start - current_end <= merge_gap_samples:
            current_end = interval.end
        else:
            frames.append(Interval(current_start, current_end))
            current_start = interval.start
            current_end = interval.end
    frames.append(Interval(current_start, current_end))
    return frames


def locate_sector0_frames(
    frames: list[Interval],
    *,
    expected_frames: int,
    minimum_start_sample: int,
    transaction_gap_samples: int,
) -> tuple[int, int]:
    """Return indexes spanning the inferred sector-0 RF frames."""
    candidate_start: int | None = None
    for index in range(1, len(frames)):
        gap = frames[index].start - frames[index - 1].end
        if (
            frames[index].start >= minimum_start_sample
            and gap >= transaction_gap_samples
        ):
            candidate_start = index
            break

    if candidate_start is None:
        raise ValueError("cannot locate the first sector operation after selection")

    candidate_end = candidate_start + expected_frames
    if candidate_end > len(frames):
        available = len(frames) - candidate_start
        raise ValueError(
            f"incomplete transaction: expected {expected_frames} RF frames, "
            f"found {available}"
        )
    return candidate_start, candidate_end


def validate_sector0_pattern(
    sector_frames: list[Interval],
    plan: SectorPlan,
    *,
    sample_rate: float,
) -> None:
    """Reject frame sequences that do not match the configured successful flow.

    The tolerances intentionally describe the stable timing pattern observed
    with the current ACR122T and PM3 sampling profile. They are broad enough for
    normal jitter, but reject a merged/missing frame that would shift the crop
    boundary into a later sector.
    """
    if len(sector_frames) != plan.expected_frames:
        raise ValueError("internal error: sector frame count does not match plan")

    gaps_ms = [
        (current.start - previous.end) / sample_rate * 1000.0
        for previous, current in zip(sector_frames, sector_frames[1:])
    ]

    cursor = 0
    for auth_index, _key_type in enumerate(plan.auth_types, start=1):
        if cursor + 3 >= len(sector_frames):
            raise ValueError(f"authentication {auth_index}: missing RF frames")
        auth_gaps = gaps_ms[cursor : cursor + 3]
        expected_ranges = ((0.40, 1.00), (0.40, 1.00), (1.10, 1.80))
        for gap_index, (gap, limits) in enumerate(
            zip(auth_gaps, expected_ranges),
            start=1,
        ):
            if not limits[0] <= gap <= limits[1]:
                raise ValueError(
                    f"ambiguous authentication {auth_index} frame gap "
                    f"{gap_index}: {gap:.3f} ms"
                )
        cursor += 4

    # Every configured read contributes a command and response. The gap from
    # the preceding authentication/read response to the next command is wider
    # than the command-to-response gap in this capture profile.
    for read_index, _block in enumerate(plan.read_blocks, start=1):
        command_gap = gaps_ms[cursor - 1]
        response_gap = gaps_ms[cursor]
        if not 0.60 <= command_gap <= 1.20:
            raise ValueError(
                f"ambiguous read {read_index} command gap: {command_gap:.3f} ms"
            )
        if not 0.35 <= response_gap <= 0.90:
            raise ValueError(
                f"ambiguous read {read_index} response gap: {response_gap:.3f} ms"
            )
        cursor += 2


def write_pm3(path: Path, samples: np.ndarray) -> None:
    """Write the PM3 one-integer-per-line format without changing sample values."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as handle:
        for value in samples:
            handle.write(f"{int(value)}\n")


def crop_one(
    source: Path,
    output: Path,
    plan: SectorPlan,
    args: argparse.Namespace,
) -> dict[str, object]:
    """Detect and optionally write one sector-0 crop plus its audit fields."""
    samples = read_pm3(source)
    intervals = detect_activity_intervals(
        samples,
        bin_size=args.bin_size,
        threshold=args.activity_threshold,
    )
    frames = group_intervals_into_frames(
        intervals,
        merge_gap_samples=milliseconds_to_samples(
            args.frame_merge_ms, args.sample_rate
        ),
    )
    frame_start, frame_end = locate_sector0_frames(
        frames,
        expected_frames=plan.expected_frames,
        minimum_start_sample=milliseconds_to_samples(2.0, args.sample_rate),
        transaction_gap_samples=milliseconds_to_samples(
            args.transaction_gap_ms, args.sample_rate
        ),
    )
    sector_frames = frames[frame_start:frame_end]
    validate_sector0_pattern(
        sector_frames,
        plan,
        sample_rate=args.sample_rate,
    )

    preroll_samples = milliseconds_to_samples(args.preroll_ms, args.sample_rate)
    postroll_samples = milliseconds_to_samples(args.postroll_ms, args.sample_rate)
    crop_start = max(
        0,
        frames[frame_start].start - preroll_samples,
    )
    requested_crop_end = frames[frame_end - 1].end + postroll_samples
    if requested_crop_end > samples.size:
        raise ValueError(
            "sector-0 response reaches the capture boundary; waveform may be truncated"
        )
    crop_end = requested_crop_end
    if crop_end <= crop_start:
        raise ValueError("computed crop is empty")

    if not args.dry_run:
        write_pm3(output, samples[crop_start:crop_end])

    return {
        "status": "ok",
        "error": "",
        "original_sample_count": int(samples.size),
        "activity_interval_count": len(intervals),
        "detected_frame_count": len(frames),
        "sector0_frame_count": plan.expected_frames,
        "sector0_auth_types": "/".join(plan.auth_types),
        "sector0_read_blocks": "/".join(str(value) for value in plan.read_blocks),
        "crop_start_sample": crop_start,
        "crop_end_sample": crop_end,
        "cropped_sample_count": crop_end - crop_start,
        "crop_start_ms": crop_start / args.sample_rate * 1000.0,
        "crop_end_ms": crop_end / args.sample_rate * 1000.0,
        "post_sector0_frame_count": len(frames) - frame_end,
    }


def capture_files(input_root: Path) -> list[Path]:
    """Return labeled PM3 files from group subdirectories."""
    return sorted(
        path
        for path in input_root.glob("*/*.pm3")
        if path.stem.startswith(("formal", "magic"))
    )


def run(args: argparse.Namespace) -> Path:
    """Process the capture tree and write a complete segmentation manifest."""
    sources = capture_files(args.input_root)
    if not sources:
        raise ValueError(f"{args.input_root}: no formal/magic PM3 files found")

    args.output_root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    plan_cache: dict[str, SectorPlan] = {}

    for source in sources:
        group = source.parent.name
        config_path = args.config_root / f"{group}.json"
        output = args.output_root / group / source.name
        row: dict[str, object] = {
            "group": group,
            "label": "formal" if source.stem.startswith("formal") else "magic",
            "source_file": str(source.resolve()),
            "output_file": "" if args.dry_run else str(output.resolve()),
            "config_file": str(config_path.resolve()),
        }
        try:
            plan = plan_cache.setdefault(group, load_sector0_plan(config_path))
            row.update(crop_one(source, output, plan, args))
        except Exception as exc:
            row.update(
                {
                    "status": "rejected",
                    "error": str(exc),
                    "original_sample_count": "",
                    "activity_interval_count": "",
                    "detected_frame_count": "",
                    "sector0_frame_count": "",
                    "sector0_auth_types": "",
                    "sector0_read_blocks": "",
                    "crop_start_sample": "",
                    "crop_end_sample": "",
                    "cropped_sample_count": "",
                    "crop_start_ms": "",
                    "crop_end_ms": "",
                    "post_sector0_frame_count": "",
                }
            )
        rows.append(row)

    manifest_path = args.output_root / "crop_manifest.csv"
    with manifest_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-root",
        type=Path,
        default=Path("capture"),
        help="Capture tree with one subdirectory per card/group",
    )
    parser.add_argument(
        "--config-root",
        type=Path,
        default=Path("lock/config"),
        help="Directory containing <group>.json lock configurations",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("capture_sector0"),
        help="Destination tree; source files are never overwritten",
    )
    parser.add_argument("--sample-rate", type=float, default=DEFAULT_SAMPLE_RATE)
    parser.add_argument("--bin-size", type=int, default=DEFAULT_BIN_SIZE)
    parser.add_argument(
        "--activity-threshold",
        type=float,
        default=DEFAULT_ACTIVITY_THRESHOLD,
    )
    parser.add_argument("--frame-merge-ms", type=float, default=DEFAULT_FRAME_MERGE_MS)
    parser.add_argument(
        "--transaction-gap-ms",
        type=float,
        default=DEFAULT_TRANSACTION_GAP_MS,
    )
    parser.add_argument("--preroll-ms", type=float, default=DEFAULT_PREROLL_MS)
    parser.add_argument("--postroll-ms", type=float, default=DEFAULT_POSTROLL_MS)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only write the decision manifest, not cropped PM3 files",
    )
    args = parser.parse_args()

    if args.sample_rate <= 0:
        parser.error("--sample-rate must be positive")
    if args.bin_size <= 0:
        parser.error("--bin-size must be positive")
    for name in (
        "activity_threshold",
        "frame_merge_ms",
        "transaction_gap_ms",
        "preroll_ms",
        "postroll_ms",
    ):
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} cannot be negative")
    return args


def main() -> None:
    args = parse_args()
    manifest = run(args)
    print(f"Wrote {manifest}")


if __name__ == "__main__":
    main()
