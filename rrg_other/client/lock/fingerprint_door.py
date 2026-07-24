"""Integrated ACR122T door verification and Proxmark3 waveform workflow.

Modes:

* ``sample``: capture AUTH A, AUTH B, and READ block-0 waveforms.
* ``train``: fit one one-class model for each of the three stages.
* ``use``: combine card verification with fail-closed waveform inference.

The program is read-only with respect to the MIFARE card.  It never sends a
write-block command.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_PM3_BATCH = PROJECT_ROOT.parent / "pm3.bat"
LOCAL_RUNTIME_PACKAGES = Path(__file__).resolve().parent / ".runtime_packages"
if LOCAL_RUNTIME_PACKAGES.is_dir() and str(LOCAL_RUNTIME_PACKAGES) not in sys.path:
    sys.path.insert(0, str(LOCAL_RUNTIME_PACKAGES))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import door_lock_sim as door  # noqa: E402
from fingerprint_capture.convert_pm3 import read_pm3, waveform_stats  # noqa: E402
from fingerprint_capture import train_fingerprint_model as model_api  # noqa: E402


PM3_PORT = "COM5"
DEFAULT_SRATIO = 4
DEFAULT_SAMPLE_RATE_HZ = 1_695_000.0
DEFAULT_PM3_READY_TIMEOUT_SECONDS = 20.0
DEFAULT_PM3_CAPTURE_TIMEOUT_SECONDS = 30.0
DEFAULT_CARD_TIMEOUT_SECONDS = 15.0
DEFAULT_ARM_DELAY_SECONDS = 0.25
DEFAULT_PM3_OPERATION_DELAY_SECONDS = 0.200
QC_ACTIVITY_BLOCK_SAMPLES = 32
QC_MIN_ACTIVE_BLOCKS = 20
QC_MIN_ACTIVITY_TO_NOISE_RATIO = {
    "auth_a": 3.5,
    "auth_b": 3.5,
    "read_block0": 6.0,
}
QC_DEFAULT_MIN_ACTIVITY_TO_NOISE_RATIO = 3.5
STAGES = ("auth_a", "auth_b", "read_block0")
CAPTURE_LABELS = ("formal", "magic")


class WorkflowError(RuntimeError):
    """Expected integration failure that should produce a fail-closed result."""


@dataclass(frozen=True)
class CapturePaths:
    """Files belonging to one transaction."""

    capture_id: str
    stage_waveforms: dict[str, Path]
    audit_log: Path


class Pm3Capture:
    """One non-interactive PM3 client process and its raw output file."""

    def __init__(
        self,
        *,
        port: str = PM3_PORT,
        sratio: int = DEFAULT_SRATIO,
        ready_timeout: float = DEFAULT_PM3_READY_TIMEOUT_SECONDS,
        capture_timeout: float = DEFAULT_PM3_CAPTURE_TIMEOUT_SECONDS,
        arm_delay: float = DEFAULT_ARM_DELAY_SECONDS,
    ):
        self.port = port
        self.sratio = sratio
        self.ready_timeout = ready_timeout
        self.capture_timeout = capture_timeout
        self.arm_delay = arm_delay
        self.process: subprocess.Popen[str] | None = None
        self.reader_thread: threading.Thread | None = None
        self.ready_event = threading.Event()
        self.output_lines: list[str] = []
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.staging_file: Path | None = None
        self.command_file: Path | None = None

    def _read_output(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        for line in self.process.stdout:
            cleaned = line.rstrip("\r\n")
            self.output_lines.append(cleaned)
            self.output_queue.put(cleaned)
            display_encoding = sys.stdout.encoding or "utf-8"
            safe_line = cleaned.encode(
                display_encoding,
                errors="replace",
            ).decode(display_encoding, errors="replace")
            print(f"[PM3] {safe_line}")
            if "Buffer cleared" in cleaned:
                self.ready_event.set()

    def start(self, capture_id: str) -> None:
        """Start data-clear/sniff/save/data-clear and wait until sniff is armed."""
        if self.process is not None:
            raise WorkflowError("PM3 capture process is already running")

        staging_dir = PROJECT_ROOT / ".pm3_staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staging_base = staging_dir / capture_id
        self.staging_file = staging_base.with_suffix(".pm3")
        if self.staging_file.exists():
            raise WorkflowError(f"PM3 staging file already exists: {self.staging_file}")

        relative_base = staging_base.relative_to(PROJECT_ROOT).as_posix()
        sniff = "hf sniff --sp 0 --st 0"
        if self.sratio:
            sniff += f" --smode drop --sratio {self.sratio}"
        command_text = (
            f'data clear; {sniff}; data save -f "{relative_base}"; data clear'
        )
        # The distributed parent pm3.bat calls client/setup.bat before starting
        # the client. Reuse that proven environment because launching the bare
        # executable cannot locate all bundled DLLs on this Windows package.
        self.command_file = staging_dir / f"{capture_id}.cmd"
        self.command_file.write_text(
            "@echo off\r\n"
            "call setup.bat\r\n"
            "if errorlevel 1 exit /b %errorlevel%\r\n"
            f'proxmark3.exe -p {self.port} -c "{command_text}"\r\n'
            "exit /b %errorlevel%\r\n",
            encoding="ascii",
        )
        relative_command = str(
            self.command_file.relative_to(PROJECT_ROOT)
        ).replace("/", "\\")
        command = [
            "cmd.exe",
            "/d",
            "/c",
            f"call {relative_command}",
        ]
        self.process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()

        deadline = time.monotonic() + self.ready_timeout
        while not self.ready_event.wait(0.05):
            if self.process.poll() is not None:
                raise WorkflowError(
                    "PM3 exited before clearing/arming the GraphBuffer: "
                    + self.output_tail()
                )
            if time.monotonic() >= deadline:
                self.abort()
                raise WorkflowError(
                    f"PM3 did not become ready within {self.ready_timeout:.1f}s: "
                    + self.output_tail()
                )

        # The clear message is emitted immediately before the blocking sniff
        # command. A short guard removes the remaining process-scheduling race.
        time.sleep(self.arm_delay)
        if self.process.poll() is not None:
            raise WorkflowError("PM3 exited before ACR122T RF wake: " + self.output_tail())

    def finish(self, destination: Path) -> Path:
        """Wait for data save, then move the staging waveform to its final path."""
        if self.process is None or self.staging_file is None:
            raise WorkflowError("PM3 capture was not started")
        try:
            return_code = self.process.wait(timeout=self.capture_timeout)
        except subprocess.TimeoutExpired as exc:
            self.abort()
            raise WorkflowError(
                f"PM3 capture exceeded {self.capture_timeout:.1f}s"
            ) from exc
        finally:
            if self.reader_thread is not None:
                self.reader_thread.join(timeout=2.0)
            self._cleanup_command_file()

        if return_code != 0:
            raise WorkflowError(
                f"PM3 client exited with code {return_code}: {self.output_tail()}"
            )
        if not self.staging_file.exists() or self.staging_file.stat().st_size <= 100:
            raise WorkflowError(
                f"PM3 did not create a valid waveform: {self.staging_file}"
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise WorkflowError(f"refusing to overwrite waveform: {destination}")
        shutil.move(str(self.staging_file), str(destination))
        return destination

    def abort(self) -> None:
        """Stop a stuck client without touching completed destination files."""
        if self.process is None or self.process.poll() is not None:
            self._cleanup_command_file()
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3.0)
        finally:
            self._cleanup_command_file()

    def output_tail(self, lines: int = 12) -> str:
        return " | ".join(self.output_lines[-lines:])

    def _cleanup_command_file(self) -> None:
        if self.command_file is None:
            return
        try:
            self.command_file.unlink(missing_ok=True)
        except OSError:
            pass


class PersistentPm3Session:
    """Keep one PM3 client connected and run many synchronized captures.

    This mirrors the working parent ``pm3.bat`` by loading ``setup.bat`` and
    using its fixed COM5 port.  The Bash helper itself is intentionally
    bypassed: when its input/output are redirected by Python, MSYS cannot
    resolve bundled commands such as dirname/basename from this Unicode path.
    """

    def __init__(
        self,
        *,
        port: str = PM3_PORT,
        sratio: int = DEFAULT_SRATIO,
        ready_timeout: float = DEFAULT_PM3_READY_TIMEOUT_SECONDS,
        capture_timeout: float = DEFAULT_PM3_CAPTURE_TIMEOUT_SECONDS,
        operation_delay_seconds: float = DEFAULT_PM3_OPERATION_DELAY_SECONDS,
    ):
        self.port = port
        self.sratio = sratio
        self.ready_timeout = ready_timeout
        self.capture_timeout = capture_timeout
        self.operation_delay_seconds = operation_delay_seconds
        self.process: subprocess.Popen[str] | None = None
        self.reader_thread: threading.Thread | None = None
        self.command_file: Path | None = None
        self.connected_event = threading.Event()
        self.capture_ready_event = threading.Event()
        self.capture_saved_event = threading.Event()
        self.capture_cleared_event = threading.Event()
        self.output_lines: list[str] = []
        self.active_staging_name: str | None = None
        self.saved_seen = False
        self.capture_lock = threading.Lock()

    @staticmethod
    def _print_pm3_line(cleaned: str) -> None:
        display_encoding = sys.stdout.encoding or "utf-8"
        safe_line = cleaned.encode(
            display_encoding,
            errors="replace",
        ).decode(display_encoding, errors="replace")
        print(f"[PM3] {safe_line}")

    def _read_output(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        for line in self.process.stdout:
            cleaned = line.rstrip("\r\n")
            self.output_lines.append(cleaned)
            self._print_pm3_line(cleaned)
            if "Communicating with PM3 over USB-CDC" in cleaned:
                self.connected_event.set()
            if "Skipping first" in cleaned:
                self.capture_ready_event.set()
            if "Buffer cleared" in cleaned and self.saved_seen:
                self.capture_cleared_event.set()
            if (
                self.active_staging_name
                and "Saved " in cleaned
                and self.active_staging_name in cleaned
            ):
                self.saved_seen = True
                self.capture_saved_event.set()

    def start(self) -> None:
        if self.process is not None:
            raise WorkflowError("persistent PM3 session is already started")
        if self.port != PM3_PORT:
            raise WorkflowError(
                f"parent pm3.bat is configured for {PM3_PORT}, got {self.port}"
            )
        if not PARENT_PM3_BATCH.is_file():
            raise WorkflowError(f"PM3 launcher does not exist: {PARENT_PM3_BATCH}")

        staging_dir = PROJECT_ROOT / ".pm3_staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        session_id = uuid.uuid4().hex[:12]
        self.command_file = staging_dir / f"session-{session_id}.cmd"
        self.command_file.write_text(
            "@echo off\r\n"
            "call setup.bat\r\n"
            "if errorlevel 1 exit /b %errorlevel%\r\n"
            f"proxmark3.exe -p {self.port}\r\n"
            "exit /b %errorlevel%\r\n",
            encoding="ascii",
        )
        relative_command = str(
            self.command_file.relative_to(PROJECT_ROOT)
        ).replace("/", "\\")
        self.process = subprocess.Popen(
            ["cmd.exe", "/d", "/c", f"call {relative_command}"],
            cwd=PROJECT_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()
        if not self.connected_event.wait(self.ready_timeout):
            self.close(force=True)
            raise WorkflowError(
                f"PM3 did not connect to {self.port} within "
                f"{self.ready_timeout:.1f}s"
            )
        time.sleep(0.2)
        if self.process.poll() is not None:
            raise WorkflowError("PM3 client exited after connecting")

    def capture_operation(
        self,
        capture_name: str,
        destination: Path,
        operation: Any,
    ) -> tuple[Any, dict[str, Any]]:
        """Capture one APDU, save/QC its waveform, and return the APDU result."""
        with self.capture_lock:
            if self.process is None or self.process.poll() is not None:
                raise WorkflowError("persistent PM3 session is not running")
            assert self.process.stdin is not None

            staging_base = PROJECT_ROOT / ".pm3_staging" / capture_name
            staging_file = staging_base.with_suffix(".pm3")
            if staging_file.exists():
                raise WorkflowError(f"PM3 staging file already exists: {staging_file}")

            self.capture_ready_event.clear()
            self.capture_saved_event.clear()
            self.capture_cleared_event.clear()
            self.saved_seen = False
            self.active_staging_name = staging_file.name
            relative_base = staging_base.relative_to(PROJECT_ROOT).as_posix()
            sniff = (
                "hf sniff --sp 0 --st 0 "
                f"--smode drop --sratio {self.sratio}"
            )
            command_text = (
                f"data clear; {sniff}; "
                f"data save -f {relative_base}; data clear"
            )
            self.process.stdin.write(command_text + "\n")
            self.process.stdin.flush()

            operation_finished = threading.Event()
            operation_state: dict[str, Any] = {}

            def run_operation() -> None:
                time.sleep(self.operation_delay_seconds)
                operation_state["started_utc"] = utc_now()
                try:
                    operation_state["result"] = operation()
                except BaseException as exc:
                    operation_state["error"] = exc
                finally:
                    operation_state["finished_utc"] = utc_now()
                    operation_finished.set()

            operation_thread = threading.Thread(target=run_operation, daemon=True)
            operation_thread.start()

            if not self.capture_ready_event.wait(self.ready_timeout):
                raise WorkflowError(
                    f"PM3 did not arm stage {capture_name} within "
                    f"{self.ready_timeout:.1f}s"
                )
            if not self.capture_saved_event.wait(self.capture_timeout):
                raise WorkflowError(
                    f"PM3 did not save stage {capture_name} within "
                    f"{self.capture_timeout:.1f}s"
                )
            if not operation_finished.wait(self.capture_timeout):
                raise WorkflowError(f"APDU did not finish for stage {capture_name}")
            if "error" in operation_state:
                raise operation_state["error"]
            result = operation_state["result"]
            if not self.capture_cleared_event.wait(2.0):
                raise WorkflowError(
                    f"PM3 did not clear after saving stage {capture_name}"
                )
            if not staging_file.exists() or staging_file.stat().st_size <= 100:
                raise WorkflowError(f"invalid PM3 stage file: {staging_file}")

            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise WorkflowError(f"refusing to overwrite waveform: {destination}")
            shutil.move(str(staging_file), str(destination))
            qc = stage_waveform_qc(destination)
            self.active_staging_name = None
            return result, {
                "capture_status": "saved",
                "file": str(destination),
                "bytes": destination.stat().st_size,
                "qc": qc,
                "timestamps": {
                    "apdu_started_utc": operation_state["started_utc"],
                    "apdu_finished_utc": operation_state["finished_utc"],
                    "waveform_saved_utc": utc_now(),
                },
                "pm3_output_tail": self.output_lines[-20:],
            }

    def close(self, *, force: bool = False) -> None:
        if self.process is not None and self.process.poll() is None:
            if not force and self.process.stdin is not None:
                try:
                    self.process.stdin.write("quit\n")
                    self.process.stdin.flush()
                    self.process.wait(timeout=5.0)
                except (OSError, subprocess.TimeoutExpired):
                    force = True
            if force and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3.0)
        if self.reader_thread is not None:
            self.reader_thread.join(timeout=2.0)
        if self.command_file is not None:
            try:
                self.command_file.unlink(missing_ok=True)
            except OSError:
                pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_capture_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def build_capture_paths(
    output_dir: Path,
    capture_id: str,
    *,
    capture_label: str | None,
) -> CapturePaths:
    """Build three stage paths; sample files remain pending until validated."""
    root = output_dir.resolve()
    # Sample files remain pending until card verification and all three waveform
    # QC checks pass. This prevents a partial transaction entering training.
    if capture_label is not None and capture_label not in CAPTURE_LABELS:
        raise ValueError(f"unsupported capture label: {capture_label}")
    prefix = "pending" if capture_label is not None else "use"
    return CapturePaths(
        capture_id=capture_id,
        stage_waveforms={
            stage: root / "stages" / stage / f"{prefix}-{capture_id}.pm3"
            for stage in STAGES
        },
        audit_log=root / "audit.jsonl",
    )


def append_audit(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        handle.write("\n")


def stage_waveform_qc(path: Path, stage: str | None = None) -> dict[str, Any]:
    """Reject flat files and windows which missed the requested RF operation.

    PM3 always records a short start-up transient, even when the APDU is sent
    too early.  General statistics therefore cannot prove that AUTH/READ was
    inside the window.  Activity is measured in 32-sample blocks and compared
    with the quiet second half of the same capture.  The calibrated defaults
    distinguish the start-up-only trace from all three operations while still
    leaving margin for card-to-card amplitude variation.
    """
    samples = read_pm3(path)
    stats = waveform_stats(samples)
    resolved_stage = stage if stage in STAGES else path.parent.name
    minimum_activity_ratio = QC_MIN_ACTIVITY_TO_NOISE_RATIO.get(
        resolved_stage,
        QC_DEFAULT_MIN_ACTIVITY_TO_NOISE_RATIO,
    )
    usable_count = (samples.size // QC_ACTIVITY_BLOCK_SAMPLES) * QC_ACTIVITY_BLOCK_SAMPLES
    activity = np.asarray([], dtype=np.float64)
    if usable_count:
        usable = np.asarray(samples[:usable_count], dtype=np.float64)
        absolute_difference = np.abs(np.diff(usable, prepend=usable[0]))
        activity = absolute_difference.reshape(
            -1,
            QC_ACTIVITY_BLOCK_SAMPLES,
        ).mean(axis=1)

    if activity.size:
        quiet_half = activity[activity.size // 2 :]
        noise_floor = max(float(np.median(quiet_half)), 1e-9)
        mean_activity = float(np.mean(activity))
        activity_to_noise_ratio = mean_activity / noise_floor
        active_block_count = int(np.count_nonzero(activity > 3.0))
    else:
        noise_floor = 0.0
        mean_activity = 0.0
        activity_to_noise_ratio = 0.0
        active_block_count = 0

    passed = (
        int(stats["sample_count"]) >= 1024
        and float(stats["sample_std"]) >= 1.0
        and float(stats["changed_sample_fraction"]) >= 0.001
        and activity_to_noise_ratio >= minimum_activity_ratio
        and active_block_count >= QC_MIN_ACTIVE_BLOCKS
    )
    return {
        "status": "ok" if passed else "rejected",
        "file": str(path),
        "operation_activity": {
            "stage": resolved_stage if resolved_stage in STAGES else None,
            "block_samples": QC_ACTIVITY_BLOCK_SAMPLES,
            "mean_absolute_difference": mean_activity,
            "quiet_half_median_absolute_difference": noise_floor,
            "activity_to_noise_ratio": activity_to_noise_ratio,
            "minimum_activity_to_noise_ratio": minimum_activity_ratio,
            "active_block_threshold": 3.0,
            "active_block_count": active_block_count,
            "minimum_active_block_count": QC_MIN_ACTIVE_BLOCKS,
        },
        **stats,
    }


def load_oneclass_model(path: Path) -> dict[str, Any]:
    model = json.loads(path.read_text(encoding="utf-8"))
    if model.get("schema_version") != model_api.MODEL_SCHEMA_VERSION:
        raise WorkflowError("model schema version is not supported")
    if model.get("model_type") != "oneclass":
        raise WorkflowError("use mode requires a one-class model")
    if tuple(model.get("feature_names", ())) != model_api.FEATURE_NAMES:
        raise WorkflowError("model feature list does not match this program")
    return model


def load_model_bundle(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise WorkflowError("fingerprint model bundle schema is not supported")
    if tuple(raw.get("required_stages", ())) != STAGES:
        raise WorkflowError("fingerprint model bundle stages do not match this program")
    combination = raw.get("combination", "all_stages_must_pass")
    if combination not in {"all_stages_must_pass", "weighted_sum"}:
        raise WorkflowError(f"unsupported stage combination: {combination}")

    models: dict[str, Any] = {}
    for stage in STAGES:
        model_value = raw.get("models", {}).get(stage)
        if not isinstance(model_value, str):
            raise WorkflowError(f"model bundle is missing stage {stage}")
        model_path = Path(model_value)
        if not model_path.is_absolute():
            model_path = path.parent / model_path
        models[stage] = load_oneclass_model(model_path.resolve())

    sample_rates = {float(model["sample_rate_hz"]) for model in models.values()}
    if len(sample_rates) != 1:
        raise WorkflowError("stage models use different sample rates")

    if combination == "weighted_sum":
        raw_weights = raw.get("stage_weights")
        if not isinstance(raw_weights, dict) or set(raw_weights) != set(STAGES):
            raise WorkflowError("weighted model bundle has invalid stage weights")
        weights = {stage: float(raw_weights[stage]) for stage in STAGES}
        if any(not math.isfinite(value) or value < 0.0 for value in weights.values()):
            raise WorkflowError("weighted model bundle weights must be finite and nonnegative")
        weight_sum = sum(weights.values())
        if not math.isclose(weight_sum, 1.0, rel_tol=1e-6, abs_tol=1e-9):
            raise WorkflowError("weighted model bundle weights must sum to 1")
        combined_threshold = float(raw.get("combined_threshold", 0.0))
        if not math.isfinite(combined_threshold) or combined_threshold <= 0.0:
            raise WorkflowError(
                "weighted model bundle requires a positive combined threshold"
            )
        raw["stage_weights"] = weights
        raw["combined_threshold"] = combined_threshold

    raw["loaded_models"] = models
    raw["sample_rate_hz"] = sample_rates.pop()
    return raw


def load_supervised_binary_model(path: Path) -> dict[str, Any]:
    """Load the final three-stage Formal/Magic supervised classifier."""

    model = json.loads(path.read_text(encoding="utf-8"))
    if model.get("schema_version") != 1:
        raise WorkflowError("supervised fingerprint model schema is not supported")
    if model.get("model_type") != "three_stage_supervised_binary_logistic":
        raise WorkflowError("unsupported supervised fingerprint model type")
    if tuple(model.get("required_stages", ())) != STAGES:
        raise WorkflowError("supervised fingerprint model stages do not match")
    feature_map = model.get("stage_feature_names")
    if not isinstance(feature_map, dict) or any(
        tuple(feature_map.get(stage, ())) != model_api.FEATURE_NAMES
        for stage in STAGES
    ):
        raise WorkflowError("supervised fingerprint feature list does not match")

    parameters = model.get("parameters")
    expected_features = len(STAGES) * len(model_api.FEATURE_NAMES)
    if not isinstance(parameters, dict) or any(
        len(parameters.get(name, ())) != expected_features
        for name in ("mean", "scale", "weights")
    ):
        raise WorkflowError("supervised fingerprint parameter dimensions are invalid")
    threshold = float(model.get("threshold", -1.0))
    if not 0.0 <= threshold <= 1.0:
        raise WorkflowError("supervised fingerprint threshold must be in [0, 1]")
    sample_rate_hz = float(model.get("sample_rate_hz", 0.0))
    if not math.isfinite(sample_rate_hz) or sample_rate_hz <= 0.0:
        raise WorkflowError("supervised fingerprint sample rate is invalid")
    return model


def load_fingerprint_model(path: Path) -> dict[str, Any]:
    """Load either the final supervised model or a legacy one-class bundle."""

    header = json.loads(path.read_text(encoding="utf-8"))
    if header.get("model_type") == "three_stage_supervised_binary_logistic":
        return load_supervised_binary_model(path)
    return load_model_bundle(path)


def infer_waveform(model: dict[str, Any], waveform: Path) -> dict[str, Any]:
    sample_rate_hz = float(model["sample_rate_hz"])
    samples = model_api.read_pm3(waveform)
    extracted = model_api.extract_features(samples, sample_rate_hz)
    matrix = np.asarray(
        [[extracted[name] for name in model_api.FEATURE_NAMES]],
        dtype=np.float64,
    )
    scores, family_scores = model_api.score_oneclass(matrix, model["parameters"])
    score = float(scores[0])
    threshold = float(model["parameters"]["threshold"])
    trusted = score <= threshold
    return {
        "status": "ok",
        "model_type": "oneclass",
        "model_created_utc": model.get("created_utc"),
        "score": score,
        "threshold": threshold,
        "relative_score": model_api.safe_div(score, threshold),
        "trusted": trusted,
        "decision": "accept_formal" if trusted else "reject_anomaly",
        "family_scores": {
            family: float(values[0]) for family, values in family_scores.items()
        },
    }


def infer_stages(
    bundle: dict[str, Any],
    stage_waveforms: dict[str, Path],
) -> dict[str, Any]:
    if bundle.get("model_type") == "three_stage_supervised_binary_logistic":
        extracted_by_stage: dict[str, dict[str, float]] = {}
        feature_values: list[float] = []
        sample_rate_hz = float(bundle["sample_rate_hz"])
        for stage in STAGES:
            samples = model_api.read_pm3(stage_waveforms[stage])
            extracted = model_api.extract_features(samples, sample_rate_hz)
            extracted_by_stage[stage] = extracted
            feature_values.extend(
                float(extracted[name]) for name in model_api.FEATURE_NAMES
            )
        matrix = np.asarray([feature_values], dtype=np.float64)
        magic_probability = float(
            model_api.score_binary(matrix, bundle["parameters"])[0]
        )
        threshold = float(bundle["threshold"])
        trusted = magic_probability <= threshold
        return {
            "status": "ok",
            "model_type": "three_stage_supervised_binary_logistic",
            "combination": "supervised_concatenated_features",
            "trusted": trusted,
            "decision": "accept_formal" if trusted else "reject_magic",
            "magic_probability": magic_probability,
            "threshold": threshold,
            "training_groups": bundle.get("training_groups", []),
            "stages": {
                stage: {
                    "status": "ok",
                    "feature_count": len(extracted_by_stage[stage]),
                }
                for stage in STAGES
            },
        }

    results = {
        stage: infer_waveform(bundle["loaded_models"][stage], stage_waveforms[stage])
        for stage in STAGES
    }
    combination = bundle.get("combination", "all_stages_must_pass")
    if combination == "weighted_sum":
        weights = bundle["stage_weights"]
        combined_score = sum(
            float(weights[stage]) * float(results[stage]["relative_score"])
            for stage in STAGES
        )
        combined_threshold = float(bundle["combined_threshold"])
        trusted = combined_score <= combined_threshold
        combination_details = {
            "combined_score": combined_score,
            "combined_threshold": combined_threshold,
            "stage_weights": dict(weights),
            "stage_relative_scores": {
                stage: float(results[stage]["relative_score"]) for stage in STAGES
            },
        }
    else:
        trusted = all(result["trusted"] for result in results.values())
        combination_details = {}
    return {
        "status": "ok",
        "combination": combination,
        "trusted": trusted,
        "decision": "accept_formal" if trusted else "reject_anomaly",
        "stages": results,
        **combination_details,
    }


def combined_authorization(
    *,
    card_authorized: bool,
    waveform_saved: bool,
    waveform_qc_passed: bool,
    model_trusted: bool,
) -> tuple[bool, str]:
    """Fail closed across every required card and fingerprint condition."""
    if not card_authorized:
        return False, "card_key_or_data_verification_failed"
    if not waveform_saved:
        return False, "waveform_capture_failed"
    if not waveform_qc_passed:
        return False, "stage_waveform_qc_failed"
    if not model_trusted:
        return False, "waveform_model_rejected"
    return True, "card_and_waveform_verified"


def connect_with_timeout(
    reader: Any,
    connection_errors: tuple[type[BaseException], ...],
    disconnect_disposition: int,
    timeout_seconds: float,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    while True:
        connection = door._try_connect(
            reader,
            connection_errors,
            disconnect_disposition,
        )
        if connection is not None:
            return connection
        if time.monotonic() >= deadline:
            raise WorkflowError(
                f"no card connected within {timeout_seconds:.1f} seconds"
            )
        time.sleep(0.05)


def validate_three_stage_config(config: Any) -> None:
    sector0 = next((sector for sector in config.sectors if sector.sector == 0), None)
    if sector0 is None:
        raise WorkflowError("three-stage capture requires sector 0")
    if tuple(sector0.required_key_types) != ("A", "B"):
        raise WorkflowError(
            "three-stage capture requires sector-0 auth policy 'both'"
        )
    if 0 not in sector0.selected_blocks:
        raise WorkflowError("three-stage capture requires reading sector-0 block 0")


class StageCapturingDevice:
    """Wrap the ACR122T device and capture the three sector-0 APDUs."""

    def __init__(
        self,
        device: Any,
        *,
        capture_id: str,
        destinations: dict[str, Path],
        sratio: int,
        pm3_session: PersistentPm3Session,
        stage_records: dict[str, dict[str, Any]],
    ):
        self.device = device
        self.capture_id = capture_id
        self.destinations = destinations
        self.sratio = sratio
        self.pm3_session = pm3_session
        self.stage_records = stage_records
        self.captured_stages: set[str] = set()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.device, name)

    def _capture_operation(self, stage: str, operation: Any) -> Any:
        """Arm PM3 immediately before one RF operation and always run the APDU."""
        if stage in self.captured_stages:
            return operation()
        self.captured_stages.add(stage)

        destination = self.destinations[stage]
        record: dict[str, Any] = {
            "stage": stage,
            "file": str(destination),
            "capture_status": "not_started",
            "qc": {"status": "not_run"},
            "timestamps": {"pm3_start_requested_utc": utc_now()},
        }
        self.stage_records[stage] = record

        operation_executed = False
        operation_result: Any = None

        def tracked_operation() -> Any:
            nonlocal operation_executed, operation_result
            operation_executed = True
            operation_result = operation()
            return operation_result

        try:
            result, capture_record = self.pm3_session.capture_operation(
                f"{self.capture_id}-{stage}",
                destination,
                tracked_operation,
            )
            record.update(capture_record)
            return result
        except Exception as exc:
            record["capture_status"] = "error"
            record["capture_error"] = f"{type(exc).__name__}: {exc}"
            record["pm3_output_tail"] = self.pm3_session.output_lines[-20:]
            if operation_executed:
                return operation_result
            record["timestamps"]["apdu_started_utc"] = utc_now()
            result = operation()
            record["timestamps"]["apdu_finished_utc"] = utc_now()
            return result

    def authenticate(self, block: int, key_type: str) -> Any:
        stage = None
        if block == 0 and key_type == "A":
            stage = "auth_a"
        elif block == 0 and key_type == "B":
            stage = "auth_b"
        operation = lambda: self.device.authenticate(block, key_type)
        return self._capture_operation(stage, operation) if stage else operation()

    def read_block(self, block: int) -> Any:
        operation = lambda: self.device.read_block(block)
        return (
            self._capture_operation("read_block0", operation)
            if block == 0
            else operation()
        )


def capture_cycle(
    *,
    reader: Any,
    standby_session: Any,
    connection_errors: tuple[type[BaseException], ...],
    unpower_card: int,
    config: Any,
    config_path: Path,
    output_dir: Path,
    mode: str,
    capture_label: str | None,
    model: dict[str, Any] | None,
    pm3_session: PersistentPm3Session,
    sratio: int,
    sample_rate_hz: float,
    card_timeout: float,
) -> tuple[Any, dict[str, Any]]:
    """Capture AUTH A, AUTH B and READ block 0 as three high-rate windows."""
    paths = build_capture_paths(
        output_dir,
        new_capture_id(),
        capture_label=capture_label,
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "capture_id": paths.capture_id,
        "mode": mode,
        "capture_label": capture_label,
        "started_utc": utc_now(),
        "pm3_port": PM3_PORT,
        "sratio": sratio,
        "sample_rate_hz": sample_rate_hz,
        "pm3_operation_delay_ms": pm3_session.operation_delay_seconds * 1000.0,
        "config_file": str(config_path.resolve()),
        "timestamps": {},
        "door_result": None,
        "stages": {},
        "model_inference": {"status": "not_run"},
        "final_decision": {"authorized": False, "reason": "cycle_not_completed"},
    }
    connection = None

    try:
        record["timestamps"]["acr122t_rf_wake_utc"] = utc_now()
        standby_session.wake()
        standby_session.close()
        standby_session = None

        connection = connect_with_timeout(
            reader,
            connection_errors,
            unpower_card,
            card_timeout,
        )
        record["timestamps"]["card_connected_utc"] = utc_now()
        base_device = door.Acr122tDevice(connection)
        device = StageCapturingDevice(
            base_device,
            capture_id=paths.capture_id,
            destinations=paths.stage_waveforms,
            sratio=sratio,
            pm3_session=pm3_session,
            stage_records=record["stages"],
        )
        try:
            atr = connection.getATR()
        except Exception:
            atr = []
        record["timestamps"]["door_scan_started_utc"] = utc_now()
        door_result = door.scan_card(device, config, str(reader), atr)
        record["timestamps"]["door_scan_finished_utc"] = utc_now()
        record["door_result"] = door_result
        door.print_result(door_result)
    except Exception as exc:
        record["cycle_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if connection is not None:
            door._close_connection(connection)
        if standby_session is None:
            try:
                standby_session = door._enter_antenna_standby(reader)
                record["timestamps"]["acr122t_rf_standby_utc"] = utc_now()
            except Exception as exc:
                record["standby_error"] = f"{type(exc).__name__}: {exc}"

    stages_present = all(stage in record["stages"] for stage in STAGES)
    waveform_saved = stages_present and all(
        record["stages"][stage].get("capture_status") == "saved"
        for stage in STAGES
    )
    waveform_qc_passed = waveform_saved and all(
        record["stages"][stage].get("qc", {}).get("status") == "ok"
        for stage in STAGES
    )

    if mode == "use" and waveform_qc_passed and model:
        try:
            record["model_inference"] = infer_stages(
                model,
                paths.stage_waveforms,
            )
        except Exception as exc:
            record["model_inference"] = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "trusted": False,
            }

    card_authorized = bool(
        record["door_result"]
        and record["door_result"].get("decision", {}).get("authorized")
    )
    model_trusted = (
        True
        if mode == "sample"
        else bool(record["model_inference"].get("trusted", False))
    )
    authorized, reason = combined_authorization(
        card_authorized=card_authorized,
        waveform_saved=waveform_saved,
        waveform_qc_passed=waveform_qc_passed,
        model_trusted=model_trusted,
    )
    if mode == "sample" and authorized:
        assert capture_label in CAPTURE_LABELS
        try:
            for stage in STAGES:
                source = paths.stage_waveforms[stage]
                destination = source.with_name(
                    source.name.replace("pending-", f"{capture_label}-", 1)
                )
                if destination.exists():
                    raise WorkflowError(
                        f"refusing to overwrite promoted waveform: {destination}"
                    )
                source.replace(destination)
                paths.stage_waveforms[stage] = destination
                record["stages"][stage]["file"] = str(destination)
                record["stages"][stage]["qc"]["file"] = str(destination)
        except Exception as exc:
            authorized = False
            reason = "sample_waveform_promotion_failed"
            record["promotion_error"] = f"{type(exc).__name__}: {exc}"
    record["final_decision"] = {
        "authorized": authorized,
        "reason": reason,
    }
    record["finished_utc"] = utc_now()
    append_audit(paths.audit_log, record)
    return standby_session, record


def run_hardware_loop(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    config = door.load_config(config_path)
    validate_three_stage_config(config)
    model = load_fingerprint_model(args.model.resolve()) if args.mode == "use" else None
    sample_rate_hz = 13_560_000.0 / (2 * args.sratio)
    if model is not None and not np.isclose(
        float(model["sample_rate_hz"]),
        sample_rate_hz,
    ):
        raise WorkflowError(
            "model/capture sample-rate mismatch: "
            f"model={float(model['sample_rate_hz']):.1f}Hz, "
            f"capture={sample_rate_hz:.1f}Hz"
        )
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    reader = door._select_reader(config)
    _, connection_errors, _, _, unpower_card = door._load_pcsc()
    operation_delay_seconds = args.pm3_operation_delay_ms / 1000.0
    pm3_session = PersistentPm3Session(
        port=PM3_PORT,
        sratio=args.sratio,
        operation_delay_seconds=operation_delay_seconds,
    )
    pm3_session.start()
    try:
        standby_session = door._enter_antenna_standby(reader)
    except Exception:
        pm3_session.close()
        raise
    print(f"Reader: {reader}")
    print(f"PM3: {PM3_PORT}")
    print(f"PM3/APDU delay: {args.pm3_operation_delay_ms:.1f} ms")
    if args.mode == "sample":
        print(f"Capture label: {args.label}")
    print(f"Output: {output_dir}")
    print("RF is off. Press Space for one transaction; Q or Esc exits.")

    try:
        while True:
            if not door._wait_for_space():
                return 0
            standby_session, record = capture_cycle(
                reader=reader,
                standby_session=standby_session,
                connection_errors=connection_errors,
                unpower_card=unpower_card,
                config=config,
                config_path=config_path,
                output_dir=output_dir,
                mode=args.mode,
                capture_label=args.label if args.mode == "sample" else None,
                model=model,
                pm3_session=pm3_session,
                sratio=args.sratio,
                sample_rate_hz=sample_rate_hz,
                card_timeout=args.card_timeout,
            )
            decision = record["final_decision"]
            print(
                f"{'Sample status' if args.mode == 'sample' else 'Final decision'}: "
                f"{'VALID' if args.mode == 'sample' and decision['authorized'] else 'OPEN' if decision['authorized'] else 'DENY'} "
                f"({decision['reason']})"
            )
            print(f"Audit: {(output_dir / 'audit.jsonl')}")
            if args.once:
                return 0
            print("Press Space for the next transaction; Q or Esc exits.")
    finally:
        if standby_session is not None:
            standby_session.close()
        pm3_session.close()


def evaluate_three_stage_bundle(
    *,
    model_dir: Path,
    entries: list[tuple[str, str, str]],
    stage_files: dict[str, dict[str, dict[tuple[str, str], Path]]],
    target_frr: float,
    z_clip: float,
) -> Path:
    """Evaluate the final AND rule and leave one physical card group out."""
    labels = np.asarray([label == "magic" for label, _, _ in entries], dtype=int)
    card_ids = np.asarray([card_id for _, card_id, _ in entries], dtype=object)
    matrices: dict[str, np.ndarray] = {}
    final_models: dict[str, dict[str, Any]] = {}

    for stage in STAGES:
        feature_rows: dict[Path, dict[str, str]] = {}
        with (model_dir / stage / "features.csv").open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as handle:
            for row in csv.DictReader(handle):
                feature_rows[Path(row["file"]).resolve()] = row
        matrices[stage] = np.asarray(
            [
                [
                    float(
                        feature_rows[
                            stage_files[stage][label][(card_id, filename)]
                        ][name]
                    )
                    for name in model_api.FEATURE_NAMES
                ]
                for label, card_id, filename in entries
            ],
            dtype=np.float64,
        )
        final_models[stage] = load_oneclass_model(
            model_dir / stage / "oneclass_model.json"
        )

    relative_scores: dict[str, np.ndarray] = {}
    for stage in STAGES:
        parameters = final_models[stage]["parameters"]
        scores, _ = model_api.score_oneclass(matrices[stage], parameters)
        relative_scores[stage] = scores / float(parameters["threshold"])
    combined_scores = np.max(
        np.column_stack([relative_scores[stage] for stage in STAGES]),
        axis=1,
    )

    prediction_rows: list[dict[str, object]] = []
    for index, (label, card_id, filename) in enumerate(entries):
        prediction_rows.append(
            {
                "label": label,
                "card_id": card_id,
                "capture_file": filename,
                **{
                    f"{stage}_relative_score": float(relative_scores[stage][index])
                    for stage in STAGES
                },
                "combined_max_relative_score": float(combined_scores[index]),
                "accepted_as_formal": bool(combined_scores[index] <= 1.0),
            }
        )
    predictions_path = model_dir / "three_stage_predictions.csv"
    with predictions_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(prediction_rows[0]))
        writer.writeheader()
        writer.writerows(prediction_rows)

    folds: list[dict[str, object]] = []
    pooled_labels: list[int] = []
    pooled_scores: list[float] = []
    for held_out_card in sorted(set(card_ids.tolist())):
        train = (labels == 0) & (card_ids != held_out_card)
        test = card_ids == held_out_card
        if np.count_nonzero(train) < 2 or not np.any(test):
            continue
        fold_stage_scores: list[np.ndarray] = []
        for stage in STAGES:
            parameters = model_api.fit_oneclass(
                matrices[stage][train],
                target_false_reject_rate=target_frr,
                z_clip=z_clip,
            )
            scores, _ = model_api.score_oneclass(
                matrices[stage][test],
                parameters,
            )
            fold_stage_scores.append(scores / float(parameters["threshold"]))
        fold_combined = np.max(np.column_stack(fold_stage_scores), axis=1)
        fold_labels = labels[test]
        folds.append(
            {
                "held_out_card": held_out_card,
                **model_api.classification_metrics(
                    fold_labels,
                    fold_combined,
                    1.0,
                ),
            }
        )
        pooled_labels.extend(fold_labels.tolist())
        pooled_scores.extend(fold_combined.tolist())

    report = {
        "schema_version": 1,
        "created_utc": utc_now(),
        "decision_rule": (
            "accept only when auth_a, auth_b and read_block0 relative scores "
            "are all <= 1"
        ),
        "important_note": (
            "Magic captures are never used for fitting or threshold calibration."
        ),
        "complete_formal_capture_count": int(np.count_nonzero(labels == 0)),
        "complete_magic_capture_count": int(np.count_nonzero(labels == 1)),
        "physical_card_groups": sorted(set(card_ids.tolist())),
        "final_models_all_data_evaluation": {
            "note": "formal scores are resubstitution; use grouped result for generalization",
            "combined": model_api.classification_metrics(
                labels,
                combined_scores,
                1.0,
            ),
            "per_stage": {
                stage: model_api.classification_metrics(
                    labels,
                    relative_scores[stage],
                    1.0,
                )
                for stage in STAGES
            },
        },
        "leave_one_card_group_out": {
            "folds": folds,
            "aggregate": model_api.classification_metrics(
                np.asarray(pooled_labels, dtype=int),
                np.asarray(pooled_scores, dtype=np.float64),
                1.0,
            ),
        },
        "predictions_csv": str(predictions_path),
    }
    report_path = model_dir / "three_stage_evaluation.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return report_path


def run_training(args: argparse.Namespace) -> int:
    data_root = args.data_root.resolve()
    model_dir = args.model_dir.resolve()
    model_dir.mkdir(parents=True, exist_ok=True)

    stage_files: dict[
        str,
        dict[str, dict[tuple[str, str], Path]],
    ] = {}
    for stage in STAGES:
        stage_files[stage] = {}
        for label in CAPTURE_LABELS:
            files: dict[tuple[str, str], Path] = {}
            for path in sorted(
                data_root.rglob(f"stages/{stage}/{label}-*.pm3")
            ):
                relative = path.relative_to(data_root)
                try:
                    stages_index = relative.parts.index("stages")
                except ValueError:
                    continue
                card_parts = relative.parts[:stages_index]
                card_id = "/".join(card_parts) if card_parts else data_root.name
                files[(card_id, path.name)] = path.resolve()
            stage_files[stage][label] = files

    complete_keys_by_label = {
        label: set.intersection(
            *(set(stage_files[stage][label]) for stage in STAGES)
        )
        for label in CAPTURE_LABELS
    }
    if len(complete_keys_by_label["formal"]) < 2:
        raise WorkflowError(
            "training requires at least two complete three-stage formal captures"
        )
    entries = [
        (label, card_id, filename)
        for label in CAPTURE_LABELS
        for card_id, filename in sorted(complete_keys_by_label[label])
    ]

    for stage in STAGES:
        stage_dir = model_dir / stage
        stage_dir.mkdir(parents=True, exist_ok=True)
        manifest = stage_dir / "training_manifest.csv"
        with manifest.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=("file", "label", "card_id", "batch_id"),
            )
            writer.writeheader()
            for label, card_id, filename in entries:
                writer.writerow(
                    {
                        "file": str(
                            stage_files[stage][label][(card_id, filename)]
                        ),
                        "label": label,
                        "card_id": card_id,
                        "batch_id": card_id,
                    }
                )

        training_args = argparse.Namespace(
            manifest=manifest,
            data_root=None,
            card_id_mode="prefix",
            mode="oneclass",
            output_dir=stage_dir,
            sample_rate_hz=args.sample_rate_hz,
            target_frr=args.target_frr,
            z_clip=args.z_clip,
            ridge=1.0,
        )
        result = model_api.train_command(training_args)
        if result != 0:
            return int(result)

    bundle = {
        "schema_version": 1,
        "created_utc": utc_now(),
        "model_type": "three_stage_oneclass",
        "required_stages": list(STAGES),
        "combination": "all_stages_must_pass",
        "sample_rate_hz": float(args.sample_rate_hz),
        "complete_training_capture_count": len(
            complete_keys_by_label["formal"]
        ),
        "complete_magic_evaluation_capture_count": len(
            complete_keys_by_label["magic"]
        ),
        "physical_card_ids": sorted(
            {
                card_id
                for _, card_id, _ in entries
            }
        ),
        "models": {
            stage: f"{stage}/oneclass_model.json"
            for stage in STAGES
        },
    }
    bundle_path = model_dir / "fingerprint_bundle.json"
    bundle_path.write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    evaluation_path = evaluate_three_stage_bundle(
        model_dir=model_dir,
        entries=entries,
        stage_files=stage_files,
        target_frr=args.target_frr,
        z_clip=args.z_clip,
    )
    print(f"\nModel bundle: {bundle_path}")
    print(f"Three-stage evaluation: {evaluation_path}")
    return 0


def add_hardware_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--sratio",
        type=int,
        choices=(2, 4, 8),
        default=DEFAULT_SRATIO,
    )
    parser.add_argument(
        "--card-timeout",
        type=float,
        default=DEFAULT_CARD_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--pm3-operation-delay-ms",
        type=float,
        default=DEFAULT_PM3_OPERATION_DELAY_SECONDS * 1000.0,
        help=(
            "delay after submitting each PM3 sniff command before sending the "
            "ACR122T APDU (default: 200 ms, calibrated for this setup)"
        ),
    )


def run_supervised_training(args: argparse.Namespace) -> int:
    """Run the finalized supervised 5|1, 4|2, and generation evaluations."""

    from fingerprint_capture import evaluate_mix_supervised_binary as supervised

    training_args = argparse.Namespace(
        data_root=args.data_root,
        output_dir=args.model_dir,
        feature_cache=args.model_dir / "feature_cache.npz",
        group_metadata=args.group_metadata,
        sample_rate_hz=args.sample_rate_hz,
        max_group_frr=args.max_group_frr,
        ridge=args.ridge,
    )
    return int(supervised.run(training_args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sample = subparsers.add_parser("sample", help="capture labeled card waveforms")
    add_hardware_arguments(sample)
    sample.add_argument(
        "--label",
        choices=CAPTURE_LABELS,
        required=True,
        help="label every validated capture from this run as formal or magic",
    )
    sample.set_defaults(function=run_hardware_loop)

    train = subparsers.add_parser(
        "train",
        help="train and evaluate the finalized supervised Formal/Magic model",
    )
    train.add_argument("--data-root", type=Path, required=True)
    train.add_argument("--model-dir", type=Path, required=True)
    train.add_argument(
        "--group-metadata",
        type=Path,
        required=True,
        help="JSON mapping each group to its Magic generation",
    )
    train.add_argument(
        "--sample-rate-hz",
        type=float,
        default=DEFAULT_SAMPLE_RATE_HZ,
    )
    train.add_argument("--max-group-frr", type=float, default=0.05)
    train.add_argument("--ridge", type=float, default=1.0)
    train.set_defaults(function=run_supervised_training)

    use = subparsers.add_parser("use", help="verify card and waveform")
    add_hardware_arguments(use)
    use.add_argument(
        "--model",
        type=Path,
        required=True,
        help="supervised model JSON or legacy one-class bundle JSON",
    )
    use.set_defaults(function=run_hardware_loop)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "sample_rate_hz", 1.0) <= 0:
        parser.error("--sample-rate-hz must be positive")
    if getattr(args, "card_timeout", 1.0) <= 0:
        parser.error("--card-timeout must be positive")
    if getattr(args, "pm3_operation_delay_ms", 1.0) <= 0:
        parser.error("--pm3-operation-delay-ms must be positive")
    if hasattr(args, "max_group_frr") and not 0.0 <= args.max_group_frr < 0.5:
        parser.error("--max-group-frr must be in [0, 0.5)")
    if hasattr(args, "ridge") and args.ridge <= 0:
        parser.error("--ridge must be positive")
    try:
        return int(args.function(args))
    except (
        WorkflowError,
        door.ConfigurationError,
        door.PcscUnavailableError,
        OSError,
        ValueError,
        np.linalg.LinAlgError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
