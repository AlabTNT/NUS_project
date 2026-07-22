from __future__ import annotations

import csv
import json
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np


RRR_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RRR_ROOT))

import fingerprint_pipeline as pipeline  # noqa: E402


class FingerprintPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data_root = self.root / "fingerprint_data"
        self.session = self.data_root / "session_01"
        self.session.mkdir(parents=True)
        self.rows: list[dict[str, str]] = []
        rng = np.random.default_rng(42)

        for card_index in range(4):
            for trial in range(16):
                samples = self._waveform(rng, anomaly=False, card_offset=card_index * 0.04)
                self._write_capture(f"g{card_index}", "genuine", trial, samples)
        for card_index in range(2):
            for trial in range(16):
                samples = self._waveform(rng, anomaly=True, card_offset=card_index * 0.03)
                self._write_capture(f"m{card_index}", "magic_gen1", trial, samples)
        self._write_manifest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _waveform(
        rng: np.random.Generator, *, anomaly: bool, card_offset: float
    ) -> np.ndarray:
        length = 4096
        values = rng.normal(0.0, 0.7, length)
        start = 320 + int(rng.integers(-8, 9))
        time_axis = np.arange(length - start)
        envelope = np.sin(2 * np.pi * time_axis / 31.0)
        gate = ((time_axis // 90) % 2).astype(float)
        if anomaly:
            signal = 8.0 * np.sign(envelope) * gate
            signal += 3.5 * np.sin(2 * np.pi * time_axis / 11.0)
        else:
            signal = (4.0 + card_offset) * envelope * gate
            signal += 0.5 * np.sin(2 * np.pi * time_axis / 67.0)
        values[start:] += signal
        return np.clip(np.rint(values), -127, 127).astype(np.int16)

    def _write_capture(
        self, card_id: str, label: str, trial: int, samples: np.ndarray
    ) -> None:
        capture_id = f"session_01__{card_id}__{trial:04d}"
        relative = Path("fingerprint_data") / "session_01" / card_id / f"{capture_id}.pm3"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(str(int(value)) for value in samples) + "\n", encoding="ascii")
        self.rows.append(
            {
                "capture_id": capture_id,
                "session_id": "session_01",
                "card_id": card_id,
                "uid": "unknown",
                "label": label,
                "reader_id": "synthetic_reader",
                "fixture_id": "fixture_01",
                "trial": str(trial),
                "sratio": "4",
                "decimation": "8",
                "sample_rate_hz": "1695000",
                "started_utc": "2026-07-22T00:00:00Z",
                "finished_utc": "2026-07-22T00:00:01Z",
                "file": str(relative),
                "file_bytes": str(path.stat().st_size),
                "status": "ok",
            }
        )

    def _write_manifest(self) -> None:
        path = self.session / "manifest.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(self.rows[0]))
            writer.writeheader()
            writer.writerows(self.rows)

    def _write_blind_dataset(self) -> tuple[Path, Path]:
        blind_root = self.root / "blind_test"
        session = blind_root / "session_blind"
        session.mkdir(parents=True)
        rows: list[dict[str, str]] = []
        rng = np.random.default_rng(314)
        first_anomaly: Path | None = None
        for card_id, label, anomaly in (
            ("g_unseen", "genuine", False),
            ("m_unseen", "magic_gen2", True),
        ):
            for trial in range(16):
                samples = self._waveform(rng, anomaly=anomaly, card_offset=0.02)
                capture_id = f"session_blind__{card_id}__{trial:04d}"
                path = session / card_id / f"{capture_id}.pm3"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "\n".join(str(int(value)) for value in samples) + "\n",
                    encoding="ascii",
                )
                if anomaly and first_anomaly is None:
                    first_anomaly = path
                rows.append(
                    {
                        "capture_id": capture_id,
                        "session_id": "session_blind",
                        "card_id": card_id,
                        "uid": "unknown",
                        "label": label,
                        "reader_id": "synthetic_reader",
                        "fixture_id": "fixture_01",
                        "trial": str(trial),
                        "sratio": "4",
                        "decimation": "8",
                        "sample_rate_hz": "1695000",
                        "started_utc": "2026-07-23T00:00:00Z",
                        "finished_utc": "2026-07-23T00:00:01Z",
                        "file": str(path),
                        "file_bytes": str(path.stat().st_size),
                        "status": "ok",
                    }
                )
        with (session / "manifest.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        assert first_anomaly is not None
        return blind_root, first_anomaly

    def test_complete_train_evaluate_predict_flow(self) -> None:
        captures = pipeline.discover_captures(self.data_root)
        self.assertEqual(len(captures), 96)

        config = pipeline.FeatureConfig(window_samples=3072, temporal_bins=48, spectral_bins=12)
        genuine = [capture for capture in captures if capture.label == "genuine"]
        matrix, valid, rejected, names = pipeline.build_feature_matrix(genuine, config)
        self.assertEqual(matrix.shape[0], 64)
        self.assertEqual(len(valid), 64)
        self.assertFalse(rejected)
        self.assertEqual(matrix.shape[1], len(names))

        model = self.root / "model.npz"
        train_args = type(
            "Args",
            (),
            {
                "data_root": self.data_root,
                "model_out": model,
                "genuine_label": "genuine",
                "calibration_fraction": 0.25,
                "threshold_quantile": 0.99,
                "max_components": 12,
                "variance_target": 0.95,
                "seed": 7,
                "window_samples": 3072,
                "temporal_bins": 48,
                "spectral_bins": 12,
                "min_samples": 1000,
                "min_std": 1.0,
                "min_changed_fraction": 0.001,
                "max_clipped_fraction": 0.05,
            },
        )()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pipeline.command_train(train_args), 0)
        self.assertTrue(model.exists())

        arrays, metadata = pipeline.load_model(model)
        all_matrix, all_valid, _, _ = pipeline.build_feature_matrix(captures, config)
        scores = pipeline.score_matrix(all_matrix, arrays)
        threshold = float(arrays["threshold"])
        genuine_scores = np.asarray(
            [score for score, capture in zip(scores, all_valid) if capture.label == "genuine"]
        )
        anomaly_scores = np.asarray(
            [score for score, capture in zip(scores, all_valid) if capture.label != "genuine"]
        )
        self.assertEqual(metadata["model_type"], "pca_oneclass_v1")
        self.assertLess(float(np.median(genuine_scores)), float(np.median(anomaly_scores)))
        self.assertGreater(float(np.mean(anomaly_scores > threshold)), 0.9)

        blind_root, anomaly_waveform = self._write_blind_dataset()
        report = self.root / "evaluation.json"
        evaluate_args = type(
            "Args",
            (),
            {
                "data_root": blind_root,
                "model": model,
                "genuine_label": None,
                "output": report,
                "include_seen_genuine": False,
            },
        )()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pipeline.command_evaluate(evaluate_args), 0)
        self.assertTrue(report.exists())
        report_data = json.loads(report.read_text(encoding="utf-8"))
        self.assertGreaterEqual(report_data["average_precision"], 0.0)
        self.assertLessEqual(report_data["average_precision"], 1.0)

        prediction_vector, _, quality = pipeline.extract_features(
            pipeline.read_pm3(anomaly_waveform), config
        )
        self.assertTrue(quality.ok)
        prediction_score = float(
            pipeline.score_matrix(prediction_vector.reshape(1, -1), arrays)[0]
        )
        self.assertGreater(prediction_score, threshold)


if __name__ == "__main__":
    unittest.main()
