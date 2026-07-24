import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np


LOCK_DIR = Path(__file__).resolve().parents[1]
if str(LOCK_DIR) not in sys.path:
    sys.path.insert(0, str(LOCK_DIR))

import fingerprint_door as workflow


class CapturePathTests(unittest.TestCase):
    def test_sample_crop_is_training_eligible(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = workflow.build_capture_paths(
                Path(temporary),
                "capture-1",
                capture_label="formal",
            )
            self.assertEqual(
                paths.stage_waveforms["auth_a"].name,
                "pending-capture-1.pm3",
            )
            self.assertEqual(set(paths.stage_waveforms), set(workflow.STAGES))

    def test_use_crop_is_not_discovered_as_formal_training_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = workflow.build_capture_paths(
                Path(temporary),
                "capture-2",
                capture_label=None,
            )
            self.assertEqual(
                paths.stage_waveforms["read_block0"].name,
                "use-capture-2.pm3",
            )

    def test_magic_sample_stays_pending_until_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = workflow.build_capture_paths(
                Path(temporary),
                "capture-3",
                capture_label="magic",
            )
            self.assertEqual(
                paths.stage_waveforms["auth_b"].name,
                "pending-capture-3.pm3",
            )


class FailClosedDecisionTests(unittest.TestCase):
    def test_all_conditions_are_required(self):
        allowed = workflow.combined_authorization(
            card_authorized=True,
            waveform_saved=True,
            waveform_qc_passed=True,
            model_trusted=True,
        )
        self.assertEqual(allowed, (True, "card_and_waveform_verified"))

        cases = (
            (
                dict(
                    card_authorized=False,
                    waveform_saved=True,
                    waveform_qc_passed=True,
                    model_trusted=True,
                ),
                "card_key_or_data_verification_failed",
            ),
            (
                dict(
                    card_authorized=True,
                    waveform_saved=False,
                    waveform_qc_passed=True,
                    model_trusted=True,
                ),
                "waveform_capture_failed",
            ),
            (
                dict(
                    card_authorized=True,
                    waveform_saved=True,
                    waveform_qc_passed=False,
                    model_trusted=True,
                ),
                "stage_waveform_qc_failed",
            ),
            (
                dict(
                    card_authorized=True,
                    waveform_saved=True,
                    waveform_qc_passed=True,
                    model_trusted=False,
                ),
                "waveform_model_rejected",
            ),
        )
        for conditions, expected_reason in cases:
            with self.subTest(expected_reason):
                authorized, reason = workflow.combined_authorization(**conditions)
                self.assertFalse(authorized)
                self.assertEqual(reason, expected_reason)


class ModelTests(unittest.TestCase):
    def test_load_rejects_binary_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": workflow.model_api.MODEL_SCHEMA_VERSION,
                        "model_type": "binary",
                        "feature_names": list(workflow.model_api.FEATURE_NAMES),
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(workflow.WorkflowError, "one-class"):
                workflow.load_oneclass_model(path)

    def test_zero_distance_waveform_is_trusted(self):
        feature_count = len(workflow.model_api.FEATURE_NAMES)
        parameters = {
            "center": [0.0] * feature_count,
            "scale": [1.0] * feature_count,
            "z_clip": 6.0,
            "threshold": 1.0,
        }
        model = {
            "sample_rate_hz": workflow.DEFAULT_SAMPLE_RATE_HZ,
            "parameters": parameters,
            "created_utc": "test",
        }
        extracted = {name: 0.0 for name in workflow.model_api.FEATURE_NAMES}
        with (
            patch.object(
                workflow.model_api,
                "read_pm3",
                return_value=np.zeros(2048, dtype=np.int16),
            ),
            patch.object(
                workflow.model_api,
                "extract_features",
                return_value=extracted,
            ),
        ):
            result = workflow.infer_waveform(model, Path("unused.pm3"))
        self.assertTrue(result["trusted"])
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["decision"], "accept_formal")

    def test_weighted_stage_inference_uses_bundle_weights(self):
        bundle = {
            "combination": "weighted_sum",
            "stage_weights": {
                "auth_a": 0.5,
                "auth_b": 0.1,
                "read_block0": 0.4,
            },
            "combined_threshold": 0.8,
            "loaded_models": {stage: object() for stage in workflow.STAGES},
        }
        relative_scores = iter((0.6, 1.0, 0.9))

        def fake_infer(_model, _waveform):
            relative_score = next(relative_scores)
            return {
                "trusted": relative_score <= 1.0,
                "relative_score": relative_score,
            }

        with patch.object(workflow, "infer_waveform", side_effect=fake_infer):
            result = workflow.infer_stages(
                bundle,
                {stage: Path(f"{stage}.pm3") for stage in workflow.STAGES},
            )

        self.assertAlmostEqual(result["combined_score"], 0.76)
        self.assertTrue(result["trusted"])
        self.assertEqual(result["decision"], "accept_formal")
        self.assertEqual(result["combination"], "weighted_sum")

    def test_supervised_three_stage_model_is_loaded_and_inferred(self):
        feature_count = len(workflow.model_api.FEATURE_NAMES)
        total_features = len(workflow.STAGES) * feature_count
        document = {
            "schema_version": 1,
            "model_type": "three_stage_supervised_binary_logistic",
            "required_stages": list(workflow.STAGES),
            "stage_feature_names": {
                stage: list(workflow.model_api.FEATURE_NAMES)
                for stage in workflow.STAGES
            },
            "sample_rate_hz": workflow.DEFAULT_SAMPLE_RATE_HZ,
            "threshold": 0.6,
            "training_groups": ["test"],
            "parameters": {
                "mean": [0.0] * total_features,
                "scale": [1.0] * total_features,
                "weights": [0.0] * total_features,
                "intercept": 0.0,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "supervised.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = workflow.load_fingerprint_model(path)

        extracted = {name: 0.0 for name in workflow.model_api.FEATURE_NAMES}
        with (
            patch.object(
                workflow.model_api,
                "read_pm3",
                return_value=np.zeros(2048, dtype=np.int16),
            ),
            patch.object(
                workflow.model_api,
                "extract_features",
                return_value=extracted,
            ),
        ):
            result = workflow.infer_stages(
                loaded,
                {stage: Path(f"{stage}.pm3") for stage in workflow.STAGES},
            )

        self.assertEqual(result["model_type"], document["model_type"])
        self.assertAlmostEqual(result["magic_probability"], 0.5)
        self.assertTrue(result["trusted"])
        self.assertEqual(result["decision"], "accept_formal")


class WaveformQualityTests(unittest.TestCase):
    @staticmethod
    def _write_activity_waveform(path: Path, active_blocks: int) -> None:
        block_samples = workflow.QC_ACTIVITY_BLOCK_SAMPLES
        samples = np.arange(2048, dtype=np.int16) % 2
        active_count = active_blocks * block_samples
        samples[:active_count] = np.resize(
            np.asarray((-20, 20), dtype=np.int16),
            active_count,
        )
        np.savetxt(path, samples, fmt="%d")

    def test_qc_accepts_waveform_with_operation_activity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "captured.pm3"
            self._write_activity_waveform(path, workflow.QC_MIN_ACTIVE_BLOCKS)
            result = workflow.stage_waveform_qc(path)
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(
            result["operation_activity"]["active_block_count"],
            workflow.QC_MIN_ACTIVE_BLOCKS,
        )

    def test_qc_rejects_startup_transient_without_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missed.pm3"
            self._write_activity_waveform(
                path,
                workflow.QC_MIN_ACTIVE_BLOCKS - 4,
            )
            result = workflow.stage_waveform_qc(path)
        self.assertEqual(result["status"], "rejected")
        self.assertLess(
            result["operation_activity"]["active_block_count"],
            workflow.QC_MIN_ACTIVE_BLOCKS,
        )


if __name__ == "__main__":
    unittest.main()
