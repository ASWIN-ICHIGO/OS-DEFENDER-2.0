"""Verify fully offline operation — no network calls required for core AI."""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytestmark = pytest.mark.slow

from features.extractor import NUM_FEATURES, events_to_feature_vector
from inference.engine import OnnxAnomalyDetector
from inference.explainer import AnomalyExplainer
from training.baseline import BaselineProfile
from training.isolation_forest import AnomalyTrainer


def test_full_offline_pipeline(tmp_path):
    """End-to-end: events → features → train → export → inference → explain.

    No network calls. Everything runs locally with ONNX Runtime CPU.
    """
    # 1. Generate synthetic events
    events = []
    for i in range(60):
        events.append({
            "event_type": "process",
            "timestamp": f"2026-11-03T10:{i:02d}:00Z",
            "process_context": {"pid": i + 100, "name": "worker", "cmdline": f"worker --id={i}"},
        })
        events.append({
            "event_type": "network",
            "timestamp": f"2026-11-03T10:{i:02d}:05Z",
            "network_context": {
                "remote_addr": f"10.0.0.{i % 10}",
                "remote_port": 443,
                "direction": "outbound",
            },
        })

    # 2. Extract features in windows of 10 events
    feature_rows = []
    for start in range(0, len(events), 10):
        window = events[start:start + 10]
        vec = events_to_feature_vector(window)
        feature_rows.append(vec)

    X = np.array(feature_rows)
    assert X.shape == (12, NUM_FEATURES)

    # 3. Train IsolationForest
    trainer = AnomalyTrainer(n_estimators=20)
    meta = trainer.train(X)
    assert meta["n_samples"] == 12

    # 4. Export to ONNX
    paths = trainer.save_all(tmp_path / "model")
    assert paths["onnx"].exists()
    assert paths["scaler"].exists()

    # 5. Learn baseline
    baseline = BaselineProfile()
    baseline.learn(X)
    baseline.save(tmp_path / "baseline.json")

    # 6. Inference with ONNX Runtime (CPU, no network)
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])
    score, is_anomaly = detector.predict(X[0])
    assert isinstance(score, float)
    assert isinstance(is_anomaly, bool)

    # 7. Explain
    explainer = AnomalyExplainer(paths["scaler"])
    explanation = explainer.explain(X[0], anomaly_score=score, is_anomaly=is_anomaly)
    d = explanation.to_dict()
    assert "top_contributors" in d
    assert "summary" in d

    # 8. Drift detection (no drift on same data)
    assert not baseline.has_significant_drift(X)

    # 9. Drift detection (shifted data triggers drift)
    shifted = X + 50.0
    assert baseline.has_significant_drift(shifted)


def test_model_load_and_reuse(tmp_path):
    """Model saved once can be loaded and reused without retraining."""
    rng = np.random.default_rng(42)
    X = rng.normal(5.0, 1.0, (50, NUM_FEATURES)).astype(np.float32)

    trainer = AnomalyTrainer(n_estimators=20)
    trainer.train(X)
    paths = trainer.save_all(tmp_path / "m")

    # Load in a fresh detector
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])
    scores = detector.batch_score(X)
    assert scores.shape == (50,)

    # Load baseline
    baseline = BaselineProfile()
    baseline.learn(X)
    baseline.save(tmp_path / "b.json")
    loaded = BaselineProfile.load(tmp_path / "b.json")
    assert not loaded.has_significant_drift(X)
