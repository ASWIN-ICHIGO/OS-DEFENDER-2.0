"""Tests for ONNX inference engine and anomaly explainer."""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.extractor import NUM_FEATURES
from inference.engine import OnnxAnomalyDetector
from inference.explainer import AnomalyExplainer
from training.isolation_forest import AnomalyTrainer

pytestmark = pytest.mark.slow


@pytest.fixture
def trained_model(tmp_path):
    """Train a small model and save to tmp_path, return paths."""
    rng = np.random.default_rng(42)
    data = rng.normal(loc=5.0, scale=1.0, size=(100, NUM_FEATURES)).astype(np.float32)

    trainer = AnomalyTrainer(n_estimators=20)
    trainer.train(data)
    paths = trainer.save_all(tmp_path / "model")
    return paths, data


def test_onnx_detector_scores(trained_model):
    paths, data = trained_model
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])

    score = detector.score(data[0])
    assert isinstance(score, float)


def test_onnx_detector_predict(trained_model):
    paths, data = trained_model
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])

    score, is_anomaly = detector.predict(data[0])
    assert isinstance(score, float)
    assert isinstance(is_anomaly, bool)


def test_onnx_detector_detects_anomaly(trained_model):
    paths, _ = trained_model
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])

    anomaly = np.full(NUM_FEATURES, 100.0, dtype=np.float32)
    _, is_anomaly = detector.predict(anomaly)
    assert is_anomaly, "Extreme outlier should be detected"


def test_onnx_batch_score(trained_model):
    paths, data = trained_model
    detector = OnnxAnomalyDetector(paths["onnx"], paths["scaler"])

    scores = detector.batch_score(data[:10])
    assert scores.shape == (10,)


def test_explainer_produces_explanation(trained_model):
    paths, data = trained_model
    explainer = AnomalyExplainer(paths["scaler"], top_k=5)

    explanation = explainer.explain(data[0], anomaly_score=-0.5, is_anomaly=True)
    assert explanation.is_anomaly
    assert len(explanation.top_contributors) == 5
    assert explanation.summary.startswith("Anomalous:")


def test_explainer_normal_summary(trained_model):
    paths, data = trained_model
    explainer = AnomalyExplainer(paths["scaler"], top_k=3)

    explanation = explainer.explain(data[0], anomaly_score=0.5, is_anomaly=False)
    assert not explanation.is_anomaly
    assert "normal" in explanation.summary.lower()


def test_explanation_to_dict(trained_model):
    paths, data = trained_model
    explainer = AnomalyExplainer(paths["scaler"], top_k=3)

    explanation = explainer.explain(data[0], anomaly_score=-0.3, is_anomaly=True)
    d = explanation.to_dict()
    assert "anomaly_score" in d
    assert "top_contributors" in d
    assert len(d["top_contributors"]) == 3
    assert "feature" in d["top_contributors"][0]
    assert "z_score" in d["top_contributors"][0]


def test_explainer_contributions_sum_to_100(trained_model):
    paths, data = trained_model
    explainer = AnomalyExplainer(paths["scaler"], top_k=NUM_FEATURES)

    explanation = explainer.explain(data[0], anomaly_score=-0.5, is_anomaly=True)
    total = sum(c.contribution_pct for c in explanation.top_contributors)
    assert abs(total - 100.0) < 0.5
