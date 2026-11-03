"""Tests for IsolationForest training and ONNX export."""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.extractor import NUM_FEATURES
from training.isolation_forest import AnomalyTrainer


def _generate_normal_data(n: int = 100, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(loc=5.0, scale=1.0, size=(n, NUM_FEATURES)).astype(np.float32)


def _generate_anomaly(seed: int = 99) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(loc=50.0, scale=5.0, size=(1, NUM_FEATURES)).astype(np.float32)


def test_train_requires_minimum_samples():
    trainer = AnomalyTrainer()
    small = np.zeros((5, NUM_FEATURES), dtype=np.float32)
    with pytest.raises(ValueError, match="at least 10"):
        trainer.train(small)


def test_train_rejects_wrong_shape():
    trainer = AnomalyTrainer()
    bad = np.zeros((20, 5), dtype=np.float32)
    with pytest.raises(ValueError, match="Expected shape"):
        trainer.train(bad)


def test_train_returns_metadata():
    trainer = AnomalyTrainer()
    data = _generate_normal_data()
    meta = trainer.train(data)
    assert meta["n_samples"] == 100
    assert meta["n_features"] == NUM_FEATURES
    assert "feature_names" in meta
    assert "score_mean" in meta


def test_score_after_training():
    trainer = AnomalyTrainer()
    data = _generate_normal_data()
    trainer.train(data)

    normal_vec = data[0]
    score = trainer.score(normal_vec)
    assert isinstance(score, float)


def test_predict_returns_tuple():
    trainer = AnomalyTrainer()
    data = _generate_normal_data()
    trainer.train(data)

    score, is_anomaly = trainer.predict(data[0])
    assert isinstance(score, float)
    assert isinstance(is_anomaly, bool)


def test_anomaly_detected():
    trainer = AnomalyTrainer(contamination=0.05)
    normal = _generate_normal_data(200)
    trainer.train(normal)

    anomaly = _generate_anomaly()
    _, is_anomaly = trainer.predict(anomaly[0])
    assert is_anomaly, "Extreme outlier should be detected as anomaly"


@pytest.mark.slow
def test_onnx_export(tmp_path):
    trainer = AnomalyTrainer(n_estimators=20)
    data = _generate_normal_data()
    trainer.train(data)

    onnx_path = trainer.export_onnx(tmp_path / "model.onnx")
    assert onnx_path.exists()
    assert onnx_path.stat().st_size > 0


def test_save_scaler(tmp_path):
    trainer = AnomalyTrainer()
    data = _generate_normal_data()
    trainer.train(data)

    scaler_path = trainer.save_scaler(tmp_path / "scaler.json")
    assert scaler_path.exists()

    import json
    scaler_data = json.loads(scaler_path.read_text())
    assert "mean" in scaler_data
    assert "scale" in scaler_data
    assert len(scaler_data["mean"]) == NUM_FEATURES


@pytest.mark.slow
def test_save_all(tmp_path):
    trainer = AnomalyTrainer(n_estimators=20)
    data = _generate_normal_data()
    trainer.train(data)

    paths = trainer.save_all(tmp_path / "model_dir")
    assert paths["onnx"].exists()
    assert paths["scaler"].exists()
    assert paths["meta"].exists()


def test_untrained_model_raises():
    trainer = AnomalyTrainer()
    vec = np.zeros(NUM_FEATURES, dtype=np.float32)
    with pytest.raises(RuntimeError, match="not trained"):
        trainer.score(vec)
