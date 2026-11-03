"""Tests for baseline learning and drift detection."""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.extractor import NUM_FEATURES
from training.baseline import BaselineProfile


def _normal_data(n: int = 50, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(loc=5.0, scale=1.0, size=(n, NUM_FEATURES))


def test_learn_returns_stats():
    profile = BaselineProfile()
    data = _normal_data()
    stats = profile.learn(data)
    assert stats["n_samples"] == 50
    assert "feature_stats" in stats
    assert len(stats["feature_stats"]) == NUM_FEATURES


def test_no_drift_on_similar_data():
    profile = BaselineProfile(drift_threshold=3.0)
    data = _normal_data(100)
    profile.learn(data)

    recent = _normal_data(20, seed=123)
    assert not profile.has_significant_drift(recent)


def test_drift_detected_on_shifted_data():
    profile = BaselineProfile(drift_threshold=3.0)
    data = _normal_data(100)
    profile.learn(data)

    shifted = _normal_data(20, seed=123) + 50.0
    assert profile.has_significant_drift(shifted)


def test_drifted_features_returns_only_drifted():
    profile = BaselineProfile(drift_threshold=3.0)
    data = _normal_data(100)
    profile.learn(data)

    shifted = _normal_data(20, seed=123) + 50.0
    drifted = profile.drifted_features(shifted)
    assert len(drifted) > 0
    assert all(r.drifted for r in drifted)


def test_check_drift_sorted_by_z_score():
    profile = BaselineProfile()
    data = _normal_data(100)
    profile.learn(data)

    shifted = _normal_data(20, seed=123) + 10.0
    results = profile.check_drift(shifted)
    z_scores = [abs(r.z_score) for r in results]
    assert z_scores == sorted(z_scores, reverse=True)


def test_save_and_load(tmp_path):
    profile = BaselineProfile(drift_threshold=2.5)
    data = _normal_data()
    profile.learn(data)

    save_path = tmp_path / "baseline.json"
    profile.save(save_path)
    assert save_path.exists()

    loaded = BaselineProfile.load(save_path)
    assert loaded.n_samples == profile.n_samples
    assert loaded.drift_threshold == 2.5
    np.testing.assert_array_almost_equal(loaded.mean, profile.mean)
    np.testing.assert_array_almost_equal(loaded.std, profile.std)


def test_single_vector_drift_check():
    profile = BaselineProfile()
    data = _normal_data(100)
    profile.learn(data)

    single = np.full(NUM_FEATURES, 100.0)
    results = profile.check_drift(single)
    assert len(results) == NUM_FEATURES


def test_unfitted_raises():
    profile = BaselineProfile()
    data = _normal_data(10)
    with pytest.raises(RuntimeError, match="not learned"):
        profile.check_drift(data)
