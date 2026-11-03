"""Baseline learning and distributional drift detection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from features.extractor import FEATURE_NAMES, NUM_FEATURES


@dataclass
class DriftResult:
    """Result of a drift check for one feature."""
    feature_name: str
    baseline_mean: float
    baseline_std: float
    current_mean: float
    z_score: float
    drifted: bool


class BaselineProfile:
    """Maintains a statistical baseline of normal behaviour and detects drift."""

    def __init__(self, drift_threshold: float = 3.0):
        self.drift_threshold = drift_threshold
        self.mean: np.ndarray | None = None
        self.std: np.ndarray | None = None
        self.n_samples: int = 0
        self._is_fitted = False

    def learn(self, feature_matrix: np.ndarray) -> dict:
        """Learn baseline statistics from a matrix of feature vectors.

        Args:
            feature_matrix: shape (n_windows, NUM_FEATURES)

        Returns:
            Summary dict with per-feature statistics.
        """
        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected shape (n, {NUM_FEATURES}), got {feature_matrix.shape}"
            )

        self.mean = feature_matrix.mean(axis=0)
        self.std = feature_matrix.std(axis=0)
        self.std = np.where(self.std < 1e-8, 1e-8, self.std)
        self.n_samples = feature_matrix.shape[0]
        self._is_fitted = True

        return {
            "n_samples": self.n_samples,
            "feature_stats": {
                name: {"mean": float(self.mean[i]), "std": float(self.std[i])}
                for i, name in enumerate(FEATURE_NAMES)
            },
        }

    def check_drift(self, recent_features: np.ndarray) -> list[DriftResult]:
        """Check if recent feature vectors have drifted from baseline.

        Args:
            recent_features: shape (n_recent, NUM_FEATURES)

        Returns:
            List of DriftResult for each feature, sorted by |z_score| descending.
        """
        if not self._is_fitted:
            raise RuntimeError("Baseline not learned yet")

        if recent_features.ndim == 1:
            recent_features = recent_features.reshape(1, -1)

        current_mean = recent_features.mean(axis=0)
        z_scores = (current_mean - self.mean) / self.std

        results = []
        for i, name in enumerate(FEATURE_NAMES):
            results.append(DriftResult(
                feature_name=name,
                baseline_mean=float(self.mean[i]),
                baseline_std=float(self.std[i]),
                current_mean=float(current_mean[i]),
                z_score=float(z_scores[i]),
                drifted=abs(float(z_scores[i])) > self.drift_threshold,
            ))

        results.sort(key=lambda r: abs(r.z_score), reverse=True)
        return results

    def has_significant_drift(self, recent_features: np.ndarray) -> bool:
        """Quick check: has any feature drifted beyond threshold?"""
        results = self.check_drift(recent_features)
        return any(r.drifted for r in results)

    def drifted_features(self, recent_features: np.ndarray) -> list[DriftResult]:
        """Return only features that have drifted."""
        return [r for r in self.check_drift(recent_features) if r.drifted]

    def save(self, path: Path) -> None:
        """Save baseline profile to JSON."""
        if not self._is_fitted:
            raise RuntimeError("Baseline not learned yet")

        data = {
            "n_samples": self.n_samples,
            "drift_threshold": self.drift_threshold,
            "feature_names": FEATURE_NAMES,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: Path) -> BaselineProfile:
        """Load a saved baseline profile."""
        data = json.loads(Path(path).read_text())
        profile = cls(drift_threshold=data["drift_threshold"])
        profile.mean = np.array(data["mean"], dtype=np.float64)
        profile.std = np.array(data["std"], dtype=np.float64)
        profile.n_samples = data["n_samples"]
        profile._is_fitted = True
        return profile
