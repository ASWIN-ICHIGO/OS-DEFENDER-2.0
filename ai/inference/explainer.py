"""Anomaly explanation with per-feature contributing factors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from features.extractor import FEATURE_NAMES


@dataclass
class FeatureContribution:
    """A single feature's contribution to the anomaly score."""
    feature_name: str
    value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    contribution_pct: float


@dataclass
class AnomalyExplanation:
    """Full explanation of why an event window was flagged as anomalous."""
    anomaly_score: float
    is_anomaly: bool
    top_contributors: list[FeatureContribution]
    summary: str

    def to_dict(self) -> dict:
        return {
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "summary": self.summary,
            "top_contributors": [
                {
                    "feature": c.feature_name,
                    "value": round(c.value, 4),
                    "baseline_mean": round(c.baseline_mean, 4),
                    "baseline_std": round(c.baseline_std, 4),
                    "z_score": round(c.z_score, 2),
                    "contribution_pct": round(c.contribution_pct, 1),
                }
                for c in self.top_contributors
            ],
        }


class AnomalyExplainer:
    """Explain anomalies by computing per-feature deviation from baseline."""

    def __init__(self, scaler_path: Path, top_k: int = 5):
        self.top_k = top_k
        scaler_data = json.loads(Path(scaler_path).read_text())
        self.baseline_mean = np.array(scaler_data["mean"], dtype=np.float64)
        self.baseline_std = np.array(scaler_data["scale"], dtype=np.float64)
        self.baseline_std = np.where(self.baseline_std < 1e-8, 1e-8, self.baseline_std)

    def explain(
        self,
        feature_vector: np.ndarray,
        anomaly_score: float,
        is_anomaly: bool,
    ) -> AnomalyExplanation:
        """Explain why a feature vector is anomalous.

        Uses z-score decomposition: each feature's |z-score| is its
        contribution weight. Top-k features by contribution are reported.
        """
        vec = feature_vector.flatten().astype(np.float64)
        z_scores = (vec - self.baseline_mean) / self.baseline_std
        abs_z = np.abs(z_scores)
        total_z = abs_z.sum()
        if total_z < 1e-8:
            total_z = 1.0

        contributions = []
        for i, name in enumerate(FEATURE_NAMES):
            contributions.append(FeatureContribution(
                feature_name=name,
                value=float(vec[i]),
                baseline_mean=float(self.baseline_mean[i]),
                baseline_std=float(self.baseline_std[i]),
                z_score=float(z_scores[i]),
                contribution_pct=float(abs_z[i] / total_z * 100),
            ))

        contributions.sort(key=lambda c: abs(c.z_score), reverse=True)
        top = contributions[: self.top_k]

        summary = self._build_summary(top, is_anomaly)

        return AnomalyExplanation(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            top_contributors=top,
            summary=summary,
        )

    def _build_summary(self, top: list[FeatureContribution], is_anomaly: bool) -> str:
        if not is_anomaly:
            return "Behaviour within normal baseline parameters."

        parts = []
        for c in top[:3]:
            direction = "above" if c.z_score > 0 else "below"
            parts.append(
                f"{c.feature_name} is {abs(c.z_score):.1f}σ {direction} baseline "
                f"(value={c.value:.2f}, expected≈{c.baseline_mean:.2f})"
            )

        return "Anomalous: " + "; ".join(parts) + "."
