"""IsolationForest training pipeline with ONNX export."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features.extractor import FEATURE_NAMES, NUM_FEATURES


class AnomalyTrainer:
    """Train an IsolationForest on baseline behavioural features and export to ONNX."""

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model: IsolationForest | None = None
        self._is_fitted = False

    def train(self, feature_matrix: np.ndarray) -> dict:
        """Train on a matrix of shape (n_windows, NUM_FEATURES).

        Returns training metadata dict.
        """
        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected shape (n, {NUM_FEATURES}), got {feature_matrix.shape}"
            )

        n_samples = feature_matrix.shape[0]
        if n_samples < 10:
            raise ValueError(f"Need at least 10 samples, got {n_samples}")

        X_scaled = self.scaler.fit_transform(feature_matrix)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self._is_fitted = True

        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        n_anomalies = int((predictions == -1).sum())

        return {
            "n_samples": n_samples,
            "n_features": NUM_FEATURES,
            "feature_names": FEATURE_NAMES,
            "n_anomalies_in_training": n_anomalies,
            "anomaly_ratio": n_anomalies / n_samples,
            "score_mean": float(scores.mean()),
            "score_std": float(scores.std()),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
        }

    def score(self, feature_vector: np.ndarray) -> float:
        """Score a single feature vector. Lower = more anomalous."""
        if not self._is_fitted:
            raise RuntimeError("Model not trained yet")
        vec = feature_vector.reshape(1, -1)
        X_scaled = self.scaler.transform(vec)
        return float(self.model.decision_function(X_scaled)[0])

    def predict(self, feature_vector: np.ndarray) -> tuple[float, bool]:
        """Return (score, is_anomaly) for a single feature vector."""
        if not self._is_fitted:
            raise RuntimeError("Model not trained yet")
        vec = feature_vector.reshape(1, -1)
        X_scaled = self.scaler.transform(vec)
        score = float(self.model.decision_function(X_scaled)[0])
        label = int(self.model.predict(X_scaled)[0])
        return score, label == -1

    def export_onnx(self, output_path: Path) -> Path:
        """Export the trained model to ONNX format."""
        if not self._is_fitted:
            raise RuntimeError("Model not trained yet")

        from skl2onnx import to_onnx

        X_sample = np.zeros((1, NUM_FEATURES), dtype=np.float32)
        X_sample_scaled = self.scaler.transform(X_sample)

        onnx_model = to_onnx(
            self.model,
            X_sample_scaled.astype(np.float32),
            target_opset={"ai.onnx.ml": 3, "": 17},
        )

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        return output_path

    def save_scaler(self, output_path: Path) -> Path:
        """Save scaler parameters as JSON for the inference engine."""
        if not self._is_fitted:
            raise RuntimeError("Scaler not fitted yet")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "feature_names": FEATURE_NAMES,
            "mean": self.scaler.mean_.tolist(),
            "scale": self.scaler.scale_.tolist(),
            "var": self.scaler.var_.tolist(),
        }
        output_path.write_text(json.dumps(data, indent=2))
        return output_path

    def save_all(self, model_dir: Path) -> dict[str, Path]:
        """Save ONNX model and scaler to a directory."""
        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)

        onnx_path = self.export_onnx(model_dir / "anomaly_detector.onnx")
        scaler_path = self.save_scaler(model_dir / "scaler.json")

        meta = {
            "model_type": "IsolationForest",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "n_features": NUM_FEATURES,
            "feature_names": FEATURE_NAMES,
        }
        meta_path = model_dir / "model_meta.json"
        meta_path.write_text(json.dumps(meta, indent=2))

        return {"onnx": onnx_path, "scaler": scaler_path, "meta": meta_path}
