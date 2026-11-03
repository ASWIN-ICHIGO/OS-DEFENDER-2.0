"""ONNX Runtime inference engine for anomaly detection."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import onnxruntime as ort


class OnnxAnomalyDetector:
    """Score events using a pre-trained ONNX IsolationForest model."""

    def __init__(self, model_path: Path, scaler_path: Path):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)

        self.session = ort.InferenceSession(
            str(self.model_path),
            providers=["CPUExecutionProvider"],
        )

        scaler_data = json.loads(self.scaler_path.read_text())
        self.scaler_mean = np.array(scaler_data["mean"], dtype=np.float32)
        self.scaler_scale = np.array(scaler_data["scale"], dtype=np.float32)

        self.input_name = self.session.get_inputs()[0].name

    def _scale(self, features: np.ndarray) -> np.ndarray:
        return ((features - self.scaler_mean) / self.scaler_scale).astype(np.float32)

    def _extract_score(self, outputs: list, idx: int = 0) -> float:
        """Extract a scalar score from ONNX outputs.

        skl2onnx IsolationForest outputs:
          [0] = labels, shape (n,1) — values 1 (normal) or -1 (anomaly)
          [1] = decision_function scores, shape (n,1)
        """
        if len(outputs) >= 2:
            raw = outputs[1]
        else:
            raw = outputs[0]
        val = raw[idx]
        while hasattr(val, '__len__') and len(val) == 1:
            val = val[0]
        return float(val)

    def _extract_label(self, outputs: list, idx: int = 0) -> int:
        val = outputs[0][idx]
        while hasattr(val, '__len__') and len(val) == 1:
            val = val[0]
        return int(val)

    def score(self, feature_vector: np.ndarray) -> float:
        """Score a single feature vector. Lower = more anomalous."""
        vec = feature_vector.reshape(1, -1).astype(np.float32)
        X_scaled = self._scale(vec)
        outputs = self.session.run(None, {self.input_name: X_scaled})
        return self._extract_score(outputs, 0)

    def predict(self, feature_vector: np.ndarray) -> tuple[float, bool]:
        """Return (score, is_anomaly) for a single feature vector."""
        vec = feature_vector.reshape(1, -1).astype(np.float32)
        X_scaled = self._scale(vec)
        outputs = self.session.run(None, {self.input_name: X_scaled})
        score = self._extract_score(outputs, 0)
        label = self._extract_label(outputs, 0)
        return score, label == -1

    def batch_score(self, feature_matrix: np.ndarray) -> np.ndarray:
        """Score a batch of feature vectors. Returns array of scores."""
        X_scaled = self._scale(feature_matrix.astype(np.float32))
        outputs = self.session.run(None, {self.input_name: X_scaled})
        scores_raw = outputs[1] if len(outputs) >= 2 else outputs[0]
        return scores_raw.flatten().astype(np.float64)
