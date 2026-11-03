"""Optional local LLM integration via Ollama for natural language explanations."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"
TIMEOUT_SECONDS = 30


@dataclass
class LlmExplanation:
    """LLM-generated natural language explanation of an anomaly."""
    text: str
    model: str
    available: bool


SYSTEM_PROMPT = """\
You are a security analyst assistant for OS-DEFENDER, an endpoint detection and response system.
Given anomaly detection results with contributing factors, provide a brief, actionable explanation.
Focus on: what happened, why it's suspicious, and what the operator should investigate.
Keep responses under 100 words. Do not speculate beyond the data provided."""


class OllamaClient:
    """Client for local Ollama LLM. Falls back gracefully when unavailable."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout: int = TIMEOUT_SECONDS,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is loaded."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5,
            )
            if resp.status_code != 200:
                return False
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            return any(self.model in m for m in models)
        except (requests.ConnectionError, requests.Timeout, requests.RequestException, ValueError):
            return False

    def explain_anomaly(self, anomaly_data: dict) -> LlmExplanation:
        """Generate a natural language explanation of an anomaly.

        Args:
            anomaly_data: Dict from AnomalyExplanation.to_dict()

        Returns:
            LlmExplanation with text and availability status.
        """
        if not self.is_available():
            return self._fallback(anomaly_data)

        prompt = self._build_prompt(anomaly_data)

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "system": SYSTEM_PROMPT,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 200},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            if not text:
                return self._fallback(anomaly_data)

            return LlmExplanation(text=text, model=self.model, available=True)

        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            logger.warning("Ollama request failed: %s", e)
            return self._fallback(anomaly_data)

    def _build_prompt(self, anomaly_data: dict) -> str:
        score = anomaly_data.get("anomaly_score", 0)
        contributors = anomaly_data.get("top_contributors", [])
        summary = anomaly_data.get("summary", "")

        lines = [f"Anomaly score: {score:.4f}", f"Detection summary: {summary}", ""]
        lines.append("Top contributing factors:")
        for c in contributors[:5]:
            lines.append(
                f"  - {c['feature']}: value={c['value']}, "
                f"expected≈{c['baseline_mean']}, z-score={c['z_score']}"
            )

        lines.append("")
        lines.append("Explain this anomaly for a security operator.")
        return "\n".join(lines)

    def _fallback(self, anomaly_data: dict) -> LlmExplanation:
        """Rule-based fallback when Ollama is unavailable."""
        summary = anomaly_data.get("summary", "Anomaly detected.")
        contributors = anomaly_data.get("top_contributors", [])

        parts = [summary]
        if contributors:
            top = contributors[0]
            parts.append(
                f"Primary driver: {top['feature']} "
                f"(z-score={top['z_score']})."
            )

        return LlmExplanation(
            text=" ".join(parts),
            model="rule-based-fallback",
            available=False,
        )
