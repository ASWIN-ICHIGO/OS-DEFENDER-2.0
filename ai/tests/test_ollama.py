"""Tests for Ollama LLM client — tests fallback path (no live Ollama needed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm.ollama_client import LlmExplanation, OllamaClient


def test_fallback_when_unavailable():
    client = OllamaClient(base_url="http://127.0.0.1:99999")

    anomaly_data = {
        "anomaly_score": -0.75,
        "is_anomaly": True,
        "summary": "Anomalous: failed_login_rate is 8.2σ above baseline.",
        "top_contributors": [
            {
                "feature": "failed_login_rate",
                "value": 12.5,
                "baseline_mean": 0.3,
                "z_score": 8.2,
                "contribution_pct": 45.0,
            },
        ],
    }

    result = client.explain_anomaly(anomaly_data)
    assert isinstance(result, LlmExplanation)
    assert not result.available
    assert result.model == "rule-based-fallback"
    assert "failed_login_rate" in result.text


def test_is_available_returns_false_for_bad_url():
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    assert not client.is_available()


def test_fallback_with_empty_contributors():
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    anomaly_data = {
        "anomaly_score": -0.1,
        "is_anomaly": False,
        "summary": "Normal behaviour.",
        "top_contributors": [],
    }
    result = client.explain_anomaly(anomaly_data)
    assert "Normal" in result.text
