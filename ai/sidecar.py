#!/usr/bin/env python3
"""OS-DEFENDER AI Sidecar — JSON-line stdin/stdout scoring process.

The Rust agent spawns this process. Protocol:
  - Agent sends one JSON object per line on stdin
  - Sidecar replies with one JSON object per line on stdout
  - stderr is used for logging only

Request types:
  {"cmd": "ping"}
    → {"ok": true}

  {"cmd": "score", "events": [...]}
    → {"score": float, "is_anomaly": bool, "explanation": {...} | null}

  {"cmd": "status"}
    → {"model_loaded": bool, "events_scored": int, "anomalies_detected": int}

  {"cmd": "shutdown"}
    → {"ok": true}  (then exit)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _find_model_dir() -> Path:
    for candidate in [
        Path.home() / ".local" / "share" / "os-defender",
        Path("/var/lib/os-defender"),
        Path.cwd(),
    ]:
        if (candidate / "anomaly_detector.onnx").exists():
            return candidate
        if (candidate / "model.onnx").exists():
            return candidate
    return Path.home() / ".local" / "share" / "os-defender"


def _load_engine(model_dir: Path):
    """Try to load ONNX model. Returns (engine, explainer) or (None, None)."""
    model_path = None
    for name in ["anomaly_detector.onnx", "model.onnx"]:
        p = model_dir / name
        if p.exists():
            model_path = p
            break

    scaler_path = model_dir / "scaler.json"
    if model_path is None or not scaler_path.exists():
        return None, None

    try:
        from inference.engine import OnnxAnomalyDetector
        from inference.explainer import AnomalyExplainer

        engine = OnnxAnomalyDetector(model_path, scaler_path)
        explainer = AnomalyExplainer(scaler_path)
        return engine, explainer
    except (ImportError, OSError, ValueError) as e:
        print(f"[sidecar] model load failed: {e}", file=sys.stderr)
        return None, None


def _score_events(engine, explainer, events: list[dict]) -> dict:
    """Score a batch of events and return result dict."""
    from features.extractor import events_to_feature_vector

    feature_vec = events_to_feature_vector(events)
    score, is_anomaly = engine.predict(feature_vec)

    explanation = None
    if is_anomaly and explainer is not None:
        exp = explainer.explain(feature_vec, score, is_anomaly)
        explanation = exp.to_dict()

    return {
        "score": float(score),
        "is_anomaly": is_anomaly,
        "explanation": explanation,
    }


def main():
    model_dir_env = sys.argv[1] if len(sys.argv) > 1 else None
    model_dir = Path(model_dir_env) if model_dir_env else _find_model_dir()

    # Add ai/ to path so imports work
    ai_root = Path(__file__).resolve().parent
    if str(ai_root) not in sys.path:
        sys.path.insert(0, str(ai_root))

    engine, explainer = _load_engine(model_dir)
    events_scored = 0
    anomalies_detected = 0

    print(f"[sidecar] started, model_dir={model_dir}, loaded={engine is not None}", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            _respond({"error": f"invalid JSON: {e}"})
            continue

        cmd = req.get("cmd", "")

        if cmd == "ping":
            _respond({"ok": True})

        elif cmd == "status":
            _respond({
                "model_loaded": engine is not None,
                "events_scored": events_scored,
                "anomalies_detected": anomalies_detected,
            })

        elif cmd == "score":
            events = req.get("events", [])
            if engine is None:
                _respond({"score": 0.0, "is_anomaly": False, "explanation": None})
            else:
                try:
                    result = _score_events(engine, explainer, events)
                    events_scored += 1
                    if result["is_anomaly"]:
                        anomalies_detected += 1
                    _respond(result)
                except (ValueError, OSError, RuntimeError) as e:
                    _respond({"error": f"scoring failed: {e}"})

        elif cmd == "reload":
            engine, explainer = _load_engine(model_dir)
            _respond({"ok": True, "model_loaded": engine is not None})

        elif cmd == "shutdown":
            _respond({"ok": True})
            break

        else:
            _respond({"error": f"unknown command: {cmd}"})


def _respond(obj: dict):
    """Write a single JSON-line response to stdout and flush."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
