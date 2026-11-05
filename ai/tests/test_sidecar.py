"""Tests for the AI sidecar JSON-line protocol."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SIDECAR = Path(__file__).resolve().parent.parent / "sidecar.py"


def _start_sidecar(model_dir: str = "/nonexistent") -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-I", str(SIDECAR), model_dir],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _send(proc: subprocess.Popen, cmd: dict) -> dict:
    proc.stdin.write(json.dumps(cmd) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline().strip()
    return json.loads(line)


def test_sidecar_ping():
    proc = _start_sidecar()
    try:
        resp = _send(proc, {"cmd": "ping"})
        assert resp["ok"] is True
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)


def test_sidecar_status_no_model():
    proc = _start_sidecar()
    try:
        resp = _send(proc, {"cmd": "status"})
        assert resp["model_loaded"] is False
        assert resp["events_scored"] == 0
        assert resp["anomalies_detected"] == 0
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)


def test_sidecar_score_without_model():
    proc = _start_sidecar()
    try:
        events = [
            {
                "event_type": "process",
                "timestamp": "2024-01-01T00:00:00Z",
                "process_context": {"pid": 1, "name": "bash", "cmdline": "bash"},
            }
        ]
        resp = _send(proc, {"cmd": "score", "events": events})
        assert resp["is_anomaly"] is False
        assert resp["score"] == 0.0
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)


def test_sidecar_invalid_json():
    proc = _start_sidecar()
    try:
        proc.stdin.write("not json\n")
        proc.stdin.flush()
        line = proc.stdout.readline().strip()
        resp = json.loads(line)
        assert "error" in resp
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)


def test_sidecar_unknown_command():
    proc = _start_sidecar()
    try:
        resp = _send(proc, {"cmd": "foobar"})
        assert "error" in resp
        assert "unknown command" in resp["error"]
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)


def test_sidecar_shutdown():
    proc = _start_sidecar()
    resp = _send(proc, {"cmd": "shutdown"})
    assert resp["ok"] is True
    proc.wait(timeout=5)
    assert proc.returncode == 0


def test_sidecar_reload_no_model():
    proc = _start_sidecar()
    try:
        resp = _send(proc, {"cmd": "reload"})
        assert resp["ok"] is True
        assert resp["model_loaded"] is False
    finally:
        _send(proc, {"cmd": "shutdown"})
        proc.wait(timeout=5)
