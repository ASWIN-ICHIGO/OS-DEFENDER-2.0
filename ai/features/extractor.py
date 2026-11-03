"""Behavioural feature extraction from NormalizedEvent streams."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path

import numpy as np
from pydantic import BaseModel

FEATURE_NAMES: list[str] = [
    "process_count",
    "new_process_rate",
    "suspicious_parent_child",
    "privilege_escalation_attempts",
    "unique_dest_ips",
    "unique_dest_ports",
    "connection_rate",
    "outbound_ratio",
    "nonstandard_port_ratio",
    "file_modification_rate",
    "sensitive_file_access",
    "unique_paths_modified",
    "failed_login_rate",
    "unique_auth_sources",
    "auth_escalation_count",
    "events_per_minute",
    "hour_of_day",
]

NUM_FEATURES = len(FEATURE_NAMES)

SENSITIVE_PATHS = {
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
    "/etc/ld.so.preload",
}

COMMON_PORTS = {22, 53, 80, 443, 993, 995, 8080, 8443}


class EventRecord(BaseModel):
    """Minimal NormalizedEvent fields needed for feature extraction."""
    event_type: str
    timestamp: str
    severity: str | None = None
    process_context: dict | None = None
    file_context: dict | None = None
    network_context: dict | None = None
    auth_context: dict | None = None


@dataclass
class WindowAccumulator:
    """Accumulates raw counters within a single time window."""
    process_pids: set[int] = field(default_factory=set)
    new_processes: int = 0
    suspicious_parents: int = 0
    priv_escalations: int = 0
    dest_ips: set[str] = field(default_factory=set)
    dest_ports: set[int] = field(default_factory=set)
    connections: int = 0
    outbound: int = 0
    inbound: int = 0
    nonstandard_port_conns: int = 0
    file_modifications: int = 0
    sensitive_accesses: int = 0
    modified_paths: set[str] = field(default_factory=set)
    failed_logins: int = 0
    auth_sources: set[str] = field(default_factory=set)
    escalations: int = 0
    total_events: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    hour_sum: float = 0.0

    def duration_minutes(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 1.0
        d = (self.last_ts - self.first_ts) / 60.0
        return max(d, 1.0 / 60.0)


SUSPICIOUS_PARENTS = {"bash", "sh", "cmd.exe", "powershell.exe"}


def _parse_ts(ts_str: str) -> float:
    from datetime import datetime
    ts_str = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(ts_str)
    return dt.replace(tzinfo=UTC if dt.tzinfo is None else dt.tzinfo).timestamp()


def accumulate_event(acc: WindowAccumulator, event: EventRecord) -> None:
    acc.total_events += 1
    try:
        ts = _parse_ts(event.timestamp)
    except (ValueError, TypeError):
        ts = None

    if ts is not None:
        if acc.first_ts is None or ts < acc.first_ts:
            acc.first_ts = ts
        if acc.last_ts is None or ts > acc.last_ts:
            acc.last_ts = ts
        from datetime import datetime
        acc.hour_sum += datetime.fromtimestamp(ts, tz=UTC).hour

    if event.event_type == "process" and event.process_context:
        pc = event.process_context
        pid = pc.get("pid", 0)
        if pid not in acc.process_pids:
            acc.new_processes += 1
        acc.process_pids.add(pid)
        parent_name = pc.get("name", "")
        cmdline = pc.get("cmdline", "") or ""
        if parent_name in SUSPICIOUS_PARENTS and ("reverse" in cmdline or "/dev/tcp" in cmdline):
            acc.suspicious_parents += 1
        if "+s" in cmdline or "chmod" in cmdline:
            acc.priv_escalations += 1

    elif event.event_type == "network" and event.network_context:
        nc = event.network_context
        acc.connections += 1
        remote = nc.get("remote_addr")
        port = nc.get("remote_port")
        direction = nc.get("direction", "unknown")
        if remote:
            acc.dest_ips.add(remote)
        if port is not None:
            acc.dest_ports.add(int(port))
            if int(port) not in COMMON_PORTS:
                acc.nonstandard_port_conns += 1
        if direction == "outbound":
            acc.outbound += 1
        elif direction == "inbound":
            acc.inbound += 1

    elif event.event_type == "file" and event.file_context:
        fc = event.file_context
        action = fc.get("action", "")
        path = fc.get("path", "")
        if action in ("modify", "create", "delete"):
            acc.file_modifications += 1
            acc.modified_paths.add(path)
        if path in SENSITIVE_PATHS:
            acc.sensitive_accesses += 1

    elif event.event_type == "authentication" and event.auth_context:
        ac = event.auth_context
        action = ac.get("action", "")
        source = ac.get("source_addr")
        if action == "failed":
            acc.failed_logins += 1
        if action == "escalation":
            acc.escalations += 1
        if source:
            acc.auth_sources.add(source)


def extract_features(acc: WindowAccumulator) -> np.ndarray:
    """Convert accumulated counters into a fixed-length feature vector."""
    dur = acc.duration_minutes()
    total_net = acc.outbound + acc.inbound
    avg_hour = (acc.hour_sum / acc.total_events) if acc.total_events > 0 else 12.0

    vec = np.array([
        len(acc.process_pids),                                      # process_count
        acc.new_processes / dur,                                     # new_process_rate
        acc.suspicious_parents,                                      # suspicious_parent_child
        acc.priv_escalations,                                        # privilege_escalation_attempts
        len(acc.dest_ips),                                           # unique_dest_ips
        len(acc.dest_ports),                                         # unique_dest_ports
        acc.connections / dur,                                       # connection_rate
        acc.outbound / total_net if total_net > 0 else 0.5,         # outbound_ratio
        acc.nonstandard_port_conns / max(acc.connections, 1),        # nonstandard_port_ratio
        acc.file_modifications / dur,                                # file_modification_rate
        acc.sensitive_accesses,                                      # sensitive_file_access
        len(acc.modified_paths),                                     # unique_paths_modified
        acc.failed_logins / dur,                                     # failed_login_rate
        len(acc.auth_sources),                                       # unique_auth_sources
        acc.escalations,                                             # auth_escalation_count
        acc.total_events / dur,                                      # events_per_minute
        avg_hour,                                                    # hour_of_day
    ], dtype=np.float32)

    return vec


def events_to_feature_vector(events: list[dict]) -> np.ndarray:
    """Convert a batch of raw event dicts into a single feature vector."""
    acc = WindowAccumulator()
    for raw in events:
        try:
            ev = EventRecord(**raw)
        except (ValueError, TypeError, KeyError):
            continue
        accumulate_event(acc, ev)
    return extract_features(acc)


def load_events_from_jsonl(path: Path) -> list[dict]:
    """Load events from a JSON-Lines file."""
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
