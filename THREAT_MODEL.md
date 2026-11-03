# OS-DEFENDER 2.0 — Threat Model

## Assets Under Protection

1. **Endpoint processes** — user and system processes on the monitored machine
2. **File system integrity** — configuration files, user data, system binaries
3. **Network connections** — outbound/inbound traffic patterns
4. **Authentication** — login attempts, privilege transitions
5. **Agent integrity** — the OS-DEFENDER agent itself

## Trust Boundaries

```
┌─ Kernel Space ──────────────────────────┐
│  eBPF probes (read-only tracing)        │
│  fanotify (file access decisions)       │
│  nftables (network policy enforcement)  │
└─────────────────┬───────────────────────┘
                  │ syscalls
┌─ Agent (User Space, privileged) ────────┐
│  Collectors → Detection → Response      │
│  Storage (SQLite) │ Audit Log           │
└─────────────────┬───────────────────────┘
                  │ IPC (Unix socket)
┌─ Desktop App (User Space, unprivileged) ┐
│  Tauri UI — read-only + approve actions │
└─────────────────────────────────────────┘
```

## Threat Categories

### T1: Agent Tampering
- **Attack**: Kill agent process, modify config, corrupt database
- **Mitigation**: systemd restart-on-failure, signed configuration, database integrity checks, tamper-protection monitoring
- **Limitation**: A root-level attacker can bypass all user-space protections

### T2: Detection Evasion
- **Attack**: Modify behaviour to stay below anomaly thresholds
- **Mitigation**: Multiple detection methods (rules + anomaly), baseline drift detection, blind-spot monitoring
- **Limitation**: Novel attacks with no matching rules or anomaly signature may evade detection

### T3: IPC Injection
- **Attack**: Forge IPC messages to agent to trigger response actions
- **Mitigation**: Socket permissions (owner-only), authenticated protocol, policy engine validates all actions
- **Limitation**: Requires same-user or root access

### T4: AI Model Poisoning
- **Attack**: Feed crafted events to shift anomaly baselines
- **Mitigation**: Baseline frozen after training period, model integrity verification, manual retraining approval
- **Limitation**: Training on attacker-controlled data would compromise the model

### T5: Sensor Blindness
- **Attack**: Disable specific collectors to create monitoring gaps
- **Mitigation**: Blind-spot detector, heartbeat monitoring, degraded-protection notifications
- **Limitation**: If the agent itself is killed, no detection occurs

### T6: Privilege Escalation via Agent
- **Attack**: Exploit agent's privileged operations to escalate access
- **Mitigation**: Least-privilege design, no network-exposed APIs, strict input validation on all event data
- **Limitation**: Bugs in privileged enforcement paths could be exploitable

## Explicit Limitations

1. **Not a replacement for kernel-level security** — user-space monitoring can be bypassed by root-level attackers
2. **Not a guaranteed ransomware preventer** — detection is best-effort; recovery depends on backup strategies
3. **No network-wide visibility** — monitors only the local endpoint
4. **AI is advisory only** — all enforcement decisions go through deterministic policy
5. **Windows enforcement depth** — without signed kernel drivers, Windows enforcement is limited to WFP and user-space mechanisms
6. **Resource constraints** — on modest hardware (12GB RAM), LLM inference may impact system performance
