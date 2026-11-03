# OS-DEFENDER 2.0 — Development Roadmap

## Phase 0 — Repository Audit ✅
- [x] Inspected OS-DEFENDER 1.0 codebase
- [x] Identified: genuine Python EDR prototype, 19K lines, 994 tests
- [x] Gap analysis: no Rust, no kernel integration, no real enforcement
- [x] Decision: fresh start with Rust core architecture

## Phase 1 — Architecture and Foundation ✅
- [x] Cargo workspace with three crates (core, agent, cli)
- [x] Normalized event schema with Serde validation
- [x] Platform abstraction traits (ProcessCollector, FileCollector, etc.)
- [x] Linux process collector (/proc polling with diff detection)
- [x] Linux file collector (inotify integration)
- [x] Linux network collector (/proc/net parsing)
- [x] Linux auth collector (journalctl streaming)
- [x] SQLite storage with WAL mode
- [x] Detection engine framework (rules + alert types)
- [x] Blind-spot health detector
- [x] IPC protocol (Unix domain socket, JSON-line)
- [x] Agent daemon with signal handling
- [x] CLI for agent communication
- [x] systemd service definition
- [x] Documentation suite

## Phase 2 — Linux Protection ✅
- [x] 5 detection rules: brute-force (R001), suspicious process (R002), file tampering (R003), anomalous network (R004), persistence change (R005)
- [x] MITRE ATT&CK mapping: T1110, T1059, T1059.004, T1565.001, T1486, T1071, T1571, T1053.003, T1543.002, T1546.004, T1574.006, T1098.004, T1547.001
- [x] File monitoring for sensitive paths (/etc/shadow, sudoers, authorized_keys, ld.so.preload, ssh configs)
- [x] Persistence mechanism monitoring (systemd, cron, shell rc files, init.d, XDG autostart — 14 patterns)
- [x] Process tree tracking and parent-child analysis with cycle protection
- [x] Integrate all collectors + detection engine into agent main loop
- [ ] IsolationForest anomaly detection — deferred to Phase 6
- [ ] End-to-end integration tests with real OS events
- [ ] Performance benchmarks (CPU, RAM, latency)

## Phase 3 — Linux Prevention ✅
- [x] Policy engine with dry-run/approve/execute workflow (severity-based auto-execute)
- [x] Hash-chained audit log with SHA-256 tamper detection
- [x] nftables integration for network blocking (add/remove rules, comment-tagged)
- [x] Process containment via cgroup v2 freeze/thaw (safety: refuses PID ≤2)
- [x] File quarantine with SHA-256 integrity verification on restore
- [x] Rollback mechanisms for all enforcement actions (token-based)
- [x] Agent integration: alert → suggest actions → policy decision → audit log
- [x] CLI: audit log viewer, policy mode get/set, audit chain verification
- [ ] fanotify for file access control decisions (deferred — requires CAP_SYS_ADMIN)
- [ ] OS enforcement verification in isolated VMs

## Phase 4 — Windows Protection ✅
- [x] Windows process collector (ToolHelp32 snapshot, PID diff, ProcessCollector trait)
- [x] Windows file collector (FindFirstChangeNotification, subtree watch, FileCollector trait)
- [x] Windows network collector (GetExtendedTcpTable, TCP IPv4, NetworkCollector trait)
- [x] Windows auth collector (Security Event Log: 4624/4625/4634/4672, AuthCollector trait)
- [x] Windows system info (Registry MachineGuid, hostname via GetComputerNameExW)
- [x] Cross-platform event parity tests (9 tests: all detection rules fire on Windows events)
- [ ] Windows service architecture (requires Windows testing environment)
- [ ] Real Windows testing on dual-boot setup

## Phase 5 — Windows Prevention ✅
- [x] WFP enforcer via netsh advfirewall CLI (block/unblock IP in+out, mirrors nftables)
- [x] Process containment via Job Objects + thread suspension (SuspendThread/ResumeThread)
- [x] File quarantine with Windows ACL permissions (cross-platform module)
- [x] Policy engine parity: 13 cross-platform enforcement tests
- [x] Agent Windows collector loop with health heartbeats
- [x] Platform-aware IPC status (reports correct collectors per OS)
- [ ] Direct WFP API integration (replace netsh CLI for lower latency)
- [ ] Full DACL-based quarantine directory ACLs
- [ ] Real Windows testing on dual-boot setup

## Phase 6 — AI Intelligence ✅
- [x] Behavioural feature extraction (17 features: process/network/file/auth/temporal)
- [x] IsolationForest training pipeline (scikit-learn, configurable parameters)
- [x] ONNX model export via skl2onnx + ONNX Runtime local inference
- [x] Baseline learning with z-score drift detection (save/load profiles)
- [x] Anomaly explanations with per-feature contributing factors
- [x] Optional local LLM via Ollama (graceful fallback when unavailable)
- [x] Fully offline operation verified (end-to-end test, no network)
- [x] IPC integration: GetAiStatus command, CLI ai-status subcommand
- [x] 41 Python tests passing, ruff clean
- [ ] Wire AI sidecar process to agent main loop
- [ ] Real-time event scoring during collection

## Phase 7 — Advanced Security Modules ✅
- [x] Ransomware defense (canary files, entropy detection, rapid-mod/rename aggregation, known extension matching)
- [x] Persistence defense (Linux: systemd, cron, shell rc, init.d, XDG, udev; Windows: Run keys, startup folder, scheduled tasks)
- [x] File intelligence (SHA-256, local reputation DB, known-good/known-bad lists, IOC loading, file analysis)
- [x] Threat hunting query engine (SQL-backed, filter by type/severity/time/process/file/network/auth/payload)
- [x] Digital forensics (timeline builder, evidence collector, forensic report generation with JSON export)
- [x] Security posture assessment (10 checks: shadow perms, SSH config, firewall, SUID, noexec, ASLR, updates, empty passwords)
- [x] Tamper protection (integrity manifest, SHA-256 verification, signed config with hash validation)
- [x] IPC integration: ThreatHunt, GetPosture, GetPersistence, VerifyIntegrity commands
- [x] CLI commands: hunt, posture, persistence, integrity
- [x] New detection rule: R006-ransomware-defense (MITRE T1486)
- [ ] PDF report generation (requires additional dependency)
- [ ] Windows persistence scanner testing on real Windows

## Phase 8 — Desktop Application ✅
- [x] Tauri v2 project setup (Rust backend, Vite + React frontend)
- [x] React 18 + TypeScript UI framework with Vite bundler
- [x] IPC bridge to agent via Unix domain socket (13 Tauri commands)
- [x] 22 navigation sections: Dashboard, Alerts, Process Explorer, File Monitor, Network Monitor, Auth Events, Detection Rules, Enforcement, Audit Log, AI Engine, Ransomware Defense, Persistence Scanner, File Intelligence, Threat Hunting, Digital Forensics, Security Posture, Tamper Protection, System Health, Command Center, Settings, About
- [x] Dark graphite professional SOC theme (40+ CSS custom properties)
- [x] Real-time event visualization with auto-polling (3–10s intervals)
- [x] Collapsible sidebar with 6 grouped sections
- [x] Top bar with live agent status, event/alert counts, policy mode
- [x] Command Center terminal with 12 interactive commands
- [ ] Linux installer (.deb, AppImage) — requires Node.js + Tauri CLI
- [ ] Windows installer (.msi) — requires Windows build environment

## Phase 9 — Security Validation ✅
- [x] Attack simulation lab (18 tests covering 14 MITRE techniques, 4 negative controls)
- [x] MITRE ATT&CK technique mapping (13 techniques documented with rules, methods, prevention)
- [x] Cross-platform capability matrix (Linux vs Windows feature parity)
- [x] Performance benchmarks (90K events/sec detection, 5.5K SQLite inserts/sec, 13us ransomware check)
- [x] Threat model (7 asset classes, 4 actor profiles, 5 attack surfaces)
- [ ] Prevention verification in isolated VMs (requires VM lab setup)
- [ ] False positive tuning with production workload data

## Phase 10 — Final Product ✅
- [x] Complete documentation
- [x] Installation guide (docs/INSTALLATION.md)
- [x] Configuration reference (docs/CONFIGURATION.md)
- [x] Architecture document (docs/ARCHITECTURE.md)
- [x] Threat model (tests/security/THREAT_MODEL.md — completed in Phase 9)
- [x] Test reports (docs/TEST_REPORT.md)
- [x] Demo scenarios (docs/DEMO_SCENARIOS.md)
- [x] Release packaging (scripts/build-release.sh, scripts/demo.sh)
