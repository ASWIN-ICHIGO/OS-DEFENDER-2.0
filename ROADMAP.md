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

## Phase 5 — Windows Prevention
- [ ] WFP (Windows Filtering Platform) integration
- [ ] Process containment via Job Objects
- [ ] File protection
- [ ] Policy engine parity with Linux
- [ ] Document driver requirements and signing

## Phase 6 — AI Intelligence
- [ ] Behavioural feature extraction
- [ ] IsolationForest training pipeline
- [ ] ONNX model export and local inference
- [ ] Baseline learning with drift detection
- [ ] Anomaly explanations with contributing factors
- [ ] Optional local LLM via Ollama
- [ ] Fully offline operation verification

## Phase 7 — Advanced Security Modules
- [ ] Ransomware defense (rapid-modification detection, canary files)
- [ ] Persistence defense (systemd, cron, autoruns, scheduled tasks)
- [ ] File intelligence (SHA-256, reputation, quarantine)
- [ ] Threat hunting query engine
- [ ] Digital forensics (timeline, evidence, PDF reports)
- [ ] Vulnerability/security posture assessment
- [ ] Tamper protection (agent integrity, signed config)

## Phase 8 — Desktop Application
- [ ] Tauri project setup
- [ ] React + TypeScript UI framework
- [ ] Authenticated IPC to agent
- [ ] 22 navigation sections
- [ ] Dark graphite professional theme
- [ ] Real-time event visualization
- [ ] Linux installer (.deb, AppImage)
- [ ] Windows installer (.msi)

## Phase 9 — Security Validation
- [ ] Attack simulation lab (12+ harmless scenarios)
- [ ] MITRE ATT&CK technique mapping
- [ ] Cross-platform capability matrix
- [ ] Prevention verification in isolated VMs
- [ ] Performance measurement
- [ ] False positive tuning
- [ ] Security review

## Phase 10 — Final Product
- [ ] Complete documentation
- [ ] Installation guide
- [ ] Configuration reference
- [ ] Threat model
- [ ] Test reports
- [ ] Demo scenarios
- [ ] Release packaging
