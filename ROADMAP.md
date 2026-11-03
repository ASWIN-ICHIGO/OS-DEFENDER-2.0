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

## Phase 2 — Linux Protection (Next)
- [ ] Implement 5+ detection rules (brute-force, suspicious process, file tampering, etc.)
- [ ] IsolationForest anomaly detection (Rust or Python bridge)
- [ ] File monitoring for sensitive paths (/etc, ~/.ssh, crontabs)
- [ ] Persistence mechanism monitoring (systemd, cron, shell rc files)
- [ ] Process tree tracking and parent-child analysis
- [ ] Integrate all collectors into agent main loop
- [ ] End-to-end integration tests with real OS events
- [ ] Performance benchmarks (CPU, RAM, latency)

## Phase 3 — Linux Prevention
- [ ] nftables integration for network blocking
- [ ] fanotify for file access control decisions
- [ ] Process containment (cgroups freeze, not just SIGSTOP)
- [ ] Policy engine with dry-run/approve/execute workflow
- [ ] Hash-chained audit log for all response actions
- [ ] File quarantine with SHA-256 integrity verification
- [ ] Rollback mechanisms for all enforcement actions
- [ ] Verify actual OS enforcement in isolated tests

## Phase 4 — Windows Protection
- [ ] Windows service architecture
- [ ] ETW consumer for process/file/network events
- [ ] Windows Event Log reader (Security channel)
- [ ] Process monitoring via psutil or native APIs
- [ ] File monitoring via ReadDirectoryChangesW
- [ ] Network monitoring
- [ ] Sensor health monitoring
- [ ] Cross-platform event parity tests

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
