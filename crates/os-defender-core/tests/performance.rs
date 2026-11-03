use std::time::Instant;

use os_defender_core::detection::{DetectionEngine, default_ruleset};
use os_defender_core::events::*;
use os_defender_core::storage::SqliteStore;

fn make_process_event(name: &str, pid: u32) -> NormalizedEvent {
    NormalizedEvent::new("bench-ep".into(), OsType::Linux, EventType::Process, Severity::Info)
        .with_process(ProcessContext {
            pid,
            ppid: Some(1),
            name: name.into(),
            exe: Some(format!("/usr/bin/{name}")),
            cmdline: Some(name.into()),
            uid: Some(1000),
            username: Some("bench".into()),
            start_time: None,
            children_pids: vec![],
        })
}

fn make_file_event(path: &str, action: FileAction) -> NormalizedEvent {
    NormalizedEvent::new("bench-ep".into(), OsType::Linux, EventType::File, Severity::Info)
        .with_file(FileContext {
            path: path.into(),
            action,
            sha256: None,
            size_bytes: Some(1024),
            owner_uid: Some(1000),
            permissions: Some("0644".into()),
        })
}

fn make_network_event(remote: &str, port: u16) -> NormalizedEvent {
    NormalizedEvent::new("bench-ep".into(), OsType::Linux, EventType::Network, Severity::Info)
        .with_network(NetworkContext {
            protocol: NetworkProtocol::Tcp,
            direction: NetDirection::Outbound,
            local_addr: "192.168.1.100".into(),
            local_port: 54321,
            remote_addr: Some(remote.into()),
            remote_port: Some(port),
            state: Some("ESTABLISHED".into()),
            pid: Some(1234),
            process_name: Some("curl".into()),
            bytes_sent: Some(100),
            bytes_received: Some(200),
        })
}

fn make_auth_event(user: &str, action: AuthAction, source: &str) -> NormalizedEvent {
    NormalizedEvent::new("bench-ep".into(), OsType::Linux, EventType::Authentication, Severity::Info)
        .with_auth(AuthContext {
            action,
            username: user.into(),
            source_addr: Some(source.into()),
            method: Some("password".into()),
            service: Some("sshd".into()),
            session_id: None,
        })
}

#[test]
fn benchmark_detection_engine_throughput() {
    let rules = default_ruleset();
    let mut engine = DetectionEngine::new(rules);

    let events: Vec<NormalizedEvent> = (0..10_000)
        .map(|i| match i % 4 {
            0 => make_process_event("sshd", 1000 + i as u32),
            1 => make_file_event(&format!("/tmp/bench_{i}.txt"), FileAction::Create),
            2 => make_network_event("93.184.216.34", 443),
            _ => make_auth_event("testuser", AuthAction::Login, "10.0.0.1"),
        })
        .collect();

    let start = Instant::now();
    let mut total_alerts = 0usize;
    for event in &events {
        total_alerts += engine.process_event(event).len();
    }
    let elapsed = start.elapsed();

    let events_per_sec = events.len() as f64 / elapsed.as_secs_f64();

    eprintln!("=== Detection Engine Throughput ===");
    eprintln!("Events processed: {}", events.len());
    eprintln!("Alerts generated: {total_alerts}");
    eprintln!("Time: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    eprintln!("Throughput: {events_per_sec:.0} events/sec");

    assert!(events_per_sec > 1000.0, "Detection engine should process >1000 events/sec, got {events_per_sec:.0}");
}

#[test]
fn benchmark_mixed_attack_workload() {
    let rules = default_ruleset();
    let mut engine = DetectionEngine::new(rules);

    let mut events = Vec::new();
    // Mix of benign + attack events
    for i in 0..5000 {
        // Mostly benign
        events.push(make_process_event("nginx", 2000 + i as u32));
        events.push(make_file_event(&format!("/var/log/app_{i}.log"), FileAction::Modify));
        events.push(make_network_event("10.0.0.1", 80));

        // Occasional attack patterns
        if i % 100 == 0 {
            // Brute force burst
            for _ in 0..6 {
                events.push(make_auth_event("root", AuthAction::Failed, "10.0.0.50"));
            }
        }
        if i % 200 == 0 {
            // Suspicious process
            events.push(make_process_event("ncat", 9000 + i as u32));
        }
        if i % 300 == 0 {
            // File tampering
            events.push(make_file_event("/etc/shadow", FileAction::Modify));
        }
    }

    let start = Instant::now();
    let mut total_alerts = 0usize;
    for event in &events {
        total_alerts += engine.process_event(event).len();
    }
    let elapsed = start.elapsed();

    eprintln!("=== Mixed Attack Workload ===");
    eprintln!("Events: {} | Alerts: {total_alerts} | Time: {:.2}ms",
        events.len(), elapsed.as_secs_f64() * 1000.0);
    eprintln!("False positive rate: {:.4}%",
        (total_alerts as f64 / events.len() as f64) * 100.0);

    assert!(total_alerts > 0, "Should detect some attacks");
}

#[test]
fn benchmark_sqlite_storage_throughput() {
    let store = SqliteStore::open_in_memory().expect("open in-memory store");

    let events: Vec<NormalizedEvent> = (0..1000)
        .map(|i| make_process_event(&format!("proc_{i}"), 1000 + i as u32))
        .collect();

    let start = Instant::now();
    for event in &events {
        store.insert_event(event).expect("insert event");
    }
    let insert_elapsed = start.elapsed();

    let start = Instant::now();
    let fetched = store.get_events(1000).expect("fetch events");
    let query_elapsed = start.elapsed();

    eprintln!("=== SQLite Storage Throughput ===");
    eprintln!("Insert: {} events in {:.2}ms ({:.0} ops/sec)",
        events.len(),
        insert_elapsed.as_secs_f64() * 1000.0,
        events.len() as f64 / insert_elapsed.as_secs_f64());
    eprintln!("Query: {} events in {:.2}ms",
        fetched.len(),
        query_elapsed.as_secs_f64() * 1000.0);

    assert_eq!(fetched.len(), 1000);
}

#[test]
fn benchmark_ransomware_detection_latency() {
    let rules = default_ruleset();
    let mut engine = DetectionEngine::new(rules);

    let events: Vec<NormalizedEvent> = (0..100)
        .map(|i| {
            NormalizedEvent::new("bench-ep".into(), OsType::Linux, EventType::File, Severity::Info)
                .with_file(FileContext {
                    path: format!("/home/user/docs/file_{i}.txt.encrypted"),
                    action: FileAction::Rename,
                    sha256: Some("a".repeat(64)),
                    size_bytes: Some(4096),
                    owner_uid: Some(1000),
                    permissions: Some("0644".into()),
                })
        })
        .collect();

    let start = Instant::now();
    let mut alerts = 0usize;
    for event in &events {
        alerts += engine.process_event(event).len();
    }
    let elapsed = start.elapsed();

    eprintln!("=== Ransomware Detection Latency ===");
    eprintln!("Events: {} | Alerts: {alerts} | Time: {:.2}ms",
        events.len(), elapsed.as_secs_f64() * 1000.0);
    eprintln!("Per-event: {:.3}us", elapsed.as_micros() as f64 / events.len() as f64);
}

#[test]
fn benchmark_hunting_query_performance() {
    use os_defender_core::advanced::hunting::{HuntingEngine, HuntQuery};

    let store = SqliteStore::open_in_memory().expect("open store");

    // Insert diverse events
    for i in 0..500 {
        let event = match i % 4 {
            0 => make_process_event(&format!("proc_{}", i % 10), 1000 + i as u32),
            1 => make_file_event(&format!("/var/log/file_{i}.log"), FileAction::Modify),
            2 => make_network_event(&format!("10.0.0.{}", i % 255), 443),
            _ => make_auth_event(&format!("user_{}", i % 5), AuthAction::Login, "10.0.0.1"),
        };
        store.insert_event(&event).expect("insert");
    }

    let query = HuntQuery::new()
        .with_event_type("process")
        .with_limit(50);

    let start = Instant::now();
    let result = HuntingEngine::execute(&store, &query).expect("hunt");
    let elapsed = start.elapsed();

    eprintln!("=== Hunting Query Performance ===");
    eprintln!("Results: {} / {} total | Time: {:.2}ms",
        result.events.len(), result.total_matches,
        elapsed.as_secs_f64() * 1000.0);

    assert!(result.events.len() <= 50);
}
