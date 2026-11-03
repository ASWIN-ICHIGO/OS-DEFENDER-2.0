use os_defender_core::detection::Alert;
use os_defender_core::events::Severity;
use os_defender_core::response::{
    AuditLog, PolicyEngine, PolicyMode, PolicyDecision,
    ResponseAction, ResponseActionKind,
};
use os_defender_core::response::enforce::{Enforcer, EnforcementResult};
use uuid::Uuid;

// --- Policy engine is already cross-platform; verify parity ---

#[test]
fn policy_engine_suggests_block_ip_for_brute_force() {
    let alert = Alert::from_rule(
        Uuid::new_v4(),
        "R001",
        Severity::High,
        "Brute-force attack".into(),
        "5 failed logins from 10.0.0.99 for user admin".into(),
        0.9,
    )
    .with_mitre("T1110");

    let engine = PolicyEngine::new(PolicyMode::Execute);
    let actions = engine.suggest_actions(&alert);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, ResponseActionKind::BlockIp);
    assert_eq!(actions[0].target, "10.0.0.99");
}

#[test]
fn policy_engine_suggests_freeze_for_suspicious_process() {
    let alert = Alert::from_rule(
        Uuid::new_v4(),
        "R002",
        Severity::High,
        "Reverse shell detected".into(),
        "Process 'nc' (PID 9876) opened reverse shell".into(),
        0.95,
    )
    .with_mitre("T1059.004");

    let engine = PolicyEngine::default();
    let actions = engine.suggest_actions(&alert);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, ResponseActionKind::FreezeProcess);
    assert_eq!(actions[0].target, "9876");
}

#[test]
fn policy_engine_suggests_quarantine_for_file_tampering() {
    let alert = Alert::from_rule(
        Uuid::new_v4(),
        "R003",
        Severity::Critical,
        "Sensitive file modified".into(),
        "File '/etc/shadow' was modified by unknown process".into(),
        0.85,
    )
    .with_mitre("T1565.001");

    let engine = PolicyEngine::default();
    let actions = engine.suggest_actions(&alert);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, ResponseActionKind::QuarantineFile);
    assert_eq!(actions[0].target, "/etc/shadow");
}

#[test]
fn dry_run_mode_never_executes() {
    let engine = PolicyEngine::new(PolicyMode::DryRun);
    let action = ResponseAction::new(
        Uuid::new_v4(),
        ResponseActionKind::BlockIp,
        "1.2.3.4".into(),
        "test".into(),
    );
    let result = engine.evaluate(action, Severity::Critical);
    assert_eq!(result.decision, PolicyDecision::DryRun);
}

#[test]
fn execute_mode_always_runs() {
    let engine = PolicyEngine::new(PolicyMode::Execute);
    let action = ResponseAction::new(
        Uuid::new_v4(),
        ResponseActionKind::FreezeProcess,
        "123".into(),
        "test".into(),
    );
    let result = engine.evaluate(action, Severity::Low);
    assert_eq!(result.decision, PolicyDecision::Execute);
}

#[test]
fn approve_mode_auto_executes_critical_only() {
    let engine = PolicyEngine::new(PolicyMode::Approve);

    let critical_action = ResponseAction::new(
        Uuid::new_v4(),
        ResponseActionKind::BlockIp,
        "1.2.3.4".into(),
        "test".into(),
    );
    let result = engine.evaluate(critical_action, Severity::Critical);
    assert_eq!(result.decision, PolicyDecision::Execute);

    let low_action = ResponseAction::new(
        Uuid::new_v4(),
        ResponseActionKind::BlockIp,
        "5.6.7.8".into(),
        "test".into(),
    );
    let result = engine.evaluate(low_action, Severity::Low);
    assert_eq!(result.decision, PolicyDecision::PendingApproval);
}

// --- Audit log is cross-platform ---

#[test]
fn audit_log_records_and_verifies() {
    let store = os_defender_core::storage::SqliteStore::open_in_memory().unwrap();
    let mut audit = AuditLog::new();

    let action = ResponseAction::new(
        Uuid::new_v4(),
        ResponseActionKind::BlockIp,
        "10.0.0.1".into(),
        "brute-force".into(),
    );
    audit
        .record(&store.connection(), &action, PolicyDecision::Execute, "agent")
        .unwrap();

    let (valid, count) = AuditLog::verify_chain(&store.connection()).unwrap();
    assert!(valid);
    assert_eq!(count, 1);
}

#[test]
fn audit_chain_detects_tampering() {
    let store = os_defender_core::storage::SqliteStore::open_in_memory().unwrap();
    let mut audit = AuditLog::new();

    for i in 0..3 {
        let action = ResponseAction::new(
            Uuid::new_v4(),
            ResponseActionKind::BlockIp,
            format!("10.0.0.{i}"),
            "test".into(),
        );
        audit
            .record(&store.connection(), &action, PolicyDecision::DryRun, "agent")
            .unwrap();
    }

    // Tamper with an entry
    let conn = store.connection();
    conn.execute(
        "UPDATE audit_log SET reason = 'tampered' WHERE rowid = 2",
        [],
    )
    .unwrap();

    let (valid, _) = AuditLog::verify_chain(&conn).unwrap();
    assert!(!valid, "tampered chain should fail verification");
}

// --- Linux-specific enforcer dry-run tests (always available) ---

#[test]
fn nftables_dry_run_block_and_rollback() {
    use os_defender_core::response::enforce::nftables::NftablesEnforcer;

    let enforcer = NftablesEnforcer::new(true);
    let result = enforcer.execute("192.168.1.100", "cross-platform test").unwrap();
    assert!(result.success);
    assert!(result.detail.contains("DRY-RUN"));

    let token = result.rollback_token.unwrap();
    let rollback = enforcer.rollback(&token).unwrap();
    assert!(rollback.success);
}

#[test]
fn cgroup_dry_run_freeze_and_thaw() {
    use os_defender_core::response::enforce::cgroup::CgroupContainment;

    let enforcer = CgroupContainment::new(true);
    let result = enforcer.execute("5555", "cross-platform test").unwrap();
    assert!(result.success);
    assert!(result.detail.contains("DRY-RUN"));

    let token = result.rollback_token.unwrap();
    let rollback = enforcer.rollback(&token).unwrap();
    assert!(rollback.success);
}

#[test]
fn quarantine_dry_run_cycle() {
    use os_defender_core::response::enforce::quarantine::FileQuarantine;
    use std::path::PathBuf;

    let enforcer = FileQuarantine::new(PathBuf::from("/tmp/test-q"), true);
    let result = enforcer.execute("/tmp/suspicious.bin", "test").unwrap();
    assert!(result.success);
    assert!(result.detail.contains("DRY-RUN"));

    let token = result.rollback_token.unwrap();
    let rollback = enforcer.rollback(&token).unwrap();
    assert!(rollback.success);
}

#[test]
fn quarantine_real_file_roundtrip() {
    use os_defender_core::response::enforce::quarantine::FileQuarantine;
    use tempfile::TempDir;
    use std::fs;

    let source_dir = TempDir::new().unwrap();
    let quarantine_dir = TempDir::new().unwrap();
    let enforcer = FileQuarantine::new(quarantine_dir.path().to_path_buf(), false);

    let file = source_dir.path().join("important.dat");
    fs::write(&file, "critical data 12345").unwrap();

    let path_str = file.to_str().unwrap();
    let result = enforcer.execute(path_str, "cross-platform test").unwrap();
    assert!(result.success);
    assert!(!file.exists());

    let token = result.rollback_token.unwrap();
    let restore = enforcer.rollback(&token).unwrap();
    assert!(restore.success);
    assert!(file.exists());
    assert_eq!(fs::read_to_string(&file).unwrap(), "critical data 12345");
}

// --- Enforcement result helper tests ---

#[test]
fn enforcement_result_constructors() {
    let ok = EnforcementResult::ok("blocked", "token-1");
    assert!(ok.success);
    assert_eq!(ok.rollback_token, Some("token-1".to_string()));

    let ok_nr = EnforcementResult::ok_no_rollback("done");
    assert!(ok_nr.success);
    assert!(ok_nr.rollback_token.is_none());

    let fail = EnforcementResult::fail("error");
    assert!(!fail.success);
    assert!(fail.rollback_token.is_none());
}
