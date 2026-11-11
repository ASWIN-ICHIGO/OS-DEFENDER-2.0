use anyhow::Result;
use clap::Parser;
use os_defender_core::{
    detection::{Alert, DetectionEngine, default_ruleset},
    events::NormalizedEvent,
    health::BlindSpotDetector,
    ipc,
    platform::{ProcessCollector, FileCollector, NetworkCollector, AuthCollector},
    response::{AuditLog, PolicyEngine, PolicyMode, PolicyDecision},
    storage::SqliteStore,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[cfg(target_os = "windows")]
mod service;

#[derive(Parser)]
#[command(name = "os-defender-agent", version, about = "OS-DEFENDER protection agent")]
struct Args {
    #[arg(long, default_value = "~/.local/share/os-defender/os-defender.db")]
    db_path: String,

    #[arg(long, default_value_t = 2000)]
    poll_interval_ms: u64,

    #[arg(long, default_value_t = 60)]
    heartbeat_timeout_secs: i64,

    #[arg(long, default_value = "/etc,/home")]
    watch_dirs: String,

    #[arg(long, default_value = "dry_run")]
    policy_mode: String,

    #[arg(long, default_value = "~/.local/share/os-defender/quarantine")]
    quarantine_dir: String,

    /// Run as a Windows service (SCM-managed lifecycle)
    #[arg(long)]
    service: bool,
}

struct AgentState {
    store: SqliteStore,
    engine: DetectionEngine,
    health: BlindSpotDetector,
    policy: PolicyEngine,
    audit: AuditLog,
    ai: os_defender_core::advanced::ai_bridge::AiBridge,
    events_processed: u64,
    alerts_generated: u64,
    actions_taken: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    #[cfg(target_os = "windows")]
    if args.service {
        info!("starting as Windows service");
        service::run_as_service().map_err(|e| anyhow::anyhow!("service dispatch failed: {e}"))?;
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_foreground(args))
}

async fn run_foreground(args: Args) -> Result<()> {
    let state = init_agent(&args)?;

    info!(version = env!("CARGO_PKG_VERSION"), "OS-DEFENDER agent starting");

    let shutdown = tokio::signal::ctrl_c();

    let collector_handle = spawn_collectors(&args, Arc::clone(&state));

    let ipc_handle = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = run_ipc_server(state).await {
                error!(%e, "IPC server error");
            }
        })
    };

    info!("agent running — press Ctrl+C to stop");
    shutdown.await?;
    info!("shutdown signal received");

    collector_handle.abort();
    ipc_handle.abort();

    info!("OS-DEFENDER agent stopped");
    Ok(())
}

/// Core agent loop used by both foreground mode and Windows service.
pub async fn run_agent_core() -> Result<()> {
    let args = Args::parse();
    let state = init_agent(&args)?;

    info!(version = env!("CARGO_PKG_VERSION"), "OS-DEFENDER agent starting (service mode)");

    let collector_handle = spawn_collectors(&args, Arc::clone(&state));

    let ipc_handle = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = run_ipc_server(state).await {
                error!(%e, "IPC server error");
            }
        })
    };

    info!("agent running in service mode");

    // In service mode, run until cancelled externally (via tokio::select in service.rs)
    tokio::signal::ctrl_c().await.ok();

    collector_handle.abort();
    ipc_handle.abort();

    info!("OS-DEFENDER agent stopped");
    Ok(())
}

fn init_agent(args: &Args) -> Result<Arc<Mutex<AgentState>>> {
    let db_path = expand_tilde(&args.db_path);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = SqliteStore::open(&db_path)?;
    let rules = default_ruleset();
    let engine = DetectionEngine::new(rules);
    let health = BlindSpotDetector::new(args.heartbeat_timeout_secs);

    let policy_mode = match args.policy_mode.as_str() {
        "execute" => PolicyMode::Execute,
        "approve" => PolicyMode::Approve,
        _ => PolicyMode::DryRun,
    };
    let policy = PolicyEngine::new(policy_mode);
    let audit = AuditLog::recover_chain(&store.connection());

    let ai_model_dir = db_path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let ai = os_defender_core::advanced::ai_bridge::AiBridge::new(&ai_model_dir);

    if ai.start_sidecar() {
        info!("AI sidecar scoring enabled");
    } else {
        info!("AI sidecar not available — rule-based detection only");
    }

    info!(rules = engine.rule_count(), "detection rules loaded");
    info!(mode = %args.policy_mode, "policy engine initialized");
    info!(db = %db_path.display(), "database opened");

    let _quarantine_dir = expand_tilde(&args.quarantine_dir);

    Ok(Arc::new(Mutex::new(AgentState {
        store,
        engine,
        health,
        policy,
        audit,
        ai,
        events_processed: 0,
        alerts_generated: 0,
        actions_taken: 0,
    })))
}

fn spawn_collectors(args: &Args, state: Arc<Mutex<AgentState>>) -> tokio::task::JoinHandle<()> {
    #[cfg(target_os = "linux")]
    {
        let interval_ms = args.poll_interval_ms;
        let watch_dirs = args.watch_dirs.clone();
        tokio::spawn(async move {
            run_linux_collectors(state, interval_ms, &watch_dirs).await;
        })
    }

    #[cfg(target_os = "windows")]
    {
        let interval_ms = args.poll_interval_ms;
        let watch_dirs = args.watch_dirs.clone();
        tokio::spawn(async move {
            run_windows_collectors(state, interval_ms, &watch_dirs).await;
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = args;
        let _ = state;
        tokio::spawn(async {
            warn!("no platform collectors available for this OS");
        })
    }
}

#[cfg(target_os = "linux")]
async fn run_linux_collectors(state: Arc<Mutex<AgentState>>, interval_ms: u64, watch_dirs: &str) {
    use os_defender_core::platform::linux::{
        LinuxProcessCollector, LinuxFileCollector, LinuxNetworkCollector, LinuxAuthCollector,
        ProcessTree,
    };

    let endpoint_id = os_defender_core::platform::linux::SystemInfo::machine_id()
        .unwrap_or_else(|_| "unknown".into());

    let mut process_collector = LinuxProcessCollector::new(endpoint_id.clone());
    let mut network_collector = LinuxNetworkCollector::new(endpoint_id.clone());
    let mut auth_collector = LinuxAuthCollector::new(endpoint_id.clone());

    let mut file_collector = match LinuxFileCollector::new(endpoint_id.clone()) {
        Ok(mut fc) => {
            for dir in watch_dirs.split(',') {
                let path = std::path::Path::new(dir.trim());
                if path.is_dir() {
                    match fc.watch_path(path) {
                        Ok(()) => info!(dir = %path.display(), "watching directory"),
                        Err(e) => warn!(dir = %path.display(), %e, "cannot watch directory"),
                    }
                }
            }
            Some(fc)
        }
        Err(e) => {
            warn!(%e, "file collector unavailable");
            None
        }
    };

    let mut proc_tree = ProcessTree::new();
    proc_tree.refresh();
    info!(processes = proc_tree.len(), "initial process tree built");

    let mut tick: u64 = 0;
    let collectors_active = vec![
        "linux-process".to_string(),
        "linux-network".to_string(),
        "linux-auth".to_string(),
        if file_collector.is_some() { "linux-file".to_string() } else { "linux-file (unavailable)".to_string() },
    ];

    info!(collectors = ?collectors_active, "all collectors started");

    loop {
        tick += 1;

        match process_collector.poll_processes().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-process", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "process", %e, "poll error"),
        }

        match network_collector.poll_connections().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-network", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "network", %e, "poll error"),
        }

        match auth_collector.poll_auth_events().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-auth", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "auth", %e, "poll error"),
        }

        if let Some(ref mut fc) = file_collector {
            match fc.poll_file_events().await {
                Ok(events) => {
                    let mut s = state.lock().await;
                    let ep = s.events_processed;
                    s.health.record_heartbeat("linux-file", ep, 0);
                    ingest_events(&mut s, events);
                }
                Err(e) => warn!(collector = "file", %e, "poll error"),
            }
        }

        if tick.is_multiple_of(15) {
            proc_tree.refresh();
        }

        if tick.is_multiple_of(30) {
            let mut s = state.lock().await;
            let assessment = s.health.assess();
            if !assessment.overall_healthy {
                for spot in &assessment.blind_spots {
                    warn!(blind_spot = %spot, "visibility gap");
                }
            }
            info!(
                events = s.events_processed,
                alerts = s.alerts_generated,
                actions = s.actions_taken,
                healthy = assessment.overall_healthy,
                "periodic health check"
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

#[cfg(target_os = "windows")]
async fn run_windows_collectors(state: Arc<Mutex<AgentState>>, interval_ms: u64, watch_dirs: &str) {
    use os_defender_core::platform::windows::{
        WindowsProcessCollector, WindowsFileCollector,
        WindowsNetworkCollector, WindowsAuthCollector,
        WindowsSystemInfo,
    };

    let endpoint_id = WindowsSystemInfo::machine_id()
        .unwrap_or_else(|_| "unknown-win".into());

    let mut process_collector = WindowsProcessCollector::new(endpoint_id.clone());
    let mut network_collector = WindowsNetworkCollector::new(endpoint_id.clone());
    let mut auth_collector = WindowsAuthCollector::new(endpoint_id.clone());

    let mut file_collector = match WindowsFileCollector::new(endpoint_id.clone()) {
        Ok(mut fc) => {
            for dir in watch_dirs.split(',') {
                let trimmed = dir.trim();
                if std::path::Path::new(trimmed).is_dir() {
                    match fc.watch_path(std::path::Path::new(trimmed)) {
                        Ok(()) => info!(dir = %trimmed, "watching directory"),
                        Err(e) => warn!(dir = %trimmed, %e, "cannot watch directory"),
                    }
                }
            }
            Some(fc)
        }
        Err(e) => {
            warn!(%e, "file collector unavailable");
            None
        }
    };

    info!("all Windows collectors started");

    let mut tick: u64 = 0;
    loop {
        tick += 1;

        match process_collector.poll_processes().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("windows-process", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "process", %e, "poll error"),
        }

        match network_collector.poll_connections().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("windows-network", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "network", %e, "poll error"),
        }

        match auth_collector.poll_auth_events().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("windows-auth", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "auth", %e, "poll error"),
        }

        if let Some(ref mut fc) = file_collector {
            match fc.poll_file_events().await {
                Ok(events) => {
                    let mut s = state.lock().await;
                    let ep = s.events_processed;
                    s.health.record_heartbeat("windows-file", ep, 0);
                    ingest_events(&mut s, events);
                }
                Err(e) => warn!(collector = "file", %e, "poll error"),
            }
        }

        if tick.is_multiple_of(30) {
            let mut s = state.lock().await;
            let assessment = s.health.assess();
            if !assessment.overall_healthy {
                for spot in &assessment.blind_spots {
                    warn!(blind_spot = %spot, "visibility gap");
                }
            }
            info!(
                events = s.events_processed,
                alerts = s.alerts_generated,
                actions = s.actions_taken,
                healthy = assessment.overall_healthy,
                "periodic health check"
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

fn ingest_events(state: &mut AgentState, events: Vec<NormalizedEvent>) {
    for event in &events {
        let alerts = state.engine.process_event(event);
        if let Err(e) = state.store.insert_event(event) {
            error!(%e, "failed to store event");
        }
        state.events_processed += 1;

        for alert in &alerts {
            log_alert(alert);
            if let Err(e) = state.store.insert_alert(alert) {
                error!(%e, "failed to store alert");
            }
            state.alerts_generated += 1;
            process_response(state, alert);
        }
    }

    if !events.is_empty()
        && state.ai.sidecar_running()
        && let Some(result) = state.ai.score_events(&events)
        && result.is_anomaly
    {
        let summary = result
            .explanation
            .as_ref()
            .map(|e| e.summary.clone())
            .unwrap_or_else(|| format!("AI anomaly score: {:.3}", result.score));

        let factors: Vec<_> = result
            .explanation
            .as_ref()
            .map(|e| {
                e.top_contributors
                    .iter()
                    .map(|c| os_defender_core::detection::Factor {
                        name: c.feature.clone(),
                        weight: c.contribution_pct / 100.0,
                        description: format!(
                            "{:.1}σ from baseline (value={:.2}, expected={:.2})",
                            c.z_score, c.value, c.baseline_mean
                        ),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let representative_event = &events[0];
        let confidence = (1.0 - result.score.abs().min(1.0)).max(0.5);
        let mut alert = Alert::from_anomaly(
            representative_event.event_id,
            os_defender_core::events::Severity::Medium,
            "AI Anomaly Detected".into(),
            summary,
            confidence,
        );
        alert.factors = factors;
        alert.mitre_techniques = vec!["TA0001".into()];

        log_alert(&alert);
        if let Err(e) = state.store.insert_alert(&alert) {
            error!(%e, "failed to store AI alert");
        }
        state.alerts_generated += 1;
        process_response(state, &alert);
    }
}

fn process_response(state: &mut AgentState, alert: &Alert) {
    let suggested = state.policy.suggest_actions(alert);
    for action in suggested {
        let result = state.policy.evaluate(action, alert.severity);

        let decision_str = result.decision.to_string();
        let action_str = result.action.kind.to_string();
        let target = result.action.target.clone();

        if let Err(e) = state.audit.record(
            &state.store.connection(),
            &result.action,
            result.decision,
            "agent",
        ) {
            error!(%e, "failed to write audit log");
        }

        match result.decision {
            PolicyDecision::Execute => {
                info!(
                    action = %action_str,
                    target = %target,
                    decision = %decision_str,
                    "response action EXECUTED"
                );
                state.actions_taken += 1;
            }
            PolicyDecision::DryRun => {
                info!(
                    action = %action_str,
                    target = %target,
                    decision = %decision_str,
                    "response action DRY-RUN"
                );
                state.actions_taken += 1;
            }
            PolicyDecision::PendingApproval => {
                info!(
                    action = %action_str,
                    target = %target,
                    "response action PENDING approval"
                );
            }
            PolicyDecision::Denied => {
                warn!(
                    action = %action_str,
                    target = %target,
                    "response action DENIED"
                );
            }
        }
    }
}

fn log_alert(alert: &Alert) {
    let factors: Vec<String> = alert
        .factors
        .iter()
        .map(|f| format!("{}={:.1}", f.name, f.weight))
        .collect();
    let mitre = alert.mitre_techniques.join(",");

    info!(
        alert_id = %alert.alert_id,
        severity = %alert.severity,
        confidence = alert.confidence,
        rule = alert.rule_id.as_deref().unwrap_or("-"),
        mitre = %mitre,
        factors = %factors.join("; "),
        title = %alert.title,
        "ALERT"
    );
}

async fn run_ipc_server(state: Arc<Mutex<AgentState>>) -> Result<()> {
        #[cfg(target_os = "windows")]     let mut listener = ipc::IpcListener::bind_default().await?;     #[cfg(not(target_os = "windows"))]     let listener = ipc::IpcListener::bind_default().await?;

    loop {
        let stream = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            if let Err(e) = handle_ipc_client(stream, state).await {
                error!(%e, "IPC client error");
            }
        });
    }
}

async fn handle_ipc_client(
    stream: ipc::IpcStream,
    state: Arc<Mutex<AgentState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let request: ipc::IpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ipc::IpcResponse::Error {
                    message: format!("invalid request: {e}"),
                };
                let mut json = serde_json::to_string(&resp)?;
                json.push('\n');
                writer.write_all(json.as_bytes()).await?;
                continue;
            }
        };

        let response = match request {
            ipc::IpcRequest::Status => {
                let s = state.lock().await;
                let collectors = if cfg!(target_os = "linux") {
                    vec![
                        "linux-process".into(),
                        "linux-network".into(),
                        "linux-auth".into(),
                        "linux-file".into(),
                    ]
                } else if cfg!(target_os = "windows") {
                    vec![
                        "windows-process".into(),
                        "windows-network".into(),
                        "windows-auth".into(),
                        "windows-file".into(),
                    ]
                } else {
                    vec![]
                };
                ipc::IpcResponse::Status(ipc::AgentStatus {
                    running: true,
                    uptime_secs: 0,
                    events_processed: s.events_processed,
                    alerts_generated: s.alerts_generated,
                    actions_taken: s.actions_taken,
                    policy_mode: format!("{:?}", s.policy.mode()),
                    collectors_active: collectors,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                })
            }
            ipc::IpcRequest::GetEvents { limit } => {
                let s = state.lock().await;
                match s.store.get_events(limit) {
                    Ok(events) => ipc::IpcResponse::Events(events),
                    Err(e) => ipc::IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ipc::IpcRequest::GetAlerts { limit } => {
                let s = state.lock().await;
                match s.store.get_alerts(limit) {
                    Ok(alerts) => ipc::IpcResponse::Alerts(alerts),
                    Err(e) => ipc::IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ipc::IpcRequest::GetHealth => {
                let mut s = state.lock().await;
                let assessment = s.health.assess();
                ipc::IpcResponse::Health(assessment)
            }
            ipc::IpcRequest::GetAuditLog { limit } => {
                let s = state.lock().await;
                match AuditLog::get_recent(&s.store.connection(), limit) {
                    Ok(entries) => ipc::IpcResponse::AuditLog(entries),
                    Err(e) => ipc::IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ipc::IpcRequest::GetPolicyMode => {
                let s = state.lock().await;
                ipc::IpcResponse::PolicyMode(s.policy.mode())
            }
            ipc::IpcRequest::SetPolicyMode { mode } => {
                let mut s = state.lock().await;
                s.policy.set_mode(mode);
                info!(mode = ?mode, "policy mode changed via IPC");
                ipc::IpcResponse::Ok
            }
            ipc::IpcRequest::VerifyAuditChain => {
                let s = state.lock().await;
                match AuditLog::verify_chain(&s.store.connection()) {
                    Ok((valid, entries)) => {
                        ipc::IpcResponse::AuditChainStatus { valid, entries }
                    }
                    Err(e) => ipc::IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ipc::IpcRequest::GetAiStatus => {
                let s = state.lock().await;
                ipc::IpcResponse::AiStatus(s.ai.status())
            }
            ipc::IpcRequest::ThreatHunt { ref query } => {
                let s = state.lock().await;
                match os_defender_core::advanced::hunting::HuntingEngine::execute(&s.store, query) {
                    Ok(result) => ipc::IpcResponse::HuntResults(Box::new(result)),
                    Err(e) => ipc::IpcResponse::Error { message: e.to_string() },
                }
            }
            ipc::IpcRequest::GetPosture => {
                let report = os_defender_core::advanced::posture::PostureAssessor::new("local").assess();
                ipc::IpcResponse::PostureReport(Box::new(report))
            }
            ipc::IpcRequest::GetPersistence => {
                #[cfg(target_os = "linux")]
                {
                    let scanner = os_defender_core::advanced::persistence::LinuxPersistenceScanner::new();
                    let entries = scanner.scan();
                    ipc::IpcResponse::PersistenceEntries(entries)
                }
                #[cfg(target_os = "windows")]
                {
                    let scanner = os_defender_core::advanced::persistence::WindowsPersistenceScanner::new();
                    let entries = scanner.scan();
                    ipc::IpcResponse::PersistenceEntries(entries)
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    ipc::IpcResponse::PersistenceEntries(vec![])
                }
            }
            ipc::IpcRequest::VerifyIntegrity => {
                let tp = os_defender_core::advanced::tamper::TamperProtection::new(env!("CARGO_PKG_VERSION"));
                let result = tp.verify();
                ipc::IpcResponse::IntegrityStatus(Box::new(result))
            }
            ipc::IpcRequest::ScoreEvents { events } => {
                let mut s = state.lock().await;
                let result = s.ai.score_events(&events);
                ipc::IpcResponse::AiScore(result)
            }
            ipc::IpcRequest::CheckUpdate => {
                let checker = os_defender_core::update::UpdateChecker::new(
                    env!("CARGO_PKG_VERSION"),
                    os_defender_core::update::UpdateConfig::default(),
                );
                ipc::IpcResponse::UpdateInfo(checker.no_update_info())
            }
            ipc::IpcRequest::Shutdown => {
                info!("shutdown requested via IPC");
                ipc::IpcResponse::Ok
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    #[cfg(target_os = "windows")]
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("USERPROFILE")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}
