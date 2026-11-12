use anyhow::Result;
use clap::Parser;
use os_defender_core::{
    detection::{Alert, DetectionEngine, default_ruleset},
    events::NormalizedEvent,
    health::BlindSpotDetector,
    ipc,
    platform::{ProcessCollector, FileCollector, NetworkCollector, AuthCollector},
    response::{
        AuditLog, PolicyEngine, PolicyMode, PolicyDecision, ResponseAction, ResponseActionKind,
        enforce::{EnforcementResult, Enforcer, quarantine::FileQuarantine},
    },
    storage::SqliteStore,
};
#[cfg(target_os = "linux")]
use os_defender_core::response::enforce::nftables::NftablesEnforcer;
#[cfg(target_os = "windows")]
use os_defender_core::response::enforce::{job_object::JobObjectEnforcer, wfp::WfpEnforcer};
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

    #[arg(long, default_value = "approve")]
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
    dispatcher: ResponseDispatcher,
    ai: os_defender_core::advanced::ai_bridge::AiBridge,
    events_processed: u64,
    alerts_generated: u64,
    actions_taken: u64,
}

/// Executes response actions for real: kills/freezes processes, quarantines
/// files, and blocks attacker IPs via the platform firewall.
struct ResponseDispatcher {
    quarantine: FileQuarantine,
}

impl ResponseDispatcher {
    fn new(quarantine_dir: PathBuf, dry_run: bool) -> Self {
        Self {
            quarantine: FileQuarantine::new(quarantine_dir, dry_run),
        }
    }

    fn execute(&self, action: &ResponseAction) -> EnforcementResult {
        match action.kind {
            ResponseActionKind::KillProcess => self.kill_process(&action.target),
            ResponseActionKind::FreezeProcess => self.freeze_process(&action.target),
            ResponseActionKind::QuarantineFile => {
                if let Err(e) = self.quarantine.ensure_dir() {
                    return EnforcementResult::fail(format!("quarantine dir unavailable: {e}"));
                }
                match self.quarantine.execute(&action.target, &action.reason) {
                    Ok(r) => r,
                    Err(e) => EnforcementResult::fail(format!("quarantine failed: {e}")),
                }
            }
            ResponseActionKind::BlockIp => self.block_ip(&action.target),
            ResponseActionKind::UnblockIp | ResponseActionKind::ThawProcess => {
                EnforcementResult::ok_no_rollback(format!(
                    "rollback action {} recorded (manual restoration required)",
                    action.kind
                ))
            }
            ResponseActionKind::RestoreFile => {
                match self.quarantine.rollback(&action.target) {
                    Ok(r) => r,
                    Err(e) => EnforcementResult::fail(format!("restore failed: {e}")),
                }
            }
        }
    }

    fn kill_process(&self, target: &str) -> EnforcementResult {
        let pid: u32 = match target.parse() {
            Ok(p) => p,
            Err(_) => return EnforcementResult::fail(format!("invalid PID: {target}")),
        };
        if pid <= 4 {
            return EnforcementResult::fail(format!(
                "refusing to kill PID {pid} (system-critical)"
            ));
        }

        #[cfg(target_os = "windows")]
        {
            match std::process::Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .output()
            {
                Ok(o) if o.status.success() => {
                    EnforcementResult::ok_no_rollback(format!("killed PID {pid} (taskkill /F /T)"))
                }
                Ok(o) => EnforcementResult::fail(format!(
                    "taskkill failed for PID {pid}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => EnforcementResult::fail(format!("taskkill spawn failed: {e}")),
            }
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
                Ok(()) => EnforcementResult::ok_no_rollback(format!("killed PID {pid} (SIGKILL)")),
                Err(e) => EnforcementResult::fail(format!("kill failed for PID {pid}: {e}")),
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = pid;
            EnforcementResult::fail("process kill unsupported on this platform".into())
        }
    }

    fn freeze_process(&self, target: &str) -> EnforcementResult {
        #[cfg(target_os = "windows")]
        {
            match JobObjectEnforcer::new(false).execute(target, "freeze suspicious process") {
                Ok(r) => r,
                Err(e) => EnforcementResult::fail(format!("freeze failed: {e}")),
            }
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            let pid: u32 = match target.parse() {
                Ok(p) => p,
                Err(_) => return EnforcementResult::fail(format!("invalid PID: {target}")),
            };
            if pid <= 4 {
                return EnforcementResult::fail(format!(
                    "refusing to freeze PID {pid} (system-critical)"
                ));
            }
            match kill(Pid::from_raw(pid as i32), Signal::SIGSTOP) {
                Ok(()) => {
                    EnforcementResult::ok(format!("froze PID {pid} (SIGSTOP)"), format!("thaw:{pid}"))
                }
                Err(e) => EnforcementResult::fail(format!("freeze failed for PID {pid}: {e}")),
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = target;
            EnforcementResult::fail("process freeze unsupported on this platform".into())
        }
    }

    fn block_ip(&self, target: &str) -> EnforcementResult {
        #[cfg(target_os = "windows")]
        {
            match WfpEnforcer::new(false).execute(target, "block attacker IP") {
                Ok(r) => r,
                Err(e) => EnforcementResult::fail(format!("firewall block failed: {e}")),
            }
        }

        #[cfg(target_os = "linux")]
        {
            match NftablesEnforcer::new(false).execute(target, "block attacker IP") {
                Ok(r) => r,
                Err(e) => EnforcementResult::fail(format!("firewall block failed: {e}")),
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = target;
            EnforcementResult::fail("firewall block unsupported on this platform".into())
        }
    }
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
    let dispatcher =
        ResponseDispatcher::new(expand_tilde(&args.quarantine_dir), policy_mode == PolicyMode::DryRun);

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

    Ok(Arc::new(Mutex::new(AgentState {
        store,
        engine,
        health,
        policy,
        audit,
        dispatcher,
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
            let tick_alerts = s.engine.tick();
            for alert in tick_alerts {
                handle_alert(&mut s, &alert);
            }
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
            let tick_alerts = s.engine.tick();
            for alert in tick_alerts {
                handle_alert(&mut s, &alert);
            }
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
            handle_alert(state, alert);
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

        handle_alert(state, &alert);
    }
}

fn handle_alert(state: &mut AgentState, alert: &Alert) {
    log_alert(alert);
    if let Err(e) = state.store.insert_alert(alert) {
        error!(%e, "failed to store alert");
    }
    state.alerts_generated += 1;
    process_response(state, alert);
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
                let outcome = state.dispatcher.execute(&result.action);
                if outcome.success {
                    info!(
                        action = %action_str,
                        target = %target,
                        detail = %outcome.detail,
                        "response action EXECUTED"
                    );
                } else {
                    warn!(
                        action = %action_str,
                        target = %target,
                        detail = %outcome.detail,
                        "response action FAILED"
                    );
                }
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

async fn run_ipc_server(state: Arc<Mutex<AgentState>>) -> Result<()> {
    #[cfg(target_os = "windows")]
    let mut listener = ipc::IpcListener::bind_default().await?;
    #[cfg(not(target_os = "windows"))]
    let listener = ipc::IpcListener::bind_default().await?;

    loop {
        let stream = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_ipc_client(stream, state).await {
                warn!(%e, "ipc client error");
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
        let request: ipc::IpcRequest = serde_json::from_str(&line)
            .map_err(|e| anyhow::anyhow!("invalid request: {e}"))?;

        let response = {
            let mut s = state.lock().await;
            handle_ipc_request(&mut s, request)
        };

        let payload = serde_json::to_string(&response)?;
        writer.write_all(payload.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

fn handle_ipc_request(state: &mut AgentState, request: ipc::IpcRequest) -> ipc::IpcResponse {
    match request {
        ipc::IpcRequest::Status => {
            let health = state.health.assess();
            ipc::IpcResponse::Status {
                events_processed: state.events_processed,
                alerts_generated: state.alerts_generated,
                actions_taken: state.actions_taken,
                uptime_secs: state.health.uptime_secs(),
                collectors_active: health.active_collectors,
            }
        }
        ipc::IpcRequest::GetEvents { limit } => match state.store.recent_events(limit) {
            Ok(events) => ipc::IpcResponse::Events(events),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("failed to load events: {e}"),
            },
        },
        ipc::IpcRequest::GetAlerts { limit } => match state.store.recent_alerts(limit) {
            Ok(alerts) => ipc::IpcResponse::Alerts(alerts),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("failed to load alerts: {e}"),
            },
        },
        ipc::IpcRequest::GetHealth => {
            let health = state.health.assess();
            ipc::IpcResponse::Health {
                overall_healthy: health.overall_healthy,
                blind_spots: health.blind_spots.iter().map(|s| s.to_string()).collect(),
                collectors: health
                    .active_collectors
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            }
        }
        ipc::IpcRequest::GetAuditLog { limit } => match state.audit.recent(&state.store.connection(), limit) {
            Ok(entries) => ipc::IpcResponse::AuditLog(entries),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("failed to load audit log: {e}"),
            },
        },
        ipc::IpcRequest::GetPolicyMode => {
            ipc::IpcResponse::PolicyMode(state.policy.mode().to_string())
        }
        ipc::IpcRequest::SetPolicyMode { mode } => {
            state.policy.set_mode(mode);
            ipc::IpcResponse::PolicyMode(state.policy.mode().to_string())
        }
        ipc::IpcRequest::VerifyAuditChain => match state.audit.verify_chain(&state.store.connection()) {
            Ok(valid) => ipc::IpcResponse::AuditChainValid(valid),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("chain verification failed: {e}"),
            },
        },
        ipc::IpcRequest::GetAiStatus => {
            let status = state.ai.status();
            ipc::IpcResponse::AiStatus {
                model_loaded: status.model_loaded,
                baseline_learned: status.baseline_learned,
                anomalies_detected: status.anomalies_detected,
                drift_detected: status.drift_detected,
            }
        }
        ipc::IpcRequest::ThreatHunt { query } => {
            match os_defender_core::advanced::hunting::run_hunt(&state.store.connection(), &query) {
                Ok(results) => ipc::IpcResponse::HuntResults(results),
                Err(e) => ipc::IpcResponse::Error {
                    message: format!("hunt failed: {e}"),
                },
            }
        }
        ipc::IpcRequest::GetPosture => match os_defender_core::advanced::posture::assess_posture() {
            Ok(report) => ipc::IpcResponse::Posture(report),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("posture assessment failed: {e}"),
            },
        },
        ipc::IpcRequest::GetPersistence => {
            match os_defender_core::advanced::persistence::scan_persistence() {
                Ok(entries) => ipc::IpcResponse::Persistence(entries),
                Err(e) => ipc::IpcResponse::Error {
                    message: format!("persistence scan failed: {e}"),
                },
            }
        }
        ipc::IpcRequest::VerifyIntegrity => {
            match os_defender_core::advanced::tamper::verify_self_integrity() {
                Ok(report) => ipc::IpcResponse::Integrity(report),
                Err(e) => ipc::IpcResponse::Error {
                    message: format!("integrity check failed: {e}"),
                },
            }
        }
        ipc::IpcRequest::CheckUpdate => match os_defender_core::update::check_for_update() {
            Ok(info) => ipc::IpcResponse::UpdateInfo(info),
            Err(e) => ipc::IpcResponse::Error {
                message: format!("update check failed: {e}"),
            },
        },
    }
}

fn log_alert(alert: &Alert) {
    let factors: Vec<String> = alert
        .factors
        .iter()
        .map(|f| format!("{}={:.2} ({})", f.name, f.weight, f.description))
        .collect();
    error!(
        alert_id = %alert.alert_id,
        rule = alert.rule_id.as_deref().unwrap_or("ai"),
        severity = %alert.severity,
        title = %alert.title,
        description = %alert.description,
        confidence = alert.confidence,
        mitre = ?alert.mitre_techniques,
        factors = ?factors,
        "ALERT"
    );
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}
