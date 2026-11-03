use anyhow::Result;
use clap::Parser;
use os_defender_core::{
    detection::{Alert, DetectionEngine, default_ruleset},
    events::NormalizedEvent,
    health::BlindSpotDetector,
    ipc,
    platform::{ProcessCollector, FileCollector, NetworkCollector, AuthCollector},
    storage::SqliteStore,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "os-defender-agent", version, about = "OS-DEFENDER protection agent")]
struct Args {
    #[arg(long, default_value = "~/.local/share/os-defender/os-defender.db")]
    db_path: String,

    #[arg(long, default_value_t = 2000)]
    poll_interval_ms: u64,

    #[arg(long, default_value_t = 60)]
    heartbeat_timeout_secs: i64,

    /// Directories to watch for file changes (comma-separated)
    #[arg(long, default_value = "/etc,/home")]
    watch_dirs: String,
}

struct AgentState {
    store: SqliteStore,
    engine: DetectionEngine,
    health: BlindSpotDetector,
    events_processed: u64,
    alerts_generated: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    let db_path = expand_tilde(&args.db_path);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = SqliteStore::open(&db_path)?;
    let rules = default_ruleset();
    let engine = DetectionEngine::new(rules);
    let health = BlindSpotDetector::new(args.heartbeat_timeout_secs);

    info!(rules = engine.rule_count(), "detection rules loaded");

    let state = Arc::new(Mutex::new(AgentState {
        store,
        engine,
        health,
        events_processed: 0,
        alerts_generated: 0,
    }));

    info!(version = env!("CARGO_PKG_VERSION"), "OS-DEFENDER agent starting");
    info!(db = %db_path.display(), "database opened");

    let shutdown = tokio::signal::ctrl_c();

    // Start platform-specific collectors
    #[cfg(target_os = "linux")]
    let collector_handle = {
        let state = Arc::clone(&state);
        let interval_ms = args.poll_interval_ms;
        let watch_dirs = args.watch_dirs.clone();
        tokio::spawn(async move {
            run_linux_collectors(state, interval_ms, &watch_dirs).await;
        })
    };

    #[cfg(not(target_os = "linux"))]
    let collector_handle = tokio::spawn(async {
        warn!("no platform collectors available for this OS");
    });

    // Start IPC listener
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

#[cfg(target_os = "linux")]
async fn run_linux_collectors(state: Arc<Mutex<AgentState>>, interval_ms: u64, watch_dirs: &str) {
    use os_defender_core::platform::linux::{
        LinuxProcessCollector, LinuxFileCollector, LinuxNetworkCollector, LinuxAuthCollector,
        ProcessTree,
    };

    let endpoint_id = os_defender_core::platform::linux::SystemInfo::machine_id()
        .unwrap_or_else(|_| "unknown".into());

    // Initialize collectors
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

        // -- Process collector --
        match process_collector.poll_processes().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-process", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "process", %e, "poll error"),
        }

        // -- Network collector --
        match network_collector.poll_connections().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-network", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "network", %e, "poll error"),
        }

        // -- Auth collector (journalctl) --
        match auth_collector.poll_auth_events().await {
            Ok(events) => {
                let mut s = state.lock().await;
                let ep = s.events_processed;
                s.health.record_heartbeat("linux-auth", ep, 0);
                ingest_events(&mut s, events);
            }
            Err(e) => warn!(collector = "auth", %e, "poll error"),
        }

        // -- File collector (inotify) --
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

        // -- Periodic tasks --
        // Refresh process tree every 15 ticks (~30s at 2s interval)
        if tick.is_multiple_of(15) {
            proc_tree.refresh();
        }

        // Health assessment every 30 ticks (~60s)
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
                healthy = assessment.overall_healthy,
                "periodic health check"
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

fn ingest_events(state: &mut AgentState, events: Vec<NormalizedEvent>) {
    for event in events {
        let alerts = state.engine.process_event(&event);
        if let Err(e) = state.store.insert_event(&event) {
            error!(%e, "failed to store event");
        }
        state.events_processed += 1;

        for alert in &alerts {
            log_alert(alert);
            state.alerts_generated += 1;
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
    use tokio::net::UnixListener;

    let socket_path = ipc::user_socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    info!(path = %socket_path.display(), "IPC listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            if let Err(e) = handle_ipc_client(stream, state).await {
                error!(%e, "IPC client error");
            }
        });
    }
}

async fn handle_ipc_client(
    stream: tokio::net::UnixStream,
    state: Arc<Mutex<AgentState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
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
                ipc::IpcResponse::Status(ipc::AgentStatus {
                    running: true,
                    uptime_secs: 0,
                    events_processed: s.events_processed,
                    alerts_generated: s.alerts_generated,
                    collectors_active: vec![
                        "linux-process".into(),
                        "linux-network".into(),
                        "linux-auth".into(),
                        "linux-file".into(),
                    ],
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
            ipc::IpcRequest::GetAlerts { .. } => {
                ipc::IpcResponse::Error {
                    message: "not yet implemented".into(),
                }
            }
            ipc::IpcRequest::GetHealth => {
                let mut s = state.lock().await;
                let assessment = s.health.assess();
                ipc::IpcResponse::Health(assessment)
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
    PathBuf::from(path)
}
