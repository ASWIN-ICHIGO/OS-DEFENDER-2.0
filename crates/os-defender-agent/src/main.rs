use anyhow::Result;
use clap::Parser;
use os_defender_core::{
    detection::{DetectionEngine, RuleSet},
    events::NormalizedEvent,
    health::BlindSpotDetector,
    ipc,
    platform::ProcessCollector,
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
    let rules = RuleSet::new();
    let engine = DetectionEngine::new(rules);
    let health = BlindSpotDetector::new(args.heartbeat_timeout_secs);

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
        tokio::spawn(async move {
            run_linux_collectors(state, interval_ms).await;
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
async fn run_linux_collectors(state: Arc<Mutex<AgentState>>, interval_ms: u64) {
    use os_defender_core::platform::linux::LinuxProcessCollector;

    let endpoint_id = os_defender_core::platform::linux::SystemInfo::machine_id()
        .unwrap_or_else(|_| "unknown".into());

    let mut process_collector = LinuxProcessCollector::new(endpoint_id);
    let mut tick: u64 = 0;

    loop {
        tick += 1;

        match process_collector.poll_processes().await {
            Ok(events) => {
                let mut s = state.lock().await;
                s.health
                    .record_heartbeat("linux-process", s.events_processed, 0);
                process_events(&mut s, events);
            }
            Err(e) => {
                warn!(%e, "process collector error");
            }
        }

        if tick % 30 == 0 {
            let mut s = state.lock().await;
            let assessment = s.health.assess();
            if !assessment.overall_healthy {
                for spot in &assessment.blind_spots {
                    warn!(blind_spot = %spot, "visibility gap");
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
}

fn process_events(state: &mut AgentState, events: Vec<NormalizedEvent>) {
    for event in events {
        let alerts = state.engine.process_event(&event);
        if let Err(e) = state.store.insert_event(&event) {
            error!(%e, "failed to store event");
        }
        state.events_processed += 1;
        state.alerts_generated += alerts.len() as u64;

        for alert in &alerts {
            info!(
                alert_id = %alert.alert_id,
                severity = %alert.severity,
                title = %alert.title,
                "alert generated"
            );
        }
    }
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

        let response = {
            let s = state.lock().await;
            match request {
                ipc::IpcRequest::Status => ipc::IpcResponse::Status(ipc::AgentStatus {
                    running: true,
                    uptime_secs: 0, // TODO: track actual uptime
                    events_processed: s.events_processed,
                    alerts_generated: s.alerts_generated,
                    collectors_active: vec!["linux-process".into()],
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }),
                ipc::IpcRequest::GetEvents { limit } => {
                    match s.store.get_events(limit) {
                        Ok(events) => ipc::IpcResponse::Events(events),
                        Err(e) => ipc::IpcResponse::Error {
                            message: e.to_string(),
                        },
                    }
                }
                ipc::IpcRequest::GetAlerts { .. } => {
                    // TODO: implement alert storage query
                    ipc::IpcResponse::Error {
                        message: "not yet implemented".into(),
                    }
                }
                ipc::IpcRequest::GetHealth => {
                    drop(s);
                    let mut s = state.lock().await;
                    let assessment = s.health.assess();
                    ipc::IpcResponse::Health(assessment)
                }
                ipc::IpcRequest::Shutdown => {
                    info!("shutdown requested via IPC");
                    ipc::IpcResponse::Ok
                }
            }
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    PathBuf::from(path)
}
