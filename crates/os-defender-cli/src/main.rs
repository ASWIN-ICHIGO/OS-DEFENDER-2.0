use anyhow::Result;
use clap::{Parser, Subcommand};
use os_defender_core::ipc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "os-defender", version, about = "OS-DEFENDER CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show agent status
    Status,
    /// List recent events
    Events {
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },
    /// Show sensor health and visibility
    Health,
    /// Show recent audit log entries
    Audit {
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },
    /// Show or change policy mode
    Policy {
        /// Set mode: dry_run, approve, execute
        #[arg(long)]
        set: Option<String>,
    },
    /// Verify audit log hash chain integrity
    VerifyAudit,
    /// Show AI engine status
    AiStatus,
    /// Threat hunting query
    Hunt {
        /// Event type filter (process, file, network, authentication)
        #[arg(long)]
        event_type: Option<String>,
        /// Minimum severity (info, low, medium, high, critical)
        #[arg(long)]
        severity: Option<String>,
        /// Process name filter
        #[arg(long)]
        process: Option<String>,
        /// File path pattern filter
        #[arg(long)]
        file_path: Option<String>,
        /// Remote address filter
        #[arg(long)]
        remote_addr: Option<String>,
        /// Username filter
        #[arg(long)]
        username: Option<String>,
        /// Text search in event payload
        #[arg(long)]
        contains: Option<String>,
        /// Max results
        #[arg(short, long, default_value_t = 50)]
        limit: u32,
    },
    /// Security posture assessment
    Posture,
    /// Scan persistence mechanisms
    Persistence,
    /// Verify agent integrity
    Integrity,
    /// Request agent shutdown
    Shutdown,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let request = match &cli.command {
        Commands::Status => ipc::IpcRequest::Status,
        Commands::Events { limit } => ipc::IpcRequest::GetEvents { limit: *limit },
        Commands::Health => ipc::IpcRequest::GetHealth,
        Commands::Audit { limit } => ipc::IpcRequest::GetAuditLog { limit: *limit },
        Commands::Policy { set: None } => ipc::IpcRequest::GetPolicyMode,
        Commands::Policy { set: Some(mode) } => {
            let m = match mode.as_str() {
                "execute" => os_defender_core::response::PolicyMode::Execute,
                "approve" => os_defender_core::response::PolicyMode::Approve,
                _ => os_defender_core::response::PolicyMode::DryRun,
            };
            ipc::IpcRequest::SetPolicyMode { mode: m }
        }
        Commands::VerifyAudit => ipc::IpcRequest::VerifyAuditChain,
        Commands::AiStatus => ipc::IpcRequest::GetAiStatus,
        Commands::Hunt {
            event_type, severity, process, file_path,
            remote_addr, username, contains, limit,
        } => {
            let mut q = os_defender_core::advanced::hunting::HuntQuery::new()
                .with_limit(*limit);
            if let Some(et) = event_type { q = q.with_event_type(et); }
            if let Some(s) = severity { q = q.with_severity_min(s); }
            if let Some(p) = process { q = q.with_process_name(p); }
            if let Some(f) = file_path { q = q.with_file_path(f); }
            if let Some(r) = remote_addr { q = q.with_remote_addr(r); }
            if let Some(u) = username { q = q.with_username(u); }
            if let Some(c) = contains { q = q.with_payload_contains(c); }
            ipc::IpcRequest::ThreatHunt { query: Box::new(q) }
        }
        Commands::Posture => ipc::IpcRequest::GetPosture,
        Commands::Persistence => ipc::IpcRequest::GetPersistence,
        Commands::Integrity => ipc::IpcRequest::VerifyIntegrity,
        Commands::Shutdown => ipc::IpcRequest::Shutdown,
    };

    let stream = ipc::IpcStream::connect_default().await.map_err(|e| {
        anyhow::anyhow!("cannot connect to agent: {} — is the agent running?", e)
    })?;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut json = serde_json::to_string(&request)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let response: ipc::IpcResponse = serde_json::from_str(&line)?;
        print_response(&response);
    }

    Ok(())
}

fn print_response(response: &ipc::IpcResponse) {
    match response {
        ipc::IpcResponse::Status(status) => {
            println!("OS-DEFENDER Agent v{}", status.version);
            println!("  Running:          {}", status.running);
            println!("  Policy mode:      {}", status.policy_mode);
            println!("  Events processed: {}", status.events_processed);
            println!("  Alerts generated: {}", status.alerts_generated);
            println!("  Actions taken:    {}", status.actions_taken);
            println!("  Active collectors: {}", status.collectors_active.join(", "));
        }
        ipc::IpcResponse::Events(events) => {
            if events.is_empty() {
                println!("No events.");
            } else {
                for event in events {
                    println!(
                        "[{}] {} {:?} — {} ({})",
                        event.timestamp.format("%H:%M:%S"),
                        event.severity,
                        event.event_type,
                        event.process_context
                            .as_ref()
                            .map(|p| p.name.as_str())
                            .or(event.file_context.as_ref().map(|f| f.path.as_str()))
                            .or(event.network_context.as_ref().map(|n| n.local_addr.as_str()))
                            .unwrap_or("-"),
                        event.endpoint_id,
                    );
                }
            }
        }
        ipc::IpcResponse::Health(assessment) => {
            let status = if assessment.overall_healthy {
                "HEALTHY"
            } else {
                "DEGRADED"
            };
            println!("Visibility: {status}");
            for sensor in &assessment.sensors {
                let icon = if sensor.is_healthy { "+" } else { "!" };
                println!(
                    "  [{icon}] {} — collected: {}, dropped: {}",
                    sensor.name, sensor.events_collected, sensor.events_dropped
                );
            }
            if !assessment.blind_spots.is_empty() {
                println!("\nBlind spots:");
                for spot in &assessment.blind_spots {
                    println!("  - {spot}");
                }
            }
            println!("\n{}", assessment.caveat);
        }
        ipc::IpcResponse::AuditLog(entries) => {
            if entries.is_empty() {
                println!("No audit entries.");
            } else {
                for entry in entries {
                    println!(
                        "[{}] {} {} → {} ({})",
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.decision,
                        entry.action,
                        entry.target,
                        entry.reason,
                    );
                }
            }
        }
        ipc::IpcResponse::PolicyMode(mode) => {
            println!("Policy mode: {mode:?}");
        }
        ipc::IpcResponse::AuditChainStatus { valid, entries } => {
            if *valid {
                println!("Audit chain: VALID ({entries} entries verified)");
            } else {
                println!("Audit chain: TAMPERED (break detected at entry ~{entries})");
            }
        }
        ipc::IpcResponse::AiStatus(ai) => {
            let status_str = if ai.available { "AVAILABLE" } else { "NOT CONFIGURED" };
            println!("AI Engine: {status_str}");
            println!("  Model loaded:     {}", ai.model_loaded);
            if let Some(ref path) = ai.model_path {
                println!("  Model path:       {path}");
            }
            println!("  Baseline learned: {}", ai.baseline_learned);
            println!("  Events scored:    {}", ai.events_scored);
            println!("  Anomalies:        {}", ai.anomalies_detected);
            println!("  Drift detected:   {}", ai.drift_detected);
            println!("  Ollama LLM:       {}", if ai.ollama_available { "available" } else { "not available" });
        }
        ipc::IpcResponse::HuntResults(result) => {
            println!("Hunt: {} matches", result.total_matches);
            for event in &result.events {
                println!(
                    "  [{}] {} {:?} — {} ({})",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    event.severity,
                    event.event_type,
                    event.process_context.as_ref().map(|p| p.name.as_str())
                        .or(event.file_context.as_ref().map(|f| f.path.as_str()))
                        .or(event.network_context.as_ref().map(|n| n.local_addr.as_str()))
                        .or(event.auth_context.as_ref().map(|a| a.username.as_str()))
                        .unwrap_or("-"),
                    event.endpoint_id,
                );
            }
        }
        ipc::IpcResponse::PostureReport(report) => {
            print!("{}", report.to_text());
        }
        ipc::IpcResponse::PersistenceEntries(entries) => {
            println!("Persistence mechanisms: {} found", entries.len());
            for entry in entries {
                let icon = match entry.risk {
                    os_defender_core::advanced::persistence::PersistenceRisk::Known => ".",
                    os_defender_core::advanced::persistence::PersistenceRisk::Suspicious => "?",
                    os_defender_core::advanced::persistence::PersistenceRisk::HighRisk => "!",
                };
                println!("  [{icon}] {} — {} ({})", entry.kind, entry.name, entry.mitre_technique);
            }
        }
        ipc::IpcResponse::IntegrityStatus(result) => {
            if result.is_clean() {
                println!("Integrity: CLEAN ({} files verified)", result.intact);
            } else {
                println!("Integrity: VIOLATED");
                for v in &result.tampered {
                    println!("  TAMPERED: {} (expected: {}..)", v.path, &v.expected_sha256[..16]);
                }
                for m in &result.missing {
                    println!("  MISSING: {m}");
                }
            }
        }
        ipc::IpcResponse::Ok => println!("OK"),
        ipc::IpcResponse::Error { message } => {
            eprintln!("Error: {message}");
        }
    }
}
