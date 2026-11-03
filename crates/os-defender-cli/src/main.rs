use anyhow::Result;
use clap::{Parser, Subcommand};
use os_defender_core::ipc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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
        Commands::Shutdown => ipc::IpcRequest::Shutdown,
    };

    let socket_path = ipc::user_socket_path();
    let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot connect to agent at {}: {} — is the agent running?",
            socket_path.display(),
            e
        )
    })?;

    let (reader, mut writer) = stream.into_split();
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
        ipc::IpcResponse::Ok => println!("OK"),
        ipc::IpcResponse::Error { message } => {
            eprintln!("Error: {message}");
        }
    }
}
