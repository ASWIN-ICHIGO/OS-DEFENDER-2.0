use serde::{Deserialize, Serialize};

pub const SOCKET_PATH: &str = "/run/os-defender/agent.sock";
pub const USER_SOCKET_DIR: &str = ".local/share/os-defender";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    Status,
    GetEvents { limit: u32 },
    GetAlerts { limit: u32 },
    GetHealth,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcResponse {
    Status(AgentStatus),
    Events(Vec<crate::events::NormalizedEvent>),
    Health(crate::health::VisibilityAssessment),
    Ok,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub collectors_active: Vec<String>,
    pub version: String,
}

pub fn user_socket_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home)
        .join(USER_SOCKET_DIR)
        .join("agent.sock")
}
