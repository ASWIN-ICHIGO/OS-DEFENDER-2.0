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
    GetAuditLog { limit: u32 },
    GetPolicyMode,
    SetPolicyMode { mode: crate::response::PolicyMode },
    VerifyAuditChain,
    GetAiStatus,
    ThreatHunt { query: Box<crate::advanced::hunting::HuntQuery> },
    GetPosture,
    GetPersistence,
    VerifyIntegrity,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcResponse {
    Status(AgentStatus),
    Events(Vec<crate::events::NormalizedEvent>),
    Health(crate::health::VisibilityAssessment),
    AuditLog(Vec<crate::response::AuditEntry>),
    PolicyMode(crate::response::PolicyMode),
    AuditChainStatus { valid: bool, entries: usize },
    AiStatus(AiEngineStatus),
    HuntResults(Box<crate::advanced::hunting::HuntResult>),
    PostureReport(Box<crate::advanced::posture::PostureReport>),
    PersistenceEntries(Vec<crate::advanced::persistence::PersistenceEntry>),
    IntegrityStatus(Box<crate::advanced::tamper::TamperCheckResult>),
    Ok,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub actions_taken: u64,
    pub policy_mode: String,
    pub collectors_active: Vec<String>,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiEngineStatus {
    pub available: bool,
    pub model_loaded: bool,
    pub model_path: Option<String>,
    pub baseline_learned: bool,
    pub events_scored: u64,
    pub anomalies_detected: u64,
    pub last_drift_check: Option<String>,
    pub drift_detected: bool,
    pub ollama_available: bool,
}

pub fn user_socket_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home)
        .join(USER_SOCKET_DIR)
        .join("agent.sock")
}
