use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventType {
    Process,
    File,
    Authentication,
    Network,
    SensorHealth,
    Persistence,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
    pub username: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub children_pids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub path: String,
    pub action: FileAction,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub owner_uid: Option<u32>,
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileAction {
    Create,
    Modify,
    Delete,
    Rename,
    Permission,
    Access,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub protocol: NetworkProtocol,
    pub direction: NetDirection,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetDirection {
    Inbound,
    Outbound,
    Local,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub action: AuthAction,
    pub username: String,
    pub source_addr: Option<String>,
    pub method: Option<String>,
    pub service: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthAction {
    Login,
    Logout,
    Failed,
    Escalation,
    KeyAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub collector_name: String,
    pub state: CollectorState,
    pub events_collected: u64,
    pub events_dropped: u64,
    pub lag_ms: Option<u64>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectorState {
    Running,
    Degraded,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub endpoint_id: String,
    pub os_type: OsType,
    pub event_type: EventType,
    pub severity: Severity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_context: Option<ProcessContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_context: Option<FileContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_context: Option<NetworkContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<AuthContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_status: Option<CollectorStatus>,

    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,

    pub fingerprint: String,
}

impl NormalizedEvent {
    pub fn new(
        endpoint_id: String,
        os_type: OsType,
        event_type: EventType,
        severity: Severity,
    ) -> Self {
        let event_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let fingerprint = Self::compute_fingerprint(&event_id, &timestamp, &endpoint_id);

        Self {
            event_id,
            timestamp,
            endpoint_id,
            os_type,
            event_type,
            severity,
            process_context: None,
            file_context: None,
            network_context: None,
            auth_context: None,
            collector_status: None,
            evidence_refs: Vec::new(),
            fingerprint,
        }
    }

    fn compute_fingerprint(id: &Uuid, ts: &DateTime<Utc>, endpoint: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(ts.to_rfc3339().as_bytes());
        hasher.update(endpoint.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn with_process(mut self, ctx: ProcessContext) -> Self {
        self.process_context = Some(ctx);
        self
    }

    pub fn with_file(mut self, ctx: FileContext) -> Self {
        self.file_context = Some(ctx);
        self
    }

    pub fn with_network(mut self, ctx: NetworkContext) -> Self {
        self.network_context = Some(ctx);
        self
    }

    pub fn with_auth(mut self, ctx: AuthContext) -> Self {
        self.auth_context = Some(ctx);
        self
    }

    pub fn with_evidence(mut self, evidence: EvidenceRef) -> Self {
        self.evidence_refs.push(evidence);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_creation_generates_unique_ids() {
        let e1 = NormalizedEvent::new(
            "test-endpoint".into(),
            OsType::Linux,
            EventType::Process,
            Severity::Info,
        );
        let e2 = NormalizedEvent::new(
            "test-endpoint".into(),
            OsType::Linux,
            EventType::Process,
            Severity::Info,
        );
        assert_ne!(e1.event_id, e2.event_id);
        assert_ne!(e1.fingerprint, e2.fingerprint);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let event = NormalizedEvent::new(
            "ep-001".into(),
            OsType::Linux,
            EventType::Process,
            Severity::High,
        )
        .with_process(ProcessContext {
            pid: 1234,
            ppid: Some(1),
            name: "bash".into(),
            exe: Some("/usr/bin/bash".into()),
            cmdline: Some("bash -c whoami".into()),
            uid: Some(1000),
            username: Some("aswin".into()),
            start_time: None,
            children_pids: vec![],
        });

        let json = serde_json::to_string(&event).unwrap();
        let restored: NormalizedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.event_id, event.event_id);
        assert_eq!(restored.severity, Severity::High);
        assert_eq!(restored.process_context.unwrap().pid, 1234);
    }

    #[test]
    fn fingerprint_is_sha256_hex() {
        let event = NormalizedEvent::new(
            "ep-001".into(),
            OsType::Linux,
            EventType::File,
            Severity::Low,
        );
        assert_eq!(event.fingerprint.len(), 64);
        assert!(event.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
