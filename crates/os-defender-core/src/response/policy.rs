use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::detection::Alert;
use crate::events::Severity;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    DryRun,
    Approve,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    BlockIp,
    UnblockIp,
    FreezeProcess,
    ThawProcess,
    QuarantineFile,
    RestoreFile,
    KillProcess,
}

impl std::fmt::Display for ResponseActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockIp => write!(f, "block_ip"),
            Self::UnblockIp => write!(f, "unblock_ip"),
            Self::FreezeProcess => write!(f, "freeze_process"),
            Self::ThawProcess => write!(f, "thaw_process"),
            Self::QuarantineFile => write!(f, "quarantine_file"),
            Self::RestoreFile => write!(f, "restore_file"),
            Self::KillProcess => write!(f, "kill_process"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: Uuid,
    pub alert_id: Uuid,
    pub kind: ResponseActionKind,
    pub target: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

impl ResponseAction {
    pub fn new(alert_id: Uuid, kind: ResponseActionKind, target: String, reason: String) -> Self {
        Self {
            action_id: Uuid::new_v4(),
            alert_id,
            kind,
            target,
            reason,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Execute,
    DryRun,
    PendingApproval,
    Denied,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execute => write!(f, "execute"),
            Self::DryRun => write!(f, "dry_run"),
            Self::PendingApproval => write!(f, "pending_approval"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub action: ResponseAction,
    pub decision: PolicyDecision,
    pub mode: PolicyMode,
}

pub struct PolicyEngine {
    mode: PolicyMode,
    auto_execute_min_severity: Severity,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyMode::DryRun)
    }
}

impl PolicyEngine {
    pub fn new(mode: PolicyMode) -> Self {
        Self {
            mode,
            auto_execute_min_severity: Severity::Critical,
        }
    }

    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: PolicyMode) {
        self.mode = mode;
    }

    pub fn set_auto_execute_severity(&mut self, min: Severity) {
        self.auto_execute_min_severity = min;
    }

    pub fn evaluate(&self, action: ResponseAction, alert_severity: Severity) -> PolicyResult {
        let decision = match self.mode {
            PolicyMode::DryRun => PolicyDecision::DryRun,
            PolicyMode::Execute => PolicyDecision::Execute,
            PolicyMode::Approve => {
                if alert_severity >= self.auto_execute_min_severity {
                    PolicyDecision::Execute
                } else {
                    PolicyDecision::PendingApproval
                }
            }
        };
        PolicyResult {
            action,
            decision,
            mode: self.mode,
        }
    }

    pub fn suggest_actions(&self, alert: &Alert) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for technique in &alert.mitre_techniques {
            match technique.as_str() {
                "T1110" => {
                    // Brute force — block source IP if available
                    if let Some(ip) = extract_ip_from_description(&alert.description) {
                        actions.push(ResponseAction::new(
                            alert.alert_id,
                            ResponseActionKind::BlockIp,
                            ip,
                            format!("Brute-force detection: {}", alert.title),
                        ));
                    }
                }
                "T1059" | "T1059.004" => {
                    // Suspicious process — freeze it
                    if let Some(pid) = extract_pid_from_description(&alert.description) {
                        actions.push(ResponseAction::new(
                            alert.alert_id,
                            ResponseActionKind::FreezeProcess,
                            pid.to_string(),
                            format!("Suspicious process: {}", alert.title),
                        ));
                    }
                }
                "T1565.001" | "T1486" => {
                    // File tampering / ransomware — quarantine
                    if let Some(path) = extract_path_from_description(&alert.description) {
                        actions.push(ResponseAction::new(
                            alert.alert_id,
                            ResponseActionKind::QuarantineFile,
                            path,
                            format!("File tampering: {}", alert.title),
                        ));
                    }
                }
                "T1571" => {
                    // Non-standard port — block remote IP
                    if let Some(ip) = extract_ip_from_description(&alert.description) {
                        actions.push(ResponseAction::new(
                            alert.alert_id,
                            ResponseActionKind::BlockIp,
                            ip,
                            format!("Anomalous network: {}", alert.title),
                        ));
                    }
                }
                _ => {}
            }
        }
        actions
    }
}

fn extract_ip_from_description(desc: &str) -> Option<String> {
    // Look for IPv4 pattern in description
    for word in desc.split(|c: char| !c.is_ascii_digit() && c != '.') {
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return Some(word.to_string());
        }
    }
    None
}

fn extract_pid_from_description(desc: &str) -> Option<u32> {
    // Look for "PID <number>" pattern
    let mut iter = desc.split_whitespace();
    while let Some(word) = iter.next() {
        if (word == "PID" || word == "(PID")
            && let Some(next) = iter.next()
        {
            let clean = next.trim_end_matches(')');
            if let Ok(pid) = clean.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

fn extract_path_from_description(desc: &str) -> Option<String> {
    // Look for quoted path starting with /
    for segment in desc.split('\'') {
        let trimmed = segment.trim();
        if trimmed.starts_with('/') {
            return Some(trimmed.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_action(kind: ResponseActionKind) -> ResponseAction {
        ResponseAction::new(Uuid::new_v4(), kind, "target".into(), "test".into())
    }

    #[test]
    fn dry_run_never_executes() {
        let engine = PolicyEngine::new(PolicyMode::DryRun);
        let result = engine.evaluate(test_action(ResponseActionKind::BlockIp), Severity::Critical);
        assert_eq!(result.decision, PolicyDecision::DryRun);
    }

    #[test]
    fn execute_mode_always_executes() {
        let engine = PolicyEngine::new(PolicyMode::Execute);
        let result = engine.evaluate(test_action(ResponseActionKind::BlockIp), Severity::Low);
        assert_eq!(result.decision, PolicyDecision::Execute);
    }

    #[test]
    fn approve_mode_auto_executes_critical() {
        let engine = PolicyEngine::new(PolicyMode::Approve);
        let result = engine.evaluate(test_action(ResponseActionKind::FreezeProcess), Severity::Critical);
        assert_eq!(result.decision, PolicyDecision::Execute);
    }

    #[test]
    fn approve_mode_queues_low_severity() {
        let engine = PolicyEngine::new(PolicyMode::Approve);
        let result = engine.evaluate(test_action(ResponseActionKind::BlockIp), Severity::Medium);
        assert_eq!(result.decision, PolicyDecision::PendingApproval);
    }

    #[test]
    fn suggest_actions_for_brute_force() {
        let alert = Alert::from_rule(
            Uuid::new_v4(),
            "R001",
            Severity::High,
            "Brute-force".into(),
            "5 failed logins from 10.0.0.5 for user root".into(),
            0.9,
        )
        .with_mitre("T1110");

        let engine = PolicyEngine::default();
        let actions = engine.suggest_actions(&alert);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, ResponseActionKind::BlockIp);
        assert_eq!(actions[0].target, "10.0.0.5");
    }

    #[test]
    fn suggest_actions_for_suspicious_process() {
        let alert = Alert::from_rule(
            Uuid::new_v4(),
            "R002",
            Severity::High,
            "Reverse shell".into(),
            "Process 'bash' (PID 4567) executed with suspicious pattern".into(),
            0.8,
        )
        .with_mitre("T1059.004");

        let engine = PolicyEngine::default();
        let actions = engine.suggest_actions(&alert);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, ResponseActionKind::FreezeProcess);
        assert_eq!(actions[0].target, "4567");
    }

    #[test]
    fn extract_ip_works() {
        assert_eq!(extract_ip_from_description("from 192.168.1.5 for"), Some("192.168.1.5".into()));
        assert_eq!(extract_ip_from_description("no ip here"), None);
    }

    #[test]
    fn extract_pid_works() {
        assert_eq!(extract_pid_from_description("Process 'bash' (PID 1234) ran"), Some(1234));
        assert_eq!(extract_pid_from_description("no pid"), None);
    }

    #[test]
    fn extract_path_works() {
        assert_eq!(extract_path_from_description("file '/etc/shadow' was modified"), Some("/etc/shadow".into()));
        assert_eq!(extract_path_from_description("no path"), None);
    }
}
