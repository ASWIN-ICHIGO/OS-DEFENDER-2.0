use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::{NormalizedEvent, Severity};
use crate::detection::Alert;

// --- Timeline ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub kind: TimelineKind,
    pub summary: String,
    pub severity: Severity,
    pub source_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    Event,
    Alert,
    Action,
    Evidence,
}

pub struct TimelineBuilder {
    entries: BTreeMap<DateTime<Utc>, Vec<TimelineEntry>>,
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelineBuilder {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn add_event(&mut self, event: &NormalizedEvent) {
        let summary = Self::summarize_event(event);
        self.entries
            .entry(event.timestamp)
            .or_default()
            .push(TimelineEntry {
                timestamp: event.timestamp,
                kind: TimelineKind::Event,
                summary,
                severity: event.severity,
                source_id: event.event_id.to_string(),
            });
    }

    pub fn add_alert(&mut self, alert: &Alert) {
        self.entries
            .entry(alert.timestamp)
            .or_default()
            .push(TimelineEntry {
                timestamp: alert.timestamp,
                kind: TimelineKind::Alert,
                summary: format!("[{}] {}", alert.severity, alert.title),
                severity: alert.severity,
                source_id: alert.alert_id.to_string(),
            });
    }

    pub fn add_action(&mut self, ts: DateTime<Utc>, action: &str, severity: Severity) {
        self.entries
            .entry(ts)
            .or_default()
            .push(TimelineEntry {
                timestamp: ts,
                kind: TimelineKind::Action,
                summary: action.to_string(),
                severity,
                source_id: Uuid::new_v4().to_string(),
            });
    }

    pub fn build(&self) -> Vec<TimelineEntry> {
        self.entries.values().flatten().cloned().collect()
    }

    pub fn build_range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<TimelineEntry> {
        self.entries
            .range(from..=to)
            .flat_map(|(_, v)| v)
            .cloned()
            .collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    fn summarize_event(event: &NormalizedEvent) -> String {
        if let Some(ref proc) = event.process_context {
            return format!("[{:?}] Process '{}' (PID {})", event.event_type, proc.name, proc.pid);
        }
        if let Some(ref file) = event.file_context {
            return format!("[{:?}] File {:?}: {}", event.event_type, file.action, file.path);
        }
        if let Some(ref net) = event.network_context {
            return format!(
                "[{:?}] {}:{} → {}:{}",
                event.event_type,
                net.local_addr, net.local_port,
                net.remote_addr.as_deref().unwrap_or("?"),
                net.remote_port.unwrap_or(0),
            );
        }
        if let Some(ref auth) = event.auth_context {
            return format!("[{:?}] {:?} for user '{}'", event.event_type, auth.action, auth.username);
        }
        format!("[{:?}] event {}", event.event_type, event.event_id)
    }
}

// --- Evidence collection ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: Uuid,
    pub kind: EvidenceKind,
    pub description: String,
    pub data: String,
    pub collected_at: DateTime<Utc>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    EventLog,
    FileSnapshot,
    ProcessInfo,
    NetworkCapture,
    ConfigSnapshot,
    CommandOutput,
}

pub struct EvidenceCollector {
    items: Vec<EvidenceItem>,
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceCollector {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn add_event_log(&mut self, events: &[NormalizedEvent], description: &str) {
        let data = serde_json::to_string_pretty(events).unwrap_or_default();
        let hash = crate::advanced::file_intel::FileIntelligence::hash_bytes(data.as_bytes());
        self.items.push(EvidenceItem {
            evidence_id: Uuid::new_v4(),
            kind: EvidenceKind::EventLog,
            description: description.to_string(),
            data,
            collected_at: Utc::now(),
            sha256: Some(hash),
        });
    }

    pub fn add_file_snapshot(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("cannot snapshot {}", path.display()))?;
        let hash = crate::advanced::file_intel::FileIntelligence::hash_bytes(content.as_bytes());
        self.items.push(EvidenceItem {
            evidence_id: Uuid::new_v4(),
            kind: EvidenceKind::FileSnapshot,
            description: format!("Snapshot of {}", path.display()),
            data: content,
            collected_at: Utc::now(),
            sha256: Some(hash),
        });
        Ok(())
    }

    pub fn add_raw(&mut self, kind: EvidenceKind, description: &str, data: &str) {
        let hash = crate::advanced::file_intel::FileIntelligence::hash_bytes(data.as_bytes());
        self.items.push(EvidenceItem {
            evidence_id: Uuid::new_v4(),
            kind,
            description: description.to_string(),
            data: data.to_string(),
            collected_at: Utc::now(),
            sha256: Some(hash),
        });
    }

    pub fn items(&self) -> &[EvidenceItem] {
        &self.items
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }
}

// --- Forensic report ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub report_id: Uuid,
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub endpoint_id: String,
    pub summary: String,
    pub timeline: Vec<TimelineEntry>,
    pub evidence: Vec<EvidenceItem>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ForensicReport {
    pub fn new(title: &str, endpoint_id: &str) -> Self {
        Self {
            report_id: Uuid::new_v4(),
            title: title.to_string(),
            generated_at: Utc::now(),
            endpoint_id: endpoint_id.to_string(),
            summary: String::new(),
            timeline: Vec::new(),
            evidence: Vec::new(),
            findings: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn with_summary(mut self, summary: &str) -> Self {
        self.summary = summary.to_string();
        self
    }

    pub fn with_timeline(mut self, timeline: Vec<TimelineEntry>) -> Self {
        self.timeline = timeline;
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<EvidenceItem>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn add_finding(&mut self, finding: &str) {
        self.findings.push(finding.to_string());
    }

    pub fn add_recommendation(&mut self, rec: &str) {
        self.recommendations.push(rec.to_string());
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("═══ FORENSIC REPORT: {} ═══\n", self.title));
        out.push_str(&format!("Report ID:   {}\n", self.report_id));
        out.push_str(&format!("Generated:   {}\n", self.generated_at.to_rfc3339()));
        out.push_str(&format!("Endpoint:    {}\n", self.endpoint_id));
        out.push_str(&format!("\n── Summary ──\n{}\n", self.summary));

        if !self.timeline.is_empty() {
            out.push_str(&format!("\n── Timeline ({} entries) ──\n", self.timeline.len()));
            for entry in &self.timeline {
                out.push_str(&format!(
                    "  {} [{:?}] {} ({})\n",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    entry.kind,
                    entry.summary,
                    entry.severity,
                ));
            }
        }

        if !self.evidence.is_empty() {
            out.push_str(&format!("\n── Evidence ({} items) ──\n", self.evidence.len()));
            for item in &self.evidence {
                out.push_str(&format!(
                    "  [{:?}] {} (collected: {}, SHA-256: {})\n",
                    item.kind,
                    item.description,
                    item.collected_at.format("%H:%M:%S"),
                    item.sha256.as_deref().unwrap_or("n/a"),
                ));
            }
        }

        if !self.findings.is_empty() {
            out.push_str("\n── Findings ──\n");
            for (i, f) in self.findings.iter().enumerate() {
                out.push_str(&format!("  {}. {f}\n", i + 1));
            }
        }

        if !self.recommendations.is_empty() {
            out.push_str("\n── Recommendations ──\n");
            for (i, r) in self.recommendations.iter().enumerate() {
                out.push_str(&format!("  {}. {r}\n", i + 1));
            }
        }

        out.push_str("\n═══ END OF REPORT ═══\n");
        out
    }

    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
            .with_context(|| format!("cannot write report to {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventType, OsType, ProcessContext, FileContext, FileAction};
    use tempfile::TempDir;

    fn proc_event() -> NormalizedEvent {
        NormalizedEvent::new("ep1".into(), OsType::Linux, EventType::Process, Severity::High)
            .with_process(ProcessContext {
                pid: 42, ppid: Some(1), name: "bash".into(),
                exe: None, cmdline: None, uid: None, username: None,
                start_time: None, children_pids: vec![],
            })
    }

    fn file_event() -> NormalizedEvent {
        NormalizedEvent::new("ep1".into(), OsType::Linux, EventType::File, Severity::Medium)
            .with_file(FileContext {
                path: "/etc/shadow".into(), action: FileAction::Modify,
                sha256: None, size_bytes: None, owner_uid: None, permissions: None,
            })
    }

    #[test]
    fn timeline_ordering() {
        let mut builder = TimelineBuilder::new();
        let e1 = proc_event();
        let e2 = file_event();
        builder.add_event(&e1);
        builder.add_event(&e2);

        let timeline = builder.build();
        assert_eq!(timeline.len(), 2);
        assert!(timeline[0].timestamp <= timeline[1].timestamp);
    }

    #[test]
    fn timeline_with_alerts() {
        let mut builder = TimelineBuilder::new();
        let alert = Alert::from_rule(
            Uuid::new_v4(), "R001", Severity::High,
            "Brute-force".into(), "5 failures".into(), 0.9,
        );
        builder.add_alert(&alert);
        assert_eq!(builder.entry_count(), 1);
        let entries = builder.build();
        assert_eq!(entries[0].kind, TimelineKind::Alert);
    }

    #[test]
    fn timeline_range_filter() {
        let mut builder = TimelineBuilder::new();
        let now = Utc::now();
        builder.add_action(now, "blocked IP", Severity::High);
        builder.add_action(
            now + chrono::Duration::hours(2),
            "unblocked IP",
            Severity::Info,
        );

        let range = builder.build_range(
            now - chrono::Duration::minutes(1),
            now + chrono::Duration::minutes(1),
        );
        assert_eq!(range.len(), 1);
    }

    #[test]
    fn evidence_collector() {
        let mut collector = EvidenceCollector::new();
        let events = vec![proc_event()];
        collector.add_event_log(&events, "suspicious processes");
        collector.add_raw(EvidenceKind::CommandOutput, "ps aux", "USER PID ...");

        assert_eq!(collector.count(), 2);
        assert!(collector.items()[0].sha256.is_some());
    }

    #[test]
    fn evidence_file_snapshot() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("config.txt");
        fs::write(&file, "key=value").unwrap();

        let mut collector = EvidenceCollector::new();
        collector.add_file_snapshot(&file).unwrap();
        assert_eq!(collector.count(), 1);
        assert!(collector.items()[0].data.contains("key=value"));
    }

    #[test]
    fn forensic_report_generation() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(&proc_event());
        builder.add_event(&file_event());

        let mut collector = EvidenceCollector::new();
        collector.add_raw(EvidenceKind::CommandOutput, "netstat", "tcp 0.0.0.0:22");

        let mut report = ForensicReport::new("Incident #42", "ep1")
            .with_summary("Unauthorized access detected")
            .with_timeline(builder.build())
            .with_evidence(collector.items().to_vec());
        report.add_finding("Attacker gained shell access via SSH brute-force");
        report.add_recommendation("Reset root password and rotate SSH keys");

        let text = report.to_text();
        assert!(text.contains("Incident #42"));
        assert!(text.contains("Unauthorized access"));
        assert!(text.contains("Attacker gained shell"));
        assert!(text.contains("Reset root password"));
    }

    #[test]
    fn forensic_report_save_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.json");

        let report = ForensicReport::new("Test", "ep1")
            .with_summary("test summary");
        report.save_json(&path).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let restored: ForensicReport = serde_json::from_str(&content).unwrap();
        assert_eq!(restored.title, "Test");
    }

    #[test]
    fn event_summary_formats() {
        let builder = TimelineBuilder::new();
        let s = TimelineBuilder::summarize_event(&proc_event());
        assert!(s.contains("bash"));
        assert!(s.contains("42"));

        let s2 = TimelineBuilder::summarize_event(&file_event());
        assert!(s2.contains("shadow"));

        let _ = builder;
    }
}
