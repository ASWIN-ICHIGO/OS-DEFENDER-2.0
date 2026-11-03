use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::events::{EventType, FileAction, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

/// Detects tampering with security-sensitive files and rapid bulk modifications.
/// MITRE ATT&CK: T1565.001 (Stored Data Manipulation), T1486 (Data Encrypted for Impact)
pub struct FileTamperingRule {
    sensitive_paths: Vec<&'static str>,
    // Track rapid modifications per directory for ransomware-like detection
    mod_counts: HashMap<String, Vec<DateTime<Utc>>>,
    rapid_threshold: usize,
    rapid_window_secs: i64,
}

impl Default for FileTamperingRule {
    fn default() -> Self {
        Self::new()
    }
}

impl FileTamperingRule {
    pub fn new() -> Self {
        Self {
            sensitive_paths: vec![
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/etc/pam.d/",
                "/etc/systemd/",
                "/etc/cron",
                "/etc/ld.so.preload",
                "/etc/ld.so.conf",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/root/.ssh/",
                "/home/",  // catches ~/.ssh/authorized_keys
                "/.bashrc",
                "/.bash_profile",
                "/.profile",
                "/.zshrc",
            ],
            mod_counts: HashMap::new(),
            rapid_threshold: 20,
            rapid_window_secs: 10,
        }
    }

    fn is_sensitive(&self, path: &str) -> Option<&'static str> {
        for &sp in &self.sensitive_paths {
            if path.starts_with(sp) || path.contains(sp) {
                return Some(sp);
            }
        }
        // authorized_keys anywhere
        if path.ends_with("/authorized_keys") || path.ends_with("/authorized_keys2") {
            return Some("authorized_keys");
        }
        None
    }

    fn track_rapid_modification(&mut self, path: &str, ts: DateTime<Utc>) -> Option<(String, usize)> {
        // extract parent directory
        let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or(path).to_string();

        let entry = self.mod_counts.entry(dir.clone()).or_default();
        entry.push(ts);

        let cutoff = ts - chrono::Duration::seconds(self.rapid_window_secs);
        entry.retain(|t| *t > cutoff);
        let count = entry.len();

        // GC
        if self.mod_counts.len() > 500 {
            self.mod_counts.retain(|_, v| {
                v.last().is_some_and(|t| *t > cutoff)
            });
        }

        if count >= self.rapid_threshold {
            Some((dir, count))
        } else {
            None
        }
    }
}

impl Rule for FileTamperingRule {
    fn id(&self) -> &str { "R003-file-tampering" }
    fn name(&self) -> &str { "File Tampering Detection" }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::File {
            return None;
        }
        let file = event.file_context.as_ref()?;

        // Check for rapid bulk modification (ransomware indicator)
        if (file.action == FileAction::Modify || file.action == FileAction::Rename)
            && let Some((dir, count)) = self.track_rapid_modification(&file.path, event.timestamp)
        {
                return Some(
                    Alert::from_rule(
                        event.event_id,
                        self.id(),
                        Severity::Critical,
                        format!("Rapid file modifications in {dir}"),
                        format!(
                            "{count} file modifications in {dir} within {}s — possible ransomware or mass corruption",
                            self.rapid_window_secs
                        ),
                        0.7,
                    )
                    .with_factor("modification_rate", count as f64, "modifications per window")
                    .with_factor("window_seconds", self.rapid_window_secs as f64, "observation window")
                    .with_mitre("T1486"),
                );
        }

        // Check sensitive file modification
        if let Some(sensitive_match) = self.is_sensitive(&file.path) {
            let severity = match file.action {
                FileAction::Modify | FileAction::Create => {
                    if file.path.contains("shadow") || file.path.contains("sudoers")
                        || file.path.contains("authorized_keys") || file.path.contains("ld.so.preload")
                    {
                        Severity::High
                    } else {
                        Severity::Medium
                    }
                }
                FileAction::Delete => Severity::High,
                FileAction::Permission => Severity::Medium,
                _ => return None,
            };

            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    severity,
                    format!("Sensitive file {:?}: {}", file.action, file.path),
                    format!(
                        "Security-sensitive file '{}' was {:?} (matched pattern: {sensitive_match})",
                        file.path, file.action
                    ),
                    0.8,
                )
                .with_factor("sensitive_path", 1.0, sensitive_match)
                .with_factor("action", 1.0, &format!("{:?}", file.action))
                .with_mitre("T1565.001"),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{FileContext, OsType};

    fn file_event(path: &str, action: FileAction) -> NormalizedEvent {
        NormalizedEvent::new("ep".into(), OsType::Linux, EventType::File, Severity::Info)
            .with_file(FileContext {
                path: path.into(),
                action,
                sha256: None,
                size_bytes: None,
                owner_uid: None,
                permissions: None,
            })
    }

    #[test]
    fn detects_shadow_modification() {
        let mut rule = FileTamperingRule::new();
        let alert = rule.evaluate(&file_event("/etc/shadow", FileAction::Modify)).unwrap();
        assert_eq!(alert.severity, Severity::High);
        assert!(alert.mitre_techniques.contains(&"T1565.001".to_string()));
    }

    #[test]
    fn detects_authorized_keys_creation() {
        let mut rule = FileTamperingRule::new();
        let alert = rule.evaluate(&file_event("/home/user/.ssh/authorized_keys", FileAction::Create)).unwrap();
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn detects_rapid_modifications() {
        let mut rule = FileTamperingRule::new();
        rule.rapid_threshold = 5;
        let now = Utc::now();

        // Use a non-sensitive path so the sensitive-file check doesn't fire first
        for i in 0..4 {
            let mut e = file_event(&format!("/opt/data/file{i}.txt"), FileAction::Modify);
            e.timestamp = now;
            assert!(rule.evaluate(&e).is_none());
        }
        let mut e = file_event("/opt/data/file4.txt", FileAction::Modify);
        e.timestamp = now;
        let alert = rule.evaluate(&e).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.mitre_techniques.contains(&"T1486".to_string()));
    }

    #[test]
    fn ignores_normal_file() {
        let mut rule = FileTamperingRule::new();
        assert!(rule.evaluate(&file_event("/tmp/scratch.txt", FileAction::Create)).is_none());
    }
}
