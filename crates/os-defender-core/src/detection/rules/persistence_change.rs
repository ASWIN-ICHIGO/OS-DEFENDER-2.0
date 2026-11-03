use crate::events::{EventType, FileAction, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

/// Detects modifications to Linux persistence mechanisms.
/// MITRE ATT&CK: T1053.003 (Cron), T1543.002 (Systemd Service), T1546.004 (Unix Shell Config)
pub struct PersistenceChangeRule {
    persistence_patterns: Vec<PersistencePattern>,
}

struct PersistencePattern {
    path_contains: &'static str,
    technique: &'static str,
    description: &'static str,
    severity: Severity,
}

impl Default for PersistenceChangeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceChangeRule {
    pub fn new() -> Self {
        Self {
            persistence_patterns: vec![
                PersistencePattern {
                    path_contains: "/etc/systemd/system/",
                    technique: "T1543.002",
                    description: "systemd system service",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/.config/systemd/user/",
                    technique: "T1543.002",
                    description: "systemd user service",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/etc/cron",
                    technique: "T1053.003",
                    description: "system cron",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/var/spool/cron/",
                    technique: "T1053.003",
                    description: "user crontab",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/.bashrc",
                    technique: "T1546.004",
                    description: "bash startup config",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/.bash_profile",
                    technique: "T1546.004",
                    description: "bash login config",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/.profile",
                    technique: "T1546.004",
                    description: "shell profile",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/.zshrc",
                    technique: "T1546.004",
                    description: "zsh startup config",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/etc/profile.d/",
                    technique: "T1546.004",
                    description: "system-wide shell profile drop-in",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/etc/ld.so.preload",
                    technique: "T1574.006",
                    description: "shared library preload hijack",
                    severity: Severity::Critical,
                },
                PersistencePattern {
                    path_contains: "/etc/init.d/",
                    technique: "T1037.004",
                    description: "init script",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/.ssh/authorized_keys",
                    technique: "T1098.004",
                    description: "SSH authorized keys",
                    severity: Severity::High,
                },
                PersistencePattern {
                    path_contains: "/etc/xdg/autostart/",
                    technique: "T1547.001",
                    description: "XDG desktop autostart",
                    severity: Severity::Medium,
                },
                PersistencePattern {
                    path_contains: "/.config/autostart/",
                    technique: "T1547.001",
                    description: "user desktop autostart",
                    severity: Severity::Medium,
                },
            ],
        }
    }
}

impl Rule for PersistenceChangeRule {
    fn id(&self) -> &str { "R005-persistence-change" }
    fn name(&self) -> &str { "Persistence Mechanism Modification" }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::File {
            return None;
        }
        let file = event.file_context.as_ref()?;

        match file.action {
            FileAction::Create | FileAction::Modify | FileAction::Delete | FileAction::Permission => {}
            _ => return None,
        }

        for pat in &self.persistence_patterns {
            if file.path.contains(pat.path_contains) {
                return Some(
                    Alert::from_rule(
                        event.event_id,
                        self.id(),
                        pat.severity,
                        format!("Persistence {:?}: {}", file.action, file.path),
                        format!(
                            "{} '{}' was {:?} — this is a {} persistence mechanism",
                            pat.description, file.path, file.action, pat.description
                        ),
                        0.8,
                    )
                    .with_factor("persistence_type", 1.0, pat.description)
                    .with_factor("action", 1.0, &format!("{:?}", file.action))
                    .with_mitre(pat.technique),
                );
            }
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
    fn detects_systemd_service_creation() {
        let mut rule = PersistenceChangeRule::new();
        let alert = rule.evaluate(&file_event(
            "/etc/systemd/system/backdoor.service",
            FileAction::Create,
        )).unwrap();
        assert_eq!(alert.severity, Severity::High);
        assert!(alert.mitre_techniques.contains(&"T1543.002".to_string()));
    }

    #[test]
    fn detects_crontab_modification() {
        let mut rule = PersistenceChangeRule::new();
        let alert = rule.evaluate(&file_event(
            "/var/spool/cron/crontabs/root",
            FileAction::Modify,
        )).unwrap();
        assert_eq!(alert.severity, Severity::High);
        assert!(alert.mitre_techniques.contains(&"T1053.003".to_string()));
    }

    #[test]
    fn detects_bashrc_modification() {
        let mut rule = PersistenceChangeRule::new();
        let alert = rule.evaluate(&file_event(
            "/home/user/.bashrc",
            FileAction::Modify,
        )).unwrap();
        assert_eq!(alert.severity, Severity::Medium);
        assert!(alert.mitre_techniques.contains(&"T1546.004".to_string()));
    }

    #[test]
    fn detects_ld_preload_hijack() {
        let mut rule = PersistenceChangeRule::new();
        let alert = rule.evaluate(&file_event(
            "/etc/ld.so.preload",
            FileAction::Create,
        )).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.mitre_techniques.contains(&"T1574.006".to_string()));
    }

    #[test]
    fn detects_authorized_keys() {
        let mut rule = PersistenceChangeRule::new();
        let alert = rule.evaluate(&file_event(
            "/home/admin/.ssh/authorized_keys",
            FileAction::Modify,
        )).unwrap();
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn ignores_normal_file() {
        let mut rule = PersistenceChangeRule::new();
        assert!(rule.evaluate(&file_event("/tmp/test.txt", FileAction::Create)).is_none());
    }

    #[test]
    fn ignores_read_access() {
        let mut rule = PersistenceChangeRule::new();
        assert!(rule.evaluate(&file_event("/etc/cron.d/something", FileAction::Access)).is_none());
    }
}
