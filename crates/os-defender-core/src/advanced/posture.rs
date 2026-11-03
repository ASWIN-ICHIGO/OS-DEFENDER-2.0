use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureCheck {
    pub id: String,
    pub category: String,
    pub description: String,
    pub status: CheckStatus,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub assessed_at: DateTime<Utc>,
    pub endpoint_id: String,
    pub checks: Vec<PostureCheck>,
    pub score: f64,
    pub grade: String,
}

impl PostureReport {
    pub fn pass_count(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Pass).count()
    }
    pub fn fail_count(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Fail).count()
    }
    pub fn warn_count(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Warn).count()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("═══ Security Posture: {} ═══\n", self.endpoint_id));
        out.push_str(&format!("Grade: {}  Score: {:.0}%\n", self.grade, self.score));
        out.push_str(&format!("Assessed: {}\n\n", self.assessed_at.to_rfc3339()));

        for check in &self.checks {
            let icon = match check.status {
                CheckStatus::Pass => "+",
                CheckStatus::Warn => "~",
                CheckStatus::Fail => "!",
                CheckStatus::Skipped => "-",
            };
            out.push_str(&format!("[{icon}] {} — {}\n", check.id, check.description));
            if check.status != CheckStatus::Pass && check.status != CheckStatus::Skipped {
                out.push_str(&format!("    Detail: {}\n", check.detail));
                out.push_str(&format!("    Fix: {}\n", check.remediation));
            }
        }
        out
    }
}

pub struct PostureAssessor {
    endpoint_id: String,
}

impl PostureAssessor {
    pub fn new(endpoint_id: &str) -> Self {
        Self {
            endpoint_id: endpoint_id.to_string(),
        }
    }

    pub fn assess(&self) -> PostureReport {
        let checks = vec![
            self.check_shadow_permissions(),
            self.check_sshd_root_login(),
            self.check_sshd_password_auth(),
            self.check_firewall_active(),
            self.check_suid_audit(),
            self.check_tmp_noexec(),
            self.check_core_dumps_disabled(),
            self.check_kernel_aslr(),
            self.check_unattended_upgrades(),
            self.check_no_empty_passwords(),
        ];

        let total = checks.iter().filter(|c| c.status != CheckStatus::Skipped).count();
        let passed = checks.iter().filter(|c| c.status == CheckStatus::Pass).count();
        let score = if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 };

        let grade = match score as u32 {
            90..=100 => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        }.to_string();

        PostureReport {
            assessed_at: Utc::now(),
            endpoint_id: self.endpoint_id.clone(),
            checks,
            score,
            grade,
        }
    }

    fn check_shadow_permissions(&self) -> PostureCheck {
        let path = Path::new("/etc/shadow");
        if !path.exists() {
            return PostureCheck {
                id: "SEC-001".into(),
                category: "file-permissions".into(),
                description: "/etc/shadow file permissions".into(),
                status: CheckStatus::Skipped,
                detail: "File does not exist".into(),
                remediation: String::new(),
            };
        }

        let status = match fs::metadata(path) {
            Ok(meta) => {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode <= 0o640 {
                        CheckStatus::Pass
                    } else {
                        CheckStatus::Fail
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = meta;
                    CheckStatus::Skipped
                }
            }
            Err(_) => CheckStatus::Skipped,
        };

        PostureCheck {
            id: "SEC-001".into(),
            category: "file-permissions".into(),
            description: "/etc/shadow restricted to root".into(),
            status,
            detail: "Shadow file should be mode 0640 or stricter".into(),
            remediation: "chmod 640 /etc/shadow".into(),
        }
    }

    fn check_sshd_root_login(&self) -> PostureCheck {
        self.check_sshd_config(
            "SEC-002",
            "PermitRootLogin",
            &["no", "prohibit-password"],
            "SSH root login disabled",
            "Set PermitRootLogin no in /etc/ssh/sshd_config",
        )
    }

    fn check_sshd_password_auth(&self) -> PostureCheck {
        self.check_sshd_config(
            "SEC-003",
            "PasswordAuthentication",
            &["no"],
            "SSH password authentication disabled",
            "Set PasswordAuthentication no in /etc/ssh/sshd_config",
        )
    }

    fn check_sshd_config(
        &self,
        id: &str,
        directive: &str,
        safe_values: &[&str],
        description: &str,
        remediation: &str,
    ) -> PostureCheck {
        let config = Path::new("/etc/ssh/sshd_config");
        if !config.exists() {
            return PostureCheck {
                id: id.into(),
                category: "ssh".into(),
                description: description.into(),
                status: CheckStatus::Skipped,
                detail: "sshd_config not found".into(),
                remediation: String::new(),
            };
        }

        let content = match fs::read_to_string(config) {
            Ok(c) => c,
            Err(_) => {
                return PostureCheck {
                    id: id.into(),
                    category: "ssh".into(),
                    description: description.into(),
                    status: CheckStatus::Skipped,
                    detail: "cannot read sshd_config".into(),
                    remediation: String::new(),
                };
            }
        };

        let value = content
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(directive) {
                    Some(parts[1].to_lowercase())
                } else {
                    None
                }
            });

        let status = match &value {
            Some(v) if safe_values.iter().any(|sv| sv.eq_ignore_ascii_case(v)) => CheckStatus::Pass,
            Some(_) => CheckStatus::Fail,
            None => CheckStatus::Warn,
        };

        PostureCheck {
            id: id.into(),
            category: "ssh".into(),
            description: description.into(),
            status,
            detail: format!("{directive} = {}", value.unwrap_or_else(|| "(not set)".into())),
            remediation: remediation.into(),
        }
    }

    fn check_firewall_active(&self) -> PostureCheck {
        let nft_exists = Path::new("/usr/sbin/nft").exists() || Path::new("/sbin/nft").exists();
        let ipt_exists = Path::new("/usr/sbin/iptables").exists() || Path::new("/sbin/iptables").exists();

        let status = if nft_exists || ipt_exists {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        };

        PostureCheck {
            id: "SEC-004".into(),
            category: "network".into(),
            description: "Firewall tooling installed".into(),
            status,
            detail: format!("nftables={nft_exists}, iptables={ipt_exists}"),
            remediation: "Install and configure nftables or iptables".into(),
        }
    }

    fn check_suid_audit(&self) -> PostureCheck {
        let known_suid = [
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
            "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/chsh",
            "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chfn",
        ];

        let mut unexpected = Vec::new();
        for dir in &["/usr/bin", "/usr/sbin"] {
            let Ok(read_dir) = fs::read_dir(dir) else { continue };
            for entry in read_dir.flatten() {
                let path = entry.path();
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.permissions().mode();
                        if mode & 0o4000 != 0 {
                            let p = path.to_string_lossy().to_string();
                            if !known_suid.iter().any(|k| p == *k) {
                                unexpected.push(p);
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                { let _ = &path; }
            }
        }

        let status = if unexpected.is_empty() {
            CheckStatus::Pass
        } else if unexpected.len() <= 3 {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        };

        PostureCheck {
            id: "SEC-005".into(),
            category: "file-permissions".into(),
            description: "No unexpected SUID binaries".into(),
            status,
            detail: if unexpected.is_empty() {
                "All SUID binaries are known".into()
            } else {
                format!("Unexpected SUID: {}", unexpected.join(", "))
            },
            remediation: "Remove SUID bit from unnecessary binaries: chmod u-s <path>".into(),
        }
    }

    fn check_tmp_noexec(&self) -> PostureCheck {
        let content = fs::read_to_string("/proc/mounts").unwrap_or_default();
        let tmp_mount = content.lines().find(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == "/tmp"
        });

        let status = match tmp_mount {
            Some(line) if line.contains("noexec") => CheckStatus::Pass,
            Some(_) => CheckStatus::Warn,
            None => CheckStatus::Skipped,
        };

        PostureCheck {
            id: "SEC-006".into(),
            category: "filesystem".into(),
            description: "/tmp mounted with noexec".into(),
            status,
            detail: tmp_mount.unwrap_or("not a separate mount").to_string(),
            remediation: "Add noexec option to /tmp mount in /etc/fstab".into(),
        }
    }

    fn check_core_dumps_disabled(&self) -> PostureCheck {
        let limits = fs::read_to_string("/etc/security/limits.conf").unwrap_or_default();
        let has_limit = limits.lines().any(|l| {
            !l.starts_with('#') && l.contains("core") && l.contains('0')
        });

        let sysctl = fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_default();
        let piped_to_null = sysctl.trim() == "|/bin/false" || sysctl.trim() == "/dev/null";

        let status = if has_limit || piped_to_null {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        };

        PostureCheck {
            id: "SEC-007".into(),
            category: "system".into(),
            description: "Core dumps restricted".into(),
            status,
            detail: format!("limits.conf={has_limit}, core_pattern={}", sysctl.trim()),
            remediation: "Add '* hard core 0' to /etc/security/limits.conf".into(),
        }
    }

    fn check_kernel_aslr(&self) -> PostureCheck {
        let value = fs::read_to_string("/proc/sys/kernel/randomize_va_space")
            .unwrap_or_default()
            .trim()
            .to_string();

        let status = match value.as_str() {
            "2" => CheckStatus::Pass,
            "1" => CheckStatus::Warn,
            "0" => CheckStatus::Fail,
            _ => CheckStatus::Skipped,
        };

        PostureCheck {
            id: "SEC-008".into(),
            category: "kernel".into(),
            description: "Kernel ASLR enabled (full randomization)".into(),
            status,
            detail: format!("randomize_va_space = {value}"),
            remediation: "echo 2 > /proc/sys/kernel/randomize_va_space".into(),
        }
    }

    fn check_unattended_upgrades(&self) -> PostureCheck {
        let apt_conf = Path::new("/etc/apt/apt.conf.d/20auto-upgrades");
        let pacman_conf = Path::new("/etc/pacman.conf");

        if apt_conf.exists() {
            let content = fs::read_to_string(apt_conf).unwrap_or_default();
            let enabled = content.contains("\"1\"") || content.contains("\"true\"");
            return PostureCheck {
                id: "SEC-009".into(),
                category: "updates".into(),
                description: "Automatic security updates enabled".into(),
                status: if enabled { CheckStatus::Pass } else { CheckStatus::Warn },
                detail: "APT unattended-upgrades".into(),
                remediation: "Enable unattended-upgrades for security patches".into(),
            };
        }

        if pacman_conf.exists() {
            return PostureCheck {
                id: "SEC-009".into(),
                category: "updates".into(),
                description: "Automatic security updates".into(),
                status: CheckStatus::Warn,
                detail: "Arch-based: manual updates required".into(),
                remediation: "Run pacman -Syu regularly or configure pacman-contrib timer".into(),
            };
        }

        PostureCheck {
            id: "SEC-009".into(),
            category: "updates".into(),
            description: "Automatic security updates".into(),
            status: CheckStatus::Skipped,
            detail: "Package manager not detected".into(),
            remediation: String::new(),
        }
    }

    fn check_no_empty_passwords(&self) -> PostureCheck {
        let shadow = match fs::read_to_string("/etc/shadow") {
            Ok(c) => c,
            Err(_) => {
                return PostureCheck {
                    id: "SEC-010".into(),
                    category: "authentication".into(),
                    description: "No accounts with empty passwords".into(),
                    status: CheckStatus::Skipped,
                    detail: "Cannot read /etc/shadow (need root)".into(),
                    remediation: String::new(),
                };
            }
        };

        let empty_pw: Vec<&str> = shadow
            .lines()
            .filter_map(|l| {
                let parts: Vec<&str> = l.splitn(3, ':').collect();
                if parts.len() >= 2 && parts[1].is_empty() {
                    Some(parts[0])
                } else {
                    None
                }
            })
            .collect();

        let status = if empty_pw.is_empty() { CheckStatus::Pass } else { CheckStatus::Fail };

        PostureCheck {
            id: "SEC-010".into(),
            category: "authentication".into(),
            description: "No accounts with empty passwords".into(),
            status,
            detail: if empty_pw.is_empty() {
                "All accounts have passwords or are locked".into()
            } else {
                format!("Empty passwords: {}", empty_pw.join(", "))
            },
            remediation: "Lock or set passwords for accounts: passwd -l <user>".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_assessment_runs() {
        let assessor = PostureAssessor::new("test-ep");
        let report = assessor.assess();
        assert_eq!(report.checks.len(), 10);
        assert!(report.score >= 0.0 && report.score <= 100.0);
        assert!(!report.grade.is_empty());
    }

    #[test]
    fn grade_calculation() {
        let assessor = PostureAssessor::new("test-ep");
        let report = assessor.assess();
        match report.score as u32 {
            90..=100 => assert_eq!(report.grade, "A"),
            80..=89 => assert_eq!(report.grade, "B"),
            70..=79 => assert_eq!(report.grade, "C"),
            60..=69 => assert_eq!(report.grade, "D"),
            _ => assert_eq!(report.grade, "F"),
        }
    }

    #[test]
    fn report_text_format() {
        let assessor = PostureAssessor::new("test-ep");
        let report = assessor.assess();
        let text = report.to_text();
        assert!(text.contains("Security Posture"));
        assert!(text.contains("Grade:"));
        assert!(text.contains("SEC-001"));
    }

    #[test]
    fn check_status_display() {
        assert_eq!(CheckStatus::Pass.to_string(), "PASS");
        assert_eq!(CheckStatus::Fail.to_string(), "FAIL");
        assert_eq!(CheckStatus::Warn.to_string(), "WARN");
        assert_eq!(CheckStatus::Skipped.to_string(), "SKIP");
    }

    #[test]
    fn posture_check_serialization() {
        let check = PostureCheck {
            id: "SEC-001".into(),
            category: "test".into(),
            description: "test check".into(),
            status: CheckStatus::Pass,
            detail: "all good".into(),
            remediation: "none needed".into(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let restored: PostureCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.status, CheckStatus::Pass);
    }

    #[test]
    fn report_counters() {
        let report = PostureReport {
            assessed_at: Utc::now(),
            endpoint_id: "ep".into(),
            checks: vec![
                PostureCheck {
                    id: "1".into(), category: "a".into(), description: "a".into(),
                    status: CheckStatus::Pass, detail: "".into(), remediation: "".into(),
                },
                PostureCheck {
                    id: "2".into(), category: "b".into(), description: "b".into(),
                    status: CheckStatus::Fail, detail: "".into(), remediation: "".into(),
                },
                PostureCheck {
                    id: "3".into(), category: "c".into(), description: "c".into(),
                    status: CheckStatus::Warn, detail: "".into(), remediation: "".into(),
                },
            ],
            score: 33.3,
            grade: "F".into(),
        };
        assert_eq!(report.pass_count(), 1);
        assert_eq!(report.fail_count(), 1);
        assert_eq!(report.warn_count(), 1);
    }
}
