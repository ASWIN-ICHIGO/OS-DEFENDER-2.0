use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    SystemdService,
    SystemdTimer,
    CronJob,
    ShellRcFile,
    InitScript,
    XdgAutostart,
    UdevRule,
    #[cfg(target_os = "windows")]
    RegistryRunKey,
    #[cfg(target_os = "windows")]
    ScheduledTask,
    #[cfg(target_os = "windows")]
    WindowsService,
    #[cfg(target_os = "windows")]
    StartupFolder,
}

impl std::fmt::Display for PersistenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemdService => write!(f, "systemd-service"),
            Self::SystemdTimer => write!(f, "systemd-timer"),
            Self::CronJob => write!(f, "cron-job"),
            Self::ShellRcFile => write!(f, "shell-rc"),
            Self::InitScript => write!(f, "init-script"),
            Self::XdgAutostart => write!(f, "xdg-autostart"),
            Self::UdevRule => write!(f, "udev-rule"),
            #[cfg(target_os = "windows")]
            Self::RegistryRunKey => write!(f, "registry-run-key"),
            #[cfg(target_os = "windows")]
            Self::ScheduledTask => write!(f, "scheduled-task"),
            #[cfg(target_os = "windows")]
            Self::WindowsService => write!(f, "windows-service"),
            #[cfg(target_os = "windows")]
            Self::StartupFolder => write!(f, "startup-folder"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceRisk {
    Known,
    Suspicious,
    HighRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub kind: PersistenceKind,
    pub name: String,
    pub path: PathBuf,
    pub risk: PersistenceRisk,
    pub detail: String,
    pub mitre_technique: String,
    pub discovered_at: DateTime<Utc>,
}

// --- Linux persistence scanner ---

pub struct LinuxPersistenceScanner {
    known_services: Vec<&'static str>,
}

impl Default for LinuxPersistenceScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPersistenceScanner {
    pub fn new() -> Self {
        Self {
            known_services: vec![
                "systemd-", "dbus", "NetworkManager", "sshd", "cron",
                "rsyslog", "snapd", "bluetooth", "cups", "avahi",
                "polkit", "upower", "udisks", "accounts-daemon",
                "ModemManager", "thermald", "fwupd",
            ],
        }
    }

    pub fn scan(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();
        self.scan_systemd_services(&mut entries);
        self.scan_cron(&mut entries);
        self.scan_shell_rc(&mut entries);
        self.scan_init_scripts(&mut entries);
        self.scan_xdg_autostart(&mut entries);
        self.scan_udev_rules(&mut entries);
        entries
    }

    fn scan_systemd_services(&self, entries: &mut Vec<PersistenceEntry>) {
        let dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/usr/local/lib/systemd/system",
        ];
        // User-level
        if let Ok(home) = std::env::var("HOME") {
            let user_dir = PathBuf::from(&home).join(".config/systemd/user");
            self.scan_dir_for_services(&user_dir, entries);
        }
        for dir in &dirs {
            self.scan_dir_for_services(Path::new(dir), entries);
        }
    }

    fn scan_dir_for_services(&self, dir: &Path, entries: &mut Vec<PersistenceEntry>) {
        let Ok(read_dir) = std::fs::read_dir(dir) else { return };
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !(name.ends_with(".service") || name.ends_with(".timer")) {
                continue;
            }
            let kind = if name.ends_with(".timer") {
                PersistenceKind::SystemdTimer
            } else {
                PersistenceKind::SystemdService
            };
            let risk = if self.is_known_service(&name) {
                PersistenceRisk::Known
            } else {
                PersistenceRisk::Suspicious
            };
            entries.push(PersistenceEntry {
                kind,
                name: name.clone(),
                path: entry.path(),
                risk,
                detail: format!("systemd unit: {name}"),
                mitre_technique: "T1543.002".into(),
                discovered_at: Utc::now(),
            });
        }
    }

    fn scan_cron(&self, entries: &mut Vec<PersistenceEntry>) {
        let dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
        let files = ["/etc/crontab"];

        for f in &files {
            let p = Path::new(f);
            if p.exists() {
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::CronJob,
                    name: f.to_string(),
                    path: p.to_path_buf(),
                    risk: PersistenceRisk::Known,
                    detail: "system crontab".into(),
                    mitre_technique: "T1053.003".into(),
                    discovered_at: Utc::now(),
                });
            }
        }

        for dir in &dirs {
            let Ok(read_dir) = std::fs::read_dir(dir) else { continue };
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::CronJob,
                    name: name.clone(),
                    path: entry.path(),
                    risk: PersistenceRisk::Suspicious,
                    detail: format!("cron script: {name}"),
                    mitre_technique: "T1053.003".into(),
                    discovered_at: Utc::now(),
                });
            }
        }

        // User crontabs
        let spool = Path::new("/var/spool/cron/crontabs");
        if let Ok(read_dir) = std::fs::read_dir(spool) {
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::CronJob,
                    name: format!("user-crontab:{name}"),
                    path: entry.path(),
                    risk: PersistenceRisk::Suspicious,
                    detail: format!("user crontab for {name}"),
                    mitre_technique: "T1053.003".into(),
                    discovered_at: Utc::now(),
                });
            }
        }
    }

    fn scan_shell_rc(&self, entries: &mut Vec<PersistenceEntry>) {
        let global = ["/etc/bash.bashrc", "/etc/profile", "/etc/zsh/zshrc", "/etc/environment"];
        for f in &global {
            let p = Path::new(f);
            if p.exists() {
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::ShellRcFile,
                    name: f.to_string(),
                    path: p.to_path_buf(),
                    risk: PersistenceRisk::Known,
                    detail: "global shell config".into(),
                    mitre_technique: "T1546.004".into(),
                    discovered_at: Utc::now(),
                });
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            let user_files = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv"];
            for f in &user_files {
                let p = PathBuf::from(&home).join(f);
                if p.exists() {
                    entries.push(PersistenceEntry {
                        kind: PersistenceKind::ShellRcFile,
                        name: f.to_string(),
                        path: p,
                        risk: PersistenceRisk::Known,
                        detail: format!("user shell config: {f}"),
                        mitre_technique: "T1546.004".into(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }
    }

    fn scan_init_scripts(&self, entries: &mut Vec<PersistenceEntry>) {
        let dir = Path::new("/etc/init.d");
        let Ok(read_dir) = std::fs::read_dir(dir) else { return };
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            entries.push(PersistenceEntry {
                kind: PersistenceKind::InitScript,
                name: name.clone(),
                path: entry.path(),
                risk: PersistenceRisk::Suspicious,
                detail: format!("SysV init script: {name}"),
                mitre_technique: "T1037.004".into(),
                discovered_at: Utc::now(),
            });
        }
    }

    fn scan_xdg_autostart(&self, entries: &mut Vec<PersistenceEntry>) {
        let dirs = ["/etc/xdg/autostart"];
        let mut all_dirs: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();
        if let Ok(home) = std::env::var("HOME") {
            all_dirs.push(PathBuf::from(home).join(".config/autostart"));
        }
        for dir in &all_dirs {
            let Ok(read_dir) = std::fs::read_dir(dir) else { continue };
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".desktop") {
                    entries.push(PersistenceEntry {
                        kind: PersistenceKind::XdgAutostart,
                        name: name.clone(),
                        path: entry.path(),
                        risk: PersistenceRisk::Suspicious,
                        detail: format!("XDG autostart entry: {name}"),
                        mitre_technique: "T1547.001".into(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }
    }

    fn scan_udev_rules(&self, entries: &mut Vec<PersistenceEntry>) {
        let dirs = ["/etc/udev/rules.d", "/usr/lib/udev/rules.d"];
        for dir in &dirs {
            let Ok(read_dir) = std::fs::read_dir(dir) else { continue };
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".rules") {
                    entries.push(PersistenceEntry {
                        kind: PersistenceKind::UdevRule,
                        name: name.clone(),
                        path: entry.path(),
                        risk: PersistenceRisk::Known,
                        detail: format!("udev rule: {name}"),
                        mitre_technique: "T1546.003".into(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }
    }

    fn is_known_service(&self, name: &str) -> bool {
        self.known_services.iter().any(|k| name.starts_with(k))
    }
}

// --- Windows persistence scanner (compile-time gated) ---

#[cfg(target_os = "windows")]
pub struct WindowsPersistenceScanner;

#[cfg(target_os = "windows")]
impl WindowsPersistenceScanner {
    pub fn new() -> Self { Self }

    pub fn scan(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();
        self.scan_run_keys(&mut entries);
        self.scan_startup_folder(&mut entries);
        self.scan_scheduled_tasks(&mut entries);
        entries
    }

    fn scan_run_keys(&self, entries: &mut Vec<PersistenceEntry>) {
        let keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ];
        for key in &keys {
            entries.push(PersistenceEntry {
                kind: PersistenceKind::RegistryRunKey,
                name: key.to_string(),
                path: PathBuf::from(key),
                risk: PersistenceRisk::Suspicious,
                detail: format!("Registry autorun key: {key}"),
                mitre_technique: "T1547.001".into(),
                discovered_at: Utc::now(),
            });
        }
    }

    fn scan_startup_folder(&self, entries: &mut Vec<PersistenceEntry>) {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup = PathBuf::from(&appdata)
                .join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(read_dir) = std::fs::read_dir(&startup) {
                for entry in read_dir.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    entries.push(PersistenceEntry {
                        kind: PersistenceKind::StartupFolder,
                        name: name.clone(),
                        path: entry.path(),
                        risk: PersistenceRisk::Suspicious,
                        detail: format!("Startup folder item: {name}"),
                        mitre_technique: "T1547.001".into(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }
    }

    fn scan_scheduled_tasks(&self, entries: &mut Vec<PersistenceEntry>) {
        let tasks_dir = Path::new(r"C:\Windows\System32\Tasks");
        if let Ok(read_dir) = std::fs::read_dir(tasks_dir) {
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::ScheduledTask,
                    name: name.clone(),
                    path: entry.path(),
                    risk: PersistenceRisk::Suspicious,
                    detail: format!("Scheduled task: {name}"),
                    mitre_technique: "T1053.005".into(),
                    discovered_at: Utc::now(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_kind_display() {
        assert_eq!(PersistenceKind::SystemdService.to_string(), "systemd-service");
        assert_eq!(PersistenceKind::CronJob.to_string(), "cron-job");
        assert_eq!(PersistenceKind::ShellRcFile.to_string(), "shell-rc");
        assert_eq!(PersistenceKind::UdevRule.to_string(), "udev-rule");
    }

    #[test]
    fn linux_scanner_runs() {
        let scanner = LinuxPersistenceScanner::new();
        let entries = scanner.scan();
        // On any Linux system, we should find at least some shell configs
        // This test just verifies the scanner doesn't panic
        assert!(entries.iter().all(|e| !e.mitre_technique.is_empty()));
    }

    #[test]
    fn known_service_detection() {
        let scanner = LinuxPersistenceScanner::new();
        assert!(scanner.is_known_service("systemd-journald.service"));
        assert!(scanner.is_known_service("dbus.service"));
        assert!(!scanner.is_known_service("evil-backdoor.service"));
    }

    #[test]
    fn persistence_entry_serialization() {
        let entry = PersistenceEntry {
            kind: PersistenceKind::CronJob,
            name: "backup".into(),
            path: PathBuf::from("/etc/cron.d/backup"),
            risk: PersistenceRisk::Suspicious,
            detail: "cron job".into(),
            mitre_technique: "T1053.003".into(),
            discovered_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: PersistenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "backup");
        assert_eq!(restored.kind, PersistenceKind::CronJob);
    }
}
