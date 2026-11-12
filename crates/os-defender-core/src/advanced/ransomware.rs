use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use uuid::Uuid;

use crate::detection::{Alert, Rule};
use crate::events::{EventType, FileAction, NormalizedEvent, Severity};

// --- Canary file system ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryFile {
    pub path: PathBuf,
    pub sha256: String,
    pub deployed_at: DateTime<Utc>,
}

pub struct CanaryManager {
    canaries: Vec<CanaryFile>,
    canary_content: &'static str,
}

const CANARY_CONTENT: &str = "DO-NOT-DELETE — os-defender integrity sentinel\n";

const CANARY_NAMES: &[&str] = &[
    ".os-defender-canary",
    "IMPORTANT_DO_NOT_DELETE.docx",
    "financial_records_2025.xlsx",
];

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryManager {
    pub fn new() -> Self {
        Self {
            canaries: Vec::new(),
            canary_content: CANARY_CONTENT,
        }
    }

    pub fn deploy(&mut self, directories: &[&Path]) -> Result<Vec<CanaryFile>> {
        let mut deployed = Vec::new();
        let hash = Self::hash_content(self.canary_content.as_bytes());

        for dir in directories {
            if !dir.exists() {
                continue;
            }
            for name in CANARY_NAMES {
                let path = dir.join(name);
                if path.exists() {
                    continue;
                }
                fs::write(&path, self.canary_content)
                    .with_context(|| format!("cannot deploy canary at {}", path.display()))?;

                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o444));
                }

                let canary = CanaryFile {
                    path: path.clone(),
                    sha256: hash.clone(),
                    deployed_at: Utc::now(),
                };
                info!(path = %path.display(), "canary deployed");
                deployed.push(canary.clone());
                self.canaries.push(canary);
            }
        }
        Ok(deployed)
    }

    pub fn verify_all(&self) -> Vec<CanaryViolation> {
        let mut violations = Vec::new();
        for canary in &self.canaries {
            match self.verify_one(canary) {
                Ok(None) => {}
                Ok(Some(v)) => violations.push(v),
                Err(e) => {
                    violations.push(CanaryViolation {
                        path: canary.path.clone(),
                        kind: CanaryViolationKind::Error(e.to_string()),
                        detected_at: Utc::now(),
                    });
                }
            }
        }
        violations
    }

    fn verify_one(&self, canary: &CanaryFile) -> Result<Option<CanaryViolation>> {
        if !canary.path.exists() {
            return Ok(Some(CanaryViolation {
                path: canary.path.clone(),
                kind: CanaryViolationKind::Deleted,
                detected_at: Utc::now(),
            }));
        }

        let data = fs::read(&canary.path)?;
        let current_hash = Self::hash_content(&data);

        if current_hash != canary.sha256 {
            return Ok(Some(CanaryViolation {
                path: canary.path.clone(),
                kind: CanaryViolationKind::Modified {
                    expected_hash: canary.sha256.clone(),
                    actual_hash: current_hash,
                },
                detected_at: Utc::now(),
            }));
        }
        Ok(None)
    }

    fn hash_content(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    pub fn canaries(&self) -> &[CanaryFile] {
        &self.canaries
    }

    pub fn forget(&mut self, path: &Path) {
        self.canaries.retain(|c| c.path != path);
    }

    pub fn is_canary_path(&self, path: &str) -> bool {
        let base = Path::new(path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string());
        self.canaries.iter().any(|c| {
            c.path.to_str() == Some(path)
                || (c.path.file_name().map(|f| f.to_string_lossy().to_string()) == base
                    && base.is_some())
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryViolation {
    pub path: PathBuf,
    pub kind: CanaryViolationKind,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CanaryViolationKind {
    Deleted,
    Modified {
        expected_hash: String,
        actual_hash: String,
    },
    Error(String),
}

// --- Entropy-based detection ---

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn is_high_entropy(data: &[u8], threshold: f64) -> bool {
    shannon_entropy(data) >= threshold
}

// --- Ransomware detection rule ---

pub struct RansomwareDefenseRule {
    mod_counts: HashMap<String, Vec<DateTime<Utc>>>,
    rename_counts: HashMap<String, Vec<DateTime<Utc>>>,
    rapid_mod_threshold: usize,
    rapid_rename_threshold: usize,
    window_secs: i64,
    canary_manager: CanaryManager,
    canaries_deployed: bool,
    known_ransom_extensions: Vec<&'static str>,
}

impl Default for RansomwareDefenseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl RansomwareDefenseRule {
    pub fn new() -> Self {
        Self {
            mod_counts: HashMap::new(),
            rename_counts: HashMap::new(),
            rapid_mod_threshold: 30,
            rapid_rename_threshold: 15,
            window_secs: 10,
            canary_manager: CanaryManager::new(),
            canaries_deployed: false,
            known_ransom_extensions: vec![
                ".encrypted",
                ".locked",
                ".crypt",
                ".crypto",
                ".enc",
                ".locky",
                ".cerber",
                ".zepto",
                ".thor",
                ".aaa",
                ".abc",
                ".zzz",
                ".micro",
                ".pay",
                ".ransom",
                ".r5a",
                ".WNCRY",
                ".wnry",
            ],
        }
    }

    pub fn canary_manager(&self) -> &CanaryManager {
        &self.canary_manager
    }

    pub fn canary_manager_mut(&mut self) -> &mut CanaryManager {
        &mut self.canary_manager
    }

    fn track_modifications(&mut self, dir: &str, ts: DateTime<Utc>) -> Option<usize> {
        let entry = self.mod_counts.entry(dir.to_string()).or_default();
        entry.push(ts);
        let cutoff = ts - chrono::Duration::seconds(self.window_secs);
        entry.retain(|t| *t > cutoff);
        let count = entry.len();
        gc_map(&mut self.mod_counts, cutoff);
        if count >= self.rapid_mod_threshold {
            Some(count)
        } else {
            None
        }
    }

    fn track_renames(&mut self, dir: &str, ts: DateTime<Utc>) -> Option<usize> {
        let entry = self.rename_counts.entry(dir.to_string()).or_default();
        entry.push(ts);
        let cutoff = ts - chrono::Duration::seconds(self.window_secs);
        entry.retain(|t| *t > cutoff);
        let count = entry.len();
        gc_map(&mut self.rename_counts, cutoff);
        if count >= self.rapid_rename_threshold {
            Some(count)
        } else {
            None
        }
    }

    fn has_ransom_extension(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        self.known_ransom_extensions
            .iter()
            .any(|ext| lower.ends_with(ext))
    }

    fn parent_dir(path: &str) -> &str {
        path.rsplit_once('/')
            .map(|(d, _)| d)
            .or_else(|| path.rsplit_once('\\').map(|(d, _)| d))
            .unwrap_or(path)
    }

    fn canary_directories() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            let home = PathBuf::from(home);
            dirs.push(home.clone());
            dirs.push(home.join("Documents"));
            dirs.push(home.join("Desktop"));
        }
        dirs
    }
}

fn gc_map(map: &mut HashMap<String, Vec<DateTime<Utc>>>, cutoff: DateTime<Utc>) {
    if map.len() > 500 {
        map.retain(|_, v| v.last().is_some_and(|t| *t > cutoff));
    }
}

impl Rule for RansomwareDefenseRule {
    fn id(&self) -> &str {
        "R006-ransomware-defense"
    }
    fn name(&self) -> &str {
        "Ransomware Defense"
    }

    fn tick(&mut self) -> Vec<Alert> {
        if !self.canaries_deployed {
            self.canaries_deployed = true;
            let dirs = Self::canary_directories();
            let dir_refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
            match self.canary_manager.deploy(&dir_refs) {
                Ok(deployed) if !deployed.is_empty() => {
                    info!(count = deployed.len(), "ransomware canaries deployed");
                }
                Ok(_) => {}
                Err(e) => warn!(%e, "canary deployment failed"),
            }
            return Vec::new();
        }

        let mut alerts = Vec::new();
        for violation in self.canary_manager.verify_all() {
            warn!(path = %violation.path.display(), "canary violation");
            alerts.push(
                Alert::from_rule(
                    Uuid::new_v4(),
                    self.id(),
                    Severity::Critical,
                    "Canary file tampered — possible ransomware".into(),
                    format!(
                        "Canary sentinel '{}' was compromised — high-confidence ransomware indicator",
                        violation.path.display()
                    ),
                    0.95,
                )
                .with_factor("canary_hit", 1.0, "canary integrity check failed")
                .with_mitre("T1486"),
            );
            self.canary_manager.forget(&violation.path);
        }
        alerts
    }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::File {
            return None;
        }
        let file = event.file_context.as_ref()?;

        // Canary file tampered
        if self.canary_manager.is_canary_path(&file.path) {
            warn!(path = %file.path, "canary file touched");
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::Critical,
                    "Canary file tampered — possible ransomware".into(),
                    format!(
                        "Canary sentinel '{}' was {:?} — high-confidence ransomware indicator",
                        file.path, file.action
                    ),
                    0.95,
                )
                .with_factor("canary_hit", 1.0, "canary file was touched")
                .with_mitre("T1486"),
            );
        }

        // Known ransomware extension on rename
        if file.action == FileAction::Rename && self.has_ransom_extension(&file.path) {
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::Critical,
                    format!("Ransomware extension detected: {}", file.path),
                    format!(
                        "File renamed to known ransomware extension: '{}'",
                        file.path
                    ),
                    0.85,
                )
                .with_factor("ransom_extension", 1.0, "known ransomware file extension")
                .with_mitre("T1486"),
            );
        }

        let dir = Self::parent_dir(&file.path);

        // Rapid rename burst
        if file.action == FileAction::Rename
            && let Some(count) = self.track_renames(dir, event.timestamp)
        {
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::Critical,
                    format!("Mass file rename in {dir}"),
                    format!(
                        "{count} renames in {dir} within {}s — ransomware encryption pattern",
                        self.window_secs
                    ),
                    0.80,
                )
                .with_factor("rename_rate", count as f64, "renames per window")
                .with_mitre("T1486"),
            );
        }

        // Rapid modification burst
        if file.action == FileAction::Modify
            && let Some(count) = self.track_modifications(dir, event.timestamp)
        {
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::Critical,
                    format!("Mass file modification in {dir}"),
                    format!(
                        "{count} modifications in {dir} within {}s — possible ransomware",
                        self.window_secs
                    ),
                    0.75,
                )
                .with_factor(
                    "modification_rate",
                    count as f64,
                    "modifications per window",
                )
                .with_mitre("T1486"),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{FileContext, OsType};
    use tempfile::TempDir;

    fn file_event(path: &str, action: FileAction) -> NormalizedEvent {
        NormalizedEvent::new("ep".into(), OsType::Linux, EventType::File, Severity::Info).with_file(
            FileContext {
                path: path.into(),
                action,
                sha256: None,
                size_bytes: None,
                owner_uid: None,
                permissions: None,
            },
        )
    }

    #[test]
    fn canary_deploy_and_verify() {
        let dir = TempDir::new().unwrap();
        let mut mgr = CanaryManager::new();
        let deployed = mgr.deploy(&[dir.path()]).unwrap();
        assert_eq!(deployed.len(), CANARY_NAMES.len());

        let violations = mgr.verify_all();
        assert!(
            violations.is_empty(),
            "freshly deployed canaries should be clean"
        );

        // Tamper with one — remove readonly first
        let mut perms = fs::metadata(&deployed[0].path).unwrap().permissions();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o644);
        }
        fs::set_permissions(&deployed[0].path, perms).unwrap();
        fs::write(&deployed[0].path, "ransomware was here").unwrap();
        let violations = mgr.verify_all();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0].kind,
            CanaryViolationKind::Modified { .. }
        ));
    }

    #[test]
    fn canary_deletion_detected() {
        let dir = TempDir::new().unwrap();
        let mut mgr = CanaryManager::new();
        let deployed = mgr.deploy(&[dir.path()]).unwrap();

        fs::remove_file(&deployed[0].path).unwrap();
        let violations = mgr.verify_all();
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0].kind, CanaryViolationKind::Deleted));
    }

    #[test]
    fn shannon_entropy_values() {
        assert!((shannon_entropy(b"aaaa") - 0.0).abs() < 0.001);
        let random_like: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&random_like);
        assert!(
            e > 7.9,
            "uniform distribution should have ~8 bits entropy, got {e}"
        );
    }

    #[test]
    fn high_entropy_detection() {
        assert!(!is_high_entropy(b"hello world", 7.0));
        let random_like: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(is_high_entropy(&random_like, 7.0));
    }

    #[test]
    fn detects_ransom_extension() {
        let mut rule = RansomwareDefenseRule::new();
        let e = file_event("/home/user/docs/report.pdf.encrypted", FileAction::Rename);
        let alert = rule.evaluate(&e).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.mitre_techniques.contains(&"T1486".to_string()));
    }

    #[test]
    fn detects_rapid_renames() {
        let mut rule = RansomwareDefenseRule::new();
        rule.rapid_rename_threshold = 5;
        let now = Utc::now();

        for i in 0..4 {
            let mut e = file_event(&format!("/data/file{i}.txt.locked"), FileAction::Rename);
            e.timestamp = now;
            // These hit ransom extension first; use normal extensions for rename-rate test
        }

        // Non-ransom extensions for pure rename-rate testing
        for i in 0..4 {
            let mut e = file_event(&format!("/data/file{i}.bak"), FileAction::Rename);
            e.timestamp = now;
            assert!(rule.evaluate(&e).is_none());
        }
        let mut e = file_event("/data/file4.bak", FileAction::Rename);
        e.timestamp = now;
        let alert = rule.evaluate(&e).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.description.contains("renames"));
    }

    #[test]
    fn detects_rapid_modifications() {
        let mut rule = RansomwareDefenseRule::new();
        rule.rapid_mod_threshold = 5;
        let now = Utc::now();

        for i in 0..4 {
            let mut e = file_event(&format!("/data/file{i}.txt"), FileAction::Modify);
            e.timestamp = now;
            assert!(rule.evaluate(&e).is_none());
        }
        let mut e = file_event("/data/file4.txt", FileAction::Modify);
        e.timestamp = now;
        let alert = rule.evaluate(&e).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn canary_path_detection_in_rule() {
        let dir = TempDir::new().unwrap();
        let mut rule = RansomwareDefenseRule::new();
        rule.canary_manager_mut().deploy(&[dir.path()]).unwrap();

        let canary_path = dir.path().join(CANARY_NAMES[0]);
        let e = file_event(canary_path.to_str().unwrap(), FileAction::Modify);
        let alert = rule.evaluate(&e).unwrap();
        assert!(alert.title.contains("Canary"));
        assert_eq!(alert.confidence, 0.95);
    }
}
