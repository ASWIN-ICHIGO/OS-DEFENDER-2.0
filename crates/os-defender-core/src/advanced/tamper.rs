use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub entries: HashMap<String, FileIntegrity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrity {
    pub sha256: String,
    pub size_bytes: u64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperCheckResult {
    pub checked_at: DateTime<Utc>,
    pub total_files: usize,
    pub intact: usize,
    pub tampered: Vec<TamperViolation>,
    pub missing: Vec<String>,
}

impl TamperCheckResult {
    pub fn is_clean(&self) -> bool {
        self.tampered.is_empty() && self.missing.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperViolation {
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub detected_at: DateTime<Utc>,
}

pub struct TamperProtection {
    manifest: IntegrityManifest,
    manifest_path: Option<PathBuf>,
}

impl TamperProtection {
    pub fn new(version: &str) -> Self {
        Self {
            manifest: IntegrityManifest {
                version: version.to_string(),
                created_at: Utc::now(),
                entries: HashMap::new(),
            },
            manifest_path: None,
        }
    }

    pub fn record_file(&mut self, path: &Path) -> Result<()> {
        let data = fs::read(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let sha256 = hex::encode(Sha256::digest(&data));
        let size = data.len() as u64;

        self.manifest.entries.insert(
            path.to_string_lossy().to_string(),
            FileIntegrity {
                sha256,
                size_bytes: size,
                recorded_at: Utc::now(),
            },
        );
        Ok(())
    }

    pub fn record_directory(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        let entries: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("cannot read dir {}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();

        for entry in entries {
            let path = entry.path();
            if path.is_file() {
                self.record_file(&path)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn verify(&self) -> TamperCheckResult {
        let mut intact = 0;
        let mut tampered = Vec::new();
        let mut missing = Vec::new();

        for (path_str, expected) in &self.manifest.entries {
            let path = Path::new(path_str);
            if !path.exists() {
                missing.push(path_str.clone());
                continue;
            }

            match fs::read(path) {
                Ok(data) => {
                    let actual = hex::encode(Sha256::digest(&data));
                    if actual == expected.sha256 {
                        intact += 1;
                    } else {
                        tampered.push(TamperViolation {
                            path: path_str.clone(),
                            expected_sha256: expected.sha256.clone(),
                            actual_sha256: actual,
                            detected_at: Utc::now(),
                        });
                    }
                }
                Err(_) => {
                    missing.push(path_str.clone());
                }
            }
        }

        TamperCheckResult {
            checked_at: Utc::now(),
            total_files: self.manifest.entries.len(),
            intact,
            tampered,
            missing,
        }
    }

    pub fn save_manifest(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.manifest)?;
        fs::write(path, &json)
            .with_context(|| format!("cannot save manifest to {}", path.display()))?;
        Ok(())
    }

    pub fn load_manifest(&mut self, path: &Path) -> Result<()> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("cannot load manifest from {}", path.display()))?;
        self.manifest = serde_json::from_str(&data)?;
        self.manifest_path = Some(path.to_path_buf());
        Ok(())
    }

    pub fn file_count(&self) -> usize {
        self.manifest.entries.len()
    }
}

// --- Config signature ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    pub content: String,
    pub sha256: String,
    pub signed_at: DateTime<Utc>,
}

impl SignedConfig {
    pub fn sign(content: &str) -> Self {
        let sha256 = hex::encode(Sha256::digest(content.as_bytes()));
        Self {
            content: content.to_string(),
            sha256,
            signed_at: Utc::now(),
        }
    }

    pub fn verify(&self) -> bool {
        let computed = hex::encode(Sha256::digest(self.content.as_bytes()));
        computed == self.sha256
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
            .with_context(|| format!("cannot save signed config to {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("cannot load signed config from {}", path.display()))?;
        let config: Self = serde_json::from_str(&data)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn record_and_verify_intact() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("agent.bin");
        let file2 = dir.path().join("config.toml");
        fs::write(&file1, "binary content").unwrap();
        fs::write(&file2, "key=value").unwrap();

        let mut tp = TamperProtection::new("1.0.0");
        tp.record_file(&file1).unwrap();
        tp.record_file(&file2).unwrap();
        assert_eq!(tp.file_count(), 2);

        let result = tp.verify();
        assert!(result.is_clean());
        assert_eq!(result.intact, 2);
        assert_eq!(result.tampered.len(), 0);
        assert_eq!(result.missing.len(), 0);
    }

    #[test]
    fn detect_tampered_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("agent.bin");
        fs::write(&file, "original").unwrap();

        let mut tp = TamperProtection::new("1.0.0");
        tp.record_file(&file).unwrap();

        fs::write(&file, "tampered").unwrap();
        let result = tp.verify();
        assert!(!result.is_clean());
        assert_eq!(result.tampered.len(), 1);
        assert_ne!(result.tampered[0].expected_sha256, result.tampered[0].actual_sha256);
    }

    #[test]
    fn detect_missing_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("agent.bin");
        fs::write(&file, "content").unwrap();

        let mut tp = TamperProtection::new("1.0.0");
        tp.record_file(&file).unwrap();

        fs::remove_file(&file).unwrap();
        let result = tp.verify();
        assert!(!result.is_clean());
        assert_eq!(result.missing.len(), 1);
    }

    #[test]
    fn record_directory() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("b.txt"), "b").unwrap();

        let mut tp = TamperProtection::new("1.0.0");
        let count = tp.record_directory(dir.path()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(tp.file_count(), 2);
    }

    #[test]
    fn manifest_save_and_load() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("agent.bin");
        fs::write(&file, "content").unwrap();

        let mut tp = TamperProtection::new("1.0.0");
        tp.record_file(&file).unwrap();

        let manifest_path = dir.path().join("manifest.json");
        tp.save_manifest(&manifest_path).unwrap();

        let mut tp2 = TamperProtection::new("1.0.0");
        tp2.load_manifest(&manifest_path).unwrap();
        assert_eq!(tp2.file_count(), 1);

        let result = tp2.verify();
        assert!(result.is_clean());
    }

    #[test]
    fn signed_config_roundtrip() {
        let config = SignedConfig::sign("max_events = 1000\npolicy = dry_run\n");
        assert!(config.verify());
        assert_eq!(config.sha256.len(), 64);
    }

    #[test]
    fn signed_config_detects_tamper() {
        let mut config = SignedConfig::sign("original config");
        assert!(config.verify());

        config.content = "tampered config".to_string();
        assert!(!config.verify());
    }

    #[test]
    fn signed_config_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signed.json");

        let config = SignedConfig::sign("secure config data");
        config.save(&path).unwrap();

        let loaded = SignedConfig::load(&path).unwrap();
        assert!(loaded.verify());
        assert_eq!(loaded.content, "secure config data");
    }
}
