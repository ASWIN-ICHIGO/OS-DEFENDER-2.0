use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileReputation {
    KnownGood,
    KnownBad,
    Suspicious,
    Unknown,
}

impl std::fmt::Display for FileReputation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KnownGood => write!(f, "known-good"),
            Self::KnownBad => write!(f, "known-bad"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntelReport {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub reputation: FileReputation,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationRecord {
    reputation: FileReputation,
    tags: Vec<String>,
    added_at: DateTime<Utc>,
}

pub struct FileIntelligence {
    known_good: HashMap<String, ReputationRecord>,
    known_bad: HashMap<String, ReputationRecord>,
    seen_hashes: HashMap<String, FileIntelReport>,
}

impl Default for FileIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

impl FileIntelligence {
    pub fn new() -> Self {
        Self {
            known_good: HashMap::new(),
            known_bad: HashMap::new(),
            seen_hashes: HashMap::new(),
        }
    }

    pub fn add_known_good(&mut self, sha256: &str, tags: Vec<String>) {
        self.known_good.insert(sha256.to_string(), ReputationRecord {
            reputation: FileReputation::KnownGood,
            tags,
            added_at: Utc::now(),
        });
    }

    pub fn add_known_bad(&mut self, sha256: &str, tags: Vec<String>) {
        self.known_bad.insert(sha256.to_string(), ReputationRecord {
            reputation: FileReputation::KnownBad,
            tags,
            added_at: Utc::now(),
        });
    }

    pub fn load_ioc_list(&mut self, hashes: &[&str], tags: Vec<String>) {
        for hash in hashes {
            self.add_known_bad(hash, tags.clone());
        }
    }

    pub fn hash_file(path: &Path) -> Result<(String, u64)> {
        let data = fs::read(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let size = data.len() as u64;
        let hash = hex::encode(Sha256::digest(&data));
        Ok((hash, size))
    }

    pub fn hash_bytes(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    pub fn lookup(&self, sha256: &str) -> FileReputation {
        if self.known_bad.contains_key(sha256) {
            FileReputation::KnownBad
        } else if self.known_good.contains_key(sha256) {
            FileReputation::KnownGood
        } else {
            FileReputation::Unknown
        }
    }

    pub fn lookup_tags(&self, sha256: &str) -> Vec<String> {
        if let Some(rec) = self.known_bad.get(sha256) {
            return rec.tags.clone();
        }
        if let Some(rec) = self.known_good.get(sha256) {
            return rec.tags.clone();
        }
        Vec::new()
    }

    pub fn analyze_file(&mut self, path: &str) -> Result<FileIntelReport> {
        let p = Path::new(path);
        let (sha256, size) = Self::hash_file(p)?;

        let reputation = self.lookup(&sha256);
        let tags = self.lookup_tags(&sha256);
        let now = Utc::now();

        let report = if let Some(existing) = self.seen_hashes.get_mut(&sha256) {
            existing.last_seen = now;
            existing.path = path.to_string();
            existing.clone()
        } else {
            let r = FileIntelReport {
                path: path.to_string(),
                sha256: sha256.clone(),
                size_bytes: size,
                reputation,
                tags,
                first_seen: now,
                last_seen: now,
            };
            self.seen_hashes.insert(sha256, r.clone());
            r
        };

        Ok(report)
    }

    pub fn known_bad_count(&self) -> usize {
        self.known_bad.len()
    }

    pub fn known_good_count(&self) -> usize {
        self.known_good.len()
    }

    pub fn seen_count(&self) -> usize {
        self.seen_hashes.len()
    }

    pub fn save_lists(&self, path: &Path) -> Result<()> {
        let data = serde_json::json!({
            "known_good": self.known_good.keys().collect::<Vec<_>>(),
            "known_bad": self.known_bad.keys().collect::<Vec<_>>(),
        });
        fs::write(path, serde_json::to_string_pretty(&data)?)
            .with_context(|| format!("cannot save lists to {}", path.display()))?;
        Ok(())
    }

    pub fn load_lists(&mut self, path: &Path) -> Result<()> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&data)?;

        if let Some(good) = parsed["known_good"].as_array() {
            for h in good {
                if let Some(s) = h.as_str() {
                    self.add_known_good(s, vec!["loaded".into()]);
                }
            }
        }
        if let Some(bad) = parsed["known_bad"].as_array() {
            for h in bad {
                if let Some(s) = h.as_str() {
                    self.add_known_bad(s, vec!["loaded".into()]);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn hash_file_produces_sha256() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "hello world").unwrap();

        let (hash, size) = FileIntelligence::hash_file(&file).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(size, 11);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_bytes_deterministic() {
        let h1 = FileIntelligence::hash_bytes(b"test data");
        let h2 = FileIntelligence::hash_bytes(b"test data");
        assert_eq!(h1, h2);
        assert_ne!(h1, FileIntelligence::hash_bytes(b"different"));
    }

    #[test]
    fn reputation_lookup() {
        let mut intel = FileIntelligence::new();
        let bad_hash = "a" .repeat(64);
        let good_hash = "b".repeat(64);

        intel.add_known_bad(&bad_hash, vec!["malware".into()]);
        intel.add_known_good(&good_hash, vec!["os-binary".into()]);

        assert_eq!(intel.lookup(&bad_hash), FileReputation::KnownBad);
        assert_eq!(intel.lookup(&good_hash), FileReputation::KnownGood);
        assert_eq!(intel.lookup(&"c".repeat(64)), FileReputation::Unknown);
    }

    #[test]
    fn analyze_file_and_track() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("binary.exe");
        fs::write(&file, b"MZ\x00\x01").unwrap();

        let mut intel = FileIntelligence::new();
        let (hash, _) = FileIntelligence::hash_file(&file).unwrap();
        intel.add_known_bad(&hash, vec!["trojan".into()]);

        let report = intel.analyze_file(file.to_str().unwrap()).unwrap();
        assert_eq!(report.reputation, FileReputation::KnownBad);
        assert!(report.tags.contains(&"trojan".to_string()));
        assert_eq!(intel.seen_count(), 1);
    }

    #[test]
    fn save_and_load_lists() {
        let dir = TempDir::new().unwrap();
        let list_path = dir.path().join("lists.json");

        let mut intel = FileIntelligence::new();
        intel.add_known_good(&"a".repeat(64), vec![]);
        intel.add_known_bad(&"b".repeat(64), vec![]);
        intel.save_lists(&list_path).unwrap();

        let mut intel2 = FileIntelligence::new();
        intel2.load_lists(&list_path).unwrap();
        assert_eq!(intel2.known_good_count(), 1);
        assert_eq!(intel2.known_bad_count(), 1);
    }

    #[test]
    fn ioc_list_loading() {
        let mut intel = FileIntelligence::new();
        let iocs = vec!["a".repeat(64), "b".repeat(64)];
        let refs: Vec<&str> = iocs.iter().map(|s| s.as_str()).collect();
        intel.load_ioc_list(&refs, vec!["campaign-2025".into()]);
        assert_eq!(intel.known_bad_count(), 2);
        assert_eq!(intel.lookup(&iocs[0]), FileReputation::KnownBad);
    }

    #[test]
    fn reputation_display() {
        assert_eq!(FileReputation::KnownBad.to_string(), "known-bad");
        assert_eq!(FileReputation::KnownGood.to_string(), "known-good");
        assert_eq!(FileReputation::Unknown.to_string(), "unknown");
    }
}
