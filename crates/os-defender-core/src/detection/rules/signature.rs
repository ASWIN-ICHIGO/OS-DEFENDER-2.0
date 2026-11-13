use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::advanced::file_intel::{FileIntelligence, FileReputation};
use crate::events::{EventType, FileAction, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

/// EICAR standard antivirus test file — proves the signature engine works.
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Default cap so hashing never stalls the detection loop on huge files.
const DEFAULT_MAX_SCAN_BYTES: u64 = 25 * 1024 * 1024;

/// Hash-based signature detection: hashes created/modified files and matches
/// them against a known-malicious SHA-256 blocklist.
///
/// The blocklist is seeded with the EICAR test signature and extended at
/// startup from `~/.local/share/os-defender/signatures.json` (format:
/// `{"known_bad": ["<sha256>", ...]}` — one hash per line in a plain text
/// file also works). Users can extend the database without touching code.
pub struct SignatureRule {
    intel: FileIntelligence,
    max_scan_bytes: u64,
    alerted: HashSet<String>,
}

impl Default for SignatureRule {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureRule {
    pub fn new() -> Self {
        let mut intel = FileIntelligence::new();
        intel.add_known_bad(EICAR_SHA256, vec!["eicar-test".into(), "signature".into()]);

        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let db = PathBuf::from(home).join(".local/share/os-defender/signatures.json");
            match Self::load_database(&mut intel, &db) {
                Ok(count) if count > 0 => {
                    tracing::info!(signatures = count, db = %db.display(), "signature database loaded");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(%e, "no signature database loaded");
                }
            }
        }

        Self {
            intel,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            alerted: HashSet::new(),
        }
    }

    /// Loads a signature database file. Accepts either JSON
    /// (`{"known_bad": [...]}`, as produced by `FileIntelligence::save_lists`)
    /// or a plain text file with one 64-char SHA-256 per line.
    fn load_database(intel: &mut FileIntelligence, path: &Path) -> anyhow::Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let mut count = 0usize;

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(bad) = parsed.get("known_bad").and_then(|b| b.as_array()) {
                for h in bad {
                    if let Some(s) = h.as_str() {
                        let s = s.trim().to_ascii_lowercase();
                        if is_sha256(&s) {
                            intel.add_known_bad(&s, vec!["signature-db".into()]);
                            count += 1;
                        }
                    }
                }
            }
            return Ok(count);
        }

        for line in data.lines() {
            let s = line.trim().to_ascii_lowercase();
            if is_sha256(&s) {
                intel.add_known_bad(&s, vec!["signature-db".into()]);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn signature_count(&self) -> usize {
        self.intel.known_bad_count()
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Rule for SignatureRule {
    fn id(&self) -> &str {
        "SIG-001"
    }

    fn name(&self) -> &str {
        "Signature Match"
    }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::File {
            return None;
        }
        let fc = event.file_context.as_ref()?;
        match fc.action {
            FileAction::Create | FileAction::Modify | FileAction::Rename => {}
            _ => return None,
        }

        let sha256 = match &fc.sha256 {
            Some(h) if is_sha256(&h.to_ascii_lowercase()) => h.to_ascii_lowercase(),
            _ => {
                let p = Path::new(&fc.path);
                let meta = match std::fs::metadata(p) {
                    Ok(m) if m.is_file() => m,
                    _ => return None,
                };
                if meta.len() > self.max_scan_bytes {
                    return None;
                }
                FileIntelligence::hash_file(p).ok()?.0
            }
        };

        if self.alerted.contains(&sha256) {
            return None;
        }
        if self.intel.lookup(&sha256) != FileReputation::KnownBad {
            return None;
        }
        self.alerted.insert(sha256.clone());

        let tags = self.intel.lookup_tags(&sha256).join(", ");
        Some(Alert::from_rule(
            event.event_id,
            self.id(),
            Severity::Critical,
            "Known malware detected (signature match)".into(),
            format!(
                "File {} matches a known-malicious SHA-256 signature ({}…). Family/tags: {}. Recommended: quarantine immediately.",
                fc.path,
                &sha256[..16],
                if tags.is_empty() { "unknown" } else { &tags }
            ),
            0.99,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{FileContext, OsType};
    use tempfile::TempDir;

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
    fn eicar_seed_is_loaded() {
        let rule = SignatureRule::new();
        assert!(rule.signature_count() >= 1);
        assert_eq!(
            rule.intel.lookup(EICAR_SHA256),
            FileReputation::KnownBad
        );
    }

    #[test]
    fn detects_eicar_file_creation() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("eicar.com");
        std::fs::write(
            &file,
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let mut rule = SignatureRule::new();
        let alert = rule
            .evaluate(&file_event(&file.to_string_lossy(), FileAction::Create))
            .expect("EICAR must trigger the signature rule");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.rule_id.as_deref(), Some("SIG-001"));
    }

    #[test]
    fn clean_file_is_ignored() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("notes.txt");
        std::fs::write(&file, "just some notes").unwrap();

        let mut rule = SignatureRule::new();
        assert!(rule
            .evaluate(&file_event(&file.to_string_lossy(), FileAction::Create))
            .is_none());
    }

    #[test]
    fn alerts_only_once_per_hash() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("eicar.com");
        std::fs::write(
            &file,
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let mut rule = SignatureRule::new();
        let ev = file_event(&file.to_string_lossy(), FileAction::Create);
        assert!(rule.evaluate(&ev).is_some());
        assert!(rule.evaluate(&ev).is_none());
    }

    #[test]
    fn delete_events_are_not_scanned() {
        let mut rule = SignatureRule::new();
        assert!(rule
            .evaluate(&file_event("C:\\nonexistent\\eicar.com", FileAction::Delete))
            .is_none());
    }

    #[test]
    fn plain_text_database_loads() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("signatures.txt");
        std::fs::write(
            &db,
            format!("{}\nnot-a-hash\n{}\n", "a".repeat(64), "B".repeat(64)),
        )
        .unwrap();

        let mut intel = FileIntelligence::new();
        let count = SignatureRule::load_database(&mut intel, &db).unwrap();
        assert_eq!(count, 2);
        assert_eq!(intel.lookup(&"a".repeat(64)), FileReputation::KnownBad);
        assert_eq!(intel.lookup(&"b".repeat(64)), FileReputation::KnownBad);
    }

    #[test]
    fn json_database_loads() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("signatures.json");
        std::fs::write(
            &db,
            format!("{{\"known_bad\": [\"{}\"]}}", "c".repeat(64)),
        )
        .unwrap();

        let mut intel = FileIntelligence::new();
        let count = SignatureRule::load_database(&mut intel, &db).unwrap();
        assert_eq!(count, 1);
        assert_eq!(intel.lookup(&"c".repeat(64)), FileReputation::KnownBad);
    }
}
