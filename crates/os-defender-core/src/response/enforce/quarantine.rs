use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::{EnforcementResult, Enforcer};

pub struct FileQuarantine {
    quarantine_dir: PathBuf,
    dry_run: bool,
}

impl FileQuarantine {
    pub fn new(quarantine_dir: PathBuf, dry_run: bool) -> Self {
        Self {
            quarantine_dir,
            dry_run,
        }
    }

    fn quarantine_path(&self, original: &str) -> PathBuf {
        let safe_name = original.replace('/', "_");
        self.quarantine_dir.join(safe_name)
    }

    fn metadata_path(&self, original: &str) -> PathBuf {
        let safe_name = original.replace('/', "_");
        self.quarantine_dir.join(format!("{safe_name}.meta"))
    }

    fn compute_sha256(path: &Path) -> Result<String> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let hash = Sha256::digest(&data);
        Ok(hex::encode(hash))
    }

    pub fn ensure_dir(&self) -> Result<()> {
        if !self.quarantine_dir.exists() {
            fs::create_dir_all(&self.quarantine_dir).with_context(|| {
                format!("cannot create quarantine dir {}", self.quarantine_dir.display())
            })?;
            // Restrict permissions: only owner can access
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.quarantine_dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }
}

impl Enforcer for FileQuarantine {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult> {
        let original = Path::new(target);
        info!(path = %target, reason = %reason, dry_run = self.dry_run, "quarantine request");

        if self.dry_run {
            return Ok(EnforcementResult::ok(
                format!("[DRY-RUN] Would quarantine {target}"),
                format!("quarantine-restore:{target}"),
            ));
        }

        if !original.exists() {
            return Ok(EnforcementResult::fail(format!("File {target} does not exist")));
        }

        if !original.is_file() {
            return Ok(EnforcementResult::fail(format!("{target} is not a regular file")));
        }

        self.ensure_dir()?;

        // Compute hash before moving
        let sha256 = Self::compute_sha256(original)?;

        let q_path = self.quarantine_path(target);
        let meta_path = self.metadata_path(target);

        // Move file to quarantine
        fs::rename(original, &q_path).or_else(|_| {
            // rename fails across filesystems, fall back to copy+delete
            fs::copy(original, &q_path)?;
            fs::remove_file(original)
        }).with_context(|| format!("cannot move {target} to quarantine"))?;

        // Write metadata
        let meta = format!(
            "original_path={target}\nsha256={sha256}\nreason={reason}\ntimestamp={}\n",
            chrono::Utc::now().to_rfc3339()
        );
        fs::write(&meta_path, meta)?;

        info!(path = %target, sha256 = %sha256, "file quarantined");
        Ok(EnforcementResult::ok(
            format!("Quarantined {target} (SHA-256: {sha256})"),
            format!("quarantine-restore:{target}"),
        ))
    }

    fn rollback(&self, rollback_token: &str) -> Result<EnforcementResult> {
        let original_path = rollback_token
            .strip_prefix("quarantine-restore:")
            .unwrap_or(rollback_token);

        info!(path = %original_path, dry_run = self.dry_run, "restore request");

        if self.dry_run {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("[DRY-RUN] Would restore {original_path}"),
            ));
        }

        let q_path = self.quarantine_path(original_path);
        let meta_path = self.metadata_path(original_path);

        if !q_path.exists() {
            return Ok(EnforcementResult::fail(
                format!("Quarantined copy of {original_path} not found"),
            ));
        }

        // Verify integrity before restoring
        let current_hash = Self::compute_sha256(&q_path)?;

        if meta_path.exists() {
            let meta = fs::read_to_string(&meta_path)?;
            if let Some(stored_line) = meta.lines().find(|l| l.starts_with("sha256=")) {
                let stored_hash = stored_line.strip_prefix("sha256=").unwrap_or("");
                if stored_hash != current_hash {
                    warn!(
                        path = %original_path,
                        stored = %stored_hash,
                        current = %current_hash,
                        "quarantined file integrity mismatch"
                    );
                    return Ok(EnforcementResult::fail(format!(
                        "Integrity check failed for {original_path}: stored={stored_hash} current={current_hash}"
                    )));
                }
            }
        }

        // Restore to original location
        let dest = Path::new(original_path);
        if let Some(parent) = dest.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&q_path, dest).or_else(|_| {
            fs::copy(&q_path, dest)?;
            fs::remove_file(&q_path)
        }).with_context(|| format!("cannot restore {original_path}"))?;

        // Cleanup metadata
        let _ = fs::remove_file(&meta_path);

        info!(path = %original_path, "file restored from quarantine");
        Ok(EnforcementResult::ok_no_rollback(
            format!("Restored {original_path} (SHA-256 verified: {current_hash})"),
        ))
    }

    fn name(&self) -> &str {
        "file-quarantine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, TempDir, FileQuarantine) {
        let source_dir = TempDir::new().unwrap();
        let quarantine_dir = TempDir::new().unwrap();
        let enforcer = FileQuarantine::new(quarantine_dir.path().to_path_buf(), false);
        (source_dir, quarantine_dir, enforcer)
    }

    #[test]
    fn quarantine_and_restore() {
        let (source_dir, _q_dir, enforcer) = setup();
        let file = source_dir.path().join("secret.txt");
        fs::write(&file, "sensitive data").unwrap();

        let path_str = file.to_str().unwrap();

        // Quarantine
        let result = enforcer.execute(path_str, "suspicious").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("SHA-256"));
        assert!(!file.exists(), "original should be removed");

        // Restore
        let token = result.rollback_token.unwrap();
        let restore_result = enforcer.rollback(&token).unwrap();
        assert!(restore_result.success);
        assert!(file.exists(), "file should be restored");
        assert_eq!(fs::read_to_string(&file).unwrap(), "sensitive data");
    }

    #[test]
    fn integrity_check_fails_on_tamper() {
        let (source_dir, _q_dir, enforcer) = setup();
        let file = source_dir.path().join("data.bin");
        fs::write(&file, "original").unwrap();

        let path_str = file.to_str().unwrap();
        let result = enforcer.execute(path_str, "test").unwrap();
        assert!(result.success);

        // Tamper with quarantined file
        let q_path = enforcer.quarantine_path(path_str);
        fs::write(&q_path, "tampered").unwrap();

        let token = result.rollback_token.unwrap();
        let restore_result = enforcer.rollback(&token).unwrap();
        assert!(!restore_result.success);
        assert!(restore_result.detail.contains("Integrity check failed"));
    }

    #[test]
    fn dry_run_quarantine() {
        let enforcer = FileQuarantine::new(PathBuf::from("/tmp/q"), true);
        let result = enforcer.execute("/etc/test", "test").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
    }

    #[test]
    fn nonexistent_file_fails() {
        let (_s, _q, enforcer) = setup();
        let result = enforcer.execute("/nonexistent/file.txt", "test").unwrap();
        assert!(!result.success);
    }

    #[test]
    fn quarantine_path_is_safe() {
        let enforcer = FileQuarantine::new(PathBuf::from("/var/quarantine"), false);
        let path = enforcer.quarantine_path("/etc/shadow");
        assert!(!path.to_str().unwrap().contains("//"));
        assert!(path.starts_with("/var/quarantine"));
    }
}
