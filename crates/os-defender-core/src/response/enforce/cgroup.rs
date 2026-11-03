use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::{EnforcementResult, Enforcer};

const CGROUP_BASE: &str = "/sys/fs/cgroup";
const DEFENDER_SCOPE: &str = "os-defender-contained";

pub struct CgroupContainment {
    dry_run: bool,
}

impl Default for CgroupContainment {
    fn default() -> Self {
        Self::new(false)
    }
}

impl CgroupContainment {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    fn cgroup_path(pid: u32) -> PathBuf {
        PathBuf::from(CGROUP_BASE)
            .join(DEFENDER_SCOPE)
            .join(format!("pid-{pid}"))
    }

    fn ensure_cgroup(pid: u32) -> Result<PathBuf> {
        let path = Self::cgroup_path(pid);
        if !path.exists() {
            fs::create_dir_all(&path)
                .with_context(|| format!("cannot create cgroup at {}", path.display()))?;
        }
        Ok(path)
    }

    fn move_process_to_cgroup(pid: u32, cgroup: &Path) -> Result<()> {
        let procs_file = cgroup.join("cgroup.procs");
        fs::write(&procs_file, pid.to_string())
            .with_context(|| format!("cannot move PID {pid} to {}", procs_file.display()))?;
        Ok(())
    }

    fn set_freeze(cgroup: &Path, freeze: bool) -> Result<()> {
        let freeze_file = cgroup.join("cgroup.freeze");
        let value = if freeze { "1" } else { "0" };
        fs::write(&freeze_file, value)
            .with_context(|| format!("cannot write to {}", freeze_file.display()))?;
        Ok(())
    }

    fn is_frozen(cgroup: &Path) -> bool {
        let freeze_file = cgroup.join("cgroup.freeze");
        fs::read_to_string(freeze_file)
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    fn cleanup_cgroup(pid: u32) -> Result<()> {
        let path = Self::cgroup_path(pid);
        // Move process back to parent cgroup first
        let parent_procs = PathBuf::from(CGROUP_BASE)
            .join(DEFENDER_SCOPE)
            .join("cgroup.procs");
        if parent_procs.exists() {
            let _ = fs::write(&parent_procs, pid.to_string());
        }
        // Remove the per-PID cgroup directory
        if path.exists() {
            let _ = fs::remove_dir(&path);
        }
        Ok(())
    }
}

impl Enforcer for CgroupContainment {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult> {
        let pid: u32 = target
            .parse()
            .with_context(|| format!("invalid PID: {target}"))?;

        info!(pid, reason = %reason, dry_run = self.dry_run, "cgroup freeze request");

        if self.dry_run {
            return Ok(EnforcementResult::ok(
                format!("[DRY-RUN] Would freeze PID {pid}"),
                format!("cgroup-thaw:{pid}"),
            ));
        }

        // Verify process exists
        let proc_path = format!("/proc/{pid}");
        if !Path::new(&proc_path).exists() {
            return Ok(EnforcementResult::fail(format!("PID {pid} does not exist")));
        }

        // Don't freeze system-critical processes
        if pid <= 2 {
            return Ok(EnforcementResult::fail(
                format!("Refusing to freeze PID {pid} (system-critical)"),
            ));
        }

        match Self::ensure_cgroup(pid)
            .and_then(|cgroup| {
                Self::move_process_to_cgroup(pid, &cgroup)?;
                Self::set_freeze(&cgroup, true)?;
                Ok(cgroup)
            }) {
            Ok(cgroup) => {
                if Self::is_frozen(&cgroup) {
                    info!(pid, "process frozen via cgroup");
                    Ok(EnforcementResult::ok(
                        format!("Process {pid} frozen via cgroup v2"),
                        format!("cgroup-thaw:{pid}"),
                    ))
                } else {
                    warn!(pid, "freeze written but cgroup.freeze != 1");
                    Ok(EnforcementResult::fail(
                        format!("Freeze requested for PID {pid} but not confirmed by kernel"),
                    ))
                }
            }
            Err(e) => {
                warn!(pid, %e, "failed to freeze process");
                Ok(EnforcementResult::fail(format!("Failed to freeze PID {pid}: {e}")))
            }
        }
    }

    fn rollback(&self, rollback_token: &str) -> Result<EnforcementResult> {
        let pid_str = rollback_token
            .strip_prefix("cgroup-thaw:")
            .unwrap_or(rollback_token);
        let pid: u32 = pid_str
            .parse()
            .with_context(|| format!("invalid PID in rollback token: {pid_str}"))?;

        info!(pid, dry_run = self.dry_run, "cgroup thaw request");

        if self.dry_run {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("[DRY-RUN] Would thaw PID {pid}"),
            ));
        }

        let cgroup = Self::cgroup_path(pid);
        if !cgroup.exists() {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("Cgroup for PID {pid} does not exist — already released"),
            ));
        }

        Self::set_freeze(&cgroup, false)?;
        Self::cleanup_cgroup(pid)?;

        info!(pid, "process thawed and cgroup removed");
        Ok(EnforcementResult::ok_no_rollback(
            format!("Process {pid} thawed and released from containment"),
        ))
    }

    fn name(&self) -> &str {
        "cgroup-containment"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_freeze_returns_ok() {
        let enforcer = CgroupContainment::new(true);
        let result = enforcer.execute("1234", "test").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
        assert_eq!(result.rollback_token, Some("cgroup-thaw:1234".into()));
    }

    #[test]
    fn dry_run_thaw_returns_ok() {
        let enforcer = CgroupContainment::new(true);
        let result = enforcer.rollback("cgroup-thaw:1234").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
    }

    #[test]
    fn invalid_pid_fails() {
        let enforcer = CgroupContainment::new(false);
        let result = enforcer.execute("not-a-pid", "test");
        assert!(result.is_err());
    }

    #[test]
    fn refuses_to_freeze_init() {
        let enforcer = CgroupContainment::new(false);
        let result = enforcer.execute("1", "test").unwrap();
        assert!(!result.success);
        assert!(result.detail.contains("system-critical"));
    }

    #[test]
    fn cgroup_path_format() {
        let path = CgroupContainment::cgroup_path(4567);
        assert_eq!(
            path.to_str().unwrap(),
            "/sys/fs/cgroup/os-defender-contained/pid-4567"
        );
    }
}
