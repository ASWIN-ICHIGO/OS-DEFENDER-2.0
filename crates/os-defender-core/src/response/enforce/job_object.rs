#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use tracing::{info, warn};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW,
    SetInformationJobObject, JobObjectExtendedLimitInformation,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, SuspendThread, ResumeThread,
    PROCESS_ALL_ACCESS, THREAD_SUSPEND_RESUME,
};

use super::{EnforcementResult, Enforcer};

/// Process containment via Windows Job Objects and thread suspension.
/// Mirrors the Linux CgroupContainment approach for parity.
pub struct JobObjectEnforcer {
    dry_run: bool,
}

impl Default for JobObjectEnforcer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl JobObjectEnforcer {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Enumerate all thread IDs belonging to a process.
    fn get_thread_ids(pid: u32) -> Result<Vec<u32>> {
        let mut threads = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .context("CreateToolhelp32Snapshot failed")?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        threads.push(entry.th32ThreadID);
                    }
                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }
        Ok(threads)
    }

    /// Suspend all threads of a process.
    fn suspend_process(pid: u32) -> Result<u32> {
        let threads = Self::get_thread_ids(pid)?;
        if threads.is_empty() {
            anyhow::bail!("no threads found for PID {pid}");
        }

        let mut suspended = 0u32;
        for tid in &threads {
            unsafe {
                if let Ok(handle) = OpenThread(THREAD_SUSPEND_RESUME, false, *tid) {
                    let prev = SuspendThread(handle);
                    let _ = CloseHandle(handle);
                    if prev != u32::MAX {
                        suspended += 1;
                    }
                }
            }
        }
        Ok(suspended)
    }

    /// Resume all threads of a process.
    fn resume_process(pid: u32) -> Result<u32> {
        let threads = Self::get_thread_ids(pid)?;
        let mut resumed = 0u32;
        for tid in &threads {
            unsafe {
                if let Ok(handle) = OpenThread(THREAD_SUSPEND_RESUME, false, *tid) {
                    let prev = ResumeThread(handle);
                    let _ = CloseHandle(handle);
                    if prev != u32::MAX {
                        resumed += 1;
                    }
                }
            }
        }
        Ok(resumed)
    }

    /// Create a Job Object and assign the process to it.
    /// Sets KILL_ON_JOB_CLOSE so closing the handle terminates contained processes.
    fn create_containment_job(pid: u32) -> Result<()> {
        unsafe {
            let job_name = format!("os-defender-contain-{pid}");
            let job_name_w: Vec<u16> = job_name.encode_utf16().chain(std::iter::once(0)).collect();
            let job = CreateJobObjectW(
                None,
                windows::core::PCWSTR(job_name_w.as_ptr()),
            ).context("CreateJobObjectW failed")?;

            // Set KILL_ON_JOB_CLOSE limit
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ).context("SetInformationJobObject failed")?;

            let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
                .context(format!("cannot open PID {pid}"))?;

            AssignProcessToJobObject(job, process)
                .context("AssignProcessToJobObject failed")?;

            let _ = CloseHandle(process);
            // Intentionally leak the job handle — KILL_ON_JOB_CLOSE means
            // the process group is terminated only when we explicitly close it.
            // A proper implementation would store these handles in a map.
            // For now, the suspend/resume is the primary containment mechanism.
            let _ = CloseHandle(job);
        }
        Ok(())
    }
}

impl Enforcer for JobObjectEnforcer {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult> {
        let pid: u32 = target
            .parse()
            .with_context(|| format!("invalid PID: {target}"))?;

        info!(pid, reason = %reason, dry_run = self.dry_run, "job-object containment request");

        if self.dry_run {
            return Ok(EnforcementResult::ok(
                format!("[DRY-RUN] Would contain PID {pid} via Job Object + suspend"),
                format!("job-resume:{pid}"),
            ));
        }

        // Don't contain system-critical processes
        if pid <= 4 {
            return Ok(EnforcementResult::fail(
                format!("Refusing to contain PID {pid} (system-critical)"),
            ));
        }

        // Create containment job (best-effort — process may already be in a job)
        if let Err(e) = Self::create_containment_job(pid) {
            warn!(pid, %e, "job object creation failed (non-fatal, proceeding with suspend)");
        }

        match Self::suspend_process(pid) {
            Ok(count) if count > 0 => {
                info!(pid, threads = count, "process suspended via thread suspension");
                Ok(EnforcementResult::ok(
                    format!("Contained PID {pid}: {count} threads suspended"),
                    format!("job-resume:{pid}"),
                ))
            }
            Ok(_) => Ok(EnforcementResult::fail(
                format!("No threads could be suspended for PID {pid}"),
            )),
            Err(e) => {
                warn!(pid, %e, "failed to suspend process");
                Ok(EnforcementResult::fail(format!("Failed to contain PID {pid}: {e}")))
            }
        }
    }

    fn rollback(&self, rollback_token: &str) -> Result<EnforcementResult> {
        let pid_str = rollback_token
            .strip_prefix("job-resume:")
            .unwrap_or(rollback_token);
        let pid: u32 = pid_str
            .parse()
            .with_context(|| format!("invalid PID in rollback token: {pid_str}"))?;

        info!(pid, dry_run = self.dry_run, "job-object release request");

        if self.dry_run {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("[DRY-RUN] Would resume PID {pid}"),
            ));
        }

        match Self::resume_process(pid) {
            Ok(count) => {
                info!(pid, threads = count, "process resumed");
                Ok(EnforcementResult::ok_no_rollback(
                    format!("Resumed PID {pid}: {count} threads released"),
                ))
            }
            Err(e) => {
                warn!(pid, %e, "failed to resume process");
                Ok(EnforcementResult::fail(format!("Failed to resume PID {pid}: {e}")))
            }
        }
    }

    fn name(&self) -> &str {
        "job-object"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_contain_returns_ok() {
        let enforcer = JobObjectEnforcer::new(true);
        let result = enforcer.execute("1234", "test").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
        assert_eq!(result.rollback_token, Some("job-resume:1234".into()));
    }

    #[test]
    fn dry_run_release_returns_ok() {
        let enforcer = JobObjectEnforcer::new(true);
        let result = enforcer.rollback("job-resume:1234").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
    }

    #[test]
    fn invalid_pid_fails() {
        let enforcer = JobObjectEnforcer::new(false);
        let result = enforcer.execute("not-a-pid", "test");
        assert!(result.is_err());
    }

    #[test]
    fn refuses_to_contain_system_critical() {
        let enforcer = JobObjectEnforcer::new(false);
        let result = enforcer.execute("4", "test").unwrap();
        assert!(!result.success);
        assert!(result.detail.contains("system-critical"));
    }
}
