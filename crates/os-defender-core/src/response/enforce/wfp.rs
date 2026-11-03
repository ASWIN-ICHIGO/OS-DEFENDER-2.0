#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

use super::{EnforcementResult, Enforcer};

const RULE_PREFIX: &str = "os-defender-block";

/// Windows Filtering Platform enforcer using `netsh advfirewall` CLI.
/// Mirrors the Linux NftablesEnforcer approach for parity.
pub struct WfpEnforcer {
    dry_run: bool,
}

impl Default for WfpEnforcer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl WfpEnforcer {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    fn rule_name(ip: &str) -> String {
        format!("{RULE_PREFIX}-{ip}")
    }

    fn rule_exists(ip: &str) -> Result<bool> {
        let name = Self::rule_name(ip);
        let output = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "show", "rule",
                &format!("name={name}"),
            ])
            .output()
            .context("failed to run netsh")?;

        Ok(output.status.success()
            && !String::from_utf8_lossy(&output.stdout).contains("No rules match"))
    }

    fn add_block_rule(ip: &str) -> Result<()> {
        let name = Self::rule_name(ip);
        // Block inbound from IP
        let out_in = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={name}"),
                "dir=in", "action=block",
                &format!("remoteip={ip}"),
                "protocol=any",
            ])
            .output()
            .context("failed to add inbound block rule")?;

        if !out_in.status.success() {
            let stderr = String::from_utf8_lossy(&out_in.stderr);
            anyhow::bail!("netsh add inbound rule failed: {stderr}");
        }

        // Block outbound to IP
        let name_out = format!("{name}-out");
        let out_out = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={name_out}"),
                "dir=out", "action=block",
                &format!("remoteip={ip}"),
                "protocol=any",
            ])
            .output()
            .context("failed to add outbound block rule")?;

        if !out_out.status.success() {
            let stderr = String::from_utf8_lossy(&out_out.stderr);
            anyhow::bail!("netsh add outbound rule failed: {stderr}");
        }

        Ok(())
    }

    fn remove_block_rule(ip: &str) -> Result<()> {
        let name = Self::rule_name(ip);

        // Remove inbound rule
        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={name}"),
            ])
            .output();

        // Remove outbound rule
        let name_out = format!("{name}-out");
        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={name_out}"),
            ])
            .output();

        Ok(())
    }
}

impl Enforcer for WfpEnforcer {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult> {
        let ip = target;
        info!(ip = %ip, reason = %reason, dry_run = self.dry_run, "WFP block request");

        if self.dry_run {
            return Ok(EnforcementResult::ok(
                format!("[DRY-RUN] Would block IP {ip} via Windows Firewall"),
                format!("wfp-unblock:{ip}"),
            ));
        }

        if Self::rule_exists(ip)? {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("IP {ip} already blocked"),
            ));
        }

        match Self::add_block_rule(ip) {
            Ok(()) => {
                info!(ip = %ip, "IP blocked via Windows Firewall");
                Ok(EnforcementResult::ok(
                    format!("Blocked IP {ip} via Windows Firewall (in+out)"),
                    format!("wfp-unblock:{ip}"),
                ))
            }
            Err(e) => {
                warn!(ip = %ip, %e, "failed to block IP");
                Ok(EnforcementResult::fail(format!("Failed to block {ip}: {e}")))
            }
        }
    }

    fn rollback(&self, rollback_token: &str) -> Result<EnforcementResult> {
        let ip = rollback_token
            .strip_prefix("wfp-unblock:")
            .unwrap_or(rollback_token);

        info!(ip = %ip, dry_run = self.dry_run, "WFP unblock request");

        if self.dry_run {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("[DRY-RUN] Would unblock IP {ip}"),
            ));
        }

        match Self::remove_block_rule(ip) {
            Ok(()) => {
                info!(ip = %ip, "IP unblocked via Windows Firewall");
                Ok(EnforcementResult::ok_no_rollback(
                    format!("Unblocked IP {ip}"),
                ))
            }
            Err(e) => {
                warn!(ip = %ip, %e, "failed to unblock IP");
                Ok(EnforcementResult::fail(format!("Failed to unblock {ip}: {e}")))
            }
        }
    }

    fn name(&self) -> &str {
        "wfp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_block_returns_ok() {
        let enforcer = WfpEnforcer::new(true);
        let result = enforcer.execute("10.0.0.5", "test").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
        assert_eq!(result.rollback_token, Some("wfp-unblock:10.0.0.5".into()));
    }

    #[test]
    fn dry_run_rollback_returns_ok() {
        let enforcer = WfpEnforcer::new(true);
        let result = enforcer.rollback("wfp-unblock:10.0.0.5").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
    }

    #[test]
    fn rule_name_format() {
        let name = WfpEnforcer::rule_name("192.168.1.1");
        assert_eq!(name, "os-defender-block-192.168.1.1");
    }
}
