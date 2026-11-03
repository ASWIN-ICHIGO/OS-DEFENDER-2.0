use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

use super::{EnforcementResult, Enforcer};

const TABLE_NAME: &str = "os_defender";
const CHAIN_NAME: &str = "block_chain";

pub struct NftablesEnforcer {
    dry_run: bool,
}

impl Default for NftablesEnforcer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl NftablesEnforcer {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    pub fn ensure_table_exists(&self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }
        // Create table and chain if they don't exist
        // nft is idempotent with "add" (vs "create" which errors on duplicate)
        self.run_nft(&format!(
            "add table inet {TABLE_NAME}; \
             add chain inet {TABLE_NAME} {CHAIN_NAME} {{ type filter hook input priority 0 \\; policy accept \\; }}"
        ))?;
        Ok(())
    }

    fn run_nft(&self, ruleset: &str) -> Result<String> {
        let output = Command::new("nft")
            .args(["-e", "-a", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(ruleset.as_bytes())?;
                }
                child.wait_with_output()
            })
            .context("failed to execute nft")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft command failed: {stderr}");
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn block_ip_rule(ip: &str) -> String {
        format!(
            "add rule inet {TABLE_NAME} {CHAIN_NAME} ip saddr {ip} drop comment \"os-defender-block-{ip}\""
        )
    }

    fn find_rule_handle(&self, ip: &str) -> Result<Option<u64>> {
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
            .output()
            .context("failed to list nft chain")?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let comment_tag = format!("os-defender-block-{ip}");

        for line in stdout.lines() {
            if line.contains(&comment_tag) {
                // line ends with "# handle <N>"
                if let Some(handle_str) = line.rsplit("# handle ").next()
                    && let Ok(handle) = handle_str.trim().parse::<u64>()
                {
                    return Ok(Some(handle));
                }
            }
        }
        Ok(None)
    }
}

impl Enforcer for NftablesEnforcer {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult> {
        let ip = target;
        info!(ip = %ip, reason = %reason, dry_run = self.dry_run, "nftables block request");

        if self.dry_run {
            return Ok(EnforcementResult::ok(
                format!("[DRY-RUN] Would block IP {ip}"),
                format!("nft-unblock:{ip}"),
            ));
        }

        self.ensure_table_exists()?;

        // Check if already blocked
        if let Some(_handle) = self.find_rule_handle(ip)? {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("IP {ip} already blocked"),
            ));
        }

        let rule = Self::block_ip_rule(ip);
        match self.run_nft(&rule) {
            Ok(_) => {
                info!(ip = %ip, "IP blocked via nftables");
                Ok(EnforcementResult::ok(
                    format!("Blocked IP {ip} via nftables"),
                    format!("nft-unblock:{ip}"),
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
            .strip_prefix("nft-unblock:")
            .unwrap_or(rollback_token);

        info!(ip = %ip, dry_run = self.dry_run, "nftables unblock request");

        if self.dry_run {
            return Ok(EnforcementResult::ok_no_rollback(
                format!("[DRY-RUN] Would unblock IP {ip}"),
            ));
        }

        match self.find_rule_handle(ip)? {
            Some(handle) => {
                let rule = format!(
                    "delete rule inet {TABLE_NAME} {CHAIN_NAME} handle {handle}"
                );
                self.run_nft(&rule)?;
                info!(ip = %ip, handle, "IP unblocked via nftables");
                Ok(EnforcementResult::ok_no_rollback(
                    format!("Unblocked IP {ip} (handle {handle})"),
                ))
            }
            None => Ok(EnforcementResult::ok_no_rollback(
                format!("IP {ip} was not blocked"),
            )),
        }
    }

    fn name(&self) -> &str {
        "nftables"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_block_returns_ok() {
        let enforcer = NftablesEnforcer::new(true);
        let result = enforcer.execute("10.0.0.5", "test").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
        assert_eq!(result.rollback_token, Some("nft-unblock:10.0.0.5".into()));
    }

    #[test]
    fn dry_run_rollback_returns_ok() {
        let enforcer = NftablesEnforcer::new(true);
        let result = enforcer.rollback("nft-unblock:10.0.0.5").unwrap();
        assert!(result.success);
        assert!(result.detail.contains("DRY-RUN"));
    }

    #[test]
    fn block_ip_rule_format() {
        let rule = NftablesEnforcer::block_ip_rule("192.168.1.1");
        assert!(rule.contains("192.168.1.1"));
        assert!(rule.contains("drop"));
        assert!(rule.contains("os-defender-block-192.168.1.1"));
    }
}
