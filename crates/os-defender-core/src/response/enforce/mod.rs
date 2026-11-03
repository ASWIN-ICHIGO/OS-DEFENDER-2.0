pub mod nftables;
pub mod cgroup;
pub mod quarantine;
#[cfg(target_os = "windows")]
pub mod wfp;
#[cfg(target_os = "windows")]
pub mod job_object;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResult {
    pub success: bool,
    pub detail: String,
    pub rollback_token: Option<String>,
}

impl EnforcementResult {
    pub fn ok(detail: impl Into<String>, rollback_token: impl Into<String>) -> Self {
        Self {
            success: true,
            detail: detail.into(),
            rollback_token: Some(rollback_token.into()),
        }
    }

    pub fn ok_no_rollback(detail: impl Into<String>) -> Self {
        Self {
            success: true,
            detail: detail.into(),
            rollback_token: None,
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            success: false,
            detail: detail.into(),
            rollback_token: None,
        }
    }
}

pub trait Enforcer: Send + Sync {
    fn execute(&self, target: &str, reason: &str) -> Result<EnforcementResult>;
    fn rollback(&self, rollback_token: &str) -> Result<EnforcementResult>;
    fn name(&self) -> &str;
}
