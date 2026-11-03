use anyhow::Result;
use std::fs;

pub struct SystemInfo;

impl SystemInfo {
    pub fn machine_id() -> Result<String> {
        let id = fs::read_to_string("/etc/machine-id")?;
        Ok(id.trim().to_string())
    }

    pub fn hostname() -> Result<String> {
        let name = nix::unistd::gethostname()?;
        Ok(name.to_string_lossy().into_owned())
    }

    pub fn kernel_version() -> Result<String> {
        let info = nix::sys::utsname::uname()?;
        Ok(info.release().to_string_lossy().into_owned())
    }

    pub fn uptime_seconds() -> Result<f64> {
        let content = fs::read_to_string("/proc/uptime")?;
        let secs: f64 = content
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty /proc/uptime"))?
            .parse()?;
        Ok(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_read_machine_id() {
        let id = SystemInfo::machine_id();
        if let Ok(id) = id {
            assert!(!id.is_empty());
            assert!(id.len() <= 64);
        }
    }

    #[test]
    fn can_read_hostname() {
        let name = SystemInfo::hostname().unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn can_read_uptime() {
        let secs = SystemInfo::uptime_seconds().unwrap();
        assert!(secs > 0.0);
    }
}
