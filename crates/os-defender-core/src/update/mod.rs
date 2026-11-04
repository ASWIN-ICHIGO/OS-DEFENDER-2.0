use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub download_url: Option<String>,
    pub release_notes: Option<String>,
    pub checksum_sha256: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
    pub release_url: String,
    pub auto_download: bool,
    pub verify_signature: bool,
    pub staging_dir: PathBuf,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: 86400,
            release_url: String::from(
                "https://api.github.com/repos/ASWIN-ICHIGO/os-defender-2.0/releases/latest",
            ),
            auto_download: false,
            verify_signature: true,
            staging_dir: default_staging_dir(),
        }
    }
}

fn default_staging_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/os-defender/updates");
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(appdata).join("OS-DEFENDER\\updates");
        }
    }
    PathBuf::from("/tmp/os-defender-updates")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub body: Option<String>,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

pub struct UpdateChecker {
    config: UpdateConfig,
    current_version: String,
}

impl UpdateChecker {
    pub fn new(current_version: &str, config: UpdateConfig) -> Self {
        Self {
            config,
            current_version: current_version.to_string(),
        }
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn config(&self) -> &UpdateConfig {
        &self.config
    }

    pub fn check_version_newer(&self, remote_tag: &str) -> bool {
        let remote = remote_tag.strip_prefix('v').unwrap_or(remote_tag);
        version_gt(remote, &self.current_version)
    }

    pub fn platform_asset_name() -> String {
        let os = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unknown"
        };
        let arch = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "unknown"
        };
        let ext = if cfg!(target_os = "windows") {
            ".exe"
        } else {
            ""
        };
        format!("os-defender-agent-{os}-{arch}{ext}")
    }

    pub fn build_update_info(
        &self,
        release_tag: Option<&str>,
        release_notes: Option<&str>,
        download_url: Option<&str>,
        checksum: Option<&str>,
        signature: Option<&str>,
    ) -> UpdateInfo {
        let update_available = release_tag
            .map(|t| self.check_version_newer(t))
            .unwrap_or(false);
        UpdateInfo {
            current_version: self.current_version.clone(),
            latest_version: release_tag.map(|s| s.to_string()),
            update_available,
            download_url: download_url.map(|s| s.to_string()),
            release_notes: release_notes.map(|s| s.to_string()),
            checksum_sha256: checksum.map(|s| s.to_string()),
            signature: signature.map(|s| s.to_string()),
        }
    }

    pub fn no_update_info(&self) -> UpdateInfo {
        UpdateInfo {
            current_version: self.current_version.clone(),
            latest_version: None,
            update_available: false,
            download_url: None,
            release_notes: None,
            checksum_sha256: None,
            signature: None,
        }
    }
}

pub fn verify_file_checksum(path: &Path, expected_sha256: &str) -> std::io::Result<bool> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    let computed = hex::encode(hash);
    Ok(computed == expected_sha256.to_lowercase())
}

pub fn compute_file_checksum(path: &Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

pub fn stage_update(staging_dir: &Path, binary_name: &str, data: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(staging_dir)?;
    let dest = staging_dir.join(binary_name);
    std::fs::write(&dest, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }
    info!(path = %dest.display(), "update binary staged");
    Ok(dest)
}

pub fn apply_staged_update(staged: &Path, target: &Path) -> std::io::Result<()> {
    let backup = target.with_extension("bak");
    if target.exists() {
        std::fs::rename(target, &backup)?;
        info!(backup = %backup.display(), "current binary backed up");
    }
    match std::fs::rename(staged, target) {
        Ok(()) => {
            info!(path = %target.display(), "update applied");
            if backup.exists() {
                let _ = std::fs::remove_file(&backup);
            }
            Ok(())
        }
        Err(e) => {
            warn!(%e, "failed to apply update, restoring backup");
            if backup.exists() {
                std::fs::rename(&backup, target)?;
            }
            Err(e)
        }
    }
}

fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (Vec<u64>, bool) {
        let is_pre = s.contains('-');
        let base = s.split('-').next().unwrap_or(s);
        let nums = base.split('.').filter_map(|p| p.parse().ok()).collect();
        (nums, is_pre)
    };
    let (va, a_pre) = parse(a);
    let (vb, b_pre) = parse(b);
    for (pa, pb) in va.iter().zip(vb.iter()) {
        if pa > pb {
            return true;
        }
        if pa < pb {
            return false;
        }
    }
    if va.len() != vb.len() {
        return va.len() > vb.len();
    }
    // Same base version: release > pre-release
    !a_pre && b_pre
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn version_comparison() {
        assert!(version_gt("2.1.0", "2.0.0"));
        assert!(version_gt("2.0.1", "2.0.0"));
        assert!(!version_gt("2.0.0", "2.0.0"));
        assert!(!version_gt("1.9.9", "2.0.0"));
        assert!(version_gt("2.0.0", "2.0.0-alpha.1"));
    }

    #[test]
    fn check_version_newer() {
        let checker = UpdateChecker::new("2.0.0-alpha.1", UpdateConfig::default());
        assert!(checker.check_version_newer("v2.0.0"));
        assert!(checker.check_version_newer("v2.1.0"));
        assert!(!checker.check_version_newer("v1.0.0"));
    }

    #[test]
    fn platform_asset_name_format() {
        let name = UpdateChecker::platform_asset_name();
        assert!(name.starts_with("os-defender-agent-"));
        if cfg!(target_os = "linux") {
            assert!(name.contains("linux"));
            assert!(!name.ends_with(".exe"));
        }
    }

    #[test]
    fn update_info_no_update() {
        let checker = UpdateChecker::new("2.0.0", UpdateConfig::default());
        let info = checker.no_update_info();
        assert!(!info.update_available);
        assert_eq!(info.current_version, "2.0.0");
    }

    #[test]
    fn update_info_with_newer() {
        let checker = UpdateChecker::new("2.0.0-alpha.1", UpdateConfig::default());
        let info = checker.build_update_info(
            Some("v2.1.0"),
            Some("Bug fixes"),
            Some("https://example.com/binary"),
            None,
            None,
        );
        assert!(info.update_available);
        assert_eq!(info.latest_version.as_deref(), Some("v2.1.0"));
    }

    #[test]
    fn file_checksum_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.bin");
        let mut f = std::fs::File::create(&file).unwrap();
        f.write_all(b"hello world").unwrap();

        let checksum = compute_file_checksum(&file).unwrap();
        assert!(verify_file_checksum(&file, &checksum).unwrap());
        assert!(!verify_file_checksum(&file, "0000").unwrap());
    }

    #[test]
    fn stage_and_apply_update() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let target = dir.path().join("os-defender-agent");

        std::fs::write(&target, b"old binary").unwrap();

        let staged = stage_update(&staging, "os-defender-agent", b"new binary").unwrap();
        assert!(staged.exists());

        apply_staged_update(&staged, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new binary");
        assert!(!staged.exists());
    }
}
