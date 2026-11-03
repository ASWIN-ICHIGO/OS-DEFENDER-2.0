use crate::events::{
    AuthAction, AuthContext, EventType, EvidenceRef, NormalizedEvent, OsType, Severity,
};
use crate::platform::{AuthCollector, CollectorError, CollectorResult};
use std::io::{BufRead, BufReader};
use std::pin::Pin;
use std::process::{Command, Stdio};

pub struct LinuxAuthCollector {
    endpoint_id: String,
    child: Option<std::process::Child>,
    reader: Option<BufReader<std::fs::File>>,
}

impl LinuxAuthCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            child: None,
            reader: None,
        }
    }

    fn ensure_started(&mut self) -> Result<(), CollectorError> {
        if self.reader.is_some() {
            return Ok(());
        }

        let mut child = Command::new("/usr/bin/journalctl")
            .args([
                "--follow",
                "--output=json",
                "--no-pager",
                "_COMM=sshd",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| CollectorError::Unavailable(format!("journalctl: {e}")))?;

        let stdout = child.stdout.take().ok_or_else(|| {
            CollectorError::Internal(anyhow::anyhow!("no stdout from journalctl"))
        })?;

        // dup the fd so we own it independently of the Child
        let file = unsafe {
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let fd = stdout.as_raw_fd();
            let dup_fd = libc::dup(fd);
            if dup_fd < 0 {
                return Err(CollectorError::Internal(anyhow::anyhow!("dup() failed")));
            }
            std::fs::File::from_raw_fd(dup_fd)
        };

        self.reader = Some(BufReader::new(file));
        self.child = Some(child);
        Ok(())
    }

    fn parse_journal_entry(endpoint_id: &str, json_str: &str) -> Option<NormalizedEvent> {
        let entry: serde_json::Value = serde_json::from_str(json_str).ok()?;
        let message = entry.get("MESSAGE")?.as_str()?;
        let exe = entry.get("_EXE").and_then(|v| v.as_str());

        if let Some(exe_path) = exe
            && !exe_path.starts_with("/usr/")
        {
            return None;
        }

        let (action, severity, username, source_addr) = if message.contains("Accepted") {
            let parts: Vec<&str> = message.split_whitespace().collect();
            let user = parts.get(3).unwrap_or(&"unknown");
            let addr = parts.get(5);
            (
                AuthAction::Login,
                Severity::Info,
                user.to_string(),
                addr.map(|s| s.to_string()),
            )
        } else if message.contains("Failed password") || message.contains("authentication failure")
        {
            let parts: Vec<&str> = message.split_whitespace().collect();
            let user_idx = parts.iter().position(|&w| w == "for").map(|i| i + 1);
            let user = user_idx
                .and_then(|i| parts.get(i))
                .unwrap_or(&"unknown")
                .to_string();
            let addr_idx = parts.iter().position(|&w| w == "from").map(|i| i + 1);
            let addr = addr_idx.and_then(|i| parts.get(i).map(|s| s.to_string()));
            (AuthAction::Failed, Severity::Medium, user, addr)
        } else {
            return None;
        };

        let event = NormalizedEvent::new(
            endpoint_id.to_string(),
            OsType::Linux,
            EventType::Authentication,
            severity,
        )
        .with_auth(AuthContext {
            action,
            username,
            source_addr,
            method: Some("password".into()),
            service: Some("sshd".into()),
            session_id: None,
        })
        .with_evidence(EvidenceRef {
            source: "linux-journal".into(),
            detail: message.chars().take(200).collect(),
        });

        Some(event)
    }
}

impl Drop for LinuxAuthCollector {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl AuthCollector for LinuxAuthCollector {
    fn poll_auth_events(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            self.ensure_started()?;
            let endpoint_id = self.endpoint_id.clone();
            let reader = self.reader.as_mut().unwrap();
            let mut events = Vec::new();
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Some(event) =
                            Self::parse_journal_entry(&endpoint_id, line.trim())
                        {
                            events.push(event);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(CollectorError::Internal(e.into())),
                }
                if events.len() >= 100 {
                    break;
                }
            }

            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "linux-auth"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepted_login() {
        let json = r#"{"MESSAGE":"Accepted password for aswin from 192.168.1.100 port 22 ssh2","_EXE":"/usr/sbin/sshd"}"#;
        let event = LinuxAuthCollector::parse_journal_entry("test-ep", json).unwrap();
        let auth = event.auth_context.unwrap();
        assert_eq!(auth.action, AuthAction::Login);
        assert_eq!(auth.username, "aswin");
        assert_eq!(auth.source_addr.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn parse_failed_login() {
        let json = r#"{"MESSAGE":"Failed password for root from 10.0.0.5 port 43210 ssh2","_EXE":"/usr/sbin/sshd"}"#;
        let event = LinuxAuthCollector::parse_journal_entry("test-ep", json).unwrap();
        assert_eq!(event.severity, Severity::Medium);
        let auth = event.auth_context.unwrap();
        assert_eq!(auth.action, AuthAction::Failed);
        assert_eq!(auth.username, "root");
    }

    #[test]
    fn rejects_untrusted_exe() {
        let json = r#"{"MESSAGE":"Accepted password for victim from 1.2.3.4 port 22 ssh2","_EXE":"/tmp/fake-sshd"}"#;
        assert!(LinuxAuthCollector::parse_journal_entry("test-ep", json).is_none());
    }
}
