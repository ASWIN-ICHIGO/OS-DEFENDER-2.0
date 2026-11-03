use crate::events::{
    EventType, EvidenceRef, NormalizedEvent, OsType, ProcessContext, Severity,
};
use crate::platform::{CollectorError, CollectorResult, ProcessCollector};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::pin::Pin;

struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    name: String,
    exe: Option<String>,
    cmdline: Option<String>,
    uid: Option<u32>,
    start_ticks: u64,
}

pub struct LinuxProcessCollector {
    endpoint_id: String,
    known_processes: HashMap<u32, u64>,
}

impl LinuxProcessCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            known_processes: HashMap::new(),
        }
    }

    fn scan_proc(&self) -> Vec<ProcessSnapshot> {
        let mut snapshots = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return snapshots;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };

            if let Some(snap) = self.read_process(pid) {
                snapshots.push(snap);
            }
        }
        snapshots
    }

    fn read_process(&self, pid: u32) -> Option<ProcessSnapshot> {
        let proc_path = format!("/proc/{pid}");
        let base = Path::new(&proc_path);

        let stat_content = fs::read_to_string(base.join("stat")).ok()?;
        let (ppid, name, start_ticks) = Self::parse_stat(&stat_content)?;

        let exe = fs::read_link(base.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let cmdline = fs::read_to_string(base.join("cmdline"))
            .ok()
            .map(|s| s.replace('\0', " ").trim().to_string())
            .filter(|s| !s.is_empty());

        let uid = fs::read_to_string(base.join("status"))
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse().ok())
            });

        Some(ProcessSnapshot {
            pid,
            ppid,
            name,
            exe,
            cmdline,
            uid,
            start_ticks,
        })
    }

    fn parse_stat(content: &str) -> Option<(u32, String, u64)> {
        let open = content.find('(')?;
        let close = content.rfind(')')?;
        let name = content[open + 1..close].to_string();
        let rest = &content[close + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // field 0 = state, field 1 = ppid, field 19 = starttime
        let ppid: u32 = fields.get(1)?.parse().ok()?;
        let start_ticks: u64 = fields.get(19)?.parse().ok()?;
        Some((ppid, name, start_ticks))
    }

    fn detect_new_processes(&mut self, snapshots: &[ProcessSnapshot]) -> Vec<NormalizedEvent> {
        let mut events = Vec::new();
        let mut current_pids = HashMap::new();

        for snap in snapshots {
            current_pids.insert(snap.pid, snap.start_ticks);

            if let Some(&known_ticks) = self.known_processes.get(&snap.pid) {
                if known_ticks == snap.start_ticks {
                    continue; // same process, already known
                }
            }

            let event = NormalizedEvent::new(
                self.endpoint_id.clone(),
                OsType::Linux,
                EventType::Process,
                Severity::Info,
            )
            .with_process(ProcessContext {
                pid: snap.pid,
                ppid: Some(snap.ppid),
                name: snap.name.clone(),
                exe: snap.exe.clone(),
                cmdline: snap.cmdline.clone(),
                uid: snap.uid,
                username: snap.uid.and_then(|u| {
                    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(u))
                        .ok()
                        .flatten()
                        .map(|user| user.name)
                }),
                start_time: None,
                children_pids: vec![],
            })
            .with_evidence(EvidenceRef {
                source: "linux-proc".into(),
                detail: format!("/proc/{}/stat", snap.pid),
            });

            events.push(event);
        }

        self.known_processes = current_pids;
        events
    }
}

impl ProcessCollector for LinuxProcessCollector {
    fn poll_processes(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let snapshots = self.scan_proc();
            if snapshots.is_empty() {
                return Err(CollectorError::Unavailable("/proc not readable".into()));
            }
            Ok(self.detect_new_processes(&snapshots))
        })
    }

    fn name(&self) -> &str {
        "linux-process"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_extracts_name_and_ppid() {
        let stat = "1234 (bash) S 1 1234 1234 0 -1 4194304 1234 0 0 0 1 2 0 0 20 0 1 0 12345 67890 1234 18446744073709551615";
        let (ppid, name, ticks) = LinuxProcessCollector::parse_stat(stat).unwrap();
        assert_eq!(ppid, 1);
        assert_eq!(name, "bash");
        assert_eq!(ticks, 12345);
    }

    #[test]
    fn parse_stat_with_parens_in_name() {
        let stat = "5678 (Web Content (pid 1234)) S 100 5678 5678 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999 0 0 0";
        let (ppid, name, _) = LinuxProcessCollector::parse_stat(stat).unwrap();
        assert_eq!(name, "Web Content (pid 1234)");
        assert_eq!(ppid, 100);
    }

    #[tokio::test]
    async fn scan_detects_processes() {
        let mut collector = LinuxProcessCollector::new("test-ep".into());
        let result = collector.poll_processes().await;
        match result {
            Ok(events) => {
                // first poll: every running process is "new"
                assert!(!events.is_empty());
                // second poll: only genuinely new processes appear
                let events2 = collector.poll_processes().await.unwrap();
                assert!(events2.len() < events.len());
            }
            Err(CollectorError::Unavailable(_)) => {
                // containerized CI — /proc may be restricted
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
