use crate::events::{
    EventType, EvidenceRef, NormalizedEvent, OsType, ProcessContext, Severity,
};
use crate::platform::{CollectorError, CollectorResult, ProcessCollector};
use std::collections::HashMap;
use std::pin::Pin;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    name: String,
    exe_path: Option<String>,
    thread_count: u32,
}

pub struct WindowsProcessCollector {
    endpoint_id: String,
    known_processes: HashMap<u32, String>,
}

impl WindowsProcessCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            known_processes: HashMap::new(),
        }
    }

    fn snapshot_processes() -> Result<Vec<ProcessSnapshot>, CollectorError> {
        let mut result = Vec::new();

        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| CollectorError::Unavailable(format!("CreateToolhelp32Snapshot: {e}")))?;

            let mut entry = PROCESSENTRY32 {
                dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                ..Default::default()
            };

            if Process32First(snap, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf8_lossy(
                        &entry.szExeFile.iter().take_while(|&&c| c != 0).copied().collect::<Vec<u8>>(),
                    )
                    .to_string();

                    result.push(ProcessSnapshot {
                        pid: entry.th32ProcessID,
                        ppid: entry.th32ParentProcessID,
                        name,
                        exe_path: None, // would need OpenProcess + QueryFullProcessImageName
                        thread_count: entry.cntThreads,
                    });

                    if Process32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snap);
        }

        Ok(result)
    }
}

impl ProcessCollector for WindowsProcessCollector {
    fn poll_processes(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let snapshots = Self::snapshot_processes()?;
            let mut events = Vec::new();
            let mut current = HashMap::new();

            for snap in &snapshots {
                current.insert(snap.pid, snap.name.clone());

                if self.known_processes.get(&snap.pid).map(|n| n.as_str()) == Some(&snap.name) {
                    continue;
                }

                let event = NormalizedEvent::new(
                    self.endpoint_id.clone(),
                    OsType::Windows,
                    EventType::Process,
                    Severity::Info,
                )
                .with_process(ProcessContext {
                    pid: snap.pid,
                    ppid: Some(snap.ppid),
                    name: snap.name.clone(),
                    exe: snap.exe_path.clone(),
                    cmdline: None,
                    uid: None,
                    username: None,
                    start_time: None,
                    children_pids: vec![],
                })
                .with_evidence(EvidenceRef {
                    source: "win32-toolhelp".into(),
                    detail: format!("PID {} threads={}", snap.pid, snap.thread_count),
                });

                events.push(event);
            }

            self.known_processes = current;
            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "windows-process"
    }
}
