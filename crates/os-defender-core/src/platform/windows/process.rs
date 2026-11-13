use crate::events::{
    EventType, EvidenceRef, NormalizedEvent, OsType, ProcessContext, Severity,
};
use crate::platform::{CollectorError, CollectorResult, ProcessCollector};
use std::collections::HashMap;
use std::pin::Pin;

use windows::core::{s, w};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

const MAX_CMDLINE_BYTES: usize = 8192;
const EVIDENCE_CMDLINE_MAX: usize = 200;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessBasicInformation {
    exit_status: i32,
    _pad0: u32,
    peb_base_address: u64,
    affinity_mask: usize,
    base_priority: i32,
    _pad1: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: u64,
}

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
                        &entry
                            .szExeFile
                            .iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as u8)
                            .collect::<Vec<u8>>(),
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

unsafe fn read_remote_memory(handle: HANDLE, address: u64, size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size];
    ReadProcessMemory(
        handle,
        address as *const _,
        buf.as_mut_ptr().cast(),
        size,
        None,
    )
    .ok()?;
    Some(buf)
}

/// Reads the full command line of a process by walking its PEB:
/// PEB -> ProcessParameters (offset 0x20) -> CommandLine UNICODE_STRING
/// (offset 0x70 in RTL_USER_PROCESS_PARAMETERS on x64).
///
/// Uses NtQueryInformationProcess resolved dynamically from ntdll so no
/// import-time linkage is needed. Any failure (access denied, protected
/// process, short-lived process) yields None.
fn read_cmdline(pid: u32) -> Option<String> {
    if pid <= 4 {
        return None;
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()?;

        let result = read_cmdline_with_handle(handle);
        let _ = CloseHandle(handle);
        result
    }
}

unsafe fn read_cmdline_with_handle(handle: HANDLE) -> Option<String> {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    let proc_addr = GetProcAddress(ntdll, s!("NtQueryInformationProcess"));
    let nt_query: unsafe extern "system" fn(
        usize,
        u32,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32 = std::mem::transmute(proc_addr?);

    let mut pbi = ProcessBasicInformation::default();
    let status = nt_query(
        handle.0 as usize,
        PROCESS_BASIC_INFORMATION_CLASS,
        &mut pbi as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        std::ptr::null_mut(),
    );
    if status != 0 || pbi.peb_base_address == 0 {
        return None;
    }

    let params_raw = read_remote_memory(handle, pbi.peb_base_address + 0x20, 8)?;
    let params = u64::from_le_bytes(params_raw.try_into().ok()?);
    if params == 0 {
        return None;
    }

    let us_raw = read_remote_memory(handle, params + 0x70, std::mem::size_of::<UnicodeString>())?;
    let us = *(us_raw.as_ptr() as *const UnicodeString);
    if us.length == 0
        || us.length as usize > MAX_CMDLINE_BYTES
        || us.length % 2 != 0
        || us.buffer == 0
    {
        return None;
    }

    let raw = read_remote_memory(handle, us.buffer, us.length as usize)?;
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let cmdline = String::from_utf16_lossy(&utf16);
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn truncate_for_evidence(cmdline: &str) -> String {
    if cmdline.len() <= EVIDENCE_CMDLINE_MAX {
        cmdline.to_string()
    } else {
        let mut end = EVIDENCE_CMDLINE_MAX;
        while !cmdline.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &cmdline[..end])
    }
}

impl ProcessCollector for WindowsProcessCollector {
    fn poll_processes(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let snapshots = Self::snapshot_processes()?;
            let mut events = Vec::new();
            let mut current = HashMap::new();

            for snap in &snapshots {
                current.insert(snap.pid, snap.name.clone());

                if self.known_processes.get(&snap.pid).map(|n| n.as_str()) == Some(&snap.name) {
                    continue;
                }

                // Command lines are read only for newly-seen processes to keep
                // polling cheap; existing processes keep their first capture.
                let cmdline = read_cmdline(snap.pid);

                let detail = match &cmdline {
                    Some(c) => format!(
                        "PID {} threads={} cmd={}",
                        snap.pid,
                        snap.thread_count,
                        truncate_for_evidence(c)
                    ),
                    None => format!("PID {} threads={}", snap.pid, snap.thread_count),
                };

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
                    cmdline,
                    uid: None,
                    username: None,
                    start_time: None,
                    children_pids: vec![],
                })
                .with_evidence(EvidenceRef {
                    source: "win32-toolhelp".into(),
                    detail,
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
