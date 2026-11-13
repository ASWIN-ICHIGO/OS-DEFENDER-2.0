use super::super::Alert;
use super::traits::Rule;
use crate::events::{EventType, NormalizedEvent, Severity};

/// Suspicious interpreters, reverse shells, and known-bad parent-child relationships.
/// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1059.004 (Unix Shell)
pub struct SuspiciousProcessRule {
    suspicious_interpreters: Vec<&'static str>,
    suspicious_cmdline_patterns: Vec<&'static str>,
    windows_cmdline_patterns: Vec<&'static str>,
    suspicious_names: Vec<&'static str>,
    high_confidence_tools: Vec<&'static str>,
}

impl Default for SuspiciousProcessRule {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspiciousProcessRule {
    pub fn new() -> Self {
        Self {
            suspicious_interpreters: vec![
                "nc", "ncat", "netcat", "socat", "nmap", "masscan", "curl", "wget", "python",
                "python3", "perl", "ruby", "php",
            ],
            suspicious_cmdline_patterns: vec![
                "/dev/tcp/",
                "bash -i",
                "sh -i",
                "mkfifo",
                "base64 -d",
                "base64 --decode",
                "/bin/sh -c",
                "exec 5<>/dev/tcp",
                "curl | sh",
                "curl | bash",
                "wget -O - |",
                "chmod +s",
                "chmod u+s",
                "chmod 4",
            ],
            windows_cmdline_patterns: vec![
                "-encodedcommand",
                "-enc ",
                "-ec ",
                "-w hidden",
                "-windowstyle hidden",
                "-nop",
                " iex ",
                "iex (",
                "invoke-expression",
                "downloadstring",
                "frombase64string",
                "wscript //b",
                "mshta vbscript:",
                "rundll32 javascript:",
                "regsvr32 /i:http",
                "certutil -urlcache",
                "bitsadmin /transfer",
            ],
            suspicious_names: vec![
                "mshta.exe",
                "certutil.exe",
                "bitsadmin.exe",
                "mimikatz.exe",
                "psexec.exe",
                "psexec64.exe",
                "nc.exe",
                "ncat.exe",
                "at.exe",
                "diskshadow.exe",
                "vssadmin.exe",
                "bcdedit.exe",
            ],
            high_confidence_tools: vec![
                "mimikatz.exe",
                "psexec.exe",
                "psexec64.exe",
                "bcdedit.exe",
                "diskshadow.exe",
            ],
        }
    }

    fn check_suspicious_interpreter(&self, exe: &str, name: &str) -> Option<&'static str> {
        let basename = exe.rsplit('/').next().unwrap_or(exe);
        self.suspicious_interpreters
            .iter()
            .find(|&&interp| basename == interp || name == interp)
            .copied()
    }

    fn check_suspicious_cmdline(&self, cmdline: &str) -> Option<&'static str> {
        let lower = cmdline.to_lowercase();
        self.suspicious_cmdline_patterns
            .iter()
            .find(|&&pattern| lower.contains(pattern))
            .copied()
    }

    /// Windows-specific command-line patterns (LOLBAS / PowerShell
    /// fileless-attack indicators). MITRE: T1059.001 (PowerShell), T1027
    /// (obfuscated files), T1105 (ingress tool transfer).
    fn check_windows_cmdline(&self, cmdline: &str) -> Option<&'static str> {
        if cmdline.is_empty() {
            return None;
        }
        let lower = cmdline.to_lowercase();
        self.windows_cmdline_patterns
            .iter()
            .find(|&&pattern| lower.contains(pattern))
            .copied()
    }

    fn check_suspicious_parent_child(&self, ppid: u32, name: &str, exe: &str) -> Option<String> {
        // web server spawning shell
        let web_servers = ["nginx", "apache2", "httpd", "node", "java"];
        let shells = ["bash", "sh", "dash", "zsh", "fish", "csh"];

        let parent_name = self.read_parent_name(ppid);
        if let Some(ref pname) = parent_name {
            let pbase = pname.rsplit('/').next().unwrap_or(pname);
            let cbase = exe.rsplit('/').next().unwrap_or(name);

            for &ws in &web_servers {
                if pbase == ws {
                    for &sh in &shells {
                        if cbase == sh {
                            return Some(format!("{ws} spawned {sh}"));
                        }
                    }
                }
            }
        }
        None
    }

    fn check_suspicious_name(&self, name: &str, exe: &str) -> Option<&'static str> {
        let base = exe.rsplit(['/', '\\']).next().unwrap_or(exe);
        let base_l = base.to_lowercase();
        let name_l = name.to_lowercase();
        self.suspicious_names
            .iter()
            .find(|&&n| base_l == n || name_l == n)
            .copied()
    }

    fn office_spawn_reason(&self, parent_name: &str, name: &str, exe: &str) -> Option<String> {
        let office = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "winword",
            "excel",
            "powerpnt",
            "outlook",
        ];
        let scripts = [
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
            "wscript",
            "wscript.exe",
            "cscript",
            "cscript.exe",
            "mshta",
            "mshta.exe",
            "rundll32",
            "rundll32.exe",
            "regsvr32",
            "regsvr32.exe",
        ];

        let cbase = exe
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(name)
            .to_lowercase();
        if !scripts.contains(&cbase.as_str()) {
            return None;
        }

        let pbase = parent_name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(parent_name)
            .to_lowercase();
        if office.contains(&pbase.as_str()) {
            return Some(format!("{pbase} spawned {cbase}"));
        }
        None
    }

    fn check_suspicious_location(&self, exe: &str) -> Option<&'static str> {
        if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/var/tmp/")
        {
            return Some("execution from world-writable temp directory");
        }
        if exe.starts_with("\\\\") {
            return Some("execution from UNC network path");
        }
        let lower = exe.to_lowercase();
        if lower.starts_with("\\users\\public\\")
            || lower.starts_with("\\windows\\temp\\")
            || lower.starts_with("\\programdata\\")
        {
            return Some("execution from user-writable location");
        }
        None
    }

    fn read_parent_name(&self, ppid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{ppid}/comm"))
                .ok()
                .map(|s| s.trim().to_string())
        }

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
                TH32CS_SNAPPROCESS,
            };

            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
                let mut entry = PROCESSENTRY32 {
                    dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                    ..Default::default()
                };
                let mut found = None;
                if Process32First(snap, &mut entry).is_ok() {
                    loop {
                        if entry.th32ProcessID == ppid {
                            found = Some(
                                String::from_utf8_lossy(
                                    &entry
                                        .szExeFile
                                        .iter()
                                        .take_while(|&&c| c != 0)
                                        .map(|&c| c as u8)
                                        .collect::<Vec<u8>>(),
                                )
                                .to_string(),
                            );
                            break;
                        }
                        if Process32Next(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
                found
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = ppid;
            None
        }
    }
}

impl Rule for SuspiciousProcessRule {
    fn id(&self) -> &str {
        "R002-suspicious-process"
    }
    fn name(&self) -> &str {
        "Suspicious Process Execution"
    }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::Process {
            return None;
        }
        let proc = event.process_context.as_ref()?;
        let exe = proc.exe.as_deref().unwrap_or("");
        let cmdline = proc.cmdline.as_deref().unwrap_or("");

        // Windows command-line indicators (PowerShell obfuscation, LOLBAS
        // download-and-execute) — fires now that the Windows collector
        // captures full command lines via the PEB.
        if let Some(pattern) = self.check_windows_cmdline(cmdline) {
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::High,
                    format!("Suspicious Windows command: {}", proc.name),
                    format!(
                        "Process '{}' (PID {}) executed with suspicious pattern: '{pattern}' in command line: {}",
                        proc.name, proc.pid, cmdline
                    ),
                    0.9,
                )
                .with_factor("pattern_match", 1.0, pattern)
                .with_mitre("T1059.001")
                .with_mitre("T1027"),
            );
        }

        // Check suspicious command line patterns first (higher confidence)
        if let Some(pattern) = self.check_suspicious_cmdline(cmdline) {
            let severity = if pattern.contains("/dev/tcp")
                || pattern.contains("mkfifo")
                || pattern.contains("chmod +s")
                || pattern.contains("chmod 4")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    severity,
                    format!("Suspicious command: {}", proc.name),
                    format!(
                        "Process '{}' (PID {}) executed with suspicious pattern: '{pattern}'",
                        proc.name, proc.pid
                    ),
                    0.8,
                )
                .with_factor("pattern_match", 1.0, pattern)
                .with_factor(
                    "cmdline_length",
                    cmdline.len() as f64,
                    "command complexity indicator",
                )
                .with_mitre("T1059.004"),
            );
        }

        // Known attack/admin tooling by process name (also covers Windows
        // events whose command line could not be read)
        if let Some(tool) = self.check_suspicious_name(&proc.name, exe) {
            let severity = if self.high_confidence_tools.contains(&tool) {
                Severity::High
            } else {
                Severity::Medium
            };
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    severity,
                    format!("Attack tool executed: {tool}"),
                    format!(
                        "Process '{}' (PID {}) is a known attack/administration tool",
                        proc.name, proc.pid
                    ),
                    0.85,
                )
                .with_factor("tool_name", 1.0, tool)
                .with_mitre("T1059"),
            );
        }

        // Office application spawning a script interpreter — classic macro attack
        if let Some(ppid) = proc.ppid {
            let cbase = exe
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&proc.name)
                .to_lowercase();
            let script_like = [
                "cmd",
                "cmd.exe",
                "powershell",
                "powershell.exe",
                "pwsh",
                "pwsh.exe",
                "wscript",
                "wscript.exe",
                "cscript",
                "cscript.exe",
                "mshta",
                "mshta.exe",
                "rundll32",
                "rundll32.exe",
                "regsvr32",
                "regsvr32.exe",
            ];
            if script_like.contains(&cbase.as_str())
                && let Some(parent) = self.read_parent_name(ppid)
                && let Some(reason) = self.office_spawn_reason(&parent, &proc.name, exe)
            {
                return Some(
                    Alert::from_rule(
                        event.event_id,
                        self.id(),
                        Severity::High,
                        format!("Office macro attack: {reason}"),
                        format!(
                            "Process '{}' (PID {}) has suspicious lineage: {reason}",
                            proc.name, proc.pid
                        ),
                        0.85,
                    )
                    .with_factor("office_spawn", 1.0, &reason)
                    .with_mitre("T1566.001"),
                );
            }
        }
