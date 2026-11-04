use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ipc::AiEngineStatus;
use tracing::debug;

pub struct AiBridge {
    model_dir: PathBuf,
    python_bin: String,
    events_scored: u64,
    anomalies_detected: u64,
}

impl AiBridge {
    pub fn new(model_dir: &Path) -> Self {
        let python_bin = find_python().unwrap_or_else(|| "python3".into());
        Self {
            model_dir: model_dir.to_path_buf(),
            python_bin,
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

        AiEngineStatus {
            available,
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
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn find_python() -> Option<String> {
    for bin in ["python3", "python"] {
        if Command::new(bin)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(bin.into());
        }
    }
    None
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
        assert!(!status.available);
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
}
