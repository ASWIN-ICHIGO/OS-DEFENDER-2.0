use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorStatus {
    pub name: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub events_collected: u64,
    pub events_dropped: u64,
    pub is_healthy: bool,
    pub lag_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityAssessment {
    pub timestamp: DateTime<Utc>,
    pub sensors: Vec<SensorStatus>,
    pub overall_healthy: bool,
    pub blind_spots: Vec<String>,
    pub caveat: String,
}

pub struct BlindSpotDetector {
    sensors: HashMap<String, SensorStatus>,
    heartbeat_timeout_secs: i64,
}

impl BlindSpotDetector {
    pub fn new(heartbeat_timeout_secs: i64) -> Self {
        Self {
            sensors: HashMap::new(),
            heartbeat_timeout_secs,
        }
    }

    pub fn record_heartbeat(&mut self, name: &str, events_collected: u64, events_dropped: u64) {
        let entry = self.sensors.entry(name.to_string()).or_insert(SensorStatus {
            name: name.to_string(),
            last_heartbeat: None,
            events_collected: 0,
            events_dropped: 0,
            is_healthy: true,
            lag_ms: None,
        });
        entry.last_heartbeat = Some(Utc::now());
        entry.events_collected = events_collected;
        entry.events_dropped = events_dropped;
        entry.is_healthy = true;
    }

    pub fn assess(&mut self) -> VisibilityAssessment {
        let now = Utc::now();
        let mut blind_spots = Vec::new();

        for sensor in self.sensors.values_mut() {
            if let Some(last) = sensor.last_heartbeat {
                let gap = (now - last).num_seconds();
                if gap > self.heartbeat_timeout_secs {
                    sensor.is_healthy = false;
                    blind_spots.push(format!(
                        "{}: no heartbeat for {}s (threshold: {}s)",
                        sensor.name, gap, self.heartbeat_timeout_secs
                    ));
                }
            } else {
                sensor.is_healthy = false;
                blind_spots.push(format!("{}: never received a heartbeat", sensor.name));
            }

            if sensor.events_dropped > 0 {
                blind_spots.push(format!(
                    "{}: {} events dropped",
                    sensor.name, sensor.events_dropped
                ));
            }
        }

        let overall_healthy = self.sensors.values().all(|s| s.is_healthy);

        VisibilityAssessment {
            timestamp: now,
            sensors: self.sensors.values().cloned().collect(),
            overall_healthy,
            blind_spots,
            caveat: "Visibility assessment reflects known sensors only. \
                     Absence of alerts does not confirm absence of threats."
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_sensor() {
        let mut detector = BlindSpotDetector::new(60);
        detector.record_heartbeat("linux-process", 100, 0);
        let assessment = detector.assess();
        assert!(assessment.overall_healthy);
        assert!(assessment.blind_spots.is_empty());
    }

    #[test]
    fn dropped_events_reported() {
        let mut detector = BlindSpotDetector::new(60);
        detector.record_heartbeat("linux-file", 50, 5);
        let assessment = detector.assess();
        assert!(!assessment.blind_spots.is_empty());
        assert!(assessment.blind_spots[0].contains("5 events dropped"));
    }

    #[test]
    fn missing_heartbeat_detected() {
        let mut detector = BlindSpotDetector::new(60);
        let status = SensorStatus {
            name: "linux-auth".into(),
            last_heartbeat: Some(Utc::now() - chrono::Duration::seconds(120)),
            events_collected: 0,
            events_dropped: 0,
            is_healthy: true,
            lag_ms: None,
        };
        detector.sensors.insert("linux-auth".into(), status);
        let assessment = detector.assess();
        assert!(!assessment.overall_healthy);
    }
}
