use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSource {
    Rule,
    Anomaly,
    Correlation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    pub name: String,
    pub weight: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: Uuid,
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: DetectionSource,
    pub rule_id: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub confidence: f64,
    pub factors: Vec<Factor>,
    pub mitre_techniques: Vec<String>,
}

impl Alert {
    pub fn from_rule(
        event_id: Uuid,
        rule_id: &str,
        severity: Severity,
        title: String,
        description: String,
        confidence: f64,
    ) -> Self {
        Self {
            alert_id: Uuid::new_v4(),
            event_id,
            timestamp: Utc::now(),
            source: DetectionSource::Rule,
            rule_id: Some(rule_id.to_string()),
            severity,
            title,
            description,
            confidence,
            factors: Vec::new(),
            mitre_techniques: Vec::new(),
        }
    }

    pub fn with_factor(mut self, name: &str, weight: f64, description: &str) -> Self {
        self.factors.push(Factor {
            name: name.to_string(),
            weight,
            description: description.to_string(),
        });
        self
    }

    pub fn with_mitre(mut self, technique_id: &str) -> Self {
        self.mitre_techniques.push(technique_id.to_string());
        self
    }
}
