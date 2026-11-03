use crate::events::NormalizedEvent;
use super::super::Alert;

pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert>;
    fn tick(&mut self) -> Vec<Alert> {
        Vec::new()
    }
}

pub struct RuleSet {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn evaluate(&mut self, event: &NormalizedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &mut self.rules {
            if let Some(alert) = rule.evaluate(event) {
                alerts.push(alert);
            }
        }
        alerts
    }

    pub fn tick(&mut self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &mut self.rules {
            alerts.extend(rule.tick());
        }
        alerts
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}
