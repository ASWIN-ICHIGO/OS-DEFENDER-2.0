use crate::events::NormalizedEvent;
use super::Alert;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventType, OsType, Severity};

    struct AlwaysAlert;
    impl Rule for AlwaysAlert {
        fn id(&self) -> &str { "test-always" }
        fn name(&self) -> &str { "Always Alert" }
        fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
            Some(Alert::from_rule(
                event.event_id,
                self.id(),
                Severity::High,
                "Test alert".into(),
                "Test".into(),
                1.0,
            ))
        }
    }

    #[test]
    fn ruleset_collects_alerts() {
        let mut rs = RuleSet::new();
        rs.add_rule(Box::new(AlwaysAlert));
        let event = NormalizedEvent::new("ep".into(), OsType::Linux, EventType::Process, Severity::Info);
        let alerts = rs.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id.as_deref(), Some("test-always"));
    }
}
