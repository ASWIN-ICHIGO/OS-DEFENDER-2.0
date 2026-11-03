use crate::events::NormalizedEvent;
use super::alert::Alert;
use super::rules::RuleSet;

pub struct DetectionEngine {
    rules: RuleSet,
}

impl DetectionEngine {
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn process_event(&mut self, event: &NormalizedEvent) -> Vec<Alert> {
        self.rules.evaluate(event)
    }

    pub fn tick(&mut self) -> Vec<Alert> {
        self.rules.tick()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.rule_count()
    }
}
