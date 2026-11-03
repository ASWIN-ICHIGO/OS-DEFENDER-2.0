mod traits;
mod brute_force;
mod suspicious_process;
mod file_tampering;
mod anomalous_network;
mod persistence_change;

pub use traits::{Rule, RuleSet};
pub use brute_force::BruteForceRule;
pub use suspicious_process::SuspiciousProcessRule;
pub use file_tampering::FileTamperingRule;
pub use anomalous_network::AnomalousNetworkRule;
pub use persistence_change::PersistenceChangeRule;

pub fn default_ruleset() -> RuleSet {
    let mut rs = RuleSet::new();
    rs.add_rule(Box::new(BruteForceRule::new(5, 300)));
    rs.add_rule(Box::new(SuspiciousProcessRule::new()));
    rs.add_rule(Box::new(FileTamperingRule::new()));
    rs.add_rule(Box::new(AnomalousNetworkRule::new()));
    rs.add_rule(Box::new(PersistenceChangeRule::new()));
    rs
}
