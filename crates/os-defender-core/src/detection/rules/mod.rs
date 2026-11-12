mod anomalous_network;
mod brute_force;
mod file_tampering;
mod persistence_change;
mod suspicious_process;
mod traits;

pub use anomalous_network::AnomalousNetworkRule;
pub use brute_force::BruteForceRule;
pub use file_tampering::FileTamperingRule;
pub use persistence_change::PersistenceChangeRule;
pub use suspicious_process::SuspiciousProcessRule;
pub use traits::{Rule, RuleSet};

pub use crate::advanced::ransomware::RansomwareDefenseRule;

pub fn default_ruleset() -> RuleSet {
    let mut rs = RuleSet::new();
    rs.add_rule(Box::new(BruteForceRule::new(5, 300)));
    rs.add_rule(Box::new(SuspiciousProcessRule::new()));
    rs.add_rule(Box::new(FileTamperingRule::new()));
    rs.add_rule(Box::new(AnomalousNetworkRule::new()));
    rs.add_rule(Box::new(PersistenceChangeRule::new()));
    rs.add_rule(Box::new(RansomwareDefenseRule::new()));
    rs
}
