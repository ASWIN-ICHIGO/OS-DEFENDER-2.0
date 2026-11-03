use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::events::{AuthAction, EventType, NormalizedEvent, Severity};
use super::super::Alert;
use super::traits::Rule;

struct FailedWindow {
    timestamps: Vec<DateTime<Utc>>,
    last_alert: Option<DateTime<Utc>>,
}

/// Detects repeated authentication failures from the same source within a time window.
/// MITRE ATT&CK: T1110 — Brute Force
pub struct BruteForceRule {
    threshold: usize,
    window_secs: i64,
    // key: (username, source_addr|"local")
    failures: HashMap<(String, String), FailedWindow>,
    cooldown_secs: i64,
}

impl BruteForceRule {
    pub fn new(threshold: usize, window_secs: i64) -> Self {
        Self {
            threshold,
            window_secs,
            failures: HashMap::new(),
            cooldown_secs: 300,
        }
    }

    fn gc_old_entries(&mut self, now: DateTime<Utc>) {
        self.failures.retain(|_, w| {
            w.timestamps.retain(|t| (now - *t).num_seconds() < self.window_secs * 2);
            !w.timestamps.is_empty()
        });
        // bound total tracked keys
        if self.failures.len() > 1000 {
            let cutoff = now - chrono::Duration::seconds(self.window_secs);
            self.failures.retain(|_, w| {
                w.timestamps.last().is_some_and(|t| *t > cutoff)
            });
        }
    }
}

impl Rule for BruteForceRule {
    fn id(&self) -> &str { "R001-brute-force" }
    fn name(&self) -> &str { "Brute Force Detection" }

    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<Alert> {
        if event.event_type != EventType::Authentication {
            return None;
        }
        let auth = event.auth_context.as_ref()?;
        if auth.action != AuthAction::Failed {
            return None;
        }

        let source = auth.source_addr.clone().unwrap_or_else(|| "local".into());
        let key = (auth.username.clone(), source.clone());
        let now = event.timestamp;

        self.gc_old_entries(now);

        let window = self.failures.entry(key).or_insert(FailedWindow {
            timestamps: Vec::new(),
            last_alert: None,
        });
        window.timestamps.push(now);

        // count failures within the time window
        let cutoff = now - chrono::Duration::seconds(self.window_secs);
        let recent: Vec<_> = window.timestamps.iter().filter(|t| **t > cutoff).collect();
        let count = recent.len();

        if count < self.threshold {
            return None;
        }

        // cooldown: don't alert again too soon for the same key
        if let Some(last) = window.last_alert
            && (now - last).num_seconds() < self.cooldown_secs
        {
            return None;
        }

        window.last_alert = Some(now);

        let severity = if count >= self.threshold * 3 {
            Severity::Critical
        } else if count >= self.threshold * 2 {
            Severity::High
        } else {
            Severity::Medium
        };

        Some(
            Alert::from_rule(
                event.event_id,
                self.id(),
                severity,
                format!("{count} failed logins for '{}' from {source}", auth.username),
                format!(
                    "{count} failed authentication attempts for user '{}' from {source} within {}s",
                    auth.username, self.window_secs
                ),
                0.85,
            )
            .with_factor("failure_count", count as f64, &format!("{count} failures in window"))
            .with_factor("window_seconds", self.window_secs as f64, "observation window")
            .with_mitre("T1110"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AuthContext, EventType, OsType};

    fn make_failed_login(user: &str, addr: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut e = NormalizedEvent::new("ep".into(), OsType::Linux, EventType::Authentication, Severity::Medium);
        e.timestamp = ts;
        e.auth_context = Some(AuthContext {
            action: AuthAction::Failed,
            username: user.into(),
            source_addr: Some(addr.into()),
            method: None,
            service: Some("sshd".into()),
            session_id: None,
        });
        e
    }

    #[test]
    fn fires_after_threshold() {
        let mut rule = BruteForceRule::new(3, 60);
        let now = Utc::now();

        assert!(rule.evaluate(&make_failed_login("root", "10.0.0.1", now)).is_none());
        assert!(rule.evaluate(&make_failed_login("root", "10.0.0.1", now)).is_none());
        let alert = rule.evaluate(&make_failed_login("root", "10.0.0.1", now));
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert!(a.title.contains("3 failed logins"));
        assert!(a.mitre_techniques.contains(&"T1110".to_string()));
    }

    #[test]
    fn different_users_tracked_separately() {
        let mut rule = BruteForceRule::new(3, 60);
        let now = Utc::now();

        rule.evaluate(&make_failed_login("root", "10.0.0.1", now));
        rule.evaluate(&make_failed_login("admin", "10.0.0.1", now));
        rule.evaluate(&make_failed_login("root", "10.0.0.1", now));
        // root has 2, admin has 1 — neither at threshold
        assert!(rule.evaluate(&make_failed_login("admin", "10.0.0.1", now)).is_none());
    }

    #[test]
    fn cooldown_prevents_repeated_alerts() {
        let mut rule = BruteForceRule::new(2, 60);
        let now = Utc::now();

        rule.evaluate(&make_failed_login("root", "x", now));
        assert!(rule.evaluate(&make_failed_login("root", "x", now)).is_some());
        // third failure within cooldown — no new alert
        assert!(rule.evaluate(&make_failed_login("root", "x", now)).is_none());
    }

    #[test]
    fn old_failures_expire() {
        let mut rule = BruteForceRule::new(3, 10);
        let old = Utc::now() - chrono::Duration::seconds(20);
        let now = Utc::now();

        rule.evaluate(&make_failed_login("root", "x", old));
        rule.evaluate(&make_failed_login("root", "x", old));
        // these are outside the window, so third recent failure shouldn't trigger
        assert!(rule.evaluate(&make_failed_login("root", "x", now)).is_none());
    }
}
