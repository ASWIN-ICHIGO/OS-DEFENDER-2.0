use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::policy::{PolicyDecision, ResponseAction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub entry_id: i64,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub target: String,
    pub actor: String,
    pub reason: String,
    pub decision: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

pub struct AuditLog {
    last_hash: String,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            last_hash: "genesis".to_string(),
        }
    }

    pub fn recover_chain(conn: &Connection) -> Self {
        let last_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY entry_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "genesis".to_string());
        Self { last_hash }
    }

    pub fn record(
        &mut self,
        conn: &Connection,
        action: &ResponseAction,
        decision: PolicyDecision,
        actor: &str,
    ) -> anyhow::Result<AuditEntry> {
        let now = Utc::now();
        let action_str = action.kind.to_string();
        let decision_str = decision.to_string();

        let entry_hash = Self::compute_hash(
            &now,
            &action_str,
            &action.target,
            actor,
            &action.reason,
            &decision_str,
            &self.last_hash,
        );

        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target, actor, reason, payload, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                now.to_rfc3339(),
                action_str,
                action.target,
                actor,
                action.reason,
                decision_str,
                self.last_hash,
                entry_hash,
            ],
        )?;

        let entry_id = conn.last_insert_rowid();
        self.last_hash = entry_hash.clone();

        Ok(AuditEntry {
            entry_id,
            timestamp: now,
            action: action_str,
            target: action.target.clone(),
            actor: actor.to_string(),
            reason: action.reason.clone(),
            decision: decision_str,
            prev_hash: self.last_hash.clone(),
            entry_hash,
        })
    }

    pub fn verify_chain(conn: &Connection) -> anyhow::Result<(bool, usize)> {
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, action, target, actor, reason, payload, prev_hash, entry_hash
             FROM audit_log ORDER BY entry_id ASC",
        )?;

        let mut expected_prev = "genesis".to_string();
        let mut count = 0usize;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,  // timestamp
                row.get::<_, String>(2)?,  // action
                row.get::<_, String>(3)?,  // target
                row.get::<_, String>(4)?,  // actor
                row.get::<_, String>(5)?,  // reason
                row.get::<_, String>(6)?,  // payload (decision)
                row.get::<_, String>(7)?,  // prev_hash
                row.get::<_, String>(8)?,  // entry_hash
            ))
        })?;

        for row in rows {
            let (ts_str, action, target, actor, reason, decision, prev_hash, entry_hash) = row?;
            count += 1;

            if prev_hash != expected_prev {
                return Ok((false, count));
            }

            let ts: DateTime<Utc> = ts_str.parse().unwrap_or_default();
            let computed = Self::compute_hash(&ts, &action, &target, &actor, &reason, &decision, &prev_hash);
            if computed != entry_hash {
                return Ok((false, count));
            }

            expected_prev = entry_hash;
        }

        Ok((true, count))
    }

    fn compute_hash(
        ts: &DateTime<Utc>,
        action: &str,
        target: &str,
        actor: &str,
        reason: &str,
        decision: &str,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ts.to_rfc3339().as_bytes());
        hasher.update(b"|");
        hasher.update(action.as_bytes());
        hasher.update(b"|");
        hasher.update(target.as_bytes());
        hasher.update(b"|");
        hasher.update(actor.as_bytes());
        hasher.update(b"|");
        hasher.update(reason.as_bytes());
        hasher.update(b"|");
        hasher.update(decision.as_bytes());
        hasher.update(b"|");
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn get_recent(conn: &Connection, limit: u32) -> anyhow::Result<Vec<AuditEntry>> {
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, action, target, actor, reason, payload, prev_hash, entry_hash
             FROM audit_log ORDER BY entry_id DESC LIMIT ?1",
        )?;

        let entries = stmt
            .query_map(params![limit], |row| {
                Ok(AuditEntry {
                    entry_id: row.get(0)?,
                    timestamp: row
                        .get::<_, String>(1)?
                        .parse()
                        .unwrap_or_default(),
                    action: row.get(2)?,
                    target: row.get(3)?,
                    actor: row.get(4)?,
                    reason: row.get(5)?,
                    decision: row.get(6)?,
                    prev_hash: row.get(7)?,
                    entry_hash: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::policy::{ResponseActionKind, ResponseAction};
    use uuid::Uuid;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                action TEXT NOT NULL,
                target TEXT,
                actor TEXT NOT NULL,
                reason TEXT,
                payload TEXT,
                prev_hash TEXT,
                entry_hash TEXT NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    fn test_action() -> ResponseAction {
        ResponseAction::new(
            Uuid::new_v4(),
            ResponseActionKind::BlockIp,
            "10.0.0.5".into(),
            "brute-force detected".into(),
        )
    }

    #[test]
    fn record_and_verify_chain() {
        let conn = setup_db();
        let mut log = AuditLog::new();

        log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
            .unwrap();
        log.record(&conn, &test_action(), PolicyDecision::DryRun, "agent")
            .unwrap();
        log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
            .unwrap();

        let (valid, count) = AuditLog::verify_chain(&conn).unwrap();
        assert!(valid);
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_chain_detected() {
        let conn = setup_db();
        let mut log = AuditLog::new();

        log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
            .unwrap();
        log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
            .unwrap();

        // Tamper with an entry
        conn.execute("UPDATE audit_log SET target = 'hacked' WHERE entry_id = 1", [])
            .unwrap();

        let (valid, _) = AuditLog::verify_chain(&conn).unwrap();
        assert!(!valid);
    }

    #[test]
    fn recover_chain_from_db() {
        let conn = setup_db();
        let mut log = AuditLog::new();
        log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
            .unwrap();
        let last = log.last_hash.clone();

        // Simulate restart
        let recovered = AuditLog::recover_chain(&conn);
        assert_eq!(recovered.last_hash, last);
    }

    #[test]
    fn get_recent_returns_entries() {
        let conn = setup_db();
        let mut log = AuditLog::new();
        for _ in 0..5 {
            log.record(&conn, &test_action(), PolicyDecision::Execute, "agent")
                .unwrap();
        }
        let recent = AuditLog::get_recent(&conn, 3).unwrap();
        assert_eq!(recent.len(), 3);
    }
}
