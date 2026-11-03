use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::NormalizedEvent;
use crate::storage::SqliteStore;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HuntQuery {
    pub event_type: Option<String>,
    pub severity_min: Option<String>,
    pub endpoint_id: Option<String>,
    pub process_name: Option<String>,
    pub file_path_contains: Option<String>,
    pub remote_addr: Option<String>,
    pub username: Option<String>,
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub payload_contains: Option<String>,
    pub limit: Option<u32>,
}

impl HuntQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_event_type(mut self, t: &str) -> Self {
        self.event_type = Some(t.to_string());
        self
    }

    pub fn with_severity_min(mut self, s: &str) -> Self {
        self.severity_min = Some(s.to_string());
        self
    }

    pub fn with_process_name(mut self, name: &str) -> Self {
        self.process_name = Some(name.to_string());
        self
    }

    pub fn with_file_path(mut self, pattern: &str) -> Self {
        self.file_path_contains = Some(pattern.to_string());
        self
    }

    pub fn with_remote_addr(mut self, addr: &str) -> Self {
        self.remote_addr = Some(addr.to_string());
        self
    }

    pub fn with_username(mut self, user: &str) -> Self {
        self.username = Some(user.to_string());
        self
    }

    pub fn with_time_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.time_from = Some(from);
        self.time_to = Some(to);
        self
    }

    pub fn with_payload_contains(mut self, text: &str) -> Self {
        self.payload_contains = Some(text.to_string());
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResult {
    pub query: HuntQuery,
    pub total_matches: usize,
    pub events: Vec<NormalizedEvent>,
    pub executed_at: DateTime<Utc>,
}

pub struct HuntingEngine;

impl HuntingEngine {
    pub fn execute(store: &SqliteStore, query: &HuntQuery) -> Result<HuntResult> {
        let conn = store.connection();
        let limit = query.limit.unwrap_or(100);

        let mut sql = String::from("SELECT payload FROM events WHERE 1=1");
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(ref et) = query.event_type {
            sql.push_str(&format!(" AND event_type = ?{}", bind_values.len() + 1));
            bind_values.push(et.clone());
        }

        if let Some(ref ep) = query.endpoint_id {
            sql.push_str(&format!(" AND endpoint_id = ?{}", bind_values.len() + 1));
            bind_values.push(ep.clone());
        }

        if let Some(ref sev) = query.severity_min {
            let min_score = severity_to_score(sev);
            sql.push_str(&format!(" AND CASE severity \
                WHEN 'critical' THEN 5 \
                WHEN 'high' THEN 4 \
                WHEN 'medium' THEN 3 \
                WHEN 'low' THEN 2 \
                WHEN 'info' THEN 1 \
                ELSE 0 END >= {min_score}"));
        }

        if let Some(ref from) = query.time_from {
            sql.push_str(&format!(" AND timestamp >= ?{}", bind_values.len() + 1));
            bind_values.push(from.to_rfc3339());
        }
        if let Some(ref to) = query.time_to {
            sql.push_str(&format!(" AND timestamp <= ?{}", bind_values.len() + 1));
            bind_values.push(to.to_rfc3339());
        }

        if let Some(ref text) = query.payload_contains {
            sql.push_str(&format!(" AND payload LIKE ?{}", bind_values.len() + 1));
            bind_values.push(format!("%{text}%"));
        }

        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();

        let rows = stmt
            .query_map(rusqlite::params_from_iter(param_refs.iter()), |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })?
            .filter_map(|r| r.ok())
            .collect::<Vec<String>>();

        let mut events: Vec<NormalizedEvent> = rows
            .iter()
            .filter_map(|json| serde_json::from_str(json).ok())
            .collect();

        // Post-filter on deserialized fields for rich context queries
        if let Some(ref proc_name) = query.process_name {
            events.retain(|e| {
                e.process_context.as_ref()
                    .is_some_and(|p| p.name.contains(proc_name))
            });
        }
        if let Some(ref file_pattern) = query.file_path_contains {
            events.retain(|e| {
                e.file_context.as_ref()
                    .is_some_and(|f| f.path.contains(file_pattern))
            });
        }
        if let Some(ref addr) = query.remote_addr {
            events.retain(|e| {
                e.network_context.as_ref()
                    .is_some_and(|n| n.remote_addr.as_ref().is_some_and(|a| a == addr))
            });
        }
        if let Some(ref user) = query.username {
            events.retain(|e| {
                e.auth_context.as_ref()
                    .is_some_and(|a| a.username == *user)
            });
        }

        let total = events.len();
        Ok(HuntResult {
            query: query.clone(),
            total_matches: total,
            events,
            executed_at: Utc::now(),
        })
    }

    pub fn count_by_type(store: &SqliteStore) -> Result<Vec<(String, u64)>> {
        let conn = store.connection();
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn count_by_severity(store: &SqliteStore) -> Result<Vec<(String, u64)>> {
        let conn = store.connection();
        let mut stmt = conn.prepare(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC"
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }
}

fn severity_to_score(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventType, OsType, ProcessContext, FileContext, FileAction,
                        NetworkContext, NetworkProtocol, NetDirection,
                        AuthContext, AuthAction, Severity};

    fn make_store_with_events() -> SqliteStore {
        let store = SqliteStore::open_in_memory().unwrap();

        // Process event
        let e1 = NormalizedEvent::new("ep1".into(), OsType::Linux, EventType::Process, Severity::High)
            .with_process(ProcessContext {
                pid: 100, ppid: Some(1), name: "bash".into(),
                exe: Some("/usr/bin/bash".into()),
                cmdline: Some("bash -i".into()),
                uid: Some(1000), username: Some("attacker".into()),
                start_time: None, children_pids: vec![],
            });
        store.insert_event(&e1).unwrap();

        // File event
        let e2 = NormalizedEvent::new("ep1".into(), OsType::Linux, EventType::File, Severity::Medium)
            .with_file(FileContext {
                path: "/etc/shadow".into(), action: FileAction::Modify,
                sha256: None, size_bytes: None, owner_uid: None, permissions: None,
            });
        store.insert_event(&e2).unwrap();

        // Network event
        let e3 = NormalizedEvent::new("ep1".into(), OsType::Linux, EventType::Network, Severity::Low)
            .with_network(NetworkContext {
                protocol: NetworkProtocol::Tcp, direction: NetDirection::Outbound,
                local_addr: "10.0.0.1".into(), local_port: 54321,
                remote_addr: Some("192.168.1.100".into()), remote_port: Some(4444),
                state: None, pid: Some(100), process_name: Some("nc".into()),
                bytes_sent: None, bytes_received: None,
            });
        store.insert_event(&e3).unwrap();

        // Auth event
        let e4 = NormalizedEvent::new("ep2".into(), OsType::Linux, EventType::Authentication, Severity::High)
            .with_auth(AuthContext {
                action: AuthAction::Failed, username: "root".into(),
                source_addr: Some("10.0.0.5".into()), method: Some("password".into()),
                service: Some("sshd".into()), session_id: None,
            });
        store.insert_event(&e4).unwrap();

        store
    }

    #[test]
    fn hunt_all_events() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(&store, &HuntQuery::new().with_limit(100)).unwrap();
        assert_eq!(result.total_matches, 4);
    }

    #[test]
    fn hunt_by_event_type() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_event_type("process"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
        assert_eq!(result.events[0].process_context.as_ref().unwrap().name, "bash");
    }

    #[test]
    fn hunt_by_process_name() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_process_name("bash"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
    }

    #[test]
    fn hunt_by_file_path() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_file_path("/etc/shadow"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
    }

    #[test]
    fn hunt_by_remote_addr() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_remote_addr("192.168.1.100"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
    }

    #[test]
    fn hunt_by_username() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_username("root"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
    }

    #[test]
    fn hunt_by_severity() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_severity_min("high"),
        ).unwrap();
        assert_eq!(result.total_matches, 2);
    }

    #[test]
    fn hunt_by_payload_contains() {
        let store = make_store_with_events();
        let result = HuntingEngine::execute(
            &store,
            &HuntQuery::new().with_payload_contains("shadow"),
        ).unwrap();
        assert_eq!(result.total_matches, 1);
    }

    #[test]
    fn count_by_type_works() {
        let store = make_store_with_events();
        let counts = HuntingEngine::count_by_type(&store).unwrap();
        assert_eq!(counts.len(), 4);
        let total: u64 = counts.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn count_by_severity_works() {
        let store = make_store_with_events();
        let counts = HuntingEngine::count_by_severity(&store).unwrap();
        assert!(!counts.is_empty());
    }

    #[test]
    fn empty_query_on_empty_store() {
        let store = SqliteStore::open_in_memory().unwrap();
        let result = HuntingEngine::execute(&store, &HuntQuery::new()).unwrap();
        assert_eq!(result.total_matches, 0);
    }

    #[test]
    fn hunt_query_serialization() {
        let q = HuntQuery::new()
            .with_event_type("process")
            .with_severity_min("high")
            .with_limit(50);
        let json = serde_json::to_string(&q).unwrap();
        let restored: HuntQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.event_type.as_deref(), Some("process"));
        assert_eq!(restored.limit, Some(50));
    }
}
