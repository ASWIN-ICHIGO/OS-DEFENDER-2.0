use crate::events::NormalizedEvent;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.create_tables()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.create_tables()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                endpoint_id TEXT NOT NULL,
                os_type TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_endpoint ON events(endpoint_id);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                rule_id TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                confidence REAL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (event_id) REFERENCES events(event_id)
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts(event_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                title TEXT NOT NULL,
                description TEXT,
                risk_score REAL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                action TEXT NOT NULL,
                target TEXT,
                actor TEXT NOT NULL,
                reason TEXT,
                payload TEXT,
                prev_hash TEXT,
                entry_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sensor_health (
                collector_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                state TEXT NOT NULL,
                events_collected INTEGER NOT NULL DEFAULT 0,
                events_dropped INTEGER NOT NULL DEFAULT 0,
                lag_ms INTEGER,
                PRIMARY KEY (collector_name, timestamp)
            );",
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &NormalizedEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let payload = serde_json::to_string(event)?;
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, timestamp, endpoint_id, os_type, event_type, severity, fingerprint, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.event_id.to_string(),
                event.timestamp.to_rfc3339(),
                event.endpoint_id,
                serde_json::to_value(event.os_type)?.as_str().unwrap_or(""),
                serde_json::to_value(event.event_type)?.as_str().unwrap_or(""),
                event.severity.to_string(),
                event.fingerprint,
                payload,
            ],
        )?;
        Ok(())
    }

    pub fn get_events(&self, limit: u32) -> Result<Vec<NormalizedEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let events = stmt
            .query_map(params![limit], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        Ok(events)
    }

    pub fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    pub fn event_count(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: u64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_events_by_type(&self, event_type: &str, limit: u32) -> Result<Vec<NormalizedEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM events WHERE event_type = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;
        let events = stmt
            .query_map(params![event_type, limit], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventType, OsType, ProcessContext, Severity};

    #[test]
    fn insert_and_retrieve_event() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = NormalizedEvent::new(
            "test-ep".into(),
            OsType::Linux,
            EventType::Process,
            Severity::High,
        )
        .with_process(ProcessContext {
            pid: 42,
            ppid: Some(1),
            name: "test".into(),
            exe: None,
            cmdline: None,
            uid: None,
            username: None,
            start_time: None,
            children_pids: vec![],
        });

        store.insert_event(&event).unwrap();
        assert_eq!(store.event_count().unwrap(), 1);

        let events = store.get_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event.event_id);
    }

    #[test]
    fn dedup_by_fingerprint() {
        let store = SqliteStore::open_in_memory().unwrap();
        let event = NormalizedEvent::new(
            "test-ep".into(),
            OsType::Linux,
            EventType::File,
            Severity::Low,
        );
        store.insert_event(&event).unwrap();
        store.insert_event(&event).unwrap(); // same fingerprint
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn filter_by_event_type() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .insert_event(&NormalizedEvent::new(
                "ep".into(),
                OsType::Linux,
                EventType::Process,
                Severity::Info,
            ))
            .unwrap();
        store
            .insert_event(&NormalizedEvent::new(
                "ep".into(),
                OsType::Linux,
                EventType::Network,
                Severity::Info,
            ))
            .unwrap();

        let procs = store.get_events_by_type("process", 10).unwrap();
        assert_eq!(procs.len(), 1);
    }
}
