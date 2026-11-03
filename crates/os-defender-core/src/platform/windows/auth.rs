use crate::events::{
    AuthAction, AuthContext, EventType, EvidenceRef, NormalizedEvent, OsType, Severity,
};
use crate::platform::{CollectorError, CollectorResult, AuthCollector};
use std::pin::Pin;

use windows::Win32::System::EventLog::{
    OpenEventLogW, ReadEventLogW, CloseEventLog,
    EVENTLOG_SEQUENTIAL_READ, EVENTLOG_FORWARDS_READ,
    EVENTLOGRECORD,
};
use windows::core::HSTRING;

pub struct WindowsAuthCollector {
    endpoint_id: String,
    last_record_number: u32,
}

impl WindowsAuthCollector {
    pub fn new(endpoint_id: String) -> Self {
        Self {
            endpoint_id,
            last_record_number: 0,
        }
    }

    fn read_security_events(&mut self) -> Result<Vec<NormalizedEvent>, CollectorError> {
        let mut events = Vec::new();
        let source = HSTRING::from("Security");

        unsafe {
            let handle = OpenEventLogW(None, &source)
                .map_err(|e| CollectorError::PermissionDenied(
                    format!("Cannot open Security event log (requires admin): {e}")
                ))?;

            let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer
            let mut bytes_read: u32 = 0;
            let mut min_bytes_needed: u32 = 0;

            let flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ;

            while ReadEventLogW(
                handle,
                flags.0,
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut bytes_read,
                &mut min_bytes_needed,
            )
            .is_ok()
            {
                let mut offset = 0usize;
                while offset < bytes_read as usize {
                    let record = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                    if record.RecordNumber <= self.last_record_number {
                        offset += record.Length as usize;
                        continue;
                    }

                    // Security event IDs for logon events
                    // 4624 = successful logon, 4625 = failed logon, 4634 = logoff
                    let event_id = record.EventID as u32 & 0xFFFF;
                    let (action, severity) = match event_id {
                        4624 => (AuthAction::Login, Severity::Info),
                        4625 => (AuthAction::Failed, Severity::Medium),
                        4634 => (AuthAction::Logout, Severity::Info),
                        4672 => (AuthAction::Escalation, Severity::Low),
                        _ => {
                            offset += record.Length as usize;
                            continue;
                        }
                    };

                    let event = NormalizedEvent::new(
                        self.endpoint_id.clone(),
                        OsType::Windows,
                        EventType::Authentication,
                        severity,
                    )
                    .with_auth(AuthContext {
                        action,
                        username: String::new(), // would need string extraction from record
                        source_addr: None,
                        method: None,
                        service: Some("Security".into()),
                        session_id: Some(format!("record-{}", record.RecordNumber)),
                    })
                    .with_evidence(EvidenceRef {
                        source: "win32-event-log".into(),
                        detail: format!("EventID={event_id} Record={}", record.RecordNumber),
                    });

                    events.push(event);
                    self.last_record_number = record.RecordNumber;
                    offset += record.Length as usize;
                }

                if bytes_read == 0 {
                    break;
                }
            }

            let _ = CloseEventLog(handle);
        }

        Ok(events)
    }
}

impl AuthCollector for WindowsAuthCollector {
    fn poll_auth_events(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            self.read_security_events()
        })
    }

    fn name(&self) -> &str {
        "windows-auth"
    }
}
