use crate::events::{
    EventType, EvidenceRef, FileAction, FileContext, NormalizedEvent, OsType, Severity,
};
use crate::platform::{CollectorError, CollectorResult, FileCollector};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::mpsc;

use windows::Win32::Storage::FileSystem::{
    FindFirstChangeNotificationW, FindNextChangeNotification, FindCloseChangeNotification,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::core::HSTRING;

struct WatchEntry {
    handle: HANDLE,
    path: PathBuf,
}

pub struct WindowsFileCollector {
    endpoint_id: String,
    watches: Vec<WatchEntry>,
}

impl WindowsFileCollector {
    pub fn new(endpoint_id: String) -> Result<Self, CollectorError> {
        Ok(Self {
            endpoint_id,
            watches: Vec::new(),
        })
    }
}

impl FileCollector for WindowsFileCollector {
    fn watch_path(&mut self, path: &Path) -> Result<(), CollectorError> {
        let path_str = path.to_string_lossy();
        let hstring = HSTRING::from(path_str.as_ref());

        unsafe {
            let handle = FindFirstChangeNotificationW(
                &hstring,
                true, // watch subtree
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_SECURITY,
            )
            .map_err(|e| CollectorError::Unavailable(format!("FindFirstChangeNotification: {e}")))?;

            self.watches.push(WatchEntry {
                handle,
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn poll_file_events(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let mut events = Vec::new();

            for watch in &self.watches {
                unsafe {
                    // Non-blocking check (timeout = 0)
                    let result = WaitForSingleObject(watch.handle, 0);
                    if result.0 == 0 {
                        // WAIT_OBJECT_0 — change detected
                        let event = NormalizedEvent::new(
                            self.endpoint_id.clone(),
                            OsType::Windows,
                            EventType::File,
                            Severity::Info,
                        )
                        .with_file(FileContext {
                            path: watch.path.to_string_lossy().to_string(),
                            action: FileAction::Modify,
                            sha256: None,
                            size_bytes: None,
                            owner_uid: None,
                            permissions: None,
                        })
                        .with_evidence(EvidenceRef {
                            source: "win32-change-notification".into(),
                            detail: format!("change in {}", watch.path.display()),
                        });

                        events.push(event);

                        // Re-arm the notification
                        let _ = FindNextChangeNotification(watch.handle);
                    }
                }
            }

            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "windows-file"
    }
}

impl Drop for WindowsFileCollector {
    fn drop(&mut self) {
        for watch in &self.watches {
            unsafe {
                let _ = FindCloseChangeNotification(watch.handle);
            }
        }
    }
}
