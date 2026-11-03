use crate::events::{
    EventType, EvidenceRef, FileAction, FileContext, NormalizedEvent, OsType, Severity,
};
use crate::platform::{CollectorError, CollectorResult, FileCollector};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub struct LinuxFileCollector {
    endpoint_id: String,
    inotify: Inotify,
    watches: HashMap<WatchDescriptor, PathBuf>,
    buf: Vec<u8>,
}

impl LinuxFileCollector {
    pub fn new(endpoint_id: String) -> Result<Self, CollectorError> {
        let inotify = Inotify::init().map_err(|e| {
            CollectorError::Unavailable(format!("inotify_init failed: {e}"))
        })?;

        Ok(Self {
            endpoint_id,
            inotify,
            watches: HashMap::new(),
            buf: vec![0u8; 4096],
        })
    }

    fn mask_to_action(mask: EventMask) -> Option<FileAction> {
        if mask.contains(EventMask::CREATE) {
            Some(FileAction::Create)
        } else if mask.contains(EventMask::MODIFY) {
            Some(FileAction::Modify)
        } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::DELETE_SELF) {
            Some(FileAction::Delete)
        } else if mask.contains(EventMask::MOVED_FROM) || mask.contains(EventMask::MOVED_TO) {
            Some(FileAction::Rename)
        } else if mask.contains(EventMask::ATTRIB) {
            Some(FileAction::Permission)
        } else if mask.contains(EventMask::ACCESS) {
            Some(FileAction::Access)
        } else {
            None
        }
    }
}

impl FileCollector for LinuxFileCollector {
    fn watch_path(&mut self, path: &Path) -> Result<(), CollectorError> {
        let mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::ATTRIB;

        let wd = self
            .inotify
            .watches()
            .add(path, mask)
            .map_err(|e| CollectorError::PermissionDenied(format!("{}: {e}", path.display())))?;

        self.watches.insert(wd, path.to_path_buf());
        tracing::info!(path = %path.display(), "watching directory");
        Ok(())
    }

    fn poll_file_events(&mut self) -> Pin<Box<dyn std::future::Future<Output = CollectorResult> + Send + '_>> {
        Box::pin(async {
            let events_raw = self
                .inotify
                .read_events(&mut self.buf)
                .map_err(|e| CollectorError::Internal(e.into()))?;

            let mut events = Vec::new();

            for raw in events_raw {
                let Some(action) = Self::mask_to_action(raw.mask) else {
                    continue;
                };

                let dir = self.watches.get(&raw.wd).cloned().unwrap_or_default();
                let file_path = match raw.name {
                    Some(name) => dir.join(name),
                    None => dir,
                };

                let severity = match action {
                    FileAction::Delete | FileAction::Permission => Severity::Medium,
                    _ => Severity::Info,
                };

                let event = NormalizedEvent::new(
                    self.endpoint_id.clone(),
                    OsType::Linux,
                    EventType::File,
                    severity,
                )
                .with_file(FileContext {
                    path: file_path.to_string_lossy().into_owned(),
                    action,
                    sha256: None,
                    size_bytes: file_path.metadata().ok().map(|m| m.len()),
                    owner_uid: None,
                    permissions: None,
                })
                .with_evidence(EvidenceRef {
                    source: "linux-inotify".into(),
                    detail: format!("mask={:?}", raw.mask),
                });

                events.push(event);
            }

            Ok(events)
        })
    }

    fn name(&self) -> &str {
        "linux-file"
    }
}
