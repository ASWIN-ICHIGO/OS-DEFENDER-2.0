use crate::events::NormalizedEvent;
use std::future::Future;
use std::pin::Pin;

pub type CollectorResult = Result<Vec<NormalizedEvent>, CollectorError>;

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("OS interface unavailable: {0}")]
    Unavailable(String),
    #[error("collector degraded: {0}")]
    Degraded(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub trait ProcessCollector: Send + Sync {
    fn poll_processes(&mut self) -> Pin<Box<dyn Future<Output = CollectorResult> + Send + '_>>;
    fn name(&self) -> &str;
}

pub trait FileCollector: Send + Sync {
    fn poll_file_events(&mut self) -> Pin<Box<dyn Future<Output = CollectorResult> + Send + '_>>;
    fn watch_path(&mut self, path: &std::path::Path) -> Result<(), CollectorError>;
    fn name(&self) -> &str;
}

pub trait NetworkCollector: Send + Sync {
    fn poll_connections(&mut self) -> Pin<Box<dyn Future<Output = CollectorResult> + Send + '_>>;
    fn name(&self) -> &str;
}

pub trait AuthCollector: Send + Sync {
    fn poll_auth_events(&mut self) -> Pin<Box<dyn Future<Output = CollectorResult> + Send + '_>>;
    fn name(&self) -> &str;
}

pub trait HealthReporter: Send + Sync {
    fn report_health(&self) -> Pin<Box<dyn Future<Output = CollectorResult> + Send + '_>>;
}
