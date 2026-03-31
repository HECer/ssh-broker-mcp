use anyhow::Result;
use serde::Serialize;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AuditLogger {
    enabled: bool,
    log_commands: bool,
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl AuditLogger {
    pub fn new(path: PathBuf, log_commands: bool) -> Self {
        Self {
            enabled: true,
            log_commands,
            path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn write<E: Serialize>(&self, event: &E) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let _g = self.lock.lock().await;
        let line = serde_json::to_string(event)?;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        use tokio::io::AsyncWriteExt;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        Ok(())
    }

    pub fn log_commands(&self) -> bool {
        self.log_commands
    }
}
