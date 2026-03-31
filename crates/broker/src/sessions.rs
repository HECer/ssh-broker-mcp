 use crate::ssh::ControlMaster;
 use anyhow::{anyhow, Result};
 use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::process::Child;
 use tokio::sync::Mutex;
 
 #[derive(Clone)]
 pub struct SessionManager {
     inner: Arc<Mutex<HashMap<String, ControlMaster>>>,
     runtime_dir: PathBuf,
    forwards: Arc<Mutex<HashMap<String, Child>>>,
 }
 
 impl SessionManager {
     pub fn new(runtime_dir: PathBuf) -> Self {
         Self {
             inner: Arc::new(Mutex::new(HashMap::new())),
             runtime_dir,
            forwards: Arc::new(Mutex::new(HashMap::new())),
         }
     }
 
     pub fn runtime_dir(&self) -> &PathBuf {
         &self.runtime_dir
     }
 
     pub async fn insert(&self, session_id: String, cm: ControlMaster) {
         self.inner.lock().await.insert(session_id, cm);
     }
 
     pub async fn get(&self, session_id: &str) -> Option<ControlMaster> {
         self.inner.lock().await.get(session_id).cloned()
     }
 
     pub async fn remove(&self, session_id: &str) -> Option<ControlMaster> {
         self.inner.lock().await.remove(session_id)
     }
 
     pub async fn require(&self, session_id: &str) -> Result<ControlMaster> {
         self.get(session_id)
             .await
             .ok_or_else(|| anyhow!("unknown session_id"))
     }

    pub async fn add_forward(&self, session_id: &str, forward_id: &str, child: Child) {
        let key = format!("{session_id}:{forward_id}");
        self.forwards.lock().await.insert(key, child);
    }

    pub async fn stop_forward(&self, session_id: &str, forward_id: &str) -> Result<()> {
        let key = format!("{session_id}:{forward_id}");
        let mut child = self
            .forwards
            .lock()
            .await
            .remove(&key)
            .ok_or_else(|| anyhow!("unknown forward_id"))?;
        let _ = child.kill().await;
        Ok(())
    }

    pub async fn stop_all_forwards(&self, session_id: &str) {
        let mut map = self.forwards.lock().await;
        let keys: Vec<String> = map
            .keys()
            .filter(|k| k.starts_with(&format!("{session_id}:")))
            .cloned()
            .collect();
        for k in keys {
            if let Some(mut child) = map.remove(&k) {
                let _ = child.kill().await;
            }
        }
    }
 }
