use anyhow::Result;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug)]
struct Window {
    start: Instant,
    count: u32,
}

#[derive(Clone)]
pub struct RateLimiter {
    max_per_minute: u32,
    inner: std::sync::Arc<Mutex<HashMap<String, Window>>>,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn disabled() -> Self {
        Self::new(0)
    }

    pub async fn check(&self, key: &str) -> Result<bool> {
        if self.max_per_minute == 0 {
            return Ok(true);
        }

        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let w = map.entry(key.to_string()).or_insert(Window {
            start: now,
            count: 0,
        });

        if now.duration_since(w.start) >= Duration::from_secs(60) {
            w.start = now;
            w.count = 0;
        }

        if w.count >= self.max_per_minute {
            return Ok(false);
        }
        w.count += 1;
        Ok(true)
    }
}
