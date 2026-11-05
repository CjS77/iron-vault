//! The service's JSON log records, captured for the current thread of a test on a current-thread runtime, where the
//! request server and every task it spawns run on the test's thread.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use iron_vault::deployment::DeploymentProfile;
use iron_vault::logging::subscriber;
use tracing::subscriber::DefaultGuard;

use super::WAIT;

/// Everything written to the captured log so far.
#[derive(Clone, Default)]
pub struct RequestLog(Arc<Mutex<Vec<u8>>>);

struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Starts capturing this thread's log records, until the guard drops.
pub fn capture() -> (DefaultGuard, RequestLog) {
    let log = RequestLog::default();
    let buffer = Arc::clone(&log.0);
    let guard = tracing::subscriber::set_default(subscriber(move || Sink(Arc::clone(&buffer)), DeploymentProfile::Protected));
    (guard, log)
}

impl RequestLog {
    /// The raw text written so far.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    /// Forgets what was written, so the next assertion sees only what follows.
    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }

    /// The records of the request target (`request.completed`), parsed.
    pub fn request_events(&self) -> Vec<serde_json::Value> {
        self.records()
            .into_iter()
            .filter(|record| record["target"] == "iron-vault.request")
            .collect()
    }

    /// The audit events named `event`, parsed.
    pub fn audit_events(&self, event: &str) -> Vec<serde_json::Value> {
        let audit = |record: &serde_json::Value| record["target"] == "iron-vault.audit" && record["event"] == event;
        self.records().into_iter().filter(audit).collect()
    }

    fn records(&self) -> Vec<serde_json::Value> {
        self.text().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    /// The one request event, once it has been written; fails if there is more than one.
    pub async fn the_request_event(&self) -> serde_json::Value {
        let events = tokio::time::timeout(WAIT, async {
            loop {
                let events = self.request_events();
                if !events.is_empty() {
                    return events;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("no request event was written");
        assert_eq!(events.len(), 1, "{events:?}");
        events.into_iter().next().unwrap()
    }
}
