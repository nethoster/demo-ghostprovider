//! Persisted runtime state for public shares. This is deliberately separate
//! from `state.json`: a share is ephemeral and never changes how a service is
//! deployed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    #[default]
    Stopped,
    Starting,
    Live,
    Error,
}

impl ShareStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Live => "live",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub service: String,
    pub unit_name: String,
    pub local_url: String,
    pub port: u16,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub supervisor_pid: u32,
    #[serde(default)]
    pub cloudflared_pid: Option<u32>,
    #[serde(default)]
    pub status: ShareStatus,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub started_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(flatten)]
    shares: BTreeMap<String, ShareRecord>,
}

pub fn load() -> BTreeMap<String, ShareRecord> {
    let path = crate::paths::networks_file();
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<RegistryFile>(&bytes)
            .map(|f| f.shares)
            .unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
}

pub fn save(shares: &BTreeMap<String, ShareRecord>) -> std::io::Result<()> {
    let path = crate::paths::networks_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = RegistryFile {
        shares: shares.clone(),
    };
    crate::atomic::write_atomic(&path, &serde_json::to_vec_pretty(&file)?)
}

pub fn get(service: &str) -> Option<ShareRecord> {
    load().remove(service)
}

pub fn put(record: ShareRecord) {
    let mut shares = load();
    shares.insert(record.service.clone(), record);
    let _ = save(&shares);
}

pub fn remove(service: &str) {
    let mut shares = load();
    if shares.remove(service).is_some() {
        let _ = save(&shares);
    }
}

/// Sorted for stable UI rows.
pub fn list() -> Vec<ShareRecord> {
    load().into_values().collect()
}

/// Read the supervisor event stream. Re-reads the whole (small) file, so a
/// TUI restart or a missed tick never loses the public URL.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventSummary {
    pub public_url: Option<String>,
    pub error: Option<String>,
    pub exit: Option<String>,
}

pub fn read_events(service: &str) -> EventSummary {
    read_events_file(&crate::paths::network_dir(service).join("events.log"))
}

/// Same parser for tests and callers that already hold the exact event path.
pub fn read_events_file(path: &std::path::Path) -> EventSummary {
    let Ok(text) = std::fs::read_to_string(path) else {
        return EventSummary::default();
    };
    let mut summary = EventSummary::default();
    for line in text.lines() {
        if let Some(url) = line.strip_prefix("GP_TUNNEL_URL\t") {
            summary.public_url = Some(url.trim().to_string());
            summary.error = None;
        } else if let Some(err) = line.strip_prefix("GP_TUNNEL_ERROR\t") {
            summary.error = Some(err.trim().to_string());
        } else if let Some(code) = line.strip_prefix("GP_TUNNEL_EXIT\t") {
            summary.exit = Some(code.trim().to_string());
        }
    }
    summary
}

pub fn append_event(service: &str, kind: &str, message: &str) {
    let path = crate::paths::network_dir(service).join("events.log");
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let line = format!("{kind}\t{}\n", message.replace(['\n', '\r'], " "));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ShareRecord {
        ShareRecord {
            service: "demo".into(),
            unit_name: "demo.service".into(),
            local_url: "http://127.0.0.1:8080".into(),
            port: 8080,
            public_url: Some("https://quiet.trycloudflare.com".into()),
            supervisor_pid: 42,
            cloudflared_pid: Some(43),
            status: ShareStatus::Live,
            message: None,
            started_at: 1,
        }
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(ShareStatus::Starting.label(), "starting");
        assert_eq!(ShareStatus::Live.label(), "live");
        assert_eq!(ShareStatus::Error.label(), "error");
        assert_eq!(ShareStatus::Stopped.label(), "stopped");
    }

    #[test]
    fn record_roundtrips_through_json() {
        let bytes = serde_json::to_vec(&sample()).unwrap();
        let back: ShareRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.service, "demo");
        assert_eq!(back.status, ShareStatus::Live);
    }
}
