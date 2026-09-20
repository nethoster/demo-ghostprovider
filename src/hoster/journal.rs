//! On-disk journal of in-flight deployments.
//!
//! A deploy writes an entry (`Deploying`) before it begins, advances it at the
//! registration step (`Registering`, then `Registered`), and `run_deployment`
//! removes the entry when the deploy finishes — successfully or after the
//! in-process rollback. An entry still present at the next launch therefore
//! means the previous run was interrupted out-of-band (user exited the panel,
//! the process was killed, or the machine shut down / rebooted), and the
//! orphaned artifacts must be removed. See [`crate::hoster::deploy::reconcile_stale`].

use std::collections::BTreeMap;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::paths;

/// Lifecycle of an in-flight deploy as seen by the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployState {
    /// Clone/build/start in progress; nothing is guaranteed to exist yet.
    Deploying,
    /// Unit created and starting; registration is imminent (or already
    /// happened). Reconciliation asks `state.json`: a service that is already
    /// registered is live and must NOT be cleaned up.
    Registering,
    /// The service was registered successfully.
    Registered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub url: String,
    pub state: DeployState,
    #[serde(default)]
    pub started_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct JournalFile {
    #[serde(flatten)]
    entries: BTreeMap<String, JournalEntry>,
}

fn load() -> JournalFile {
    match std::fs::read(paths::deploy_journal_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => JournalFile::default(),
    }
}

fn store(state: &JournalFile) -> anyhow::Result<()> {
    let path = paths::deploy_journal_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    crate::atomic::write_atomic(&path, &serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("writing {}", path.display()))
}

/// Record that a deploy for `service` (from `url`) is starting. Best-effort:
/// a failed journal write must not block the deploy itself.
pub fn begin(service: &str, url: &str) {
    let mut jf = load();
    jf.entries.insert(
        service.to_string(),
        JournalEntry {
            url: url.to_string(),
            state: DeployState::Deploying,
            started_at: crate::netlog::format_utc(std::time::SystemTime::now()),
        },
    );
    let _ = store(&jf);
}

/// Advance an existing entry to `state` (best-effort; no-op when absent).
pub fn mark(service: &str, state: DeployState) {
    let mut jf = load();
    if let Some(e) = jf.entries.get_mut(service) {
        e.state = state;
        let _ = store(&jf);
    }
}

/// Forget a service's entry (idempotent).
pub fn clear(service: &str) {
    let mut jf = load();
    if jf.entries.remove(service).is_some() {
        let _ = store(&jf);
    }
}

/// All tracked `(service, entry)` pairs, sorted by service.
pub fn entries() -> Vec<(String, JournalEntry)> {
    load().entries.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state_home(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dgp-journal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ))
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_STATE_HOME)
    fn roundtrips_and_tracks_lifecycle() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = tmp_state_home("life");
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }

        assert!(entries().is_empty(), "fresh state must have no entries");
        begin("demo-vert", "https://github.com/VERT-sh/VERT");
        let (service, entry) = entries().into_iter().next().unwrap();
        assert_eq!(service, "demo-vert");
        assert_eq!(entry.state, DeployState::Deploying);
        assert_eq!(entry.url, "https://github.com/VERT-sh/VERT");
        assert!(!entry.started_at.is_empty());

        mark("demo-vert", DeployState::Registering);
        assert_eq!(entries()[0].1.state, DeployState::Registering);
        mark("demo-vert", DeployState::Registered);
        assert_eq!(entries()[0].1.state, DeployState::Registered);

        clear("demo-vert");
        assert!(entries().is_empty(), "entry must be gone after clear");
        clear("demo-vert");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_STATE_HOME)
    fn clear_preserves_unrelated_entries() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = tmp_state_home("other");
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }

        begin("demo-vert", "u1");
        begin("demo-memos", "u2");
        mark("demo-vert", DeployState::Registered);
        clear("demo-vert");

        let remaining = entries();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, "demo-memos");
        assert_eq!(remaining[0].1.url, "u2");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}