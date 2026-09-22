//! XDG-based filesystem layout.
//!
//! All paths live under the user's home; nothing is written outside
//! `$XDG_DATA_HOME`, `$XDG_STATE_HOME` and `$XDG_CONFIG_HOME`.

use std::path::PathBuf;

/// Serializes tests that mutate the process-global XDG_* env vars. Module-local
/// locks would not protect *across* modules (journal.rs, deploy.rs…), so all
/// env-mutating tests share one lock.
#[cfg(test)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share"))
}

fn state_home() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"))
}

pub fn home() -> PathBuf {
    // No `dirs` crate: keep the dependency tree minimal. $HOME is always
    // set for the user sessions this tool targets.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME must be set")
}

/// Root for deployed service clones: ~/.local/share/demo-ghostprovider/services
pub fn services_dir() -> PathBuf {
    data_home().join("demo-ghostprovider/services")
}

/// Registry of deployed services: ~/.local/state/demo-ghostprovider/state.json
pub fn state_file() -> PathBuf {
    state_home().join("demo-ghostprovider/state.json")
}

/// Local network contact log (transparency): net.log lives next to state.
pub fn netlog_file() -> PathBuf {
    state_home().join("demo-ghostprovider/net.log")
}

/// Shared deploy log streamed to every window's Logs screen.
pub fn deploy_log_file() -> PathBuf {
    state_home().join("demo-ghostprovider/deploy.log")
}

/// Persistent history of deploy interruptions and full clean removals: the
/// "Crash" screen in Logs.
pub fn crash_log_file() -> PathBuf {
    state_home().join("demo-ghostprovider/crash.log")
}

/// In-flight deploy journal: records a deploy that started but has not
/// finished, so an out-of-band interruption (panel exit/kill, reboot) can be
/// reconciled into a clean removal on the next launch.
pub fn deploy_journal_file() -> PathBuf {
    state_home().join("demo-ghostprovider/deploy-journal.json")
}

/// Cross-process deploy lock: held for the whole lifetime of a journaled
/// deploy, free as soon as the deploying process dies. See `hoster::lock`.
pub fn deploy_lock_file() -> PathBuf {
    state_home().join("demo-ghostprovider/deploy.lock")
}

/// systemd user unit directory.
pub fn user_unit_dir() -> PathBuf {
    let cfg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"));
    cfg.join("systemd/user")
}
