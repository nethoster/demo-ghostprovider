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

/// User's manifest library: imported `service.yaml` files live here as
/// `<service-id>.yaml` so the Add Service screen can list, re-validate and
/// redeploy them without retyping paths.
pub fn manifests_dir() -> PathBuf {
    data_home().join("demo-ghostprovider/manifests")
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

/// True when the binary this process is running differs from the file that
/// now sits at its path — i.e. a newer build was installed (mv-replaced)
/// while this process stayed up, so every deploy it runs is old code with
/// the already-fixed bugs still in it. The running image on Linux is
/// /proc/self/exe, readable even after its directory entry was replaced
/// (the readlink then carries a trailing " (deleted)").
pub fn binary_is_stale() -> bool {
    let Ok(running) = std::fs::metadata("/proc/self/exe") else {
        return false;
    };
    let Ok(link) = std::fs::read_link("/proc/self/exe") else {
        return false;
    };
    let raw = link.to_string_lossy();
    let path = raw.strip_suffix(" (deleted)").unwrap_or(raw.as_ref());
    let Ok(disk) = std::fs::metadata(path) else {
        return false;
    };
    stale_meta(&running, &disk)
}

/// Whether the on-disk file is a different build than the running image:
/// a different inode (the install path replaces via rename), or the same
/// inode edited in place (size or mtime moved).
pub(crate) fn stale_meta(running: &std::fs::Metadata, disk: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    running.ino() != disk.ino() || running.len() != disk.len() || running.mtime() != disk.mtime()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_meta_sees_replacement_and_ignores_same_file() {
        let dir = std::env::temp_dir().join(format!("gp-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("bin");

        // Same file, freshly stat'ed twice: the launch case — not stale.
        std::fs::write(&f, "build-one").unwrap();
        let running = std::fs::metadata(&f).unwrap();
        assert!(!stale_meta(&running, &std::fs::metadata(&f).unwrap()));

        // In-place overwrite (same inode, new bytes): stale.
        std::fs::write(&f, "build-two, but longer").unwrap();
        assert!(stale_meta(&running, &std::fs::metadata(&f).unwrap()));

        // Rename-replace: a fresh inode — exactly what `mv … .new …` does
        // when a new build is installed over the running path.
        std::fs::write(dir.join("bin.new"), "other").unwrap();
        std::fs::rename(dir.join("bin.new"), &f).unwrap();
        assert!(stale_meta(&running, &std::fs::metadata(&f).unwrap()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn freshly_launched_process_is_not_stale() {
        // The test binary runs straight from disk at its own path.
        assert!(!binary_is_stale());
    }
}
