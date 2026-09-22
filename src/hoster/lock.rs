//! Cross-process deploy lock (flock(2)).
//!
//! The "clean removal" guarantee rests on an invariant readable from disk:
//! *a leftover deploy-journal entry means the deploy was interrupted*.
//! For a background sweeper (the `demo-ghostprovider-cleanup` systemd user
//! timer) running in a *different* process than the panel, that inference is
//! only sound if a live deploy can be told apart from a dead one. The deploy
//! pipeline therefore holds an exclusive flock on
//! `<state>/demo-ghostprovider/deploy.lock` from the moment it journals the
//! deploy (`journal::begin`) until the moment it clears the entry
//! (`journal::clear`).
//!
//! While the lock is held, a sweeper that sees a journal entry knows a deploy
//! is genuinely live and defers. When the deploy process dies — Ctrl+C,
//! `SIGTERM`/`SIGHUP`, `SIGKILL`, shutdown, reboot, power loss — the kernel
//! releases the flock automatically, so "journal entry present + lock free"
//! can only mean an interrupted deploy whose leftovers must be removed.
//!
//! flock(2) is kernel-managed: there is no PID-file staleness handling, no
//! stale-lock guessing, and no race around unlinking the lock path while
//! another process waits on it.
//!
//! Unsafe is confined to the raw `flock(2)` syscall; everything else here is
//! safe Rust.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

/// Exclusive holder of the deploy lock. Dropping the guard releases the
/// flock; the OS also releases it automatically if the process dies, which is
/// exactly the interrupted-deploy signal the sweeper relies on.
pub struct LockGuard {
    // Held solely so the open file description (and its flock) stays alive for
    // the struct's lifetime; dropping the guard drops the File and releases
    // the lock. Never read directly.
    #[allow(dead_code)]
    file: File,
}

fn open_lock() -> std::io::Result<File> {
    let path = crate::paths::deploy_lock_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // The lock file itself is not secret, but 0600 is the house default for
    // every file in the state dir and costs nothing.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path)
}

/// Try to take the exclusive deploy lock without blocking.
///
/// `Some(guard)` — the lock is now held by this process; keep the guard alive
/// until this deploy's journal entry is cleared. `None` — another process in
/// this user session holds it (a deploy is running there, or another sweeper
/// is mid-pass); defer rather than act.
pub fn try_lock_exclusive() -> Option<LockGuard> {
    let file = open_lock().ok()?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    match rc {
        0 => Some(LockGuard { file }),
        _ => None,
    }
}

/// True when some other process currently holds the deploy lock. Implemented
/// as a non-destructive probe: the probe momentarily takes the lock (if it is
/// free) and releases it on guard drop.
pub fn is_locked() -> bool {
    try_lock_exclusive().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_STATE_HOME)
    fn second_exclusive_attempt_blocks_until_release() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "dgp-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }

        // flock is per open-file-description, so two opens in this process
        // contend exactly like a second process would.
        assert!(is_locked() == false, "fresh state dir has no lock");
        let guard = try_lock_exclusive().expect("first acquirer gets the lock");
        assert!(
            try_lock_exclusive().is_none(),
            "second acquirer must be refused"
        );
        assert!(is_locked(), "probe sees the held lock");
        assert!(crate::paths::deploy_lock_file().is_file());

        drop(guard);
        assert!(is_locked() == false, "lock released on guard drop");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn lock_file_is_moderate_and_guarded() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-lock-mode-{}", std::process::id()));
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }
        let guard = try_lock_exclusive().expect("acquire lock");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(crate::paths::deploy_lock_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
