//! Cooperative shutdown for an in-flight deploy.
//!
//! The panel's clean-removal promise is that an interrupted deploy leaves
//! nothing behind: no unit, no env file, no clone/build tree (the whole
//! `services/<name>` folder), no journal entry. When the interruption is a
//! *graceful* exit — `q`/Esc/Ctrl+C, `SIGTERM`/`SIGHUP`, systemd shutdown or
//! reboot — the removal must happen *before the process dies*, not be deferred
//! to the next launch. The old design deferred it (the journal entry was kept
//! so the next launch could re-verify), because a worker thread that is still
//! running can re-create artifacts in the window between the cleanup and
//! process death. That window is exactly what this module closes.
//!
//! The deploy pipeline runs as a thread inside this process, so every writer it
//! owns is a *descendant* of this process: host-side `git`/`sh` steps are direct
//! children, and sandboxed builds live in `ghost-build-*` transient user units
//! (those are stopped separately by `deploy::stop_orphaned_builds`, since
//! killing only the `systemd-run` launcher would orphan the unit). Setting
//! [`request_exit`] makes the pipeline stop starting new steps (it polls
//! [`is_exiting`] between phases); killing the descendant tree and stopping the
//! ghost units tears down whatever is mid-flight. The wipe that follows is then
//! final.
//!
//! Unsafe is confined to the raw `kill(2)` syscall in [`kill_descendants`];
//! everything else here is safe Rust.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Set once a graceful exit has begun. The deploy pipeline polls [`is_exiting`]
/// between steps and aborts instead of starting new work.
static EXITING: AtomicBool = AtomicBool::new(false);

/// Whether a graceful exit is in progress.
pub fn is_exiting() -> bool {
    EXITING.load(Ordering::SeqCst)
}

/// Mark that the process is exiting and any in-flight deploy must wind down.
pub fn request_exit() {
    EXITING.store(true, Ordering::SeqCst);
}

/// `SIGKILL` every descendant of `root` (this process), deepest-first.
///
/// Only processes whose parent chain leads back to `root` are signalled: the
/// panel's own threads share its PID and are never separate entries, and no
/// process outside this process's tree is touched. This is what lets a host
/// clone/build step be stopped *now* instead of surviving as a reparented
/// orphan that keeps writing into a tree the exit path is about to remove.
///
/// Returns how many processes were signalled. The `/proc` scan is a snapshot;
/// a process that vanishes mid-kill is simply not counted.
pub fn kill_descendants(root: u32) -> usize {
    let kids = child_map();
    let mut stack = vec![root];
    let mut pids = Vec::new();
    while let Some(pid) = stack.pop() {
        if let Some(children) = kids.get(&pid) {
            for &child in children {
                pids.push(child);
                stack.push(child);
            }
        }
    }
    let mut killed = 0;
    // `pids` is discovered top-down; reverse so deeper descendants die first.
    for pid in pids.iter().rev() {
        if unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) } == 0 {
            killed += 1;
        }
    }
    killed
}

/// Snapshot of parent-pid -> child-pids from `/proc`.
fn child_map() -> std::collections::HashMap<u32, Vec<u32>> {
    let mut map: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if let Some(ppid) = parse_ppid(&stat) {
            map.entry(ppid).or_default().push(pid);
        }
    }
    map
}

/// Extract the parent pid from a `/proc/<pid>/stat` line. `comm` is wrapped in
/// parentheses and may itself contain spaces and parentheses, so split after
/// the *final* `)`; the next token is the state, the one after is `ppid`.
fn parse_ppid(stat: &str) -> Option<u32> {
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ppid_handles_parens_in_comm() {
        // `(sd-pam)` / `(a b)` / `(x)y)` comm fields must not shift the ppid.
        assert_eq!(parse_ppid("1234 (bash) S 42 1234 1234 0 -1"), Some(42));
        assert_eq!(parse_ppid("1234 (a b) S 7 1234 1234 0 -1"), Some(7));
        assert_eq!(parse_ppid("1234 (weird)name) R 9 1 1"), Some(9));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn kill_descendants_of_a_missing_pid_is_a_noop() {
        // A pid that cannot exist has no entry in the `/proc` child map, so
        // nothing is signalled — safe to run in the test harness.
        assert_eq!(kill_descendants(u32::MAX), 0);
    }
}
