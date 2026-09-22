//! Persistent history for the Logs → Crash screen: deploy interruptions and
//! full clean removals.
//!
//! The Crash screen answers two questions that the normal deploy log does not
//! survive to tell: *did a deploy stop half-finished* (because this panel was
//! quit, killed, or the system shut down/rebooted), and *what got fully
//! removed* afterwards. Every line carries a UTC timestamp (same format as the
//! deploy log) and a kind tag so the screen can colour it without re-parsing:
//!
//! ```text
//! [interrupted]  a live in-flight deploy was aborted while this panel was
//!                alive — user exit or a termination signal — and its
//!                leftovers were removed immediately.
//! [recovered]    leftovers of a deploy whose process died out-of-band
//!                (SIGKILL, power loss, shutdown/reboot) were found later —
//!                on the next launch or by the background sweep — and removed.
//! [removed]      a deliberate full removal (My Services → delete).
//! [ghost]        orphaned `ghost-build-*` / `ghost-egress-*` transient units
//!                left by a dead deploy, stopped by the background sweep.
//! ```
//!
//! The file lives next to `deploy.log` and is bounded the same way (newest
//! tail is kept), so it never grows without limit. Recording is best-effort:
//! history is a convenience, never a hard guarantee.
//!
//! Unsafe is forbidden here; everything is plain filesystem append.

use std::io::Write;
use std::time::SystemTime;

/// Cap on `crash.log` size before the oldest bytes are dropped.
pub const MAX_CRASH_LOG_BYTES: u64 = 1 << 20;
/// Bytes of the newest history kept after a truncation.
const CRASH_LOG_KEEP_BYTES: usize = 1 << 18;

fn log_path() -> std::path::PathBuf {
    crate::paths::crash_log_file()
}

/// Append one kind-tagged, timestamped history line. Bounded by dropping the
/// oldest tail of the file once it exceeds [`MAX_CRASH_LOG_BYTES`], mirroring
/// the deploy log's truncation.
pub fn record(kind: &str, message: &str) {
    let line = format!(
        "{} [{}] {}",
        crate::netlog::format_utc(SystemTime::now()),
        kind,
        message
    );
    let path = log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let (Ok(md), Ok(content)) = (std::fs::metadata(&path), std::fs::read(&path))
        && md.len() > MAX_CRASH_LOG_BYTES
    {
        let keep = content.len().saturating_sub(CRASH_LOG_KEEP_BYTES);
        let mut slice = &content[keep..];
        if let Some(pos) = slice.iter().position(|&b| b == b'\n') {
            slice = &slice[pos + 1..];
        }
        let _ = std::fs::write(&path, slice);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// A deploy that was interrupted while this panel was alive (user exited or a
/// termination signal arrived): its leftovers were removed immediately.
pub fn interrupted(service: &str, url: &str) {
    record(
        "interrupted",
        &format!(
            "deploy aborted at exit: {service} ({url}) — unit, env, project tree and journal removed"
        ),
    );
}

/// Leftovers of a deploy whose process died out-of-band were found later
/// (next launch or background sweep) and removed.
pub fn recovered(service: &str, url: &str, had_artifacts: bool) {
    if had_artifacts {
        record(
            "recovered",
            &format!(
                "unfinished deploy: {service} ({url}) — leftover unit/env/project tree removed"
            ),
        );
    } else {
        record(
            "recovered",
            &format!("unfinished deploy: {service} ({url}) — no leftovers; journal entry settled"),
        );
    }
}

/// A deliberate full removal from "My Services" → delete.
pub fn removed(service: &str, url: &str) {
    record(
        "removed",
        &format!("full removal: {service} ({url}) — unit, env, project tree, ports and registry"),
    );
}

/// Orphaned `ghost-*` transient build/probe units were stopped by a sweep.
pub fn ghost_stopped(n: usize) {
    record(
        "ghost",
        &format!("orphaned ghost build/probe unit(s) stopped: {n}"),
    );
}

/// All history lines (newest last), for seeding the Crash screen.
pub fn read() -> Vec<String> {
    match std::fs::read_to_string(log_path()) {
        Ok(s) => s.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// Drop the history file entirely (Logs → Crash → delete).
pub fn clear() {
    let _ = std::fs::remove_file(log_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_STATE_HOME)
    fn record_then_read_roundtrips() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "dgp-crashlog-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }
        remove_for_test();

        interrupted("demo-memos", "https://github.com/usememos/memos");
        removed("demo-vert", "https://github.com/Parraghosting/vert");
        let lines = read();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("[interrupted]"), "{}", lines[0]);
        assert!(lines[0].contains("2026-"), "has a timestamp: {}", lines[0]);
        assert!(lines[1].contains("[removed]"), "{}", lines[1]);

        clear();
        assert!(read().is_empty(), "clear() drops the file");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_STATE_HOME)
    fn each_record_carries_its_kind() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-crashlog-kind-{}", std::process::id()));
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }
        remove_for_test();

        recovered("demo-a", "https://github.com/x/a", true);
        recovered("demo-b", "https://github.com/x/b", false);
        ghost_stopped(2);
        removed("demo-c", "https://github.com/x/c");

        let lines = read();
        assert!(lines[0].contains("[recovered]"));
        assert!(lines[0].contains("leftover unit/env/project tree removed"));
        assert!(lines[1].contains("[recovered]"));
        assert!(lines[1].contains("no leftovers"));
        assert!(lines[2].contains("[ghost]"));
        assert!(lines[2].contains("2"));
        assert!(lines[3].contains("[removed]"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn remove_for_test() {
        let _ = std::fs::remove_file(log_path());
    }
}
