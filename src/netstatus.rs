//! Coalesced network health reporting — the anti-spam side of the retry core.
//!
//! The HTTP client retries transient network/DNS failures *permanently*
//! (`httpclient::fetch`). Without this module every backoff step would print
//! a line per host (the `go module retry #N … waiting Xs` storm the old code
//! produced). Here we collapse all retry chatter into:
//!
//! 1. one line on the transition into a "network looks down" state,
//! 2. a heartbeat while it stays down (default 120s — the backoff cap),
//! 3. one line on recovery.
//!
//! The TUI reads [`summary`] to paint a `NET ⚠` indicator on the deploy
//! status when the machine is offline mid‑deploy, so the user sees *why* a
//! retrying deploy is not progressing. This is purely informational: no
//! deadline, no fail-closed, the retry policy lives in `httpclient`.

use std::collections::HashSet;
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Seconds between heartbeat lines while the network is classified as down.
/// Matches [`crate::hoster::httpclient::MAX_BACKOFF`]; a global outage is
/// reported anew at most once per boostrapping interval.
const HEARTBEAT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy)]
pub struct NetSummary {
    /// Distinct hosts currently classified as unreachable.
    pub down_hosts: usize,
    /// How long the outage has lasted so far.
    pub since: Duration,
}

struct State {
    down: HashSet<String>,
    since: Option<Instant>,
    last_report: Option<Instant>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn emit(line: &str) {
    // stderr keeps the feed visible in CLI mode and is captured by the same
    // daemon/deploy channels that surface other net diagnostics.
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Pure emission decision, extracted for unit-testing without stderr capture.
///
/// `first` is true on the 0→down transition (`since` was `None`),
/// `due` is true when no report was ever written or `HEARTBEAT` elapsed.
/// In all reachable states `first` implies `due` (both are set/cleared
/// together), so this is equivalent to just `due` — `first` is kept as
/// documentation of intent. The old third disjunct
/// (`fresh_host && down.len() == 1`) was removed: a fresh host bringing the
/// set 0→1 implies an empty set before, which implies `since == None`,
/// i.e. it is already covered by `first`.
fn should_emit(first: bool, due: bool) -> bool {
    first || due
}

/// A fetch attempt for `host` failed. Prints the one-shot "network looks
/// down" transition on a fresh state, then throttles by [`HEARTBEAT`].
/// Returns `true` when a line was emitted (lets tests count messages
/// without capturing stderr).
pub fn note_down(host: &str) -> bool {
    let mut g = STATE.lock().unwrap();
    let st = g.get_or_insert_with(|| State {
        down: HashSet::new(),
        since: None,
        last_report: None,
    });
    st.down.insert(host.to_string());
    let now = Instant::now();
    let first = st.since.is_none();
    if first {
        st.since = Some(now);
    }
    let due = st
        .last_report
        .map(|l| now.duration_since(l) >= HEARTBEAT)
        .unwrap_or(true);
    if should_emit(first, due) {
        st.last_report = Some(now);
        let n = st.down.len();
        let since = st.since.unwrap_or(now);
        emit(&format!(
            "net: {n} host(s) unreachable — permanent retry, next probe is automatic (since {})",
            fmt_since(since),
        ));
        true
    } else {
        false
    }
}

/// A fetch attempt for `host` succeeded. On the 0→recovered transition prints
/// the recovery line; clears host from the down set.
pub fn note_up(host: &str) {
    let mut g = STATE.lock().unwrap();
    let Some(st) = g.as_mut() else { return };
    if !st.down.remove(host) {
        return;
    }
    if st.down.is_empty() {
        if let Some(since) = st.since.take() {
            emit(&format!(
                "net: network recovered after {} — resuming",
                fmt_since(since)
            ));
        }
        st.last_report = None;
    }
}

/// Expose the current state for the TUI status line. `None` = no outage.
pub fn summary() -> Option<NetSummary> {
    let g = STATE.lock().unwrap();
    let st = g.as_ref()?;
    if st.down.is_empty() {
        return None;
    }
    let since = st.since?;
    Some(NetSummary {
        down_hosts: st.down.len(),
        since: since.elapsed(),
    })
}

fn fmt_since(i: Instant) -> String {
    let d = i.elapsed();
    let total = d.as_secs();
    let m = total / 60;
    let s = total % 60;
    if d >= Duration::from_secs(3600) {
        format!("{}h{}m", total / 3600, m % 60)
    } else if d >= Duration::from_secs(60) {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_has_no_summary() {
        *STATE.lock().unwrap() = None;
        assert!(summary().is_none());
    }

    #[test]
    fn emission_decision_table() {
        // first implies due in reachable states, but both spellings emit.
        assert!(should_emit(true, true));
        assert!(should_emit(true, false));
        assert!(should_emit(false, true));
        assert!(!should_emit(false, false));
    }

    #[test]
    fn first_failure_reports_and_second_is_silent() {
        *STATE.lock().unwrap() = None;
        assert!(note_down("github.com"), "first failure must emit one line");
        let s1 = summary().expect("down after first failure");
        assert_eq!(s1.down_hosts, 1);
        assert!(
            !note_down("github.com"),
            "repeat of the same host must be silent (heartbeat not due)"
        );
        let s2 = summary().unwrap();
        assert_eq!(s2.down_hosts, 1, "same host must not be counted twice");
    }

    #[test]
    fn recovery_clears() {
        *STATE.lock().unwrap() = None;
        let _ = note_down("github.com");
        let _ = note_down("dl.google.com");
        assert_eq!(summary().unwrap().down_hosts, 2);
        note_up("github.com");
        assert_eq!(summary().unwrap().down_hosts, 1);
        note_up("dl.google.com");
        assert!(summary().is_none(), "recovery must clear the outage");
    }
}
