//! Worker threads for the TUI: scan, deployment, service management.
//!
//! Unsafe is the cost of capturing build output without inheriting the
//! terminal: `libc::pipe`/`dup2` create an out-of-runway stderr pipe detached
//! from the TUI's alternate screen, and `File::from_raw_fd` adopts the read
//! end. One buffer duration, no ownership hand-off across threads.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc::Sender};
use std::thread::JoinHandle;

use super::Msg;
use crate::hoster::deploy;

/// The in-flight deploy worker thread (if any), so the exit path can wait out
/// its final bookkeeping — the trailing `== deploy … done: … ==` line and the
/// stderr-capture restore — before reconciling. The thread itself runs the
/// deploy; this is only its `JoinHandle`, cleared once waited on.
static DEPLOY_WORKER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// True while this process's fd 2 is rerouted into the deploy-log pipe. Text
/// written to stderr in that window (for example exit notices after a
/// mid-deploy quit) would otherwise be funneled back into deploy.log a second
/// time by the capture reader.
static STDERR_CAPTURED: AtomicBool = AtomicBool::new(false);

/// Port → unit name for every URL registered by our deployments. Purely a
/// local state.json lookup — no probing involved.
fn deployed_port_map(entries: &[(String, crate::state::ServiceEntry)]) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for (_, entry) in entries {
        for url in &entry.urls {
            if let Some((_, port)) = url.rsplit_once(':')
                && let Ok(port) = port.parse::<u16>()
            {
                map.insert(port, entry.unit_name.clone());
            }
        }
    }
    map
}

/// Every live listener, sorted and deduplicated. A port gets `Some(unit)`
/// when it belongs to one of our deployments (local state.json lookup);
/// foreign listeners stay anonymous — `None`, no owner ever attributed.
fn port_rows_from(
    listening: &[u16],
    deployed: &HashMap<u16, String>,
) -> Vec<(u16, Option<String>)> {
    let mut ports: Vec<u16> = listening.to_vec();
    ports.sort_unstable();
    ports.dedup();
    ports
        .into_iter()
        .map(|port| (port, deployed.get(&port).cloned()))
        .collect()
}

pub(crate) fn spawn_scan(tx: Sender<Msg>, seq: u64) {
    std::thread::spawn(move || {
        let started = std::time::SystemTime::now();
        let result = crate::analyzer::probe::run_analysis();
        let deployed = deployed_port_map(&crate::state::list());
        let mut out = String::new();
        // Freshness marker: makes it obvious the report is from THIS run.
        out.push_str(&format!(
            "  scanned at {}\n",
            crate::netlog::format_utc(started)
        ));
        let mark = |ok: bool| if ok { "[x]" } else { "[ ]" };
        out.push_str(&format!(
            "{} systemd          {}\n{} systemd-nspawn   {}\n{} git              {}\n{} python3 / node   {} / {}\n{} network          {}\n",
            mark(result.systemd),
            yesno(result.systemd, "found", "MISSING"),
            mark(result.systemd_nspawn),
            yesno(result.systemd_nspawn, "available", "not installed"),
            mark(result.git),
            yesno(result.git, "found", "MISSING"),
            mark(result.python3 && result.node),
            found("python3"),
            found("node"),
            mark(result.network),
            yesno(result.network, "online", "offline"),
        ));

        if !result.interfaces.is_empty() {
            out.push_str("\nInterfaces:\n");
            for i in &result.interfaces {
                out.push_str(&format!("  {:<14} {:<18} {}\n", i.name, i.ip, i.status));
            }
        }
        // Listening ports: every occupied port is listed, but ownership is
        // resolved ONLY from local state.json. Ports of our deployments are
        // labeled with their unit; anything else stays an anonymous
        // occupied port — never a process name.
        let live: Vec<u16> = result.listening_ports.iter().map(|p| p.port).collect();
        let port_rows = port_rows_from(&live, &deployed);
        // The section is ALWAYS shown: an empty list is information too.
        out.push_str("\nListening ports:\n");
        if port_rows.is_empty() {
            out.push_str("  (none)\n");
        } else {
            out.push_str(&format!("  {:<6} {}\n", "PORT", "SERVICE"));
            for (port, unit) in &port_rows {
                match unit {
                    Some(unit) => out.push_str(&format!("  {port:<6} {unit} (deployed)\n")),
                    None => out.push_str(&format!("  {port:<6}\n")),
                }
            }
        }
        for e in &result.errors {
            out.push_str(&format!("\n! {e}\n"));
        }
        let _ = tx.send(Msg::ScanDone(seq, out));
    });
}

fn yesno(cond: bool, yes: &str, no: &str) -> String {
    if cond { yes.into() } else { no.into() }
}

fn found(bin: &str) -> String {
    if which(bin) {
        "found".into()
    } else {
        "missing".into()
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

const MAX_DEPLOY_LOG_BYTES: u64 = 1 << 20;
const DEPLOY_LOG_KEEP_BYTES: usize = 64 * 1024;

pub(crate) fn deploy_log_path() -> std::path::PathBuf {
    crate::paths::deploy_log_file()
}

pub(crate) fn append_deploy_log(line: &str) {
    let path = deploy_log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(md) = std::fs::metadata(&path)
        && md.len() > MAX_DEPLOY_LOG_BYTES
        && let Ok(content) = std::fs::read(&path)
    {
        let keep = content.len().saturating_sub(DEPLOY_LOG_KEEP_BYTES);
        let mut slice = &content[keep..];
        if let Some(pos) = slice.iter().position(|&b| b == b'\n') {
            slice = &slice[pos + 1..];
        }
        let _ = std::fs::write(&path, slice);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

pub(crate) fn read_deploy_log() -> Vec<String> {
    let path = deploy_log_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => s.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

pub(crate) fn clear_deploy_log() {
    let path = deploy_log_path();
    let _ = std::fs::remove_file(&path);
}

pub(crate) fn journal_raw_for(unit: &str) -> Vec<String> {
    let out = std::process::Command::new("journalctl")
        .args([
            "--user",
            "-u",
            unit,
            "-n",
            "50",
            "--no-pager",
            "--all",
            "-o",
            "short",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn start_deployment(tx: Sender<Msg>, url: String) {
    let handle = std::thread::spawn(move || {
        append_deploy_log(&format!(
            "== deploy {url} started at {} ==",
            crate::netlog::format_utc(std::time::SystemTime::now())
        ));
        let log_tx = tx.clone();
        let log = move |line: String| {
            append_deploy_log(&line);
            let _ = log_tx.send(Msg::Log(line));
        };
        // The deploy pipeline (clone/git/rawfetch) reports diagnostics via
        // eprintln!() to the process stderr. During the TUI that stderr is the
        // terminal, so those lines would leak raw bytes over the alternate
        // screen and corrupt the interface for a moment. Redirect fd 2 into a
        // pipe for the duration of the deploy and forward the captured lines
        // into the deploy log instead.
        let capture = StderrCapture::new(tx.clone());
        let ok = deploy::run_deployment(&url, &log) == deploy::DeployOutcome::Deployed;
        capture.restore();
        if crate::hoster::cancel::is_exiting() {
            // The exit path is tearing down this deploy and writes the
            // authoritative terminal marker ("== deploy … done: interrupted ==")
            // itself, so we do not append a competing "done: failed" line and
            // every interrupted deploy has exactly one terminal marker.
            return;
        }
        append_deploy_log(&format!(
            "== deploy {url} done: {} ==",
            if ok { "ok" } else { "failed" }
        ));
        let _ = tx.send(Msg::DeployDone(ok));
    });
    if let Ok(mut worker) = DEPLOY_WORKER.lock() {
        *worker = Some(handle);
    }
}

/// Temporarily reroutes the process's stderr (fd 2) into a pipe, forwarding
/// each captured line to the TUI as it arrives. Used while a TUI deploy is
/// running so diagnostic eprintln!() output from the clone/git/rawfetch path
/// never paints over the alternate screen.
struct StderrCapture {
    /// Duplicate of the original fd 2 so we can restore it afterwards.
    saved: std::os::unix::io::RawFd,
    /// Owned write end of the pipe; made to be fd 2 for the deploy duration.
    pipe_write: std::os::unix::io::RawFd,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl StderrCapture {
    fn new(tx: Sender<Msg>) -> Self {
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return StderrCapture {
                saved: -1,
                pipe_write: -1,
                reader: None,
            };
        }
        let (read, write) = (fds[0], fds[1]);
        let saved = unsafe { libc::dup(2) };
        // fd 2 -> pipe write end (we keep our own copy of `write` open so the
        // pipe survives until restore() even if dup2 then close renumbers 2).
        unsafe { libc::dup2(write, 2) };
        use std::io::BufRead;
        use std::os::fd::FromRawFd;
        let reader = std::thread::spawn(move || {
            let file = unsafe { std::fs::File::from_raw_fd(read) };
            let mut lines = std::io::BufReader::new(file).lines();
            while let Some(Ok(line)) = lines.next() {
                append_deploy_log(&line);
                let _ = tx.send(Msg::Log(line));
            }
        });
        STDERR_CAPTURED.store(true, Ordering::SeqCst);
        StderrCapture {
            saved,
            pipe_write: write,
            reader: Some(reader),
        }
    }

    fn restore(mut self) {
        if self.saved >= 0 {
            unsafe { libc::dup2(self.saved, 2) };
            unsafe { libc::close(self.saved) };
            self.saved = -1;
        }
        if self.pipe_write >= 0 {
            unsafe { libc::close(self.pipe_write) };
            self.pipe_write = -1;
        }
        // Close the read side: the reader thread sees EOF and drains out.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        STDERR_CAPTURED.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn stderr_capture_active() -> bool {
    STDERR_CAPTURED.load(Ordering::SeqCst)
}

/// Wait (bounded) for the deploy worker thread to fully unwind — the point
/// where it has appended its trailing `== deploy … done: … ==` line and
/// restored fd 2. Returns when the thread has exited, when `timeout` elapses,
/// or immediately if no deploy worker exists. The exit path calls this after
/// [`crate::hoster::deploy::quiesce`] so reconcile never races a worker that
/// is still streaming to deploy.log, and so the final "done" line is never
/// lost to process shutdown.
pub(crate) fn wait_deploy_worker(timeout: std::time::Duration) {
    let handle = {
        let mut worker = match DEPLOY_WORKER.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        worker.take()
    };
    let Some(handle) = handle else {
        return;
    };
    let deadline = std::time::Instant::now() + timeout;
    while !handle.is_finished() {
        if std::time::Instant::now() >= deadline {
            // It ran past the bound; drop the handle and let it finish in the
            // background. EXITING is already set and the deploy lock is held
            // by this process, so nothing it writes can resurrect artifacts.
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = handle.join();
}

/// (unit name, status, url) rows for the services screen.
pub(crate) fn service_rows() -> Vec<(String, String, String)> {
    crate::state::list()
        .into_iter()
        .map(|(name, entry)| {
            let active = std::process::Command::new("systemctl")
                .args(["--user", "is-active", &entry.unit_name])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".into());
            let url = entry.urls.first().cloned().unwrap_or_default();
            (name, active, url)
        })
        .collect()
}

pub(crate) fn service_action(name: &str, action: &str) -> String {
    let res = match action {
        "stop" => systemctl(&["--user", "stop", name]),
        "start" => start_service(name),
        "delete" => {
            deploy::remove_unit_and_state(name);
            return format!("{name}: deleted");
        }
        _ => Ok(()),
    };
    match res {
        Ok(()) => format!("{name}: {action}ed"),
        Err(e) => format!("{name}: {action} failed — {e}"),
    }
}

pub(crate) fn fetch_software_logs() -> Vec<String> {
    let entries = crate::state::list();
    if entries.is_empty() {
        return vec![
            "No services deployed yet.".into(),
            "Deploy a service to see its journal here.".into(),
        ];
    }
    let mut out = Vec::new();
    for (name, entry) in entries {
        out.push(format!("== {} ({}) ==", name, entry.unit_name));
        let output = std::process::Command::new("journalctl")
            .args([
                "--user",
                "-u",
                &entry.unit_name,
                "-n",
                "50",
                "--no-pager",
                "--all",
                "-o",
                "short",
            ])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let mut added = false;
                for line in text.lines() {
                    // journalctl lines are already timestamped
                    out.push(line.to_string());
                    added = true;
                }
                if !added {
                    out.push("(no log output yet)".into());
                }
            }
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                let msg = err.trim();
                if msg.is_empty() {
                    out.push("(no journal entries)".into());
                } else {
                    out.push(format!("(journalctl: {msg})"));
                }
            }
            Err(e) => out.push(format!("(journalctl not available: {e})")),
        }
        out.push(String::new());
    }
    out
}

/// Bring a service back up from the panel, even after a rough landing.
///
/// A unit can be left `failed`/`start-limit-hit` (or `disabled`) by an
/// interrupted deploy, a crash loop, or a redeploy that never finished. A
/// plain `systemctl start` is then refused outright, which is why the only
/// way out used to be delete + redeploy. Clearing the failed state and
/// re-arming the install link first makes a single `start` enough.
fn start_service(name: &str) -> anyhow::Result<()> {
    let _ = systemctl(&["--user", "reset-failed", name]);
    let _ = systemctl(&["--user", "enable", name]);
    systemctl(&["--user", "start", name])
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServiceEntry;

    fn entry(unit: &str, urls: &[&str]) -> (String, ServiceEntry) {
        (
            unit.to_string(),
            ServiceEntry {
                unit_name: unit.to_string(),
                project_dir: format!("/tmp/{unit}"),
                url: "https://example.com/x".into(),
                urls: urls.iter().map(|s| s.to_string()).collect(),
            },
        )
    }

    #[test]
    fn port_map_parses_urls_and_skips_garbage() {
        let entries = vec![
            entry("demo-vert", &["http://localhost:10748"]),
            entry(
                "demo-memos",
                &["http://localhost:8075", "not-a-url", "ftp://x"],
            ),
        ];
        let map = deployed_port_map(&entries);
        assert_eq!(map.get(&10748).unwrap(), "demo-vert");
        assert_eq!(map.get(&8075).unwrap(), "demo-memos");
        assert!(map.len() == 2);
    }

    #[test]
    fn listening_table_lists_all_ports_but_attributes_only_deployed() {
        let entries = vec![
            entry("demo-vert", &["http://localhost:10748"]),
            entry("demo-memos", &["http://localhost:23920"]),
        ];
        let map = deployed_port_map(&entries);

        // Every occupied port appears, sorted and deduplicated; foreign
        // listeners (9050 tor, 5432 postgres) stay anonymous.
        let rows = port_rows_from(&[23920, 9050, 10748, 5432, 10748], &map);
        assert_eq!(
            rows,
            vec![
                (5432, None),
                (9050, None),
                (10748, Some("demo-vert".to_string())),
                (23920, Some("demo-memos".to_string())),
            ]
        );

        // Nothing listening → empty table.
        assert!(port_rows_from(&[], &map).is_empty());
    }
}
