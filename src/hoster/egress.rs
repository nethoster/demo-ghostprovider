//! Runtime egress verification.
//!
//! Deployed services are rendered with `IPAddressDeny=any` plus
//! `IPAddressAllow=127.0.0.1 ::1` (see [`units`]), so a service that ignores
//! loopback binding has no way out of the host. That directive is enforced by
//! an eBPF cgroup filter, which unprivileged user managers cannot load on
//! kernels with `kernel.unprivileged_bpf_disabled=1|2` (Ubuntu's default).
//! On such hosts the directive degrades to a journal decoration: rules are
//! listed but never match. This module makes the difference observable.
//!
//! The probe runs a transient unit that carries the exact runtime-service IP
//! filter, and inside it performs two beats:
//!
//!   * loopback — bind and connect on `127.0.0.1` (does IP work at all?);
//!   * outbound — an allowlisted HTTPS GET (does the filter stop it?).
//!
//! The verdict is reported by the deploy pipeline and `--selftest`, never
//! silently assumed. A hard no-egress boundary on a host whose kernel forbids
//! eBPF requires a host firewall; we surface that instead of pretending.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Allowlisted endpoint used for the outbound beat. Goes through the regular
/// hardened client, so the attempt is also visible in net.log.
const PROBE_ENDPOINT: &str = "https://api.github.com/";

/// Keep the probe from wedging a live systemd-run busy-wait.
const PROBE_WAIT: Duration = Duration::from_secs(70);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressVerdict {
    /// IP filter ran and blocked the outbound beat; loopback passed.
    Enforced,
    /// IP filter ran but the outbound beat succeeded: not enforceable here.
    Open,
    /// The probe itself could not run or be interpreted.
    ProbeFailed,
}

impl EgressVerdict {
    /// Single-line log rendering; deploy and selftest emit exactly this.
    /// Each possibility reads as a fact, including the failure mode — a
    /// missing verdict must never read as "locked".
    pub fn label(&self) -> &'static str {
        match self {
            EgressVerdict::Enforced => {
                "runtime egress: BLOCKED — IP filter enforced (loopback only)"
            }
            EgressVerdict::Open => {
                "runtime egress: OPEN — this host cannot enforce the unit IP filter \
                 (unprivileged eBPF disabled); the service keeps outbound access; \
                 use a host firewall for a hard no-egress guarantee"
            }
            EgressVerdict::ProbeFailed => {
                "runtime egress: UNVERIFIED — probe could not run (systemd-run/D-Bus?)"
            }
        }
    }
}

/// Internal beat: report the two facts to stdout. Expected lines:
/// `loopback: ok|failed` and `outbound: open|blocked`.
pub fn run_probe_cmd() -> anyhow::Result<()> {
    println!("loopback: {}", if loopback_ok() { "ok" } else { "failed" });
    println!(
        "outbound: {}",
        if outbound_open() { "open" } else { "blocked" }
    );
    Ok(())
}

/// Host-side capability check: run [`run_probe_cmd`] inside a transient unit
/// that carries the same IP filter the deploy renders for every service.
pub fn verify_runtime_egress() -> EgressVerdict {
    if !cmd_on_path("systemd-run") {
        return EgressVerdict::ProbeFailed;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return EgressVerdict::ProbeFailed,
    };
    let unit = format!(
        "ghost-egress-{}.service",
        crate::atomic::random_hex(4).unwrap_or_default()
    );
    // Same pair of properties as units::IP_FILTER; a probe unit must match the
    // enforcement plain that deployed services actually get.
    let argv: Vec<String> = vec![
        "systemd-run".into(),
        "--user".into(),
        "--wait".into(),
        "--pipe".into(),
        "--collect".into(),
        "--unit".into(),
        unit,
        "--property=IPAddressDeny=any".into(),
        "--property=IPAddressAllow=127.0.0.1 ::1".into(),
        "--property=RuntimeMaxSec=40".into(),
        "--".into(),
        exe.to_string_lossy().into_owned(),
        "__egress-probe".into(),
    ];
    // Probe stdout carries the verdict; stderr carries systemd-run diagnostics
    // we do not parse but keep for debugging.
    let Ok((_status, stdout, _stderr)) = run_timed(&argv, PROBE_WAIT) else {
        return EgressVerdict::ProbeFailed;
    };
    let mut loopback_ok = false;
    let mut outbound_blocked = false;
    for line in stdout.lines() {
        match line.trim() {
            "loopback: ok" => loopback_ok = true,
            "outbound: blocked" => outbound_blocked = true,
            "outbound: open" => outbound_blocked = false,
            _ => {}
        }
    }
    if !loopback_ok {
        EgressVerdict::ProbeFailed
    } else if outbound_blocked {
        EgressVerdict::Enforced
    } else {
        EgressVerdict::Open
    }
}

/// Loopback beat: IP routing works at all when a listener accepts a connect
/// on `127.0.0.1`.
fn loopback_ok() -> bool {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return false;
    };
    let Ok(addr) = listener.local_addr() else {
        return false;
    };
    TcpStream::connect(addr).is_ok()
}

/// Outbound beat: does an allowlisted HTTPS GET leave the unit?
fn outbound_open() -> bool {
    super::httpclient::get_text(PROBE_ENDPOINT).is_ok()
}

/// Spawn `argv`, stream stdout/stderr through reader threads so a large probe
/// output cannot deadlock the wait, and reap (or kill) the child within
/// `timeout`.
fn run_timed(
    argv: &[String],
    timeout: Duration,
) -> anyhow::Result<(Option<ExitStatus>, String, String)> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let out_pipe = child.stdout.take().unwrap();
    let err_pipe = child.stderr.take().unwrap();
    let out_th = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::BufReader::new(out_pipe).read_to_string(&mut s);
        s
    });
    let err_th = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::BufReader::new(err_pipe).read_to_string(&mut s);
        s
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                let out = out_th.join().unwrap_or_default();
                let err = err_th.join().unwrap_or_default();
                return Ok((Some(status), out, err));
            }
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_th.join();
                    let _ = err_th.join();
                    anyhow::bail!("egress probe timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn cmd_on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_beat_works_without_a_unit() {
        assert!(loopback_ok(), "loopback connect must succeed on this host");
    }

    #[test]
    fn verdict_labels_are_distinct() {
        let a = EgressVerdict::Enforced.label();
        let b = EgressVerdict::Open.label();
        let c = EgressVerdict::ProbeFailed.label();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        assert!(a.starts_with("runtime egress:"));
        assert!(b.starts_with("runtime egress:"));
        assert!(c.starts_with("runtime egress:"));
    }
}
