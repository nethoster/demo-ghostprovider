//! Runtime egress verification.
//!
//! Deployed services are rendered with `IPAddressDeny=any` plus
//! `IPAddressAllow=127.0.0.1 ::1` and any manifest `egress.allow` exceptions
//! (resolved to literal addresses first — `IPAddressAllow=` rejects
//! hostnames; see [`units`] and [`resolve_egress_hosts`]), so a service that
//! ignores loopback binding has no way out
//! of the host except to its named exceptions. That directive is enforced by
//! an eBPF cgroup filter, which unprivileged user managers cannot load on
//! kernels with `kernel.unprivileged_bpf_disabled=1|2` (Ubuntu's default).
//! On such hosts the directive degrades to a journal decoration: rules are
//! listed but never match. This module makes the difference observable.
//!
//! The probe runs a transient unit that carries the exact IP filter the
//! service would get, and inside it performs one beat per host:
//!
//!   * loopback — bind and connect on `127.0.0.1` (does IP work at all?);
//!   * control — a reliable outside host that must stay blocked, proving the
//!     filter is real (skipped when the user allowlisted it);
//!   * one beat per allowlisted host, which must come back open.
//!
//! Outcomes are honest three-state per host: `open` (a packet provably left
//! the unit — ECONNREFUSED counts, the filter did not stop it), `blocked`
//! (the kernel refused it: EPERM/EACCES from the filter), `failed(<why>)`
//! (DNS/timeout/other — proves nothing either way). The verdict is reported
//! by the deploy pipeline, `--selftest` and the Egress screen, never
//! silently assumed. A hard no-egress boundary on a host whose kernel forbids
//! eBPF requires a host firewall; we surface that instead of pretending.

use std::io::Read;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Reliable outside host for the control beat (must stay blocked unless the
/// user explicitly allowlisted it).
const CONTROL_CANDIDATES: &[&str] = &["api.github.com", "example.com"];

/// Per-host TCP beat budget: a filtered connect fails fast (EPERM); only a
/// truly dead network burns the whole budget.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Keep the probe from wedging a live systemd-run busy-wait: the control
/// beat plus one beat per allowed host (manifest caps them at 8).
const PROBE_WAIT: Duration = Duration::from_secs(150);

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
                "runtime egress: UNVERIFIED — probe could not run or not all beats passed"
            }
        }
    }
}

/// One host beat outcome. `Open` means a packet provably left the unit
/// (even ECONNREFUSED — the far end answered, so the filter did not stop
/// it). `Blocked` is the kernel refusing (EPERM/EACCES from the filter).
/// `Failed` proves nothing either way (DNS, timeout, anything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStatus {
    Open,
    Blocked,
    Failed(String),
}

impl HostStatus {
    fn label(&self) -> String {
        match self {
            HostStatus::Open => "open".into(),
            HostStatus::Blocked => "blocked".into(),
            HostStatus::Failed(why) => format!("failed({why})"),
        }
    }

    fn parse(s: &str) -> Option<HostStatus> {
        match s {
            "open" => Some(HostStatus::Open),
            "blocked" => Some(HostStatus::Blocked),
            _ => s
                .strip_prefix("failed(")
                .and_then(|r| r.strip_suffix(')'))
                .map(|why| HostStatus::Failed(why.into())),
        }
    }
}

/// Full probe outcome: the verdict plus the per-beat facts behind it.
#[derive(Debug, Clone)]
pub struct EgressReport {
    pub verdict: EgressVerdict,
    pub loopback_ok: bool,
    /// Control host (reliably-outside, must stay blocked) and its beat.
    /// None when the user allowlisted every candidate (nothing to prove
    /// against) — then only the allow beats speak.
    pub control: Option<(String, HostStatus)>,
    pub hosts: Vec<(String, HostStatus)>,
}

impl EgressReport {
    /// Multi-line rendering for the Egress screen and logs.
    pub fn describe(&self) -> Vec<String> {
        let mut out = vec![self.verdict.label().to_string()];
        out.push(format!(
            "loopback: {}",
            if self.loopback_ok { "ok" } else { "failed" }
        ));
        if let Some((h, s)) = &self.control {
            out.push(format!("control {h}: {}", s.label()));
        }
        for (h, s) in &self.hosts {
            out.push(format!("allow {h}: {}", s.label()));
        }
        out
    }
}

/// Internal beat: report the facts to stdout, one per line:
/// `loopback: ok|failed` and `host <name>: open|blocked|failed(<why>)`.
pub fn run_probe_cmd(hosts: &[String]) -> anyhow::Result<()> {
    println!("loopback: {}", if loopback_ok() { "ok" } else { "failed" });
    for h in hosts {
        println!("host {h}: {}", probe_host(h).label());
    }
    Ok(())
}

/// TCP beat for one host on its HTTPS port: DNS first, then a budgeted
/// connect. Reaching the far end in any form (even refused) is `Open`.
fn probe_host(host: &str) -> HostStatus {
    use std::io::ErrorKind;
    let mut addrs = match (host, 443).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return HostStatus::Failed("dns".into()),
    };
    let addr = match addrs.next() {
        Some(a) => a,
        None => return HostStatus::Failed("dns".into()),
    };
    match TcpStream::connect_timeout(&addr, PROBE_CONNECT_TIMEOUT) {
        Ok(_) => HostStatus::Open,
        Err(e) => match e.kind() {
            ErrorKind::PermissionDenied | ErrorKind::AddrNotAvailable => HostStatus::Blocked,
            ErrorKind::ConnectionRefused => HostStatus::Open,
            ErrorKind::TimedOut => HostStatus::Failed("timeout".into()),
            _ => HostStatus::Failed("error".into()),
        },
    }
}

/// Host-side check with the historic deny-all filter (no exceptions):
/// loopback must pass, the control host must stay blocked.
pub fn verify_runtime_egress() -> EgressVerdict {
    verify_egress_for(&[]).verdict
}

/// systemd's `IPAddressAllow=` parses bare addresses (optionally
/// `ADDRESS/PREFIXLENGTH`) and the special names `any`/`localhost`/
/// `link-local`/`multicast` — never hostnames: a name in the directive makes
/// the whole unit fail to load. Every writer of the filter (unit rendering at
/// deploy, the probe's transient unit) therefore resolves the manifest hosts
/// here first. IPv4/IPv6 literals pass through untouched; names go through
/// the system resolver (A + AAAA), and the result is deduped and sorted so
/// two renders of the same list are comparable. Fails closed: one
/// unresolvable host aborts — silently dropping it would keep the service
/// running with an unexpected filter shape. The result is a snapshot at
/// render time; DNS drift is corrected by re-running (a redeploy or a check
/// re-resolves).
pub fn resolve_egress_hosts(hosts: &[&str]) -> Result<Vec<String>, String> {
    resolve_with(hosts, |h| {
        (h, 0u16)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect())
            .map_err(|e| e.to_string())
    })
}

/// Pure resolution core: literals bypass `lookup`; names must produce at
/// least one address or the whole call fails with the host named.
fn resolve_with(
    hosts: &[&str],
    lookup: impl Fn(&str) -> Result<Vec<std::net::IpAddr>, String>,
) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        if let Ok(ip) = h.parse::<std::net::IpAddr>() {
            out.push(ip.to_string());
            continue;
        }
        let ips = lookup(h).map_err(|why| format!("{h}: {why}"))?;
        if ips.is_empty() {
            return Err(format!("{h}: resolved to no addresses"));
        }
        out.extend(ips.iter().map(|ip| ip.to_string()));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Host-side check with a service's allow list: run the probe beats inside
/// a transient unit carrying the exact filter the service's unit would get
/// (loopback + exceptions), then interpret the beats.
pub fn verify_egress_for(allow: &[String]) -> EgressReport {
    // Control: a reliably-outside host that must stay blocked — unless the
    // user allowlisted it, in which case it proves nothing.
    let lowered: Vec<String> = allow.iter().map(|h| h.to_lowercase()).collect();
    let control = CONTROL_CANDIDATES
        .iter()
        .find(|c| !lowered.iter().any(|h| h == **c))
        .map(|c| c.to_string());
    let mut probed: Vec<String> = Vec::new();
    if let Some(c) = &control {
        probed.push(c.clone());
    }
    probed.extend(allow.iter().cloned());
    let Some(lines) = run_filtered_probe(allow, &probed) else {
        return EgressReport {
            verdict: EgressVerdict::ProbeFailed,
            loopback_ok: false,
            control: control.map(|c| (c, HostStatus::Failed("probe".into()))),
            hosts: allow
                .iter()
                .map(|h| (h.clone(), HostStatus::Failed("probe".into())))
                .collect(),
        };
    };
    interpret_probe(&lines, control, allow)
}

/// Pure interpretation of probe stdout: shared by the live path and tests.
fn interpret_probe(lines: &[String], control: Option<String>, allow: &[String]) -> EgressReport {
    let mut loopback_ok = false;
    let mut beats: Vec<(String, HostStatus)> = Vec::new();
    for line in lines {
        let t = line.trim();
        if t == "loopback: ok" {
            loopback_ok = true;
        } else if let Some(rest) = t.strip_prefix("host ")
            && let Some((name, status)) = rest.split_once(": ")
            && let Some(s) = HostStatus::parse(status.trim())
        {
            beats.push((name.to_string(), s));
        }
    }
    let status_of = |name: &str| {
        beats
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.clone())
            .unwrap_or(HostStatus::Failed("missing".into()))
    };
    let control_beat = control.clone().map(|c| (c.clone(), status_of(&c)));
    let hosts: Vec<(String, HostStatus)> =
        allow.iter().map(|h| (h.clone(), status_of(h))).collect();
    let verdict = if !loopback_ok {
        EgressVerdict::ProbeFailed
    } else if let Some((_, HostStatus::Open)) = &control_beat {
        // The filter did not stop the control host: unenforced here.
        EgressVerdict::Open
    } else if control_beat
        .as_ref()
        .is_some_and(|(_, s)| !matches!(s, HostStatus::Blocked))
    {
        // Control neither open nor blocked (DNS/timeout/missing): proves nothing.
        EgressVerdict::ProbeFailed
    } else if hosts.iter().any(|(_, s)| !matches!(s, HostStatus::Open)) {
        // An allowed host did not come back open: enforcement unknown
        // (its server may be down, DNS broken) — never misread as locked.
        EgressVerdict::ProbeFailed
    } else {
        EgressVerdict::Enforced
    };
    EgressReport {
        verdict,
        loopback_ok,
        control: control_beat,
        hosts,
    }
}

/// Run the probe beats inside a transient unit with the service's filter.
/// Returns the probe's stdout lines, or None when the probe could not run.
fn run_filtered_probe(allow: &[String], probed: &[String]) -> Option<Vec<String>> {
    if !cmd_on_path("systemd-run") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let unit = format!(
        "ghost-egress-{}.service",
        crate::atomic::random_hex(4).unwrap_or_default()
    );
    // Same properties as units::render_unit, plus the service's own
    // exceptions: the probe must match the enforcement the service gets.
    // Hostnames resolve first — IPAddressAllow= would reject them and
    // systemd-run would fail before a single beat runs.
    let allow_refs: Vec<&str> = allow.iter().map(String::as_str).collect();
    let allow_ips = resolve_egress_hosts(&allow_refs).ok()?;
    let mut allow_prop = String::from("--property=IPAddressAllow=127.0.0.1 ::1");
    for h in &allow_ips {
        allow_prop.push(' ');
        allow_prop.push_str(h);
    }
    let argv: Vec<String> = vec![
        "systemd-run".into(),
        "--user".into(),
        "--wait".into(),
        "--pipe".into(),
        "--collect".into(),
        "--unit".into(),
        unit,
        "--property=IPAddressDeny=any".into(),
        allow_prop,
        "--property=RuntimeMaxSec=180".into(),
        "--".into(),
        exe.to_string_lossy().into_owned(),
        "__egress-probe".into(),
        "--hosts".into(),
        probed.join(","),
    ];
    // Probe stdout carries the verdict; stderr carries systemd-run diagnostics
    // we do not parse but keep for debugging.
    let (_, stdout, _) = run_timed(&argv, PROBE_WAIT).ok()?;
    Some(stdout.lines().map(str::to_string).collect())
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
    fn interpret_probe_reads_beats_honestly() {
        let lines = |ls: &[&str]| ls.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Control blocked, allowed open → enforced.
        let r = interpret_probe(
            &lines(&[
                "loopback: ok",
                "host api.github.com: blocked",
                "host a.example.com: open",
            ]),
            Some("api.github.com".into()),
            &["a.example.com".into()],
        );
        assert_eq!(r.verdict, EgressVerdict::Enforced);
        // Control open → filter unenforced, whatever else says.
        let r = interpret_probe(
            &lines(&[
                "loopback: ok",
                "host api.github.com: open",
                "host a.example.com: open",
            ]),
            Some("api.github.com".into()),
            &["a.example.com".into()],
        );
        assert_eq!(r.verdict, EgressVerdict::Open);
        // Allowed host unreachable → unverified, never "locked".
        let r = interpret_probe(
            &lines(&[
                "loopback: ok",
                "host api.github.com: blocked",
                "host a.example.com: failed(timeout)",
            ]),
            Some("api.github.com".into()),
            &["a.example.com".into()],
        );
        assert_eq!(r.verdict, EgressVerdict::ProbeFailed);
        // No loopback → failed even if everything else is perfect.
        let r = interpret_probe(
            &lines(&["loopback: failed", "host api.github.com: blocked"]),
            Some("api.github.com".into()),
            &[],
        );
        assert_eq!(r.verdict, EgressVerdict::ProbeFailed);
        // Garbage lines are ignored, missing beats read as failed(missing).
        let r = interpret_probe(
            &lines(&["loopback: ok", "host api.github.com: blocked", "noise"]),
            Some("api.github.com".into()),
            &["gone.example.com".into()],
        );
        assert_eq!(r.verdict, EgressVerdict::ProbeFailed);
    }

    /// Literals pass through, names resolve (A + AAAA), the output is
    /// deduped and sorted — the shape systemd's IPAddressAllow= needs.
    #[test]
    fn resolve_passes_literals_and_resolves_names() {
        let out = resolve_with(&["1.1.1.1", "a.example.com"], |h| {
            assert_eq!(h, "a.example.com", "literals must not hit the resolver");
            Ok(vec![
                "93.184.216.34".parse().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            ])
        })
        .unwrap();
        assert_eq!(
            out,
            vec![
                "1.1.1.1",
                "2606:2800:220:1:248:1893:25c8:1946",
                "93.184.216.34"
            ]
        );
        // Duplicates across hosts collapse.
        let out = resolve_with(&["a.example.com", "b.example.com", "93.184.216.34"], |_| {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        })
        .unwrap();
        assert_eq!(out, vec!["93.184.216.34"]);
        // Empty list keeps the deny-all (no addresses, no error).
        assert_eq!(
            resolve_with(&[], |_| unreachable!()).unwrap(),
            Vec::<String>::new()
        );
    }

    /// One bad name fails the whole call, naming the host — a silently
    /// dropped exception would change the filter the service actually gets.
    #[test]
    fn resolve_fails_closed_and_names_the_host() {
        let err = resolve_with(&["1.1.1.1", "gone.example.com"], |h| {
            if h == "gone.example.com" {
                Err("nxdomain".into())
            } else {
                Ok(vec![])
            }
        })
        .unwrap_err();
        assert_eq!(err, "gone.example.com: nxdomain");
        let err = resolve_with(&["void.example.com"], |_| Ok(vec![])).unwrap_err();
        assert_eq!(err, "void.example.com: resolved to no addresses");
    }

    #[test]
    fn host_status_roundtrips_through_labels() {
        for s in [
            HostStatus::Open,
            HostStatus::Blocked,
            HostStatus::Failed("dns".into()),
        ] {
            assert_eq!(HostStatus::parse(&s.label()), Some(s));
        }
        assert_eq!(HostStatus::parse("weird"), None);
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
