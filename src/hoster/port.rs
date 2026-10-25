//! Free TCP port selection by *actually binding*.
//!
//! The Python original probed ports with `connect_ex`, which (a) races
//! (TOCTOU) and (b) misses listeners on other interfaces. Here we bind the
//! socket for real; the inherent close→service-bind race window is the same
//! as any ephemeral-port allocator and is documented in README.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

/// Draw a fresh scan-offset seed from `/dev/urandom`: time+pid is guessable
/// (an observer that knows the panel's PID can predict the range), and the
/// port is part of the runtime surface. No rand crate is needed — one 8-byte
/// read. The clock+pid fallback only triggers on filesystems without urandom.
fn random_seed() -> u64 {
    let mut buf = [0u8; 8];
    let random = (|| -> std::io::Result<()> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
        Ok(())
    })();
    if random.is_ok() {
        return u64::from_ne_bytes(buf);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ d.as_secs() as u32)
        .unwrap_or(0);
    (nanos as u64) ^ ((std::process::id() as u64) << 32)
}

/// Find an available loopback port.
///
/// * `start == 0` — pick a random port in `[8000, 30000)` to avoid colliding
///   with commonly used fixed ports.
/// * `start > 0` — scan `[start, start + max_tries)`.
pub fn find_free_port(start: u16, max_tries: u16) -> anyhow::Result<u16> {
    let mut start = start;
    if start == 0 {
        start = 8000 + (random_seed() % 22_000) as u16;
    }

    for port in start..start.saturating_add(max_tries) {
        if bind_ok(port) {
            return Ok(port);
        }
    }
    anyhow::bail!("no free port found in range {start}-{}", start + max_tries)
}

pub(crate) fn bind_ok(port: u16) -> bool {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    TcpListener::bind(addr).is_ok()
}

/// Poll until something accepts TCP on 127.0.0.1:`port` or `budget` expires.
///
/// `is-active` alone can catch a crash-looping unit (`Restart=always`) in a
/// brief active window between restarts and report success for a service
/// that never serves (seen live: a service crash-looped on a stale
/// settings-path drop-in while the deploy printed `done: ok`).
/// The deploy flow calls this after `wait_until_active`, so `done: ok` /
/// `listening on` only print when the port really answers.
pub fn wait_until_port_open(port: u16, budget: std::time::Duration) -> bool {
    use std::net::{IpAddr, SocketAddr, TcpStream};
    let deadline = std::time::Instant::now() + budget;
    loop {
        for ip in [
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            if TcpStream::connect_timeout(
                &SocketAddr::new(ip, port),
                std::time::Duration::from_millis(400),
            )
            .is_ok()
            {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

/// Poll until a tunnel-style listener on 127.0.0.1:`port` reaches the app.
///
/// Netns deny-all units bind their host port via the `.socket` companion
/// the moment the socket activates — long before the app inside the
/// namespace is listening — so `wait_until_port_open` alone would give a
/// false positive. This probe connects through the shim: the shim closes
/// immediately (EOF) when the app is unreachable inside the namespace, but
/// keeps the connection open once it reached the app. So:
///
///   * `Ok(0)` (EOF) → shim could not reach the app → not ready;
///   * read timeout → connection held open → the shim reached the app →
///     ready (the app may legitimately stay silent until spoken to);
///   * `Ok(n)` → the app greeted → ready.
pub fn wait_until_tunnel_open(port: u16, budget: std::time::Duration) -> bool {
    use std::net::{IpAddr, SocketAddr};
    let deadline = std::time::Instant::now() + budget;
    loop {
        for ip in [
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            if tunnel_ready(SocketAddr::new(ip, port)) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

/// One tunnel probe: connect, then try to read a single byte with a short
/// timeout. EOF means the shim closed (app unreachable); a timeout with the
/// connection still open means the shim reached the app.
fn tunnel_ready(addr: std::net::SocketAddr) -> bool {
    use std::io::{ErrorKind, Read};
    use std::net::TcpStream;
    let Ok(mut s) = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(600)));
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => true,
        Err(_) => false,
    }
}

/// The port a unit's own processes actually listen on, if the expected one
/// is not it: the self-healing half of the healthcheck. The app ignored the
/// assigned `--port`/`PORT` and bound something of its own — instead of
/// rolling back a perfectly live service, we find where it went.
///
/// Attributes listeners strictly by PID (MainPID + the unit's cgroup tree),
/// then proves the port with a real loopback connect — so a neighbour's
/// service can never be adopted.
pub fn discover_unit_port(unit: &str, expected: u16) -> Option<u16> {
    let pids = unit_pids(unit);
    if pids.is_empty() {
        return None;
    }
    let out = std::process::Command::new("ss")
        .args(["-tlnp"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    ss_ports_for_pids(&text, &pids, expected)
        .into_iter()
        .find(|&port| tcp_reachable(port))
}

/// MainPID plus every descendant in the unit's cgroup (children, workers,
/// anything the run command spawned).
fn unit_pids(unit: &str) -> Vec<u32> {
    let show = |prop: &str| -> Option<String> {
        let out = std::process::Command::new("systemctl")
            .args([
                "--user",
                "show",
                &format!("--property={prop}"),
                "--value",
                unit,
            ])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let mut pids = Vec::new();
    if let Some(main) = show("MainPID")
        && let Ok(n) = main.parse::<u32>()
        && n > 0
    {
        pids.push(n);
    }
    if let Some(cg) = show("ControlGroup")
        && !cg.is_empty()
    {
        let base = std::path::Path::new("/sys/fs/cgroup").join(cg.trim_start_matches('/'));
        collect_cgroup_pids(&base, &mut pids);
    }
    pids
}

fn collect_cgroup_pids(dir: &std::path::Path, out: &mut Vec<u32>) {
    if let Ok(text) = std::fs::read_to_string(dir.join("cgroup.procs")) {
        for l in text.lines() {
            if let Ok(p) = l.trim().parse::<u32>()
                && p > 0
                && !out.contains(&p)
            {
                out.push(p);
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                collect_cgroup_pids(&e.path(), out);
            }
        }
    }
}

/// Ports from an `ss -tlnp` dump owned by any of `pids`, never `expected`
/// (the probe already proved that one dead). Pure — testable on fixtures.
fn ss_ports_for_pids(text: &str, pids: &[u32], expected: u16) -> Vec<u16> {
    use crate::analyzer::probe::parse_ss_row;
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let row_pids = pid_list(line);
        if !row_pids.iter().any(|p| pids.contains(p)) {
            continue;
        }
        if let Some(lp) = parse_ss_row(line)
            && lp.port != expected
            && !out.contains(&lp.port)
        {
            out.push(lp.port);
        }
    }
    out
}

/// All `pid=NNN` occurrences in an `ss` row (the `users:(...)` column).
fn pid_list(line: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find("pid=") {
        rest = &rest[i + 4..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        if let Ok(p) = digits.parse::<u32>() {
            out.push(p);
        }
    }
    out
}

/// One real connect on both loopback families — the same proof the
/// healthcheck applies, kept short (this only runs on the failure path).
fn tcp_reachable(port: u16) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
    let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let short = std::time::Duration::from_millis(400);
    if TcpStream::connect_timeout(&v4, short).is_ok() {
        return true;
    }
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    TcpStream::connect_timeout(&v6, short).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_bindable_port() {
        let p = find_free_port(0, 50).unwrap();
        assert!((8000..30000).contains(&p));
        // Port was released before returning; must be re-bindable.
        assert!(bind_ok(p));
    }

    #[test]
    fn skips_occupied_port() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        let p = find_free_port(taken, 5).unwrap();
        assert_ne!(p, taken);
    }

    #[test]
    fn random_seed_is_urandom_drawn() {
        // Two consecutive draws are equal only with probability 2^-64; if
        // urandom is broken/unavailable the fallback still returns in-range.
        assert_ne!(random_seed(), random_seed());
    }

    /// Fixture of a real `ss -tlnp` dump: only rows owned by the unit's
    /// pids count, `expected` is excluded, neighbours never leak in.
    #[test]
    fn ss_ports_are_attributed_by_pid_only() {
        let text = "\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:9412      0.0.0.0:*          users:((\"app\",pid=1234,fd=18))
LISTEN 0      4096         *:8081               *:*          users:((\"other\",pid=9999,fd=7))
LISTEN 0      4096   127.0.0.1:5555      0.0.0.0:*          users:((\"child\",pid=42,fd=4))
LISTEN 0      4096   127.0.0.1:7777      0.0.0.0:*          users:((\"app\",pid=1234,fd=5))
";
        // 1234 (unit main) + 42 (its child); 9999 belongs to a neighbour;
        // 7777 is the expected (already-probed-dead) port.
        let got = ss_ports_for_pids(text, &[1234, 42], 7777);
        assert_eq!(got, vec![9412, 5555], "own pids only, no expected, no 8081");
    }

    #[test]
    fn pid_list_finds_every_pid_in_a_row() {
        let line = "users:((\"a\",pid=12,fd=3),(\"b\",pid=3400,fd=4))";
        assert_eq!(pid_list(line), vec![12, 3400]);
        assert!(pid_list("no pids here").is_empty());
        // Degenerate "pid=" with no digits must not loop forever.
        assert!(pid_list("pid= and pid=17").contains(&17));
    }

    #[test]
    fn discovery_on_a_missing_unit_is_none() {
        assert_eq!(discover_unit_port("definitely-not-a-unit-xyz", 1), None);
    }

    #[test]
    fn port_open_poll_sees_a_listener() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(wait_until_port_open(
            port,
            std::time::Duration::from_secs(5)
        ));
    }

    #[test]
    fn port_open_poll_times_out_on_a_closed_port() {
        // Bind-then-drop to obtain a port that is very likely closed.
        let port = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(!wait_until_port_open(
            port,
            std::time::Duration::from_millis(600)
        ));
    }
}
