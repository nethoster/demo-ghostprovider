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
/// that never serves (seen live: searxng crash-looped on a stale
/// `SEARXNG_SETTINGS_PATH` drop-in while the deploy printed `done: ok`).
/// The deploy flow calls this after `wait_until_active`, so `done: ok` /
/// `listening on` only print when the port really answers.
pub fn wait_until_port_open(port: u16, budget: std::time::Duration) -> bool {
    use std::net::{IpAddr, SocketAddr, TcpStream};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let deadline = std::time::Instant::now() + budget;
    loop {
        if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
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
