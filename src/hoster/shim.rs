//! `__egress-shim` — socket-activation front for netns-isolated services.
//!
//! Deny-all units run with `PrivateNetwork=yes` (a real network namespace
//! with no route out) and receive the host-side listening socket from the
//! companion `.socket` unit as fd 3 (`LISTEN_FDS` handshake). This shim is
//! the unit's main process: it spawns the real application inside the
//! namespace and forwards every accepted host connection to the app's
//! loopback listener. The application never changes — it still binds
//! `127.0.0.1:{port}` as if it owned the port; the namespace makes that
//! binding unreachable from the host, and the shim is the only bridge.
//!
//! Exit semantics: when the app exits the shim exits with the same code so
//! `Restart=always` bounces the whole pair. `systemctl stop` kills the
//! cgroup (default `KillMode=control-group`), which reaps both.

#![allow(unsafe_code)] // fd 3 adoption from systemd's LISTEN_FDS handshake

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::Context;

/// Forward one accepted host connection to the app inside the namespace.
/// A refused connect (app not listening yet) drops just this client — the
/// shim stays up and the next connection retries.
fn pump(client: TcpStream, app: SocketAddr) {
    let Ok(server) = TcpStream::connect_timeout(&app, Duration::from_secs(5)) else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let (c2, s2) = match (client.try_clone(), server.try_clone()) {
        (Ok(c), Ok(s)) => (c, s),
        _ => return,
    };
    std::thread::spawn(move || relay(client, server));
    std::thread::spawn(move || relay(s2, c2));
}

/// Copy one direction, then half-close the sink so the peer sees EOF.
fn relay(mut from: TcpStream, mut to: TcpStream) {
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(std::net::Shutdown::Write);
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let sep = args
        .iter()
        .position(|a| a == "--")
        .context("usage: __egress-shim PORT -- CMD [ARGS...]")?;
    let port: u16 = args
        .get(
            sep.checked_sub(1)
                .context("usage: __egress-shim PORT -- CMD")?,
        )
        .context("usage: __egress-shim PORT -- CMD [ARGS...]")?
        .parse()
        .context("PORT must be a number")?;
    let cmd = &args[sep + 1..];
    anyhow::ensure!(
        !cmd.is_empty(),
        "usage: __egress-shim PORT -- CMD [ARGS...]"
    );

    // fd 3 = the first passed socket (systemd LISTEN_FDS convention).
    let fds: u32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    anyhow::ensure!(
        fds >= 1,
        "no socket passed (LISTEN_FDS={fds}) — is the .socket unit active?"
    );

    // SAFETY: fd 3 is handed to us by systemd per the LISTEN_FDS contract
    // (verified above); we take ownership exactly once and never touch it
    // as a raw fd afterwards.
    let listener = unsafe { TcpListener::from_raw_fd(3) };
    listener.set_nonblocking(true).context("listener setup")?;

    let app = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", cmd[0]))?;

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                std::thread::spawn(move || pump(stream, app));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Child exited → propagate the code; systemd restarts both.
                if let Some(status) = child.try_wait()? {
                    std::process::exit(status.code().unwrap_or(1));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
