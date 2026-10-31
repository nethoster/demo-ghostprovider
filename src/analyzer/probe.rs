//! System probing: prerequisite checks and a bare map of occupied ports.
//!
//! Privacy policy: this report must stay useless to attackers. No VPN
//! status details (the one exception is the boolean presence of the
//! `tailscale` binary — no login state, no peers), no HTTP probing of local
//! services — the port table names only what `ss` itself already shows to
//! the local user.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::process::Command;
use std::time::Duration;

use super::models::{AnalysisResult, InterfaceInfo, ListeningPort};

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

fn detect_interfaces() -> Vec<InterfaceInfo> {
    let Ok(out) = Command::new("ip").args(["-br", "addr", "show"]).output() else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            let name = parts[0].to_string();
            let status = if parts[1] == "UP" || parts[1] == "UNKNOWN" {
                "up"
            } else {
                "down"
            }
            .to_string();
            let ip_info = parts.get(2).copied().unwrap_or("");
            let ip = ip_info.split('/').next().unwrap_or("").to_string();
            let netmask = format!("/{}", ip_info.split('/').nth(1).unwrap_or(""));
            Some(InterfaceInfo {
                name,
                ip,
                netmask,
                status,
            })
        })
        .collect()
}

/// Allowlisted, net.log-recorded network probe: an HTTPS GET to github.com
/// (the host every fetch in this tool actually needs). Deliberately NOT
/// ICMP ping or raw DNS resolution — those would be outbound contacts the
/// transparency guarantees do not cover.
fn https_probe_ok() -> bool {
    crate::hoster::httpclient::get_text("https://github.com/").is_ok()
}

/// Parse one `ss -tlnp` data row.
///
/// Owner attribution never happens here — a bare port/address pair only.
/// Which service owns a port is resolved exclusively from local state.json
/// (deployments made via this panel), never from `ss`.
pub fn parse_ss_row(line: &str) -> Option<ListeningPort> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let addr_port = parts[3];
    let (_, port_str) = addr_port.rsplit_once(':')?;
    let port = port_str.parse().ok()?;
    Some(ListeningPort {
        port,
        address: addr_port.to_string(),
    })
}

/// All TCP listeners, both address families.
///
/// Deployed services frequently bind an IPv6 wildcard (`*:port`, accepting
/// v4-mapped connections) — filtering with `-4` silently hid exactly the
/// ports this panel had assigned. No family filter, ever.
fn detect_listening_ports() -> Vec<ListeningPort> {
    let Ok(out) = Command::new("ss").args(["-tlnp"]).output() else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(parse_ss_row)
        .collect()
}

fn get_gateway() -> String {
    let Ok(out) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    else {
        return String::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .to_string()
}

fn get_dns() -> Vec<String> {
    let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") else {
        return vec![];
    };
    content
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver ").map(|s| s.trim().to_string()))
        .collect()
}

/// Run the full local analysis.
pub fn run_analysis() -> AnalysisResult {
    let interfaces = detect_interfaces();
    let ports = detect_listening_ports();

    let localhost_ok = [80u16, 8080].iter().any(|p| {
        TcpStream::connect_timeout(
            &SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, *p)),
            Duration::from_secs(2),
        )
        .is_ok()
    });

    let mut result = AnalysisResult {
        systemd: which("systemctl"),
        systemd_nspawn: which("systemd-nspawn"),
        git: which("git"),
        python3: which("python3"),
        node: which("node"),
        localhost: localhost_ok,
        // Everything this tool fetches lives behind github.com, so a
        // reachable github.com is the honest definition of "network".
        network: https_probe_ok(),
        // Presence only — the scan never reports login state or peers; that
        // detail lives in the local Self-Hosting screen (hoster::tailscale).
        tailscale: which("tailscale"),
        cloudflared: which("cloudflared"),
        interfaces,
        listening_ports: ports,
        gateway: get_gateway(),
        dns: get_dns(),
        errors: vec![],
    };

    if !result.systemd {
        result
            .errors
            .push("systemd not found — required for service management".into());
    }
    if !result.systemd_nspawn {
        result
            .errors
            .push("systemd-nspawn not found — recommended for isolated hosting".into());
    }
    if !result.git {
        result
            .errors
            .push("Git not found — cannot clone repositories".into());
    }
    if !result.network {
        result
            .errors
            .push("No network — cannot fetch remote repositories".into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_row_parses_bare_port_and_address() {
        let line = "LISTEN 0      128        0.0.0.0:5222       0.0.0.0:*    users:((\"socat\",pid=1234,fd=5))";
        let p = parse_ss_row(line).expect("parses");
        assert_eq!(p.port, 5222);
        assert_eq!(p.address, "0.0.0.0:5222");
    }

    /// Deployed services usually bind an IPv6 wildcard; such rows are the
    /// whole point of the port table and must parse.
    #[test]
    fn ss_row_ipv6_wildcard_is_parsed() {
        let line = "LISTEN 0      4096       *:23920             *:*    users:((\"ghost-server\",pid=692739,fd=9))";
        let p = parse_ss_row(line).expect("parses");
        assert_eq!(p.port, 23920);
        assert_eq!(p.address, "*:23920");

        let bracketed = "LISTEN 0 4096 [::]:8080 [::]:* users:((\"node\",pid=1,fd=7))";
        let p = parse_ss_row(bracketed).expect("parses");
        assert_eq!(p.port, 8080);
    }

    /// Sockets owned by other users parse the same way — no owner data is
    /// ever recorded for foreign listeners.
    #[test]
    fn ss_row_without_owner_still_yields_port() {
        let line = "LISTEN 0      200        127.0.0.1:5432       0.0.0.0:*";
        let p = parse_ss_row(line).expect("parses");
        assert_eq!(p.port, 5432);
        assert_eq!(p.address, "127.0.0.1:5432");
    }

    #[test]
    fn ss_row_garbage_is_rejected() {
        assert!(parse_ss_row("").is_none());
        assert!(parse_ss_row("State Recv-Q Send-Q").is_none());
        assert!(parse_ss_row("LISTEN 0 0 notaport 0.0.0.0:*").is_none());
    }
}
