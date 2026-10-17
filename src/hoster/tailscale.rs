//! Tailscale presence and backend state, read locally.
//!
//! Two consumers with deliberately different depths:
//!
//!   * System Scan reports only the boolean presence of the `tailscale`
//!     binary — the report stays useless to attackers (no peer names, no
//!     login state, no status details);
//!   * the Self-Hosting screen probes the daemon and shows whether the
//!     tunnel itself is on (`running`), off (`stopped`) or waiting for a
//!     login — the operator's own TUI, so the full state stays local.
//!
//! Everything here is a local socket call (`tailscale status --json`), never
//! a network fetch, so the netlog transparency policy is untouched.

use std::process::Command;

/// Backend state as reported by `tailscale status --json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleState {
    /// No `tailscale` binary on PATH.
    NotInstalled,
    /// Binary present but `status` failed: tailscaled is not running (or the
    /// socket is unreachable).
    DaemonDown,
    /// tailscaled is up; the node has no login yet.
    NeedsLogin,
    /// tailscaled is up; logged in but the tunnel is not connected.
    Stopped,
    /// tailscaled is up and the tunnel is connected.
    Running { dns_name: String },
}

/// Probe the live state: binary presence, then `tailscale status --json`.
pub fn probe() -> TailscaleState {
    if !crate::hoster::preflight::which("tailscale") {
        return TailscaleState::NotInstalled;
    }
    let Ok(out) = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    else {
        return TailscaleState::DaemonDown;
    };
    if !out.status.success() {
        return TailscaleState::DaemonDown;
    }
    parse_status_json(&String::from_utf8_lossy(&out.stdout))
}

/// Map the status JSON to a [`TailscaleState`]. Pure — fixtures in tests.
///
/// Only the fields this screen needs are read (`BackendState`, `Self.DNSName`).
/// An unparseable body reads as `DaemonDown`: the socket answered but not with
/// the shape we understand, so nothing can be honestly claimed about the
/// tunnel.
pub fn parse_status_json(json: &str) -> TailscaleState {
    let backend = json_field(json, "BackendState").unwrap_or_default();
    match backend.as_str() {
        "Running" => {
            let dns_name = json_field(json, "DNSName")
                .map(|s| s.trim_end_matches('.').to_string())
                .unwrap_or_default();
            TailscaleState::Running { dns_name }
        }
        "NeedsLogin" => TailscaleState::NeedsLogin,
        "Stopped" => TailscaleState::Stopped,
        _ => TailscaleState::DaemonDown,
    }
}

/// First `"key": "value"` string field anywhere in the JSON — enough for the
/// few fields we read, and free of a serde dependency for a local TUI probe.
/// Top-level `BackendState` comes before the `Self` object in tailscale's
/// output; `DNSName` only exists inside `Self`.
fn json_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let idx = json.find(&needle)?;
    let rest = json[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{
  "Version": "1.76.0",
  "BackendState": "Running",
  "Self": {
    "ID": "nodekey:abc",
    "HostName": "devbox",
    "DNSName": "devbox.tailnet-abc.ts.net.",
    "OS": "linux"
  },
  "Peer": {}
}"#;

    const STOPPED: &str = r#"{"Version":"1.76.0","BackendState":"Stopped","Self":{}}"#;

    const NEEDS_LOGIN: &str = r#"{"BackendState":"NeedsLogin","Self":{}}"#;

    #[test]
    fn running_reads_dns_name_without_trailing_dot() {
        assert_eq!(
            parse_status_json(RUNNING),
            TailscaleState::Running {
                dns_name: "devbox.tailnet-abc.ts.net".into()
            }
        );
    }

    #[test]
    fn stopped_and_needs_login_map_directly() {
        assert_eq!(parse_status_json(STOPPED), TailscaleState::Stopped);
        assert_eq!(parse_status_json(NEEDS_LOGIN), TailscaleState::NeedsLogin);
    }

    #[test]
    fn unknown_or_garbled_body_fails_closed_to_daemon_down() {
        assert_eq!(
            parse_status_json("{\"BackendState\":\"NoState\"}"),
            TailscaleState::DaemonDown
        );
        assert_eq!(
            parse_status_json("not json at all"),
            TailscaleState::DaemonDown
        );
        assert_eq!(parse_status_json(""), TailscaleState::DaemonDown);
    }

    #[test]
    fn probe_without_binary_is_not_installed() {
        // This CI/host has no tailscale; the probe must degrade honestly.
        if crate::hoster::preflight::which("tailscale") {
            return;
        }
        assert_eq!(probe(), TailscaleState::NotInstalled);
    }
}
