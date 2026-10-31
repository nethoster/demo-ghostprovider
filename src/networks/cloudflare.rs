//! Cloudflare Quick Tunnel support: binary discovery, argv construction and
//! log/URL parsing. No network of our own lives here; `cloudflared` is an
//! opt-in external agent, never part of the compiled-in HTTP allowlist.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CloudflaredInfo {
    pub path: PathBuf,
    pub version: String,
    pub supports_json_output: bool,
    pub supports_management_diagnostics: bool,
}

/// Probe one explicit binary path. Used by the supervisor (which receives the
/// path from the panel) and by discovery.
pub fn probe_path(path: &Path) -> Result<CloudflaredInfo, String> {
    let out = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|e| format!("cannot run {}: {e}", path.display()))?;
    if !out.status.success() {
        return Err(format!("{} --version failed", path.display()));
    }
    let version_text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let version = version_label(&version_text);

    let help = Command::new(path)
        .args(["tunnel", "--help"])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .ok()
        .map(|h| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&h.stdout),
                String::from_utf8_lossy(&h.stderr)
            )
        })
        .unwrap_or_default();
    Ok(CloudflaredInfo::from_probe(
        path.to_path_buf(),
        version,
        &help,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTarget {
    pub service: String,
    pub port: u16,
}

impl CloudflaredInfo {
    /// Find a usable `cloudflared` without downloading anything. `PATH` first,
    /// then the fixed locations a package manager commonly uses (notably
    /// `/usr/sbin`, which is absent from many non-root interactive `PATH`s).
    pub fn discover() -> Result<Self, String> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                candidates.push(dir.join("cloudflared"));
            }
        }
        for p in [
            "/usr/sbin/cloudflared",
            "/usr/bin/cloudflared",
            "/usr/local/bin/cloudflared",
            "/usr/local/sbin/cloudflared",
            "/opt/homebrew/bin/cloudflared",
            "/snap/bin/cloudflared",
        ] {
            candidates.push(PathBuf::from(p));
        }
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(home).join(".local/bin/cloudflared"));
        }

        let mut seen = std::collections::HashSet::new();
        for candidate in candidates {
            if !seen.insert(candidate.clone()) || !candidate.is_file() {
                continue;
            }
            if let Ok(info) = probe_path(&candidate) {
                return Ok(info);
            }
        }

        Err(
            "cloudflared not found — install it with your package manager \
             (GhostProvider never downloads it), then reopen Networks."
                .into(),
        )
    }

    pub fn from_probe(path: PathBuf, version: String, help: &str) -> Self {
        Self {
            path,
            version,
            supports_json_output: help.contains("--output"),
            supports_management_diagnostics: help.contains("--management-diagnostics"),
        }
    }
}

/// Parse the local URL a user pasted: `http://localhost:8080`,
/// `http://127.0.0.1:8080/`, `localhost:8080`, `127.0.0.1:8080`, or `8080`.
/// Only loopback is accepted; HTTPS is rejected because deployed services are
/// plain HTTP behind the loopback socket.
pub fn parse_local_url(input: &str) -> Result<u16, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("enter the deployed service's local URL".into());
    }

    if raw.bytes().all(|b| b.is_ascii_digit()) {
        return parse_port(raw);
    }
    if raw.starts_with("https://") {
        return Err(
            "use the local http:// URL — deployed services are plain HTTP on loopback".into(),
        );
    }
    let rest = raw.strip_prefix("http://").unwrap_or(raw);
    if rest.contains("://") {
        return Err("unrecognized URL scheme; use http://127.0.0.1:PORT".into());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("").trim();
    if authority.is_empty() {
        return Err("enter the deployed service's local URL".into());
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| "URL must include a port, e.g. http://127.0.0.1:8080".to_string())?;
    if !matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1"
    ) {
        return Err("only loopback URLs are accepted (localhost or 127.0.0.1)".into());
    }
    parse_port(port)
}

fn parse_port(raw: &str) -> Result<u16, String> {
    let port: u16 = raw
        .trim()
        .parse()
        .map_err(|_| "port must be a number between 1 and 65535".to_string())?;
    if port == 0 {
        return Err("port must be a number between 1 and 65535".into());
    }
    Ok(port)
}

/// Find exactly one deployed service whose announced loopback URL uses the
/// pasted port. The user pastes a service's own URL; arbitrary URLs are never
/// proxied.
pub fn match_deployed(
    input: &str,
    services: &[(String, crate::state::ServiceEntry)],
) -> Result<LocalTarget, String> {
    let port = parse_local_url(input)?;
    let mut found = services
        .iter()
        .filter(|(_, entry)| entry_ports(entry).contains(&port));
    let first = found
        .next()
        .ok_or_else(|| format!("no deployed service listens on port {port}"))?;
    if found.next().is_some() {
        return Err(format!(
            "more than one deployed service uses port {port}; select one from the list"
        ));
    }
    Ok(LocalTarget {
        service: first.0.clone(),
        port,
    })
}

fn entry_ports(entry: &crate::state::ServiceEntry) -> Vec<u16> {
    let mut urls: Vec<&String> = entry.urls.iter().collect();
    if urls.is_empty() && !entry.url.is_empty() {
        urls.push(&entry.url);
    }
    urls.into_iter()
        .filter_map(|u| parse_local_url(u).ok())
        .collect()
}

/// Extract the Quick Tunnel URL from a plain or JSON log line. Reserved
/// control hosts (`api.`, `login.`, …) are not quick-tunnel endpoints and are
/// ignored, and only a bare `https://<label>.trycloudflare.com` is accepted.
pub fn parse_quick_tunnel_url(line: &str) -> Option<String> {
    let mut rest = line;
    while let Some(pos) = rest.find("https://") {
        let after = &rest[pos + "https://".len()..];
        let end = after
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '\\' | ')' | ']' | '}' | ',' | ';' | '<' | '>'
                    )
            })
            .unwrap_or(after.len());
        let candidate = after[..end].trim_end_matches(['.', ':', '!', '?']);
        if let Some(url) = validate_quick_host(candidate) {
            return Some(url);
        }
        rest = &after[end..];
    }
    None
}

fn validate_quick_host(candidate: &str) -> Option<String> {
    if candidate.is_empty()
        || candidate.contains(['/', '?', '#', '@', ':'])
        || !candidate.is_ascii()
    {
        return None;
    }
    let host = candidate.to_ascii_lowercase();
    let label = host.strip_suffix(".trycloudflare.com")?;
    if label.is_empty()
        || label.contains('.')
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return None;
    }
    if matches!(label, "api" | "login" | "www" | "dash" | "admin" | "try") {
        return None;
    }
    Some(format!("https://{host}"))
}

/// Build the `cloudflared` argv. Optional flags are only emitted when the
/// installed binary's own `--help` advertised them, so an older release still
/// gets a working Quick Tunnel instead of an unknown-flag failure.
pub fn build_args(info: &CloudflaredInfo, port: u16, label: &str) -> Result<Vec<String>, String> {
    if port == 0 {
        return Err("invalid port".into());
    }
    if label.trim().is_empty() || label.chars().any(char::is_whitespace) {
        return Err("invalid connector label".into());
    }

    let mut args = vec![
        "tunnel".to_string(),
        "--url".to_string(),
        format!("http://127.0.0.1:{port}"),
        "--no-autoupdate".to_string(),
        "--loglevel".to_string(),
        "info".to_string(),
        "--grace-period".to_string(),
        "5s".to_string(),
        "--metrics".to_string(),
        "127.0.0.1:0".to_string(),
        "--label".to_string(),
        label.to_string(),
    ];
    if info.supports_json_output {
        args.push("--output".into());
        args.push("json".into());
    }
    if info.supports_management_diagnostics {
        args.push("--management-diagnostics=false".into());
    }
    Ok(args)
}

/// Pull `2026.10.2` (or similar) out of `cloudflared version …` output.
pub fn version_label(text: &str) -> String {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for (i, token) in tokens.iter().enumerate() {
        if *token == "version"
            && let Some(next) = tokens.get(i + 1)
        {
            return next
                .trim_start_matches('v')
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.')
                .to_string();
        }
    }
    tokens
        .iter()
        .find(|t| t.starts_with(|c: char| c.is_ascii_digit()) && t.contains('.'))
        .map(|t| {
            t.trim_start_matches('v')
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.')
                .to_string()
        })
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[allow(dead_code)]
fn _path_marker(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServiceEntry;

    fn info() -> CloudflaredInfo {
        CloudflaredInfo::from_probe(
            PathBuf::from("/usr/sbin/cloudflared"),
            "2026.10.2".into(),
            "--output value\n--management-diagnostics",
        )
    }

    fn entry(unit: &str, urls: &[&str]) -> ServiceEntry {
        ServiceEntry {
            unit_name: unit.into(),
            project_dir: "/tmp/x".into(),
            url: "https://github.com/example/x".into(),
            urls: urls.iter().map(|u| (*u).to_string()).collect(),
        }
    }

    #[test]
    fn local_url_accepts_loopback_variants() {
        for input in [
            "http://localhost:8080",
            "http://127.0.0.1:8080/",
            "localhost:8080",
            "127.0.0.1:8080",
            "8080",
        ] {
            assert_eq!(parse_local_url(input).unwrap(), 8080, "{input}");
        }
    }

    #[test]
    fn local_url_rejects_non_loopback_and_https() {
        for input in [
            "https://localhost:8080",
            "http://example.com:8080",
            "http://192.168.1.2:8080",
            "localhost",
            "127.0.0.1:0",
            "127.0.0.1:99999",
        ] {
            assert!(parse_local_url(input).is_err(), "{input}");
        }
    }

    #[test]
    fn match_deployed_uses_port_not_arbitrary_urls() {
        let services = vec![
            (
                "memos".to_string(),
                entry("demo-memos", &["http://localhost:3000"]),
            ),
            (
                "blog".to_string(),
                entry("demo-blog", &["http://localhost:8080"]),
            ),
        ];
        assert_eq!(
            match_deployed("http://127.0.0.1:3000", &services).unwrap(),
            LocalTarget {
                service: "memos".into(),
                port: 3000
            }
        );
        assert!(match_deployed("http://127.0.0.1:9999", &services).is_err());
    }

    #[test]
    fn quick_url_parses_plain_json_and_ignores_control_hosts() {
        assert_eq!(
            parse_quick_tunnel_url("INF |  https://quiet-marble-otter.trycloudflare.com  |  "),
            Some("https://quiet-marble-otter.trycloudflare.com".into())
        );
        assert_eq!(
            parse_quick_tunnel_url(
                r#"{"level":"info","msg":"visit https://quiet-marble-otter.trycloudflare.com now"}"#
            ),
            Some("https://quiet-marble-otter.trycloudflare.com".into())
        );
        assert_eq!(
            parse_quick_tunnel_url("https://api.trycloudflare.com/v4/foo"),
            None
        );
        assert_eq!(
            parse_quick_tunnel_url("https://login.trycloudflare.com"),
            None
        );
        assert_eq!(parse_quick_tunnel_url("https://example.com"), None);
    }

    #[test]
    fn quick_url_strips_trailing_punctuation_and_accepts_uppercase() {
        assert_eq!(
            parse_quick_tunnel_url("Visit https://QUIET-MARBLE-OTTER.trycloudflare.com."),
            Some("https://quiet-marble-otter.trycloudflare.com".into())
        );
        assert_eq!(
            parse_quick_tunnel_url("(https://a-b.trycloudflare.com)"),
            Some("https://a-b.trycloudflare.com".into())
        );
    }

    #[test]
    fn argv_contains_only_supported_flags() {
        let args = build_args(&info(), 8080, "demo-ghostprovider-x-abc").unwrap();
        assert!(
            args.windows(2)
                .any(|w| w == ["--url", "http://127.0.0.1:8080"])
        );
        assert!(args.iter().any(|a| a == "--output"));
        assert!(args.iter().any(|a| a == "--management-diagnostics=false"));
        assert!(!args.iter().any(|a| a == "--allowed-mail"));

        let bare = CloudflaredInfo::from_probe(
            PathBuf::from("/usr/bin/cloudflared"),
            "2024.1.0".into(),
            "",
        );
        let args = build_args(&bare, 3000, "label").unwrap();
        assert!(!args.iter().any(|a| a == "--output"));
        assert!(!args.iter().any(|a| a == "--management-diagnostics=false"));
    }

    #[test]
    fn version_label_extracts_token() {
        assert_eq!(
            version_label("cloudflared version 2026.10.2 (built 20261020)"),
            "2026.10.2"
        );
        assert_eq!(version_label("nonsense"), "unknown");
    }
}
