//! Network transparency — the anti-"black box" core.
//!
//! Guarantees enforced here (and asserted by tests):
//!
//! 1. `ALLOWED_ENDPOINTS` is the complete list of remote hosts this program
//!    can ever contact over HTTP(S). The HTTP client denies everything else
//!    *before* opening a connection.
//! 2. Every outbound request attempt (success or failure) is appended to a
//!    local log file (`~/.local/state/demo-ghostprovider/net.log`) and to an
//!    in-session registry queryable via `--show-endpoints`.
//! 3. There is no runtime configuration and no code loading from the network.
//!    Only repository *data* of the service being deployed moves.
//!
//! Build-time package registries (npm, PyPI, proxy.golang.org) are contacted by
//! the *downloader tool* of the deployed services during the host-side prefetch
//! phase (before the sandboxed build), not by this binary; that distinction is
//! documented in README ("Security model"). See `src/hoster/prefetch.rs`.
//!
//! The one exception is the VERT recipe's two paraglide-js plugin modules from
//! `cdn.jsdelivr.net`: those ARE fetched by this binary, through the same
//! allowlisted client (so the host is a permitted, net.log-visible endpoint)
//! and are additionally pinned by content SHA-256 at the recipe level. They
//! execute inside the offline sandboxed build like any other dependency, but
//! never from silently drifted bytes. See `prefetch.rs::seed_paraglide_plugins`.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::time::SystemTime;

/// Hosts this binary may contact. Keep in sync with README "Security model";
/// `allowed_endpoints_match_security_model` pins the exact contents, so
/// adding a host without updating docs fails CI.
///
/// `codeload.github.com` is reachable only as the *redirect target* of
/// `github.com/<owner>/<repo>/archive/*` downloads (the tarball fallback
/// used when git is unavailable). The HTTP client re-checks the allowlist on
/// every redirect hop, so this entry is not a bypass — it is the explicit,
/// net.log-visible permit for a host the GitHub archive flow genuinely
/// needs.
///
/// `proxy.golang.org` + `storage.googleapis.com` exist for one purpose only:
/// seeding the Go toolchain module into a local `file://` GOPROXY before a
/// sandboxed build (`src/hoster/goenv.rs`), so a throttled link does not
/// re-transfer the ~75 MiB zip on every deploy. `storage.googleapis.com` is
/// the signed-URL redirect target of `proxy.golang.org` downloads. Every hop
/// (this one included) is allowlist-gated and net.log-recorded like any
/// other, and the fetched bytes are re-verified by `go` against its checksum
/// database before extraction runs — this path only saves bytes, never
/// trusts them.
///
/// `cdn.jsdelivr.net` is the CDN for the two paraglide-js *plugin* modules
/// the VERT recipe pre-seeds into `project.inlang/cache/plugins` (see
/// `prefetch.rs::seed_paraglide_plugins`). Unlike the shell prefetch steps,
/// that fetch runs inside this binary — through the allowlisted client, so
/// the permit is net.log-visible — and the content is additionally pinned by
/// content SHA-256 at the recipe level: the CDN can only ever serve
/// byte-identical plugin bytes, never a silent surprise.
///
/// `release-assets.githubusercontent.com` + `dl.google.com` serve the pinned
/// build-tool downloads (`toolbox.rs`): GitHub's signed-URL redirect target
/// for bun/pnpm release assets, and the Go release tarballs. Both are gated
/// like every other hop — the permit is explicit because the pinned asset
/// fetch needs it — and the bytes are additionally SHA-256 verified against
/// `toolbox.rs::TOOLBOX_PINS` before a single executable is placed. These
/// fetches are an alternative to a manually installed tool, never a bypass of
/// the shadowed offline build (which still has no network).
///
/// `cloudflare-dns.com` is the DNS-over-HTTPS *bootstrap* used by
/// `hoster/resolver.rs` only when the system resolver fails (broken TUN/VPN
/// DNS, `EAI_AGAIN` storms). It is a pure DNS transport, served by pinned
/// anycast IPs — it never carries application data, every lookup is recorded
/// in net.log like any other hop, and the resulting addresses are then used
/// only by the regular allowlist-gated client. The permit is explicit because
/// a raw DoH socket bypasses `ensure_allowed` by construction.
pub const ALLOWED_ENDPOINTS: &[&str] = &[
    "api.github.com",
    "cdn.jsdelivr.net",
    "cloudflare-dns.com",
    "dl.google.com",
    "github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
    "proxy.golang.org",
    "storage.googleapis.com",
];

/// Hosts treated as loopback. Allowed only for *local health checks*
/// (verifying a deployed service responds), never for API calls.
pub const LOCAL_ENDPOINTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub at: SystemTime,
    pub host: String,
    pub path: String,
    pub outcome: Result<u16, String>, // status code or error text
}

struct Registry {
    records: Vec<RequestRecord>,
    file: Option<std::path::PathBuf>,
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

/// True when the user disabled on-disk network logging
/// (`GHOSTPROVIDER_NO_NETLOG=1`). Accepts the same truthy values as the
/// sandbox opt-out so both flags parse identically. The lost guarantee is a
/// security-relevant fact and must be surfaced (TUI/deploy status), never
/// silent.
pub fn logging_disabled() -> bool {
    crate::flags::env_flag("GHOSTPROVIDER_NO_NETLOG")
}

/// Cap the in-memory request registry: a long-lived session (or a busy retry
/// loop) must never grow this without bound. On-disk rotation (`net.log`) keeps
/// the file small; this keeps the residency small too. When the cap is hit we
/// drop the oldest quarter rather than one record at a time, to stay O(1)
/// amortized.
const MAX_IN_MEMORY_RECORDS: usize = 4_096;

fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    // Never abort the whole process just because one poisoned thread took the
    // registry down with it: recover the inner state and keep auditing.
    let mut guard = REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let reg = guard.get_or_insert_with(|| Registry {
        records: Vec::new(),
        file: if logging_disabled() {
            None
        } else {
            Some(crate::paths::netlog_file())
        },
    });
    f(reg)
}

/// A single net.log may grow without bound over a long-lived session; rotate
/// at this size so the live file stays small and greppable. The rotated
/// archive keeps the same 0600 mode (a rotating rename of an opaque file).
const ROTATE_BYTES: u64 = 1024 * 1024;

fn append_to_file(file: &std::path::Path, line: &str) {
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Rotate before appending: once the log exceeds the cap, move it aside to
    // `<name>.1` so the live file restarts small. Best-effort — a failed
    // rename (e.g. a stale `.1` from an interrupted run) degrades to appending
    // to the current file rather than dropping the record.
    if std::fs::metadata(file).map(|m| m.len()).unwrap_or(0) >= ROTATE_BYTES {
        let rotated = rotated_path(file);
        let _ = std::fs::rename(file, &rotated);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&rotated, std::fs::Permissions::from_mode(0o600));
        }
    }
    // mode 0600: the log traces every outbound request host+path — a privacy
    // record other local users must not read. Enforced on every append (not
    // only at creation): a pre-existing permissive net.log from an older
    // version is tightened in place, before anything is written to it.
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(file) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600));
        }
        let _ = writeln!(f, "{line}");
    }
}

/// `<dir>/net.log` → `<dir>/net.log.1`
fn rotated_path(file: &std::path::Path) -> std::path::PathBuf {
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    file.with_file_name(name)
}

/// Record one outbound attempt. Called by the HTTP client *and* by the local
/// health checker so the log shows every socket this process opened.
pub fn record(host: &str, path: &str, outcome: Result<u16, String>) {
    let rec = RequestRecord {
        at: SystemTime::now(),
        host: host.to_string(),
        path: path.to_string(),
        outcome,
    };
    let line = format!(
        "{} {} {} {}",
        humantime_millis(rec.at),
        rec.host,
        rec.path,
        match &rec.outcome {
            Ok(code) => format!("HTTP {code}"),
            Err(e) => format!("ERR {e}"),
        }
    );
    with_registry(|reg| {
        if reg.records.len() >= MAX_IN_MEMORY_RECORDS {
            let drop = reg.records.len().saturating_sub(MAX_IN_MEMORY_RECORDS / 4);
            reg.records.drain(0..drop);
        }
        reg.records.push(rec);
        if let Some(file) = &reg.file {
            append_to_file(file, &line);
        }
    });
}

/// Compact UTC timestamp without pulling chrono: YYYY-MM-DDTHH:MM:SS.mmmZ
pub(crate) fn format_utc(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let ms = d.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, dd) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn humantime_millis(t: SystemTime) -> String {
    format_utc(t)
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// True when `host` may be contacted for remote (non-local) requests.
pub fn is_allowed_host(host: &str) -> bool {
    ALLOWED_ENDPOINTS.contains(&host.to_ascii_lowercase().as_str())
}

/// True when `host` is a loopback address usable for health checks.
pub fn is_local_host(host: &str) -> bool {
    LOCAL_ENDPOINTS.contains(&host.to_ascii_lowercase().as_str())
}

/// Summary for `--show-endpoints`: per-host request counters this session.
pub fn session_summary() -> BTreeMap<String, (usize, usize)> {
    // host -> (total, errors)
    with_registry(|reg| {
        let mut map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for r in &reg.records {
            let e = map.entry(r.host.clone()).or_insert((0, 0));
            e.0 += 1;
            if r.outcome.is_err() || matches!(r.outcome, Ok(c) if c >= 400) {
                e.1 += 1;
            }
        }
        map
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_endpoints_match_security_model() {
        // Pins the allowlist against README's documented set. Any change to
        // ALLOWED_ENDPOINTS must update both — otherwise this test fails.
        assert_eq!(
            ALLOWED_ENDPOINTS,
            &[
                "api.github.com",
                "cdn.jsdelivr.net",
                "cloudflare-dns.com",
                "dl.google.com",
                "github.com",
                "raw.githubusercontent.com",
                "codeload.github.com",
                "release-assets.githubusercontent.com",
                "proxy.golang.org",
                "storage.googleapis.com"
            ],
            "allowlist changed — keep the docs in netlog.rs and \
             tests/pin_allowlist.rs in sync in the same commit"
        );
    }

    #[test]
    fn host_checks() {
        assert!(is_allowed_host("api.github.com"));
        assert!(is_allowed_host("API.GitHub.COM"));
        assert!(!is_allowed_host("evil.example"));
        assert!(!is_allowed_host("github.com.evil.example"));
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("localhost"));
        assert!(!is_local_host("api.github.com"));
    }

    #[test]
    fn civil_date_known_values() {
        // 2026-08-23 == days since epoch 20688
        assert_eq!(civil_from_days(20_688), (2026, 8, 23));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn rotated_path_maps_to_sibling_dot_1() {
        let p = std::path::Path::new("/x/net.log");
        assert_eq!(rotated_path(p), std::path::PathBuf::from("/x/net.log.1"));
    }

    #[test]
    fn log_rotates_at_cap() {
        let dir = std::env::temp_dir().join(format!(
            "dgp-netlog-rot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("net.log");

        let big = "x".repeat(ROTATE_BYTES as usize + 64);
        append_to_file(&file, &big); // first write pushes past the cap
        append_to_file(&file, "y"); // second write must rotate the old file
        assert!(file.exists(), "fresh log re-created after rotation");
        assert!(
            rotated_path(&file).exists(),
            "oversized log must be moved to net.log.1"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            if rotated_path(&file).exists() {
                assert_eq!(
                    std::fs::metadata(rotated_path(&file))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
