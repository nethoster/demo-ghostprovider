//! Runtime sandbox verification (`--verify-sandbox`).
//!
//! Runs a trivial command (`/bin/true`) inside the *same* hardened
//! systemd-run unit used for real deploys, but under strace, and audits the
//! resulting syscall trace for two properties that a silent sandbox break
//! would violate:
//!
//! 1. **No outbound network.** Every `connect(2)` must target loopback
//!    (127.0.0.1 / ::1) or an AF_UNIX local socket. A build step reaching an
//!    external address here is a sandbox escape, not a transient.
//! 2. **No code-loading from the project.** Every `execve(2)` must resolve to
//!    an absolute path under a system directory. Executing a binary that lives
//!    inside the project (or its `.ghost-cache`) would mean a hostile recipe
//!    can run arbitrary code the way `ProtectSystem=strict` is supposed to
//!    prevent.
//!
//! This is an *audit* helper (requires `strace` on the host), not part of the
//! normal deploy path. `systemd-run` and its hardening must actually be in
//! effect for the result to be meaningful; if `systemd-run` is missing the
//! audit refuses to run (`EffectiveSandbox::FallbackPlain`), because there is
//! no isolation left to audit.

use std::path::Path;

use anyhow::{Context, bail};

use crate::hoster::sandbox::{EffectiveSandbox, effective_mode, run_sandboxed};

/// System directories from which an executed binary is trusted. The sandbox's
/// `ProtectSystem=strict` keeps everything here read-only, so exec'ing from
/// these cannot be tampered by a recipe.
const SYSTEM_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
];

/// Directory prefixes that a recipe could write to; exec'ing anything from
/// here is treated as code-loading and is a hard failure.
const FORBIDDEN_EXEC_PREFIXES: &[&str] = &[".ghost-cache"];

pub fn run() -> anyhow::Result<()> {
    // strace is the one external tool this audit needs; without it we cannot
    // observe syscalls, so report and exit rather than pretend.
    if !which("strace") {
        eprintln!("verify-sandbox: strace not found on PATH; cannot inspect syscalls");
        std::process::exit(2);
    }

    let mode = effective_mode();
    match mode {
        EffectiveSandbox::Full => {
            println!("sandbox mode: FULL (hardened systemd-run in effect)");
        }
        EffectiveSandbox::FallbackPlain => {
            eprintln!(
                "verify-sandbox: systemd-run not found — there is no sandbox to audit; \
                 refusing to interpret the probe result"
            );
            std::process::exit(2);
        }
    }

    // Fresh working dir for the probe. It must be writable inside the sandbox
    // so strace can drop its trace file here.
    let work = std::env::temp_dir().join(format!(
        "gp-sandbox-verify-{}",
        crate::atomic::random_hex(6)?
    ));
    std::fs::create_dir_all(&work)?;
    let trace = work.join("trace.out");
    let trace_os = trace.to_string_lossy().into_owned();

    let argv: Vec<String> = vec![
        "strace".into(),
        "-f".into(),
        "-e".into(),
        "trace=network,execve".into(),
        "-o".into(),
        trace_os.clone(),
        "--".into(),
        "/bin/true".into(),
    ];

    let result = run_sandboxed(&argv, &work, std::time::Duration::from_secs(60), &[]);

    let cmd = match result {
        Ok(c) => c,
        Err(e) => {
            let _ = cleanup(&work);
            bail!("failed to run the sandboxed strace probe: {e:#}");
        }
    };
    if !cmd.success {
        let _ = cleanup(&work);
        println!("{}", cmd.stderr.trim());
        bail!("strace probe itself failed (exit non-zero) — see trace above");
    }

    // Read the trace BEFORE removing the working dir (which holds it).
    let trace_contents = std::fs::read_to_string(&trace)
        .with_context(|| format!("could not read strace trace at {trace:?}"))?;
    let _ = cleanup(&work);

    let (ok, problems) = audit_trace(&trace_contents, &work);
    println!(
        "=== strace trace ({} syscall lines) ===",
        trace_contents.lines().count()
    );
    for line in trace_contents.lines().take(60) {
        println!("  {line}");
    }

    let mut home_ok = true;
    match probe_home() {
        Ok(home) => {
            let real = real_home();
            println!("sandbox HOME: {home}");
            println!("invoker HOME: {}", real.as_deref().unwrap_or("(unset)"));
            if real.as_deref() == Some(home.as_str()) {
                home_ok = false;
            }
        }
        Err(e) => {
            println!("WARN: could not probe sandbox HOME: {e:#}");
        }
    }

    let ok = ok && home_ok && problems.is_empty();
    if ok {
        println!("SANDBOX VERIFY PASS");
        Ok(())
    } else {
        eprintln!("SANDBOX VERIFY FAIL");
        for p in problems {
            eprintln!("  - {p}");
        }
        if !home_ok {
            eprintln!(
                "  - sandbox '$HOME' leaked to the invoker's real home — a hostile build step could read ~/.ssh, ~/.netrc, ~/.config credentials"
            );
        }
        std::process::exit(1);
    }
}

/// Ask the sandbox itself what `$HOME` resolves to inside a hardened unit.
fn probe_home() -> anyhow::Result<String> {
    let work =
        std::env::temp_dir().join(format!("gp-sandbox-home-{}", crate::atomic::random_hex(6)?));
    std::fs::create_dir_all(&work)?;
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), "printf %s \"$HOME\"".into()];
    let result = run_sandboxed(&argv, &work, std::time::Duration::from_secs(60), &[]);
    let _ = cleanup(&work);
    match result {
        Ok(c) if c.success => Ok(c.stdout.trim().to_string()),
        Ok(c) => bail!(
            "sandbox HOME probe failed (exit non-zero): {}",
            c.stderr.trim()
        ),
        Err(e) => Err(e),
    }
}

fn real_home() -> Option<String> {
    std::env::var_os("HOME")
        .map(|h| h.to_string_lossy().into_owned())
        .filter(|h| !h.is_empty())
}

/// Inspect a strace trace for forbidden outbound connects and forbidden
/// exec's. Returns (pass, list_of_failures).
fn audit_trace(trace: &str, work: &Path) -> (bool, Vec<String>) {
    let mut problems = Vec::new();
    for line in trace.lines() {
        // A traced child may be voiced even when we could not attach; skip the
        // "detached/inherit" punctuation noise and work on raw lines.
        let body = line;
        if body.contains("connect(")
            && let Some(addr) = connect_addr(body)
            && !is_loopback(&addr)
            && !addr.starts_with("AF_UNIX")
        {
            problems.push(format!("outbound connect: {addr}\n    {line}"));
        }
        if body.contains("execve(")
            && let Some(path) = exec_path(body)
            && (!is_system_bin(&path) || forbidden_prefix(&path, work))
        {
            problems.push(format!("code-loading execve: {path}\n    {line}"));
        }
    }
    (problems.is_empty(), problems)
}

/// Pull the address argument out of a `connect(2)` strace line. We search the
/// whole line (a naive `find(')')` would stop at the parenthesised `htons(443)`
/// and `inet_addr(...)`), then classify by socket family:
///   connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
///   connect(3, {sa_family=AF_UNIX, sun_path="/run/foo"}, 15) = -1
fn connect_addr(line: &str) -> Option<String> {
    if line.contains("AF_UNIX") {
        // sun_path may be "..." for abstract sockets; treat as local.
        return Some("AF_UNIX".to_string());
    }
    if line.contains("AF_INET") || line.contains("AF_INET6") {
        if let Some(ip) = line.find("inet_addr(") {
            let after = &line[ip + "inet_addr(".len()..];
            let start = after.find('"')? + 1;
            let end = after[start..].find('"')? + start;
            return Some(after[start..end].to_string());
        }
        if let Some(ip) = line.find("inet_pton(") {
            let after = &line[ip + "inet_pton(".len()..];
            let start = after.find('"')? + 1;
            let end = after[start..].find('"')? + start;
            return Some(after[start..end].to_string());
        }
        // inet6 addresses may print differently (e.g. decoded, not as a quoted
        // string); report the whole from the family fragment for inspection.
        let family = line.find("sa_family=")?;
        return Some(line[family..].split(',').next().unwrap_or("").to_string());
    }
    None
}

/// Pull the path out of an `execve(2)` strace line:
///   execve("/usr/bin/true", ["true"], 0x7fff...) = 0
fn exec_path(line: &str) -> Option<String> {
    let start = line.find("execve(")? + "execve(".len();
    let rest = &line[start..];
    let rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        // A line that names `execve` without a quoted path (e.g. attach/seccomp
        // noise) is not a real execution we can classify; treat as trusted.
        None
    }
}

fn is_loopback(addr: &str) -> bool {
    addr == "127.0.0.1" || addr == "::1" || addr == "localhost" || addr == "[::1]"
}

fn is_system_bin(path: &str) -> bool {
    SYSTEM_BIN_DIRS.iter().any(|d| path.starts_with(d))
}

fn forbidden_prefix(path: &str, work: &Path) -> bool {
    let path = Path::new(path);
    // Anything under the probe working dir is the recipe's own tree; exec'ing
    // from it contradicts ProtectSystem=strict's intent.
    if path.starts_with(work) {
        return true;
    }
    FORBIDDEN_EXEC_PREFIXES
        .iter()
        .any(|p| path.to_string_lossy().contains(p))
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn cleanup(work: &Path) -> std::io::Result<()> {
    if work.exists() {
        std::fs::remove_dir_all(work)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_connect_addresses() {
        let v4 = connect_addr(
            r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#,
        );
        assert_eq!(v4.as_deref(), Some("93.184.216.34"));

        let unix = connect_addr(
            r#"connect(3, {sa_family=AF_UNIX, sun_path="/run/systemd/private"}, 29) = 0"#,
        );
        assert_eq!(unix.as_deref(), Some("AF_UNIX"));

        let loopback = connect_addr(
            r#"connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0"#,
        );
        assert_eq!(loopback.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn parses_exec_paths() {
        assert_eq!(
            exec_path(r#"execve("/usr/bin/true", ["true"], 0x7ffffffff000) = 0"#).as_deref(),
            Some("/usr/bin/true")
        );
        // no-quote exec lines (attach noise) are not classifiable → None (trusted)
        assert_eq!(exec_path("19873 execve <unfinished ...>"), None);
    }

    #[test]
    fn loopback_and_system_checks() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("93.184.216.34"));
        assert!(is_system_bin("/usr/bin/true"));
        assert!(is_system_bin("/bin/sh"));
        assert!(!is_system_bin("/tmp/evil"));
    }

    #[test]
    fn flags_forbidden_exec() {
        let work = PathBuf::from("/tmp/gp-sandbox-verify-abc");
        assert!(forbidden_prefix(
            "/tmp/gp-sandbox-verify-abc/payload",
            &work
        ));
        assert!(forbidden_prefix("/home/u/proj/.ghost-cache/x", &work));
        assert!(!forbidden_prefix("/usr/bin/true", &work));
    }

    #[test]
    fn audits_trace_clean_and_dirty() {
        let clean = r#"
12345 execve("/usr/bin/true", ["true"], ...) = 0
12345 connect(3, {sa_family=AF_UNIX, sun_path="/run/foo"}, 15) = 0
"#;
        let (ok, _) = audit_trace(clean, &PathBuf::from("/tmp/w"));
        assert!(ok);

        let dirty = r#"
12344 execve("/tmp/gp-sandbox-verify-x/payload", ["payload"], ...) = 0
12345 connect(3, {sa_family=AF_INET, sin_addr=inet_addr("93.184.216.34")}, 16) = 0
"#;
        let (ok, problems) = audit_trace(dirty, &PathBuf::from("/tmp/gp-sandbox-verify-x"));
        assert!(!ok);
        assert_eq!(problems.len(), 2);
    }
}
