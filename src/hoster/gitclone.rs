//! Git clone with retries, backoff and tarball fallback.
//!
//! Credentials: `GITHUB_TOKEN`/`GH_TOKEN` (if set) is exposed to git via a
//! temporary GIT_ASKPASS helper so the token never appears in argv
//! (`/proc/PID/cmdline`) or shell history. The helper is 0600 in tmpfs-ish
//! temp dir and removed afterwards.
//!
//! Unsafe is required for `libc::prctl(PR_SET_PDEATHSIG)` in `pre_exec`: it
//! guarantees git-remote-* helpers die with this process instead of leaking
//! a half-open socket. The closure runs only async-signal-safe syscalls.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const CLONE_RETRIES: u32 = 3;
/// Name of the marker (inside a checkout) that records which SHA the tree was
/// materialized from. Written by the raw materializer, read on reuse.
pub const PIN_MARKER_FILE: &str = ".ghost-source-pin";
/// Absolute ceiling for a single `git` invocation. Truly dead HTTPS links
/// abort themselves inside git via `GIT_HTTP_LOW_SPEED_*`; this watchdog is
/// the backstop for the cases git cannot self-detect (pack-protocol stalls,
/// SSH). It is deliberately generous so an alive-but-slow link (e.g. a
/// rate-limited ~8KB/s path to GitHub) is allowed to finish instead of being
/// killed mid-pack.
const CLONE_TIMEOUT: Duration = Duration::from_secs(60 * 90);

/// How long the clone timeout may keep re-issuing SIGKILL to the process
/// group and direct child before giving up on confirming the reap. SIGKILL is
/// deterministic; this only caps a pathological D-state child so the clone
/// path can't park the deploy thread beyond the grace window.
const WATCHDOG_REAP_GRACE: Duration = Duration::from_secs(10);

fn git_env(askpass: Option<&Path>) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    // Stable, honest UA: identify the tool instead of spoofing a browser.
    // HTTP/1.1 is forced: HTTP/2 multiplexed streams get hard-reset by some
    // egress filters/firewalls mid-pack (observed "curl 92 ... stream reset"
    // after a few MB), while a single HTTP/1.1 connection survives the same
    // transfer. Cost is negligible for a depth-1/--single-branch clone.
    env.insert("GIT_CONFIG_COUNT".into(), "2".into());
    env.insert("GIT_CONFIG_KEY_0".into(), "http.userAgent".into());
    env.insert(
        "GIT_CONFIG_VALUE_0".into(),
        format!("demo-ghostprovider/{}", env!("CARGO_PKG_VERSION")),
    );
    env.insert("GIT_CONFIG_KEY_1".into(), "http.version".into());
    env.insert("GIT_CONFIG_VALUE_1".into(), "HTTP/1.1".into());
    env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    // Abort an HTTPS transfer that stalls below 1 byte/s for more than 20s
    // instead of blocking the clone forever. The watchdog in
    // run_git_with_timeout covers everything else (pack protocol, SSH).
    env.insert("GIT_HTTP_LOW_SPEED_LIMIT".into(), "1".into());
    env.insert("GIT_HTTP_LOW_SPEED_TIME".into(), "20".into());
    if let Some(p) = askpass {
        env.insert("GIT_ASKPASS".into(), p.to_string_lossy().into_owned());
    }
    env
}

fn write_askpass() -> anyhow::Result<Option<std::path::PathBuf>> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .filter(|t| !t.is_empty());
    let Some(token) = token else { return Ok(None) };

    // Prefer XDG_RUNTIME_DIR (per-user, 0700, tmpfs) so other local users
    // cannot even enumerate the helper; fall back to /tmp. The file is
    // created with O_EXCL + 0600 — never write-then-chmod through a name an
    // attacker could have predicted and symlinked.
    let parent = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let content = format!("#!/bin/sh\necho '{}'\n", shell_quote(&token));
    for _ in 0..100 {
        let path = parent.join(format!(
            "gp-askpass-{}-{}",
            std::process::id(),
            crate::atomic::random_hex(8).unwrap_or_default()
        ));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = f.write_all(content.as_bytes());
                    return Ok(Some(path));
                }
                Err(_) => continue, // name collision: try another
            }
        }
        #[cfg(not(unix))]
        {
            match std::fs::write(&path, &content) {
                Ok(()) => return Ok(Some(path)),
                Err(_) => continue,
            }
        }
    }
    anyhow::bail!("could not create a unique askpass helper")
}

/// Single-quote for POSIX sh: `'` → `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `remove_dir_all` that survives read-only directories.
///
/// Go's module cache extracts archives with mode 0555 directories; deleting
/// entries inside a directory requires write permission on it, so plain
/// `fs::remove_dir_all` fails halfway through a project tree containing
/// `.ghost-cache/go-mod` and leaves an un-removable husk behind. Walk
/// bottom-up ourselves and add owner-write back before each rmdir.
pub(crate) fn force_remove_all(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        // Writable-parent first: unlinking ANY entry below requires write
        // permission on this directory, so fix the mode before recursing.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = meta.permissions();
            if perms.mode() & 0o300 != 0o300 {
                perms.set_mode(perms.mode() | 0o300); // u+w, u+x
                std::fs::set_permissions(path, perms)?;
            }
        }
        for entry in std::fs::read_dir(path)? {
            force_remove_all(&entry?.path())?;
        }
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

pub struct CloneStatus {
    pub ok: bool,
    pub last_message: String,
}

/// A reusable clone must be intact. An interrupted clone can leave `.git`
/// with a *partial* checkout: the index lists files that never made it to
/// disk, every later build fails far away from the real cause ("no required
/// module provides package …"), and `clone()` happily reports
/// "already cloned" forever. Deleted-but-tracked files ⇒ corrupt.
fn worktree_intact(dest: &Path) -> bool {
    // A real clone has a commit; a tarball-fallback dir only ever gets a
    // bare `git init`, which must not count as reusable.
    let committed = Command::new("git")
        .arg("-C")
        .arg(dest)
        .args(["rev-parse", "--verify", "HEAD"])
        .env_remove("GIT_ASKPASS")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !committed {
        return false;
    }
    let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(dest)
        .args(["ls-files", "--deleted"])
        .env_remove("GIT_ASKPASS")
        .output()
    else {
        return false;
    };
    out.status.success() && String::from_utf8_lossy(&out.stdout).trim().is_empty()
}

/// Clone `url` into `dest`. Returns immediately when the repo already exists.
pub fn clone(url: &str, dest: &Path, pin: Option<&str>) -> CloneStatus {
    if dest.join(".git").is_dir() {
        if worktree_intact(dest) {
            // A reuse is only valid if it honours the same pin. An unpinned
            // legacy checkout (built at branch tip) must not be reused for a
            // now-pinned recipe — that would be exactly the TOFU the pin
            // exists to prevent.
            match (pin, super::rawfetch::pinned_sha(dest)) {
                (Some(want), Some(have)) if want == have => {
                    return CloneStatus {
                        ok: true,
                        last_message: "already cloned (pinned)".into(),
                    };
                }
                (Some(_), Some(_)) => {}
                (Some(_), None) => {}
                (None, _) => {
                    return CloneStatus {
                        ok: true,
                        last_message: "already cloned".into(),
                    };
                }
            }
        }
        let _ = force_remove_all(dest);
    }
    let _ = force_remove_all(dest);

    // Primary strategy: materialize the working tree through api+raw, which
    // works where per-flow throttling makes `git clone` or a codeload tarball
    // crawl for tens of minutes and then die.
    //
    // When a pin is requested the raw path is the ONLY path: it materializes
    // every blob at `raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>`
    // (Fastly, reliable) so the resulting tree is exactly the pinned commit.
    // Falling back to an unpinned git/tarball at branch tip would silently
    // break the pin, so a pinned clone that cannot be materialized fails hard.
    match super::rawfetch::materialize(url, dest, pin) {
        Ok(()) => {
            return CloneStatus {
                ok: true,
                last_message: "source tree download complete".into(),
            };
        }
        Err(e) => {
            eprintln!("source tree download failed: {}", short(&format!("{e:#}")));
            let _ = force_remove_all(dest);
            if pin.is_some() {
                return CloneStatus {
                    ok: false,
                    last_message: format!(
                        "pinned tree materialization failed (no unpinned fallback): {e:#}"
                    ),
                };
            }
        }
    }

    let askpass = match write_askpass() {
        Ok(p) => p,
        Err(e) => {
            return CloneStatus {
                ok: false,
                last_message: format!("askpass setup failed: {e}"),
            };
        }
    };
    let env = git_env(askpass.as_deref());

    let strategies: [Vec<String>; 2] = [
        vec![
            "clone".into(),
            "--depth".into(),
            "1".into(),
            "--single-branch".into(),
            "--no-tags".into(),
            url.into(),
            dest.to_string_lossy().into_owned(),
        ],
        vec![
            "clone".into(),
            "--single-branch".into(),
            url.into(),
            dest.to_string_lossy().into_owned(),
        ],
    ];

    for attempt in 0..CLONE_RETRIES {
        let args = &strategies[(attempt % strategies.len() as u32) as usize];
        match run_git_with_timeout(args, &env, CLONE_TIMEOUT) {
            Some(out) if out.status.success() && dest.join(".git").is_dir() => {
                cleanup_askpass(askpass.as_deref());
                return CloneStatus {
                    ok: true,
                    last_message: "clone complete".into(),
                };
            }
            Some(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let _ = force_remove_all(dest);
                if !err.is_empty() {
                    eprintln!("git error: {}", short(&err));
                }
            }
            None => {
                /* git missing — fall through to tarball */
                break;
            }
        }
        let wait = std::cmp::min(5 * (2u32.pow(attempt)), 60);
        std::thread::sleep(std::time::Duration::from_secs(wait as u64));
    }

    let status = tarball_fallback(url, dest);
    cleanup_askpass(askpass.as_deref());
    status
}

/// The pin a repository was materialized at, if any. `materialize` records a
/// `.ghost-source-pin` marker holding the exact SHA (or the default branch)
/// its tree was fetched from. The deploy path compares this against the
/// recipe's pinned SHA so a reuse or re-clone can never silently serve an
/// unpinned tree.
///
/// No network is touched here: verification is purely local.
pub fn pinned_sha(dir: &Path) -> Option<String> {
    super::rawfetch::pinned_sha(dir)
}

/// Resolve `refname` (a branch or tag name) to the 40-hex SHA it currently
/// points at upstream, via `git ls-remote`. Used when a manifest tracks a
/// branch instead of pinning: the tip is resolved once per deploy, then the
/// deployment proceeds exactly as if that SHA had been pinned — the
/// materializer and the anti-TOFU check only ever see the resolved commit.
pub fn resolve_ref(url: &str, refname: &str) -> anyhow::Result<String> {
    let askpass = write_askpass()?;
    let env = git_env(askpass.as_deref());
    let args = [
        "ls-remote".to_string(),
        url.to_string(),
        format!("refs/heads/{refname}"),
        format!("refs/tags/{refname}"),
        refname.to_string(),
    ];
    let out = run_git_with_timeout(&args, &env, Duration::from_secs(60));
    cleanup_askpass(askpass.as_deref());
    let Some(out) = out else {
        anyhow::bail!("git ls-remote failed to run");
    };
    if !out.status.success() {
        anyhow::bail!(
            "git ls-remote: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    pick_sha(&stdout, refname).ok_or_else(|| anyhow::anyhow!("no ref '{refname}' found upstream"))
}

/// Pure `git ls-remote` stdout parser: prefer the heads match, then a peeled
/// tag (`^{}`), then the tag itself, then a bare refname line. Only 40-hex
/// object ids count.
fn pick_sha(ls_remote_stdout: &str, refname: &str) -> Option<String> {
    let head_ref = format!("refs/heads/{refname}");
    let tag_ref = format!("refs/tags/{refname}");
    let peeled_ref = format!("{tag_ref}^{{}}");
    let (mut head, mut peeled, mut tag, mut bare) = (None, None, None, None);
    for line in ls_remote_stdout.lines() {
        let mut it = line.split_whitespace();
        let (Some(sha), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if name == head_ref {
            head = Some(sha.to_string());
        } else if name == peeled_ref {
            peeled = Some(sha.to_string());
        } else if name == tag_ref {
            tag = Some(sha.to_string());
        } else if name == refname {
            bare = Some(sha.to_string());
        }
    }
    head.or(peeled).or(tag).or(bare)
}

fn tarball_fallback(url: &str, dest: &Path) -> CloneStatus {
    let base = url.trim_end_matches(".git").trim_end_matches('/');
    let candidates = [
        format!("{base}/archive/refs/heads/master.tar.gz"),
        format!("{base}/archive/refs/heads/main.tar.gz"),
    ];
    for tb in candidates {
        // Fetch through the allowlisted client so the download is net.log-accounted
        // and the token stays out of argv (it only ever rides an Authorization
        // header for api.github.com — never for tarball hosts).
        let data = match super::httpclient::get_bytes_slow(&tb) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => continue,
        };
        let tmp = match write_tarball_temp(&data) {
            Some(p) => p,
            None => continue,
        };
        let _ = std::fs::create_dir_all(dest);
        let untar = Command::new("tar")
            .args(["xzf"])
            .arg(&tmp)
            .arg("-C")
            .arg(dest)
            .arg("--strip-components=1")
            .output();
        let _ = std::fs::remove_file(&tmp);
        match untar {
            Ok(o) if o.status.success() => {
                let _ = Command::new("git").arg("init").current_dir(dest).output();
                return CloneStatus {
                    ok: true,
                    last_message: "tarball download complete".into(),
                };
            }
            Ok(_) => {
                let _ = force_remove_all(dest);
                eprintln!("tarball extract failed");
            }
            Err(_) => {}
        }
    }
    CloneStatus {
        ok: false,
        last_message: "all clone strategies failed".into(),
    }
}

/// Write downloaded bytes to a private, unique temp file, refusing to follow
/// a pre-existing symlink (O_EXCL) and never leaving readable leftovers.
fn write_tarball_temp(data: &[u8]) -> Option<std::path::PathBuf> {
    use std::io::Write;
    for _ in 0..100 {
        let path = std::env::temp_dir().join(format!(
            "gp-tarball-{}-{}",
            std::process::id(),
            crate::atomic::random_hex(8).unwrap_or_default()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                let _ = f.write_all(data);
                return Some(path);
            }
        }
        #[cfg(not(unix))]
        {
            if std::fs::write(&path, data).is_ok() {
                return Some(path);
            }
        }
    }
    None
}

fn run_git_with_timeout(
    args: &[String],
    env: &HashMap<String, String>,
    timeout: Duration,
) -> Option<std::process::Output> {
    use std::process::Stdio;
    let mut cmd = Command::new("git");
    cmd.args(args)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group so the kill below takes down git-remote-* helpers
        // too — killing only `git` would leak its helper's half-open socket.
        cmd.process_group(0);
        // If the parent (this process) dies or is hard-killed, the clone must
        // not be orphaned with a half-open stream: SIGKILL it via PDEATHSIG.
        // Unsafe: the closure only issues isolated async-signal-safe syscalls.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let child = cmd.spawn().ok()?;
    Some(run_with_timeout(child, timeout))
}

/// Poll `child` (stdout/stderr piped) until it exits; hard-kill its whole
/// process group when `timeout` elapses first. Killed runs never report
/// success and their piped stderr is still drained so no buffer deadlock or
/// orphan persists.
fn run_with_timeout(mut child: std::process::Child, timeout: Duration) -> std::process::Output {
    let pid = child.id();
    let halt = std::time::Instant::now() + timeout;
    #[cfg(unix)]
    let group = i32::try_from(pid).ok(); // kill(-pid) needs a signed pid
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {}
            Err(_) => break false,
        }
        if std::time::Instant::now() >= halt {
            break true;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if timed_out {
        // The deadline is enforced by SIGKILL, directly (not via an external
        // `kill` binary): first to the whole process group (git-remote-*
        // helpers are in it), then to the direct child as the edge case
        // where the process lives outside the expected group. SIGKILL cannot
        // be caught or ignored, so the reap-confirm loop below exits as soon
        // as the child is gone.
        #[cfg(unix)]
        if let Some(g) = group {
            unsafe {
                libc::kill(g, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        // Re-issue SIGKILL within a grace window until the child is reaped;
        // a delayed runner must never outlive the clone deadline via a
        // missed single-shot kill.
        let grace = std::time::Instant::now() + WATCHDOG_REAP_GRACE;
        while child.try_wait().ok().flatten().is_none() && std::time::Instant::now() < grace {
            #[cfg(unix)]
            if let Some(g) = group {
                unsafe {
                    libc::kill(g, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            std::thread::sleep(Duration::from_millis(50));
        }
        // The child is dead; drain whatever git managed to write so the
        // timeout error carries the real reason (a stalled `git` normally
        // explains itself on stderr).
        use std::io::Read;
        let mut stderr = format!(
            "git timed out after {}s (network stalled?)",
            timeout.as_secs()
        );
        if let Some(err_tail) = child.stderr.take() {
            let mut buf = Vec::new();
            let _ = std::io::BufReader::new(err_tail).read_to_end(&mut buf);
            if !buf.is_empty() {
                stderr.push_str(": ");
                stderr.push_str(&String::from_utf8_lossy(&buf));
            }
        }
        let _ = child.wait();
        return std::process::Output {
            status: exit_failure(),
            stdout: Vec::new(),
            stderr: stderr.into_bytes(),
        };
    }
    child
        .wait_with_output()
        .unwrap_or_else(|e| std::process::Output {
            status: exit_failure(),
            stdout: Vec::new(),
            stderr: format!("{e}").into_bytes(),
        })
}

#[cfg(unix)]
fn exit_failure() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    // 128+SIGKILL mirrors what a shell reports for a killed process.
    std::process::ExitStatus::from_raw(137)
}

#[cfg(not(unix))]
fn exit_failure() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(1)
}

fn cleanup_askpass(path: Option<&std::path::Path>) {
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
}

fn short(s: &str) -> String {
    s.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Reproduces the corrupted-clone scenario: a tracked file that vanished
    /// from the working tree must mark the clone as not intact.
    #[test]
    fn deleted_tracked_file_breaks_intactness() {
        if !which_git() {
            return; // git is an install requirement, but don't fail exotic CI
        }
        let dir = std::env::temp_dir().join(format!("dgp-intact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(git(&dir, &["init", "-q"]));
        std::fs::write(dir.join("go.mod"), "module x\n").unwrap();
        assert!(git(&dir, &["add", "go.mod"]));
        assert!(git(&dir, &["commit", "-q", "-m", "init"]));

        // Intact right after checkout.
        assert!(worktree_intact(&dir));

        // Simulate the interrupted-checkout damage seen in the wild.
        std::fs::remove_file(dir.join("go.mod")).unwrap();
        assert!(!worktree_intact(&dir), "deleted tracked file must fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_repo_is_not_intact() {
        let dir = std::env::temp_dir().join(format!("dgp-intact-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!worktree_intact(&dir));
    }

    /// Go's module cache extracts with mode-0555 directories; plain
    /// remove_dir_all fails on them, force_remove_all must not.
    #[test]
    fn force_remove_handles_readonly_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dgp-ro-rm-{}", std::process::id()));
        let ro = dir.join(".ghost-cache/go-mod/pkg/mod/toolchain");
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::write(ro.join("go"), "binary").unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Precondition: the std helper really chokes on this layout.
        assert!(
            std::fs::remove_dir_all(&dir).is_err(),
            "0555 dir must block std removal"
        );

        assert!(force_remove_all(&dir).is_ok());
        assert!(!dir.exists());
    }

    fn which_git() -> bool {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|dir| dir.join("git").is_file()))
            .unwrap_or(false)
    }

    /// A process that never exits must be killed by the watchdog: quick,
    /// exit status non-success, and the whole process group goes down.
    #[test]
    fn watchdog_kills_hung_process_group() {
        use std::process::Stdio;
        // `cat` with a piped (open) stdin and piped stdout blocks forever
        // waiting for input that never arrives, so it can only ever be
        // released by the watchdog. Unlike `sleep N` it never depends on
        // wall-clock duration or on the runtime's sleep binary. (A null stdin
        // would deliver EOF and make cat exit 0, which is exactly the case
        // we must NOT be testing.)
        let mut cmd = Command::new("cat");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let child = cmd.spawn().unwrap();
        let start = std::time::Instant::now();
        let out = run_with_timeout(child, Duration::from_millis(300));
        assert!(!out.status.success());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "watchdog must fire well before the child would end"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("timed out"),
            "stderr must explain the timeout: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A quick success is untouched by the timeout machinery.
    #[test]
    fn watchdog_passes_fast_success() {
        use std::process::Stdio;
        let cmd = Command::new("echo")
            .arg("ok")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = run_with_timeout(cmd, Duration::from_secs(30));
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    }

    /// The pin marker is written by the materializer and read back by the
    /// deploy path's anti-TOFU check; a missing or mismatched marker must be
    /// reported as `None`/different so a legacy unpinned checkout is never
    /// silently reused for a pinned recipe.
    #[test]
    fn pin_marker_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dgp-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(pinned_sha(&dir), None, "no marker yet");

        std::fs::write(
            dir.join(PIN_MARKER_FILE),
            "5b3da65ea310f98480c5258af97ff4d5c6f9d5b0\n",
        )
        .unwrap();
        assert_eq!(
            pinned_sha(&dir).as_deref(),
            Some("5b3da65ea310f98480c5258af97ff4d5c6f9d5b0"),
            "marker must be read verbatim"
        );

        std::fs::write(dir.join(PIN_MARKER_FILE), "   \n").unwrap();
        assert_eq!(pinned_sha(&dir), None, "blank marker means unpinned");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pick_sha_prefers_head_then_peeled_tag_then_tag_then_bare() {
        let head = "f5ecdec90d52fa84d5204fb59bb8da7d31e3704a";
        let peeled = "1111111111111111111111111111111111111111";
        let tag = "2222222222222222222222222222222222222222";
        let bare = "3333333333333333333333333333333333333333";

        // heads wins over everything.
        let out = format!(
            "{tag}\trefs/tags/main\n{bare}\tmain\n{peeled}\trefs/tags/main^{{}}\n{head}\trefs/heads/main\n"
        );
        assert_eq!(pick_sha(&out, "main").as_deref(), Some(head));

        // Peeled tag beats the lightweight tag and a bare line.
        let out = format!("{tag}\trefs/tags/main\n{peeled}\trefs/tags/main^{{}}\n");
        assert_eq!(pick_sha(&out, "main").as_deref(), Some(peeled));

        // Bare tag when nothing is peeled.
        let out = format!("{tag}\trefs/tags/main\n");
        assert_eq!(pick_sha(&out, "main").as_deref(), Some(tag));

        // Bare refname line (no refs/ prefix).
        let out = format!("{bare}\tmain\n");
        assert_eq!(pick_sha(&out, "main").as_deref(), Some(bare));

        // Non-hex and wrong-ref lines are ignored.
        assert_eq!(pick_sha("nothex\trefs/heads/main\n", "main"), None);
        assert_eq!(
            pick_sha(&format!("{head}\trefs/heads/other\n"), "main"),
            None
        );
        assert_eq!(pick_sha("", "main"), None);
    }
}
