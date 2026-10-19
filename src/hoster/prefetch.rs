//! Pre-fetch build dependencies BEFORE the sandboxed build.
//!
//! Build steps run with `PrivateNetwork=yes` (see `sandbox.rs`) so a hostile
//! `setup.py` / `postinstall` / `build.rs` fetched from a package registry can
//! never phone home. That is only safe if the build itself is fully offline —
//! every dependency it needs must already be on local disk. This module does
//! that pre-seeding during the pre-flight *host* phase, where a dependency
//! downloader (`pip`, and later `bun`/`pnpm`) may reach its registry.
//!
//! The security invariant is preserved: the downloader only *fetches blobs*;
//! it does not run the project's, nor the fetched packages', build code here.
//! The `--only-binary=:all:` flag is what makes that true for pip (wheels are
//! inert archives — no sdist is built, so no `setup.py` executes). Everything
//! fetched is executed later, and only inside the offline sandbox. This keeps
//! the data flow documented in `netlog.rs` honest: registry bytes cross the
//! network via the downloader tool (which already did so from inside the
//! sandbox before), not via this binary's allowlisted client.
//!
//! One deliberate exception is the VERT recipe's two paraglide-js *plugins*:
//! they are fetched by this binary, through the allowlisted client (so
//! `cdn.jsdelivr.net` is a permitted, net.log-visible endpoint) and are
//! pinned by content SHA-256 at the recipe level. See
//! [`seed_paraglide_plugins`].
//!
//! Unsafe is required for the host-prefetch watchdog: `libc::prctl` PDEATHSIG
//! in `pre_exec` (async-signal-safe syscalls only) so a hung downloader's
//! whole process group can be reaped at the deadline and never orphaned.
//! Test-only env mutation is covered by the same gate.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::Context;

/// Wheelhouse directory for a recipe's pip dependencies, under the project's
/// persistent cache (kept in sync with the pip cache env in `sandbox.rs`).
fn wheelhouse(project_dir: &Path) -> std::path::PathBuf {
    project_dir.join(".ghost-cache").join("pip-wheelhouse")
}

/// paraglide-js (via @inlang/sdk's `plugin/cache.js`) stores each remote
/// plugin fetched from `settings.json` under
/// `project.inlang/cache/plugins/<name>`, where `<name>` is the FNV1a-64
/// hash of the module URL rendered in base36. Since those plugins resolve
/// Network-First at compile time, a build under `PrivateNetwork=yes` needs
/// them pre-seeded on local disk; this name is the other half of that pair
/// ([`seed_paraglide_plugins`] downloads each module into exactly this
/// path). The recipe hardcodes the two current filenames; the guard tests in
/// this module re-derive them so a settings.json drift is caught.
pub(crate) fn paraglide_cache_name(module_url: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in module_url.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    // Render base36, digits 0-9a-z (same alphabet @inlang/sdk uses).
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if hash == 0 {
        return "0".to_string();
    }
    let mut n = hash;
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("base36 digits are ascii")
}

/// Lowercase-hex SHA-256 of `bytes` — the form recipe plugin pins are stored
/// in and compared against.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for b in hasher.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Verify `bytes` against a pinned lowercase-hex SHA-256 (the pin comparison
/// is case-insensitive so hand-copied hex in a recipe can't silently shift
/// the trust anchor's rendering).
fn verify_pin(bytes: &[u8], pinned: &str) -> Result<(), String> {
    let got = sha256_hex(bytes);
    if got == pinned.to_ascii_lowercase() {
        Ok(())
    } else {
        Err(format!("sha256 mismatch (want {pinned}, got {got})"))
    }
}

/// Seed the VERT recipe's paraglide-js remote plugins into
/// `project.inlang/cache/plugins/` — the cache the *offline* sandboxed build
/// reads (Network-First plugin resolution under `PrivateNetwork=yes` needs
/// them pre-seeded).
///
/// This is the one host-phase fetch this binary performs itself (the rest
/// go through the recipe's downloader tool), so it is deliberately routed
/// through the allowlisted client: `cdn.jsdelivr.net` is a permitted,
/// net.log-visible endpoint, and the content is additionally pinned by
/// content SHA-256 in the recipe. Every plugin is downloaded and verified
/// BEFORE anything is placed, and each is staged as a `.seed-*` dotfile,
/// renamed into its final cache name only after ALL plugins verified. A
/// partial or drifted seed is therefore never presented to the offline
/// build — the same fail-closed contract as the old `curl` shell step it
/// replaces.
pub fn seed_paraglide_plugins(project_dir: &Path, spec: &[(&str, &str)]) -> anyhow::Result<()> {
    let plugins_dir = project_dir
        .join("project.inlang")
        .join("cache")
        .join("plugins");
    std::fs::create_dir_all(&plugins_dir)
        .with_context(|| format!("prefetch: create plugin cache {}", plugins_dir.display()))?;
    seed_pinned_plugins(&plugins_dir, spec, &crate::hoster::httpclient::get_bytes)
}

/// Testable core of [`seed_paraglide_plugins`]: `fetch` is injected so the
/// network path is unit-testable offline. Contract: nothing is renamed until
/// every spec has downloaded and verified.
fn seed_pinned_plugins(
    plugins_dir: &Path,
    spec: &[(&str, &str)],
    fetch: &dyn Fn(&str) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut staged: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for (url, pinned) in spec {
        let bytes = fetch(url).with_context(|| format!("prefetch: plugin fetch {url}"))?;
        verify_pin(&bytes, pinned)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("prefetch: plugin {url}"))?;
        let cache_name = paraglide_cache_name(url);
        let stage = plugins_dir.join(format!(".seed-{cache_name}"));
        crate::atomic::write_atomic(&stage, &bytes)
            .with_context(|| format!("prefetch: stage plugin {url}"))?;
        staged.push((stage, plugins_dir.join(cache_name)));
    }
    for (stage, final_path) in staged {
        std::fs::rename(&stage, &final_path)
            .with_context(|| format!("prefetch: place plugin {}", final_path.display()))?;
    }
    Ok(())
}

/// Pin the paraglide remote modules declared in a tree's
/// `project.inlang/settings.json` by content hash — the host-phase half of
/// [`seed_paraglide_plugins`], run during stack *detection* where the
/// network is available. Returns (url, sha256) pairs plus notes for the
/// review screen. A module that cannot be fetched is reported, never
/// silently dropped: without the pin the offline build compiles the project
/// WITHOUT its messages (paraglide warns and continues on
/// `PluginImportError`) and the app then dies at prerender with
/// `TypeError: (void 0) is not a function`.
pub fn pin_remote_paraglide_modules(project_dir: &Path) -> (Vec<(String, String)>, Vec<String>) {
    let settings = project_dir.join("project.inlang").join("settings.json");
    let Ok(text) = std::fs::read_to_string(&settings) else {
        return (vec![], vec![]);
    };
    pins_from_settings(&text, &crate::hoster::httpclient::get_bytes)
}

/// Testable core of [`pin_remote_paraglide_modules`]: `fetch` is injected so
/// the network path is unit-testable offline.
fn pins_from_settings(
    settings_json: &str,
    fetch: &dyn Fn(&str) -> anyhow::Result<Vec<u8>>,
) -> (Vec<(String, String)>, Vec<String>) {
    // Schema: too many plugin pins (max 8) — anything past the cap stays
    // unpinned and is reported so the review screen can trim the list.
    const MAX_MODULES: usize = 8;
    // The only CDN the schema accepts for plugin URLs (fail closed: a
    // foreign module URL is left unpinned and reported, not fetched).
    const ALLOWED_PREFIX: &str = "https://cdn.jsdelivr.net/npm/@inlang/plugin-";
    let mut pins = Vec::new();
    let mut notes = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(settings_json) else {
        notes.push(
            "project.inlang/settings.json is not valid JSON — inlang modules left unpinned".into(),
        );
        return (pins, notes);
    };
    let Some(modules) = v.get("modules").and_then(|m| m.as_array()) else {
        return (pins, notes);
    };
    for url in modules.iter().filter_map(|m| m.as_str()) {
        if pins.len() >= MAX_MODULES {
            notes.push(format!(
                "more than {MAX_MODULES} inlang modules — the extra ones stay unpinned"
            ));
            break;
        }
        if !url.starts_with(ALLOWED_PREFIX) {
            notes.push(format!(
                "inlang module outside the jsdelivr plugin CDN was left unpinned: {url}"
            ));
            continue;
        }
        match fetch(url) {
            Ok(bytes) => pins.push((url.to_string(), sha256_hex(&bytes))),
            Err(e) => notes.push(format!(
                "couldn't fetch inlang module {url} ({e:#}) — the offline build will compile without it"
            )),
        }
    }
    (pins, notes)
}

/// The cache-env redirects for `bun`/`pnpm` live in `sandbox.rs::cache_env`;
/// `run_host_step` applies them too, so the prefetch writes into the same
/// project cache (`XDG_CACHE_HOME`, `npm_config_store_dir`, …) that the
/// offline sandbox build reads. Without this, e.g. pnpm's self-version
/// mirror (`@pnpm/exe` metadata) lands in the host's `~/.cache` and the
/// `PrivateNetwork` build cannot resolve it.
///
/// Environment of the host prefetch runner: current env with (a) credentials
/// scrubbed exactly like the sandbox scrubs them (a prefetch downloader must
/// never inherit a deployment token either), (b) `CI=1` (pip/pnpm refuse host
/// runs that look interactive), (c) the same cache redirects as the build, and
/// (d) the provided PATH prefix when the toolbox provisioned pinned tools —
/// the prefetch must use exactly the pinned bun/pnpm/go, not whatever is on
/// the ambient PATH.
fn host_env(project_dir: &Path, path_prefix: &[PathBuf]) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    // Same credential + ambient-socket scrub as the build sandbox
    // (sandbox.rs::scrub_env): a prefetch downloader must never inherit a
    // deployment token, an SSH agent socket or a display pointer either.
    crate::hoster::sandbox::scrub_env(&mut env);
    env.insert("CI".to_string(), "1".to_string());
    let cache = crate::hoster::sandbox::cache_env_pub(Some(project_dir));
    // The redirect targets (TMPDIR, HOME, the store dirs, …) must exist *now*:
    // the host prefetch writes into them (pnpm's bundled node, for one, calls
    // realpathSync on TMPDIR eagerly and dies on ENOENT). The sandbox precreates
    // the same set before the build; do it here before the first prefetch step.
    crate::hoster::sandbox::precreate_cache_dirs(project_dir, &cache);
    for (k, v) in cache {
        env.insert(k.to_string(), v);
    }
    prepend_path_if_any(&mut env, path_prefix);
    env
}

/// Prepend `path_prefix` to the `PATH` value in `env`, preserving the rest of
/// the ambient PATH. No-op for an empty prefix.
fn prepend_path_if_any(env: &mut BTreeMap<String, String>, path_prefix: &[PathBuf]) {
    if path_prefix.is_empty() {
        return;
    }
    env.insert(
        "PATH".to_string(),
        super::toolbox::join_path_with_ambient(path_prefix),
    );
}

/// Run one host-phase dependency prefetch command. The command is a
/// *downloader* (e.g. `bun install`, `pnpm fetch`, `pip download`) that may
/// reach its registry — but by design does not run fetched package code on
/// the host (bun and pnpm skip untrusted lifecycle scripts; pip
/// `--only-binary=:all:` wheels are inert archives). Project build code never
/// executes here; it runs later, inside the offline sandbox.
pub fn run_host_step(
    cmd: &str,
    project_dir: &Path,
    path_prefix: &[PathBuf],
    log: &dyn Fn(&str),
) -> anyhow::Result<()> {
    run_host_step_timed(cmd, project_dir, path_prefix, log, PREFETCH_TIMEOUT)
}

fn run_host_step_timed(
    cmd: &str,
    project_dir: &Path,
    path_prefix: &[PathBuf],
    log: &dyn Fn(&str),
    timeout: Duration,
) -> anyhow::Result<()> {
    crate::hoster::validate::validate_build_cmd(cmd).map_err(|r| anyhow::anyhow!("{r}: {cmd}"))?;
    let env = host_env(project_dir, path_prefix);

    let _ = log;
    let mut builder = Command::new("/bin/sh");
    builder
        .args(["-c", cmd])
        .current_dir(project_dir)
        .env_clear()
        .envs(&env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group so a deadline kill takes down every child of the
        // downloader (bun/pip/pnpm spawn helpers), and PDEATHSIG so the
        // prefetch is never orphaned if this process dies mid-run.
        builder.process_group(0);
        unsafe {
            builder.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let mut child = builder.spawn()?;

    // The prefetch downloader (pip/bun/pnpm) prints a lot of progress, e.g.
    // `pip download` emits a "Downloading …" line per dependency and `bun
    // install` a "+ pkg@ver" line per package. Two constraints:
    //
    //  1. It must NEVER inherit the panel's stdout/stderr: that would spill
    //     raw bytes straight into the terminal on top of the TUI's alternate
    //     screen, corrupting the UI mid-deploy.
    //  2. It should also NOT be forwarded into the deploy log: a normal deploy
    //     would bury the build status under hundreds of download lines. The
    //     panel is meant to show the *build*, not the dependency fetch.
    //
    // So we drain both streams via bounded-tail threads, discarding the output
    // on success but keeping a bounded tail surfaced only if the prefetch
    // fails — that is when the lines matter (and the child can never wedge
    // itself on a full pipe).
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out_thread = std::thread::spawn(move || drain_tail(stdout));
    let err_thread = std::thread::spawn(move || drain_tail(stderr));

    // Hard deadline: unlike the sandboxed steps (RuntimeMaxSec) the host
    // prefetch used to run forever on a stalled registry. Now it is reaped by
    // killing its process group at the deadline, exactly like the clone
    // watchdog in gitclone.rs.
    let pid = child.id();
    #[cfg(unix)]
    let group = i32::try_from(pid).ok();
    let halt = std::time::Instant::now() + timeout;
    let mut exit: Option<std::process::ExitStatus> = None;
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit = Some(status);
                break false;
            }
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
        // `kill` binary): first to the whole process group, then to the
        // direct child as the edge case where the downloader lives outside
        // the expected group. SIGKILL cannot be caught or ignored, so the
        // reap confirm loop below exits the moment the child is gone.
        #[cfg(unix)]
        if let Some(g) = group {
            unsafe {
                libc::kill(g, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        // Bounded reap instead of a naked wait(): re-issue SIGKILL to the
        // group and the child until the child is reaped or the grace cap is
        // hit, so a wedged process can never park the deploy thread forever.
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
        let _ = child.wait();
    }
    let out_tail = out_thread.join().unwrap_or_default();
    let err_tail = err_thread.join().unwrap_or_default();
    if timed_out {
        anyhow::bail!(
            "prefetch step timed out after {}s: {cmd}",
            timeout.as_secs()
        );
    }
    let ok = exit.map(|s| s.success()).unwrap_or(false);
    if ok {
        return Ok(());
    }
    let mut detail = String::new();
    for line in err_tail.iter().chain(out_tail.iter()) {
        detail.push_str(&format!("    {line}\n"));
    }
    anyhow::bail!(
        "prefetch step failed (exit {}): {cmd}\n{detail}",
        exit.map(|s| s.to_string())
            .unwrap_or_else(|| "?".to_string())
    );
}

/// Deadline for one host-phase prefetch step (bun/pnpm/pip downloader). The
/// sandboxed steps budget 90 minutes in `sandbox.rs`; the host prefetch is the
/// same class of heavy registry fetch, so it gets the same ceiling. What it
/// deliberately does NOT get is an unbounded run — a stalled registry must not
/// park the deploy thread forever.
const PREFETCH_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// How long the deadline reap may keep re-issuing SIGKILL before giving up
/// on confirming the hang is reaped. SIGKILL is deterministic; this is only a
/// cap so a pathological D-state child can't park the deploy thread longer
/// than the grace window.
const WATCHDOG_REAP_GRACE: Duration = Duration::from_secs(10);

/// Rows of prefetch output kept for a failure tail. Enough to show the real
/// error from a package-manager failure, bounded so a pathological downloader
/// can't balloon the in-memory buffer.
const PREFETCH_TAIL: usize = 40;

/// Drain one piped stream (stdout or stderr), discarding it but keeping the
/// last `PREFETCH_TAIL` lines. Returns those lines so a *failed* prefetch can
/// surface its error tail; a successful run shows nothing.
fn drain_tail<R: std::io::Read>(stream: R) -> Vec<String> {
    let mut tail: Vec<String> = Vec::new();
    for line in BufReader::new(stream).lines().map_while(Result::ok) {
        if tail.len() == PREFETCH_TAIL {
            tail.remove(0);
        }
        tail.push(line);
    }
    tail
}

/// Marker written only after a full, successful `pip download`. Its presence
/// means the wheelhouse is a valid, complete offline source: a partial or
/// interrupted download is never trusted, so a killed run re-fetches.
const DONE: &str = ".done";

/// Return the env overrides that make the in-sandbox `pip install` consume
/// *only* the wheelhouse (no index, offline), when the wheelhouse has been
/// pre-seeded by the recipe's prefetch step. Empty vec = nothing ready.
///
/// The actual download happens in `prefetch_steps` (`pip download ...`), which
/// runs on the host. The marker file written by that successful download is
/// what this function keys on, so a partial wheelhouse is never trusted.
pub fn pip_offline_env(project_dir: &Path) -> Vec<(String, String)> {
    let req = project_dir.join("requirements.txt");
    if !req.is_file() {
        return Vec::new();
    }
    let wh = wheelhouse(project_dir);
    if wh.join(DONE).is_file() {
        offline_env(&wh)
    } else {
        Vec::new()
    }
}

/// Env overrides that force `pip install` to use only the local wheelhouse.
fn offline_env(wh: &Path) -> Vec<(String, String)> {
    let p = wh.to_string_lossy().into_owned();
    vec![
        ("PIP_NO_INDEX".to_string(), "1".to_string()),
        ("PIP_FIND_LINKS".to_string(), p),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_requirements_means_no_work() {
        let dir = std::env::temp_dir().join(format!("gp-prefetch-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = pip_offline_env(&dir);
        assert!(env.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offline_env_is_index_free_and_local() {
        let wh = std::path::PathBuf::from("/x/.ghost-cache/pip-wheelhouse");
        let env = offline_env(&wh);
        assert_eq!(env[0], ("PIP_NO_INDEX".into(), "1".into()));
        assert!(
            env[1]
                == (
                    "PIP_FIND_LINKS".into(),
                    "/x/.ghost-cache/pip-wheelhouse".into()
                )
        );
    }

    #[test]
    fn wheelhouse_env_only_when_marker_present() {
        let dir = std::env::temp_dir().join(format!("gp-prefetch-wh-{}", std::process::id()));
        let wh = dir.join(".ghost-cache").join("pip-wheelhouse");
        std::fs::create_dir_all(&wh).unwrap();
        std::fs::write(dir.join("requirements.txt"), "certifi==2026.7.22\n").unwrap();

        // No marker → no offline env (partial wheelhouse must never be used).
        assert!(pip_offline_env(&dir).is_empty());

        std::fs::write(wh.join(DONE), "ok").unwrap();
        let env = pip_offline_env(&dir);
        assert_eq!(
            env.len(),
            2,
            "marker present → offline env returned: {env:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_prefetch_step_runs_and_scrubs_credentials() {
        unsafe {
            std::env::set_var("GITHUB_TOKEN", "should-not-leak");
            std::env::set_var("CI", "0");
        }
        // The host prefetch environment must never carry a deployment
        // credential, and must force CI=1 (pip/pnpm refuse host runs that look
        // interactive, e.g. pnpm's module-dir purge prompt).
        let dir = std::env::temp_dir().join(format!("gp-prefetch-env-{}", std::process::id()));
        let env = host_env(&dir, &[]);
        assert_eq!(env.get("GITHUB_TOKEN"), None, "credential must be scrubbed");
        assert_eq!(env.get("CI").map(String::as_str), Some("1"));
        unsafe {
            std::env::remove_var("GITHUB_TOKEN");
            std::env::set_var("CI", "0");
        }
    }

    #[test]
    fn host_prefetch_env_prepends_provisioned_path() {
        let dir = std::env::temp_dir().join(format!("gp-prefetch-prefix-{}", std::process::id()));
        let prefix = vec![PathBuf::from("/srv/x/.ghost-cache/toolbox/bin")];
        let env = host_env(&dir, &prefix);
        let path = env.get("PATH").unwrap();
        assert!(
            path.starts_with("/srv/x/.ghost-cache/toolbox/bin:"),
            "pinned dir must lead PATH: {path}"
        );
        assert!(
            path.ends_with(&std::env::var("PATH").unwrap_or_default()),
            "ambient PATH preserved: {path}"
        );
        // Empty prefix → PATH untouched by the prefix.
        let env2 = host_env(&dir, &[]);
        assert_eq!(
            env2.get("PATH"),
            std::env::var("PATH").ok().as_ref(),
            "no prefix → no PATH rewrite"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_prefetch_step_rejects_dangerous_command() {
        let dir = std::env::temp_dir().join(format!("gp-prefetch-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = run_host_step("rm -rf /", &dir, &[], &|_| {}).unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hung downloader must be reaped at the deadline: the host prefetch
    /// cannot park the deploy thread forever. Mirrors gitclone's watchdog —
    /// a sleeping `/bin/sh -c` is killed through its whole process group.
    /// `exec` makes the shell become the sleeper itself (no fork to escape
    /// into another group), so a direct SIGKILL to the child is always the
    /// second, guaranteed reap path when the group-kill misses in some exotic
    /// environment; without it the test would only fail after the 300s
    /// natural exit instead of asserting the watchdog fired.
    #[test]
    fn host_prefetch_watchdog_kills_hung_step() {
        let dir = std::env::temp_dir().join(format!("gp-prefetch-hang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let start = std::time::Instant::now();
        let err = run_host_step_timed(
            "exec sleep 300",
            &dir,
            &[],
            &|_| {},
            Duration::from_millis(700),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("timed out"), "{msg}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "watchdog took too long: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The VERT recipe's prefetch seeds paraglide-js's remote plugin cache at
    /// `project.inlang/cache/plugins/<fnv1a64(url)>`. These are the two
    /// modules listed in VERT's `project.inlang/settings.json` (pinned commit
    /// cc7b5a54d5e9). If a pin bump changes those modules the filenames in
    /// the recipe's prefetch step must be re-derived — this test is the trip
    /// wire that catches a mismatch.
    #[test]
    fn paraglide_cache_names_match_vert_settings() {
        let mf = "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js";
        let fnm = "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js";
        assert_eq!(paraglide_cache_name(mf), "2sy648wh9sugi");
        assert_eq!(paraglide_cache_name(fnm), "ygx0uiahq6uw");
        // Distinct URLs must not collide.
        assert_ne!(paraglide_cache_name(mf), paraglide_cache_name(fnm));
    }

    /// Sanity: the FNV1a-64 constants match the well-known vector. This pins
    /// the length/overflow behaviour of the hash so a regression in wrapping
    /// can never silently change every recipe's cache path.
    #[test]
    fn fnv1a64_well_known_vector() {
        // FNV-1a 64-bit of "hello" is a published vector
        // (0xa430d84680aabd0b). Rendered in the base36 the @inlang/sdk uses
        // for cache filenames it is:
        assert_eq!(
            paraglide_cache_name("hello"),
            "2hvyo96lq8v0r",
            "FNV1a-64 base36 of \"hello\""
        );
    }

    /// Live, ignored by default (network): fetch BOTH pinned paraglide
    /// plugins through the real httpclient path and confirm the bytes the
    /// binary would seed are byte-identical to the recipe pins. Run manually
    /// after a pin bump (`cargo test -- --ignored live_pins`) — a CDN serving
    /// different bytes under the same URL would fail this and the deploy.
    #[test]
    #[ignore = "network — run manually to re-pin after a recipe change"]
    fn live_pins_match_what_the_client_actually_fetches() {
        let mf_url = "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js";
        let fm_url =
            "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js";
        let mf = crate::hoster::httpclient::get_bytes(mf_url).unwrap();
        let fm = crate::hoster::httpclient::get_bytes(fm_url).unwrap();
        let mf_pin = "765b487bbe95a20c7f83a940a3fba81bacef18bce0bbe916df6807f7ddd512ca";
        let fm_pin = "a7e6c41307afc64b3f34116f220e925f0ad3aca47231e849f080051a2fb459a8";
        assert_eq!(
            sha256_hex(&mf),
            mf_pin,
            "plugin-message-format bytes changed"
        );
        assert_eq!(
            sha256_hex(&fm),
            fm_pin,
            "plugin-m-function-matcher bytes changed"
        );
    }

    #[test]
    fn sha256_hex_well_known_vector() {
        // SHA-256("abc") is a published test vector.
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_pin_ok_and_mismatch() {
        let bytes = b"plugin-bytes";
        let good = sha256_hex(bytes);
        assert!(verify_pin(bytes, &good).is_ok());
        assert!(
            verify_pin(
                bytes,
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
    }

    #[test]
    fn seed_pinned_plugins_places_files_and_leaves_no_dotfiles() {
        let dir = std::env::temp_dir().join(format!("gp-seed-ok-{}", std::process::id()));
        let plugins = dir.join("project.inlang/cache/plugins");
        std::fs::create_dir_all(&plugins).unwrap();

        let a = b"plugin-a";
        let b = b"plugin-b";
        let a_sha = sha256_hex(a);
        let b_sha = sha256_hex(b);
        let a_url = "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js";
        let b_url =
            "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js";

        let spec: Vec<(&str, &str)> = vec![(a_url, &a_sha), (b_url, &b_sha)];
        let fake_fetch = |url: &str| -> anyhow::Result<Vec<u8>> {
            if url == a_url {
                Ok(a.to_vec())
            } else {
                Ok(b.to_vec())
            }
        };
        seed_pinned_plugins(&plugins, &spec, &fake_fetch).unwrap();

        assert_eq!(
            std::fs::read(plugins.join(paraglide_cache_name(a_url))).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(plugins.join(paraglide_cache_name(b_url))).unwrap(),
            b
        );
        // No staging dotfiles remain after a successful seed.
        assert!(
            plugins.read_dir().unwrap().all(|e| {
                let name = e.unwrap().file_name();
                !name.to_string_lossy().starts_with(".seed-")
            }),
            "staging dotfiles must be renamed away"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_pinned_plugins_rejects_drift_and_places_nothing_final() {
        let dir = std::env::temp_dir().join(format!("gp-seed-fail-{}", std::process::id()));
        let plugins = dir.join("project.inlang/cache/plugins");
        std::fs::create_dir_all(&plugins).unwrap();

        let a = b"plugin-a";
        let a_sha = sha256_hex(a);
        let a_url = "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js";
        let b_url =
            "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js";

        // First URL correct, second URL wrong pin.
        let spec: Vec<(&str, &str)> = vec![
            (a_url, &a_sha),
            (
                b_url,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        let fake_fetch = |url: &str| -> anyhow::Result<Vec<u8>> {
            if url == a_url {
                Ok(a.to_vec())
            } else {
                Ok(b"wrong-plugin".to_vec())
            }
        };
        let err = seed_pinned_plugins(&plugins, &spec, &fake_fetch).unwrap_err();
        let report = format!("{err:#}");
        assert!(report.contains("sha256 mismatch"), "{report}");
        // Final cache-name files must never appear (the offline build must not see them).
        assert!(!plugins.join(paraglide_cache_name(a_url)).exists());
        assert!(!plugins.join(paraglide_cache_name(b_url)).exists());
        // Staged dotfile for the first plugin exists (verify happened, then rename phase
        // never ran) — this is safe; the loader does not serve dotfiles.
        assert!(
            plugins
                .join(format!(".seed-{}", paraglide_cache_name(a_url)))
                .exists()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pins_from_settings_hashes_modules_and_reports_failures() {
        let settings = r#"{
            "modules": [
                "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js",
                "https://evil.example.com/steal.js",
                "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js"
            ]
        }"#;
        let fetch = |url: &str| -> anyhow::Result<Vec<u8>> {
            if url.contains("m-function") {
                anyhow::bail!("fetch failed")
            } else if url.contains("message-format") {
                Ok(b"format-bytes".to_vec())
            } else {
                panic!("foreign module must never be fetched: {url}")
            }
        };
        let (pins, notes) = pins_from_settings(settings, &fetch);
        assert_eq!(pins.len(), 1, "only the allowed module is pinned: {pins:?}");
        assert_eq!(
            pins[0].0,
            "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js"
        );
        assert_eq!(pins[0].1, sha256_hex(b"format-bytes"));
        // A foreign module URL is fail-closed (left unpinned) and reported.
        assert!(
            notes.iter().any(|n| n.contains("evil.example.com")),
            "foreign module reported: {notes:?}"
        );
        // A fetch failure is reported loudly — silence here means a silently
        // broken offline build later.
        assert!(
            notes
                .iter()
                .any(|n| n.contains("m-function") && n.contains("fetch failed")),
            "fetch failure reported: {notes:?}"
        );
    }

    #[test]
    fn pins_from_settings_tolerates_missing_or_invalid_json() {
        let (pins, notes) = pins_from_settings("not json {", &|_| Ok(vec![]));
        assert!(pins.is_empty());
        assert!(
            notes.iter().any(|n| n.contains("not valid JSON")),
            "{notes:?}"
        );
        // No modules key: an ordinary inlang project with no remote plugins.
        let (pins, notes) = pins_from_settings(r#"{"baseLocale":"en"}"#, &|_| Ok(vec![]));
        assert!(pins.is_empty() && notes.is_empty());
    }
}
