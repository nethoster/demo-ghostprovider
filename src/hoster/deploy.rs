//! Deploy sequence for the curated demo services.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

use super::gitclone;
use super::journal::{self, DeployState};
use super::models::{HostResult, RepoAnalysis};
use super::port::find_free_port;
use super::recipes::DemoRecipe;
use super::sandbox::run_build_cmd;
use super::secrets::write_env_file;
use super::units::{
    StartOutcome, UnitSpec, create_unit, remove_unit, service_logs, wait_until_active,
};

fn safe_dirname(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// True while a deploy pipeline is running in this process. The TUI's exit
/// path consults it to decide whether a cleaned journal entry must be kept so
/// the *next* launch re-verifies: a still-running worker thread can re-create
/// artifacts (the wiped clone tree, a unit file) in the window between the
/// cleanup and the process actually dying, and a retained entry turns that
/// leftover into a guaranteed, idempotent clean-up rather than permanent junk.
static DEPLOY_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Clone (or reuse) the repository into the permanent services directory.
pub fn clone_repo(
    analysis: &RepoAnalysis,
    work_dir: Option<&Path>,
    pin: Option<&str>,
) -> Option<PathBuf> {
    let base = work_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(crate::paths::services_dir);
    std::fs::create_dir_all(&base).ok()?;

    let dir = base.join(safe_dirname(&analysis.name));
    // Always delegate to gitclone::clone: it reuses an intact checkout,
    // reclones a corrupted one (interrupted clones ship a partial worktree
    // that would fail the build far from the cause), fetches fresh, and —
    // when `pin` is set — refuses any checkout not built from exactly that
    // SHA (a legacy unpinned tree is recloned at the pinned SHA).
    let url = format!(
        "https://github.com/{}/{}.git",
        analysis.owner, analysis.name
    );
    let status = gitclone::clone(&url, &dir, pin);
    eprintln!("clone: {}", status.last_message);
    if !status.ok {
        return None;
    }
    Some(dir)
}

/// Fill recipe start command placeholders with concrete paths.
pub fn resolve_start(recipe: &DemoRecipe, project_dir: &Path, port: u16) -> String {
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "demo-ghostprovider".into());

    let mut cmd = recipe.start_cmd.to_string();
    if recipe.language == "Go" {
        cmd = cmd.replace("{bin}", &project_dir.join("ghost-server").to_string_lossy());
    }
    cmd = cmd
        .replace(
            "{venv}",
            &project_dir.join(".venv/bin/python").to_string_lossy(),
        )
        .replace("{python}", "python3")
        .replace("{self}", &self_exe)
        .replace("{project}", &project_dir.to_string_lossy())
        .replace("{port}", &port.to_string());
    cmd
}

/// Fill the `{project}` placeholder in a build/prefetch step with the
/// concrete project directory. Kept deliberately small (store/cache paths);
/// the sandbox validates every command as it runs (see `validate.rs`).
fn resolve_project_step(step: &str, project_dir: &Path) -> String {
    step.replace("{project}", &project_dir.to_string_lossy())
}

/// Patch SearXNG settings.yml: real secret key, loopback bind, chosen port.
fn prepare_searxng_config(project_dir: &Path, port: u16) -> anyhow::Result<()> {
    let settings = project_dir.join("searx/settings.yml");
    let Ok(content) = std::fs::read_to_string(&settings) else {
        return Ok(());
    };

    let secret_key = random_hex(32)?;
    let patched: Vec<String> = content
        .lines()
        .map(|line| {
            let indent_len = line.len() - line.trim_start().len();
            let indent = &line[..indent_len];
            let trimmed = line.trim_start();
            if trimmed.starts_with("secret_key:") {
                format!("{indent}secret_key: \"{secret_key}\"")
            } else if trimmed.starts_with("bind_address:") {
                format!("{indent}bind_address: \"127.0.0.1\"")
            } else if trimmed.starts_with("http_address:") && trimmed.contains(':') {
                // Some SearXNG versions use uwsgi-style http_address.
                format!("{indent}http_address: \"127.0.0.1:{port}\"")
            } else if trimmed.starts_with("port:") {
                format!("{indent}port: {port}")
            } else {
                line.to_string()
            }
        })
        .collect();

    std::fs::write(settings, patched.join("\n") + "\n")?;
    Ok(())
}

/// `bytes` random bytes from the kernel CSPRNG as lowercase hex. No weak
/// fallback: a deployment secret derived from time+pid would be guessable, so
/// a failure to read `/dev/urandom` aborts instead of degrading.
fn random_hex(bytes: usize) -> anyhow::Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?
        .read_exact(&mut buf)
        .context("reading /dev/urandom")?;
    let mut out = String::with_capacity(bytes * 2);
    for b in &buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// Stop a previously deployed instance before replacing it, WITHOUT tearing
/// its unit down.
///
/// The redeploy only needs the old process gone so its port is free for the
/// replacement (see the install step). Deleting or disabling the unit here
/// opened a dangerous window: if the deploy was interrupted (panel closed,
/// kill, reboot) between this stop and `create_unit`, a live, working service
/// was left with no unit at all — unrecoverable except by a full delete +
/// redeploy. Keeping the old unit in place means an interruption leaves the
/// service intact (stopped, still enabled, same port), so the next boot or a
/// plain `start` brings it back. `create_unit` replaces the file atomically
/// on success, and `rollback_failed` still removes it if the deploy fails.
fn stop_existing(service_name: &str) {
    let unit = crate::paths::user_unit_dir().join(format!("{service_name}.service"));
    if unit.is_file() {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", service_name])
            .status();
    }
}

#[derive(Default)]
pub struct DeployHooks<'a> {
    pub on_status: Option<&'a dyn Fn(&str)>,
}

/// Outcome of a full pipeline run (parse → recipe → preflight → deploy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployOutcome {
    Deployed,
    Rejected(&'static str),
    Failed,
}

/// Lines that earn a spot in the (deliberately laconic) deploy output:
/// verification and warning lines plus the final reachable URL. Pure progress
/// chatter — pre-flight, source summary, build steps, unit install, service
/// start — is dropped; the final verdict line is what matters.
fn screen_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('!')
        || t.starts_with("warn: ")
        || t.starts_with("sandbox: ")
        || t.starts_with("provision: ")
        || t.contains("listening on ")
}

/// Which of the recipe's tools need provisioning into the project cache, in
/// the order the toolbox pins expect. A tool is provisioned when the doctor
/// would flag it (missing, or older than the manifest floor). Go is special:
/// an installed-but-old `go` is left to GOTOOLCHAIN=auto + the seeded file://
/// toolchain proxy, while a *missing* `go` always gets the pinned baseline
/// (`None`), whose own default toolchain mode covers the rest.
fn toolbox_needs(
    recipe: &DemoRecipe,
    project_dir: &Path,
) -> Vec<(super::toolcheck::Tool, Option<super::toolcheck::Ver>)> {
    use super::toolcheck::{
        Tool, installed_version, is_auto_provisionable, manifest_requirements, tool_from_bin,
    };
    let reqs = manifest_requirements(project_dir);
    let min_for = |t: Tool| reqs.iter().find(|(mt, _)| *mt == t).map(|(_, m)| *m);
    let mut out = Vec::new();
    for tool in recipe.tools {
        let Some(t) = tool_from_bin(tool) else {
            continue;
        };
        if !is_auto_provisionable(t) {
            continue;
        }
        let Some(have) = installed_version(t) else {
            out.push((t, if t == Tool::Go { None } else { min_for(t) }));
            continue;
        };
        if t == Tool::Go {
            // Present Go: doctor + GOTOOLCHAIN=auto handle a need>have gap.
            continue;
        }
        let Some(min) = min_for(t) else {
            continue;
        };
        if have < min {
            out.push((t, Some(min)));
        }
    }
    out
}

/// Shared entry point used by both the TUI and the `__deploy` subcommand:
/// validate the URL against the curated recipes, preflight the build tools,
/// then run the full deploy pipeline. Progress goes through `log`.
pub fn run_deployment(url: &str, log: &dyn Fn(String)) -> DeployOutcome {
    let screen = |line: String| {
        if screen_line(&line) {
            log(line);
        }
    };
    // Full build isolation is mandatory: any state short of FULL is a hard
    // rejection — a build must not run weakened or as a plain host process.
    match super::sandbox::sandbox_grade() {
        super::sandbox::SandboxGrade::Full => {
            screen("sandbox: FULL".into());
        }
        super::sandbox::SandboxGrade::Almost => {
            screen(
                "! sandbox: ALMOST — GHOSTPROVIDER_BUILD_USER set but unusable; refusing to \
                 deploy without full isolation"
                    .into(),
            );
            return DeployOutcome::Rejected("sandbox-unavailable");
        }
        super::sandbox::SandboxGrade::None => {
            screen(
                "! sandbox: NO — refusing to build without isolation (the sandbox is mandatory)"
                    .into(),
            );
            return DeployOutcome::Rejected("sandbox-unavailable");
        }
    }
    if crate::netlog::logging_disabled() {
        screen(
            "warn: GHOSTPROVIDER_NO_NETLOG — outbound requests are not written to net.log".into(),
        );
    }

    let Some((owner, name)) = super::github::parse_github_url(url) else {
        screen("! invalid GitHub URL format".into());
        return DeployOutcome::Rejected("bad-url");
    };
    let Some(recipe) = super::recipes::find_recipe(&owner, &name) else {
        screen("! this demo only supports three services:".into());
        screen("! VERT-sh/VERT · searxng/searxng · usememos/memos".into());
        return DeployOutcome::Rejected("not-curated");
    };

    // Preflight including per-recipe build tools (audit lesson).
    let issues = super::preflight::preflight_check(recipe.tools);
    if !issues.is_empty() {
        for i in issues {
            screen(format!("! {i}"));
        }
        screen("! pre-flight failed, aborting".into());
        return DeployOutcome::Rejected("preflight");
    }

    let analysis = RepoAnalysis {
        url: url.to_string(),
        owner,
        name,
        language: recipe.language.into(),
        exists: true,
        clone_path: None,
        errors: vec![],
    };
    // Journal the in-flight deploy. The entry is what lets an out-of-band
    // interruption (panel exit/kill, shutdown/reboot) become a clean removal
    // at the next launch; it is cleared at the end of this function for every
    // in-process outcome (success or rollback).
    //
    // The cross-process deploy lock serializes pipelines: only one deploy may
    // be running per user session (a second TUI, a scripted `__deploy`, or a
    // stale caller would otherwise race the same clone/unit/port namespace).
    // The lock is held from just before `journal::begin` until just after
    // `journal::clear`, so a background sweeper that finds "journal entry
    // present + lock free" knows the deploying process is dead and may remove
    // leftovers without ever tearing down a live deploy.
    DEPLOY_IN_FLIGHT.store(true, Ordering::Relaxed);
    let Some(_lock) = super::lock::try_lock_exclusive() else {
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);
        screen(
            "! another deployment is already running (deploy.lock held) — refusing to \
             start a second one"
                .into(),
        );
        return DeployOutcome::Rejected("deploy-locked");
    };
    journal::begin(recipe.service_name, url);

    // Race guard for a just-spawned worker: if the exit path already asked us
    // to stop (it set `EXITING` before this thread reached this line), settle
    // our own entry now — nothing has been cloned or built yet, so there is
    // nothing for the exit path to find and we must not leave a fresh entry
    // behind after it reconciled.
    if super::cancel::is_exiting() {
        journal::clear(recipe.service_name);
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);
        return DeployOutcome::Rejected("exiting");
    }

    let result = deploy_service(
        &analysis,
        recipe,
        None,
        DeployHooks {
            on_status: Some(&|line| screen(line.to_string())),
        },
    );

    for u in &result.urls {
        screen(format!("listening on {u}"));
    }
    // The deploy reached a terminal state the process itself handled (success
    // or the in-process rollback already removed artifacts); clear our journal
    // entry so the next launch does not re-clean a finished deploy. The deploy
    // lock is released here — after the entry is gone, so a sweeper can never
    // see a live deploy's entry while the lock is free.
    //
    // The one exception is a graceful exit in progress: the exit path is about
    // to reconcile and performs the *final* clean removal, and it needs the
    // entry to remain so it can wipe a partial clone tree that never got a
    // rollback (e.g. `clone_repo` failed — there is no project path to remove
    // on our side). Leave the entry; the exit path settles it. See `cancel.rs`.
    if super::cancel::is_exiting() {
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);
    } else {
        journal::clear(recipe.service_name);
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);
    }
    if !result.service_names.is_empty() && result.errors.is_empty() {
        DeployOutcome::Deployed
    } else {
        DeployOutcome::Failed
    }
}

/// Build, install, and start one curated demo service.
pub fn deploy_service(
    analysis: &RepoAnalysis,
    recipe: &DemoRecipe,
    work_dir: Option<&Path>,
    hooks: DeployHooks,
) -> HostResult {
    let emit = |msg: &str| {
        if let Some(cb) = hooks.on_status {
            cb(msg);
        }
    };
    let mut result = HostResult::default();
    let report_err = |result: &mut HostResult, msg: String| {
        emit(&format!("! {msg}"));
        result.errors.push(msg);
    };

    // A shutdown that began before this deploy even started must not clone:
    // nothing exists yet, and the exit path handles the empty case.
    if interrupted() {
        return result;
    }

    emit("cloning repository...");
    let Some(project_dir) = clone_repo(analysis, work_dir, Some(recipe.commit)) else {
        result
            .errors
            .push("git clone failed after retries (check network connection)".into());
        return result;
    };

    // ── pinned commit (anti-TOFU) ──
    // The recipe names one specific commit; a deployment must build exactly
    // that, never whichever `main`/`master` happens to point at download
    // time. `clone_repo` was asked for `recipe.commit`, so the tree in
    // `project_dir` was materialized blob-by-blob from that SHA — verify the
    // recorded marker matches, then refuse to build anything else.
    match super::gitclone::pinned_sha(&project_dir) {
        Some(have) if have == recipe.commit => {}
        Some(have) => {
            report_err(
                &mut result,
                format!(
                    "checkout is pinned to {have}, recipe pins {} (anti-TOFU); refusing to build an unpinned tree.",
                    recipe.commit
                ),
            );
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
        None => {
            report_err(
                &mut result,
                format!(
                    "checkout carries no pin marker, recipe pins {} (anti-TOFU); refusing to build an unpinned tree.",
                    recipe.commit
                ),
            );
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    }
    emit("build...");

    // ── tool doctor: manifest requirements vs installed tools ──
    let findings = super::toolcheck::check_findings(&project_dir, recipe.display_name);
    let blockers: Vec<_> = findings.iter().filter(|f| f.blocking).collect();
    for f in &findings {
        if f.blocking {
            emit(&format!("! {}", f.text));
            result.errors.push(f.text.clone());
        } else {
            // Informational (e.g. GOTOOLCHAIN=auto covers an old Go): no "!",
            // deployment continues.
            emit(&f.text);
        }
    }
    if !blockers.is_empty() {
        emit("! fix the tools above, then re-run the deployment");
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
    }

    // ── toolbox: auto-provision pinned build tools into the project cache ──
    // bun/pnpm/go the doctor flagged (missing, or too old for the manifest)
    // are downloaded through the allowlisted client, SHA-256 verified against
    // the pin table, and extracted into .ghost-cache/toolbox. The PATH prefix
    // below makes the host prefetch and the offline sandbox build use exactly
    // these pinned binaries. Failure is fatal, closed like the prefetch phase:
    // with PrivateNetwork=yes the build cannot reach any registry to install a
    // tool itself.
    let needs = toolbox_needs(recipe, &project_dir);
    let provisioned = if needs.is_empty() {
        super::toolbox::Provisioned::default()
    } else {
        match super::toolbox::provision(&project_dir, &needs, &emit) {
            Ok(p) => p,
            Err(e) => {
                report_err(
                    &mut result,
                    format!(
                        "Build-tool provisioning failed: {e}\nThe build sandbox has PrivateNetwork=yes; the pinned tools must be provisioned on the host."
                    ),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    };
    let path_prefix: Vec<PathBuf> = provisioned.bin_dirs.clone();

    // ── prefetch (host phase, network available) ──
    // Dependency caches are filled BEFORE the sandboxed build so the build
    // itself can run offline under PrivateNetwork=yes. These are downloader
    // commands only (see prefetch.rs); credentials are scrubbed, and no code
    // fetched from a registry is executed on the host. Failure here is fatal:
    // the sandboxed build has no network, so without a filled cache it cannot
    // produce a working tree — fail closed rather than build a broken service.
    for step in recipe.prefetch_steps {
        if interrupted() {
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
        let resolved = resolve_project_step(step, &project_dir);
        if let Err(e) = super::prefetch::run_host_step(&resolved, &project_dir, &path_prefix, &emit)
        {
            report_err(
                &mut result,
                format!(
                    "Prefetch step failed ({resolved}): {e}\nThe build sandbox has PrivateNetwork=yes, so dependencies must be pre-fetched on the host; fix the fetch, then re-deploy."
                ),
            );
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    }
    // Pinned paraglide-js plugin seed (VERT). Fetched through the allowlisted
    // client and verified against recipe SHA-256 pins before anything is
    // placed; fail closed exactly like the prefetch steps above — the offline
    // build would otherwise resolve a broken (or drifted) plugin tree.
    if !recipe.plugins.is_empty() {
        match super::prefetch::seed_paraglide_plugins(&project_dir, recipe.plugins) {
            Ok(()) => emit(&format!(
                "build: seeded {} paraglide plugin(s) (SHA-256 verified)",
                recipe.plugins.len()
            )),
            Err(e) => {
                report_err(
                    &mut result,
                    format!(
                        "Pinned paraglide plugin seed failed: {e:#}\nThe build sandbox has PrivateNetwork=yes; the plugins must be fetched and verified on the host. Refusing to build against unverified plugin bytes."
                    ),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    }

    // ── build ──
    // Go services: pre-seed the toolchain module into a file:// GOPROXY
    // (resumable Range fetch) so GOTOOLCHAIN=auto does not re-download the
    // ~75 MiB zip on every deploy. This runs on the host (like the prefetch
    // phase) and its failure is fatal: with PrivateNetwork=yes the sandboxed
    // `go build` could not fetch the toolchain itself.
    let mut build_env: Vec<(String, String)> = Vec::new();
    // Pinned toolbox tools lead PATH inside the sandbox too: the offline
    // build steps must invoke exactly the pinned bun/pnpm/go, never an
    // ambient binary. `run_sandboxed` gives extra_env precedence over the
    // ambient PATH, and pins are immutable once written.
    if let Some(path) = provisioned.prepend_path() {
        build_env.push(("PATH".to_string(), path));
    }
    if recipe.language == "Go" {
        match super::goenv::go_toolchain_env(&project_dir, &path_prefix) {
            Ok(env) => build_env.extend(env),
            Err(e) => {
                report_err(
                    &mut result,
                    format!(
                        "Go toolchain seed failed: {e:#}\nThe build sandbox has PrivateNetwork=yes; the toolchain must be pre-seeded on the host."
                    ),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    }
    // Go services: also pre-seed the module cache (every h1: zip in go.sum,
    // parallel and resumable). Network/DNS blips are retried permanently
    // (exponential backoff to 120s) — the deploy waits until the network
    // recovers. Only terminal 4xx land as failed; partial success is
    // best-effort: ≤20% failed = warning & continue, ≤50% = warning,
    // >50% = fatal (network truly dead).
    if recipe.language == "Go" {
        match super::goenv::seed_go_modules(&project_dir) {
            Ok(r) if r.failed.is_empty() => emit(&format!(
                "build: seeded Go module cache ({} module(s) ready)",
                r.ready
            )),
            Ok(r) => {
                let failed = r.failed.len();
                let total = r.total;
                let first = r.failed.first().cloned().unwrap_or_default();
                // Best-effort thresholds.
                if failed * 2 > total {
                    // >50% failed — network truly dead, fail closed.
                    report_err(
                        &mut result,
                        format!(
                            "Go module cache seed failed: {failed} of {total} module(s) failed; first: {first}\nThe build sandbox has PrivateNetwork=yes; modules must be fully pre-seeded on the host."
                        ),
                    );
                    rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                    return result;
                }
                // ≤50% failed — warn and continue; `go build` will try
                // what it can (and next deploy resumes the rest).
                emit(&format!(
                    "build: Go module cache partial: {failed} of {total} module(s) failed (best-effort, continuing); first: {first}"
                ));
                emit(&format!(
                    "build: {} module(s) ready, {failed} failed — deploy continues",
                    r.ready
                ));
            }
            Err(e) => {
                report_err(
                    &mut result,
                    format!(
                        "Go module cache seed failed: {e:#}\nThe build sandbox has PrivateNetwork=yes; modules must be fully pre-seeded on the host."
                    ),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    }
    // Python services: point pip at the pre-seeded wheelhouse so the
    // sandboxed install runs with no index (offline). The wheelhouse MUST be
    // complete here — the recipe's prefetch step failed closed otherwise.
    if recipe.language == "Python" {
        build_env.extend(super::prefetch::pip_offline_env(&project_dir));
    }
    for step in recipe.pre_build.iter().chain(recipe.build_steps.iter()) {
        if interrupted() {
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
        let resolved = resolve_project_step(step, &project_dir);
        match run_build_cmd(&resolved, &project_dir, &build_env, None) {
            Ok(r) if r.success => {}
            Ok(r) => {
                report_err(
                    &mut result,
                    format!(
                        "Build step failed ({resolved}):\n{}{}",
                        short(&r.stderr),
                        tail(&r.stdout),
                    ),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
            Err(e) => {
                report_err(&mut result, format!("Build step failed ({resolved}): {e}"));
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    }

    // ── install ──
    // Last chance to bail before any systemd state is touched: once a unit is
    // created/started the exit path's wipe must race systemd, so stop here and
    // let the exit path remove the clone/build tree.
    if interrupted() {
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
    }
    // Stop the previous instance BEFORE picking a port: a still-running old
    // unit holds the port and would push every redeploy one port up, silently
    // breaking the previously announced URL.
    stop_existing(recipe.service_name);
    let port = match find_free_port(recipe.port, 50) {
        Ok(p) => p,
        Err(e) => {
            report_err(&mut result, e.to_string());
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    };
    if recipe.searxng
        && let Err(e) = prepare_searxng_config(&project_dir, port)
    {
        report_err(&mut result, format!("searxng config failed: {e}"));
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
    }
    let exec_start = resolve_start(recipe, &project_dir, port);

    emit(&format!(
        "installing systemd unit {}...",
        recipe.service_name
    ));

    // Demo recipes carry no secrets, so this resolves to Ok(None) and the
    // unit gets no EnvironmentFile line. The writer itself is live code in
    // the full version; its escaping rules stay pinned by secrets.rs tests.
    let env_map: BTreeMap<String, String> = BTreeMap::new();
    let env_file = write_env_file(recipe.service_name, &env_map).ok().flatten();

    let spec = UnitSpec {
        service_name: recipe.service_name,
        working_dir: &project_dir,
        exec_start: &exec_start,
        description: &format!("demo: {}", recipe.description),
        env_file: env_file.as_deref(),
        extra_env: &[],
        res: recipe.res,
    };
    if let Err(e) = create_unit(&spec) {
        report_err(&mut result, format!("unit creation failed: {e:#}"));
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
    }

    // ── start + verify (polling; see units.rs / FINDINGS.md) ──
    // A non-zero exit from `systemctl --user start` means the unit/job was
    // rejected outright (bad unit, dead user manager), not merely slow to
    // activate — with `--no-block` that must not be masked as a later
    // activation check (same discipline as selftest.rs). Fail closed.
    // wait_until_active budgets a grace period for the queued async job, so a
    // healthy unit whose first is-active poll wins the race is not miscounted
    // as a crash.
    emit("starting service...");
    let started = Command::new("systemctl")
        .args(["--user", "start", "--no-block", recipe.service_name])
        .status();
    match started {
        Ok(status) if status.success() => {}
        Ok(_) => {
            report_err(
                &mut result,
                format!(
                    "systemctl start rejected the unit {} (non-zero exit)",
                    recipe.service_name
                ),
            );
            rollback_failed(
                &mut result,
                recipe.service_name,
                &project_dir,
                Some(port),
                &emit,
            );
            return result;
        }
        Err(_) => {
            report_err(&mut result, "failed to invoke systemctl start".into());
            rollback_failed(
                &mut result,
                recipe.service_name,
                &project_dir,
                Some(port),
                &emit,
            );
            return result;
        }
    }

    match wait_until_active(recipe.service_name) {
        StartOutcome::Active => {}
        StartOutcome::Failed => {
            let logs = service_logs(recipe.service_name, 20);
            report_err(
                &mut result,
                format!("Service crashed immediately after start:\n{}", short(&logs)),
            );
            rollback_failed(
                &mut result,
                recipe.service_name,
                &project_dir,
                Some(port),
                &emit,
            );
            return result;
        }
        StartOutcome::TimeoutWhileActivating => {
            let logs = service_logs(recipe.service_name, 20);
            report_err(
                &mut result,
                format!(
                    "Service did not become active within {}s:\n{}",
                    super::units::START_BUDGET.as_secs(),
                    short(&logs)
                ),
            );
            rollback_failed(
                &mut result,
                recipe.service_name,
                &project_dir,
                Some(port),
                &emit,
            );
            return result;
        }
        StartOutcome::SystemdUnavailable => {
            report_err(&mut result, "systemd user manager unavailable".into());
            rollback_failed(
                &mut result,
                recipe.service_name,
                &project_dir,
                Some(port),
                &emit,
            );
            return result;
        }
    }

    // Every catalog service binds loopback: VERT's unit runs our static
    // server (`serve.rs` binds Ipv4Addr::LOCALHOST), SearXNG's settings.yml is
    // patched to 127.0.0.1 above, and Memos is started with
    // `--addr 127.0.0.1`. This check is the last line of defence for a recipe
    // change that regresses that: a loud warn: must appear, never a silent
    // "localhost URL" while the port is reachable from the LAN.
    if listens_non_loopback(port) {
        emit(&format!(
            "warn: {} is listening on a non-loopback address (port {port}) — \
             anything on your network can reach it. This recipe regression must \
             be fixed: bind the app to 127.0.0.1 like the other services.",
            recipe.service_name
        ));
    }

    // Registration is the last step; mark it in the journal so a later
    // reconciliation knows whether a leftover entry belongs to a deployed
    // (live) service or to an interrupted deploy. `state.json` is written
    // atomically, so `Registering` + a present registry entry means "live".
    journal::mark(recipe.service_name, DeployState::Registering);
    crate::state::register(
        recipe.service_name,
        crate::state::ServiceEntry {
            unit_name: recipe.service_name.into(),
            project_dir: project_dir.to_string_lossy().into_owned(),
            url: analysis.url.clone(),
            urls: vec![format!("http://localhost:{port}")],
        },
    )
    .context("registering state")
    .ok();
    journal::mark(recipe.service_name, DeployState::Registered);

    result.service_names = vec![recipe.service_name.into()];
    result.urls = vec![format!("http://localhost:{port}")];
    result
}

/// True when `ss`'s local-address column (`addr:port`) does not fall on
/// loopback. `*` is the v4 wildcard, `[::]` the v6 one.
fn address_is_non_loopback(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    !matches!(host, "127.0.0.1" | "[::1]" | "localhost")
}

/// True when some process is listening on `port` on a non-loopback address.
/// Reads the same `ss` table the scan renders; ownership attribution stays
/// out of it.
fn listens_non_loopback(port: u16) -> bool {
    let Ok(out) = Command::new("ss").args(["-tlnp"]).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(crate::analyzer::probe::parse_ss_row)
        .any(|p| p.port == port && address_is_non_loopback(&p.address))
}

/// Roll a failed deploy back completely — the README's "clean removal"
/// promise applied to a failed attempt, not just to an explicit delete: stop
/// and remove any unit and env file created so far, wipe the cloned project
/// tree (with its build caches) so nothing is left behind, and wait for the
/// chosen port to be reusable again.
fn rollback_failed(
    result: &mut HostResult,
    service: &str,
    project_dir: &Path,
    port: Option<u16>,
    emit: &dyn Fn(&str),
) {
    let mut names = result.service_names.clone();
    if !names.iter().any(|n| n == service) {
        names.push(service.to_string());
    }
    for name in &names {
        remove_unit(name);
        super::secrets::remove_env_file(name);
    }
    if !wipe_project_dir(&project_dir.to_string_lossy()) {
        let msg = format!(
            "cleanup: could not remove the project tree left behind by this failed deploy: {}",
            project_dir.display()
        );
        result.errors.push(msg.clone());
        emit(&format!("! {msg}"));
    }
    if let Some(port) = port {
        wait_port_released(port, std::time::Duration::from_secs(3));
    }
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
}

/// Wait (best-effort) until `port` on loopback is bindable again after a
/// service stop, so the next deployment or user app can reuse it.
fn wait_port_released(port: u16, budget: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if super::port::bind_ok(port) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Wipe a cloned project directory (and the `.ghost-cache` inside it).
///
/// Safety guard: only directories that actually live under services_dir are
/// removed, so a corrupted registry entry can never point the rm at
/// arbitrary paths. Returns true when the directory was removed.
fn wipe_project_dir(project_dir: &str) -> bool {
    let dir = std::path::PathBuf::from(project_dir);
    let services_base = crate::paths::services_dir();
    if dir.is_dir() && dir.parent() == Some(services_base.as_path()) {
        super::gitclone::force_remove_all(&dir).is_ok()
    } else {
        false
    }
}

/// Stop, delete the unit, wipe the cloned project directory (including the
/// `.ghost-cache` living inside it), release the announced port and forget
/// the service. Used by "My Services" → delete.
///
/// GhostProvider cleans up the resources it manages; applications may still
/// leave their own state (databases, external sockets) elsewhere.
pub fn remove_unit_and_state(service_name: &str) {
    // Read the registry entry BEFORE unregistering: the port and project dir
    // we clean up come from it.
    let entry = crate::state::get(service_name);

    remove_unit(service_name);
    super::secrets::remove_env_file(service_name);

    if let Some(e) = entry {
        // Wipe the clone together with its build caches.
        wipe_project_dir(&e.project_dir);

        // Free the announced port: systemctl stop is asynchronous from the
        // listener's point of view; wait briefly for the socket to close.
        for url in &e.urls {
            if let Some(port) = url
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
            {
                wait_port_released(port, std::time::Duration::from_secs(3));
            }
        }
        // Full-removal history for the Logs → Crash screen.
        let url = e.urls.first().map(String::as_str).unwrap_or("?");
        crate::crashlog::removed(service_name, url);
    }

    crate::state::unregister(service_name).ok();
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    // An explicit delete also settles any leftover journal entry for the
    // service, so a later reconciliation does not try to clean it again.
    journal::clear(service_name);
}

/// Does a leftover journal entry require actual cleanup, or only be forgot?
///
/// Reconciliation must never tear down a *live* service: `Registered` entries
/// are settlements of a finished deploy, and a `Registering` entry whose
/// registration already landed in `state.json` belongs to a service that is
/// up and should keep running. Only truly unfinished deploys are returned as
/// needing cleanup.
fn stale_action(state: DeployState, registered: bool) -> bool {
    match state {
        DeployState::Registered => false,
        DeployState::Registering if registered => false,
        DeployState::Deploying | DeployState::Registering => true,
    }
}

/// What a single [`cleanup_stale`] pass actually removed, so the caller can
/// tell "leftovers wiped" from "nothing was there" — the latter is a silent
/// journal settle rather than a spurious `cleanup:` notice.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CleanResult {
    unit_removed: bool,
    env_removed: bool,
    tree_removed: bool,
}

impl CleanResult {
    fn did_anything(&self) -> bool {
        self.unit_removed || self.env_removed || self.tree_removed
    }
}

/// Remove everything a *single* in-flight deploy recorded in the journal may
/// have left behind, whether or not `state.json` mentions the service.
///
/// Idempotent: safe to run repeatedly, and to run while the tail of an
/// interrupted deploy worker is still winding down (both sides touch the same
/// paths and tolerate already-absent files). Reports what it removed so the
/// caller can decide whether a journal entry should survive (leftovers may
/// still be re-created by a living worker) or be settled right away.
fn cleanup_stale(service: &str, url: &str) -> CleanResult {
    let mut report = CleanResult::default();

    let unit_path = crate::paths::user_unit_dir().join(format!("{service}.service"));
    if unit_path.exists() {
        report.unit_removed = true;
    }
    remove_unit(service);

    let env_path = super::secrets::env_file_for(service);
    if env_path.exists() {
        report.env_removed = true;
    }
    super::secrets::remove_env_file(service);

    // The journal may outlive the registry entry (state.json is written last,
    // during `Registering`): derive the clone dir from the repository URL,
    // exactly as `clone_repo` would name it. The services_dir parent guard in
    // `wipe_project_dir` still applies.
    if let Some((_, repo)) = super::github::parse_github_url(url) {
        let dir = crate::paths::services_dir().join(safe_dirname(&repo));
        if dir.is_dir() {
            report.tree_removed = wipe_project_dir(&dir.to_string_lossy());
        }
    }

    // Free any announced port. Must be read BEFORE unregistering.
    if let Some(e) = crate::state::get(service) {
        for url in &e.urls {
            if let Some(port) = url
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
            {
                wait_port_released(port, std::time::Duration::from_secs(3));
            }
        }
    }
    crate::state::unregister(service).ok();
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    report
}

/// Where a reconciliation runs — it decides how an interrupted deploy is
/// tagged in the Crash screen's history.
///
/// * [`ReconcileBasis::Exit`] — a live in-flight deploy was aborted while this
///   panel was alive: the user quit or a termination signal arrived, and
///   [`quiesce`] has already stopped its writers.
/// * [`ReconcileBasis::Startup`] / [`ReconcileBasis::Sweep`] — leftovers of a
///   deploy whose process died out-of-band (kill, shutdown, reboot) were found
///   and removed later.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReconcileBasis {
    Exit,
    Startup,
    Sweep,
}

/// `reconcile_stale` with the default history tag (a `Startup` pass).
pub fn reconcile_stale(keep_if_inflight: bool) -> Vec<String> {
    reconcile_stale_with_basis(keep_if_inflight, ReconcileBasis::Startup)
}

/// Sweep leftover deploy-journal entries and clean their artifacts with a
/// full "clean removal" (unit + env file + project tree + registry slot).
///
/// Called on the next launch (TUI and `__deploy`) and on exit while a deploy
/// was in flight — but only *after* [`quiesce`] has stopped and waited for the
/// in-process worker, so this removal is final rather than racing a writer.
/// It never touches finished (`Registered`) or live (`Registering` with a
/// registry slot) services. `keep_if_inflight = true` (used by the surviving
/// `tui_v2` fork and unit tests) retains a still-running entry for the next
/// launch to re-verify idempotently; the live exit paths always pass `false`
/// because they have already quiesced. Returns human-readable notice lines for
/// the deploy log so the panel surfaces what it cleaned.
///
/// Every entry this pass actually settles is appended to the Crash screen's
/// history (`crash.log`), tagged by [`basis`](ReconcileBasis): an `Exit` pass
/// records the deploy as aborted at exit; `Startup`/`Sweep` passes record it
/// as recovered leftovers.
pub fn reconcile_stale_with_basis(keep_if_inflight: bool, basis: ReconcileBasis) -> Vec<String> {
    let mut msgs = Vec::new();
    for (service, entry) in journal::entries() {
        if !stale_action(entry.state, crate::state::get(&service).is_some()) {
            journal::clear(&service);
            continue;
        }
        let report = cleanup_stale(&service, &entry.url);
        let defer = keep_if_inflight && deploy_in_flight();
        if report.did_anything() || defer {
            msgs.push(format!(
                "cleanup: interrupted deploy of {service} ({}) — removing leftover unit, env file and project tree",
                entry.url
            ));
        }
        if defer {
            // The worker may still re-create files until the process dies; let
            // the next launch finish the job (idempotent). Not recorded in the
            // crash history: nothing is final yet.
            msgs.push(format!(
                "cleanup: {service}: deploy still winding down here — finalizing on next launch"
            ));
        } else {
            if report.did_anything() {
                msgs.push(format!("cleanup: {service}: removed"));
            } else {
                // Nothing to remove: the interruption left no artifacts (or the
                // previous pass already wiped them). Settle the entry — but keep a
                // visible closure line in the log so the deferred-cleanup flow
                // (interrupted → finalizing on next launch → settled) is traceable.
                msgs.push(format!(
                    "cleanup: {service}: no leftovers to remove; journal entry settled"
                ));
            }
            journal::clear(&service);
            match basis {
                ReconcileBasis::Exit => {
                    crate::crashlog::interrupted(&service, &entry.url);
                }
                ReconcileBasis::Startup | ReconcileBasis::Sweep => {
                    crate::crashlog::recovered(&service, &entry.url, report.did_anything());
                }
            }
        }
    }
    for m in &msgs {
        crate::tui::workers::append_deploy_log(m);
    }
    msgs
}

/// True while a deploy pipeline is running in this process. The TUI's exit
/// path consults it to decide whether it must quiesce (stop the deploy's
/// writers) before reconciling.
pub fn deploy_in_flight() -> bool {
    DEPLOY_IN_FLIGHT.load(Ordering::Relaxed)
}

/// True once a graceful exit is in progress. The pipeline polls this between
/// phases: an exit path owns the final clean removal, so a step that has not
/// started must not start, and a step that is mid-flight returns without
/// journaling a fresh terminal state.
fn interrupted() -> bool {
    super::cancel::is_exiting()
}

/// Stop every writer an in-flight deploy owns and wait (bounded by `timeout`)
/// for the worker to observe [`interrupted`] and unwind. This is called on the
/// exit path *before* the clean removal so that removal is final: it kills the
/// deploy's host-side descendants (a running `git clone`/build step) and stops
/// any orphaned `ghost-*` transient build units, then lets the worker notice and
/// return. Once this returns, no deploy-owned process is still writing into the
/// tree that `reconcile_stale` is about to wipe.
pub fn quiesce(timeout: std::time::Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while deploy_in_flight() && std::time::Instant::now() < deadline {
        stop_ghost_units();
        super::cancel::kill_descendants(std::process::id());
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Transient-unit name prefixes this binary creates while deploying. Unlike
/// deployed `demo-*.service` units they are managed by the user manager, not
/// by the panel process, so a killed panel (SIGKILL, power loss) leaves them
/// running for up to their `RuntimeMaxSec`. They are only stopped by a sweep
/// that holds the deploy lock, which proves no deploy is live here. See
/// `sandbox.rs` (`ghost-build-*`) and `egress.rs` (`ghost-egress-*`).
const GHOST_UNIT_PREFIXES: &[&str] = &["ghost-build-", "ghost-egress-"];

/// Names of every ghost transient unit currently loaded in the user manager.
fn ghost_units() -> Vec<String> {
    let Ok(out) = Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--all",
            "--type=service",
            "--plain",
            "--no-legend",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_ghost_units(&String::from_utf8_lossy(&out.stdout))
}

/// Map `systemctl --user list-units --plain --no-legend` output to the ghost
/// unit names in it. Split out so unit tests exercise the parsing with
/// synthetic rows and never need a live user manager.
fn parse_ghost_units(output: &str) -> Vec<String> {
    let mut units: Vec<String> = output
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .filter(|name| GHOST_UNIT_PREFIXES.iter().any(|p| name.starts_with(p)))
        .collect();
    units.sort_unstable();
    units.dedup();
    units
}

/// Stop and re-arm every orphaned ghost unit. Returns how many were stopped.
fn stop_ghost_units() -> usize {
    let mut stopped = 0;
    for unit in ghost_units() {
        let ok = Command::new("systemctl")
            .args(["--user", "stop", &unit])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            stopped += 1;
        }
        // `--collect` units vanish once stopped; clear any failed state so a
        // later sweep is not confused by a dead-but-loaded listing.
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &unit])
            .output();
    }
    stopped
}

/// Outcome of a [`sweep_stale`] pass, reported by the `__cleanup` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// The deploy lock is held by another process (a deploy is running, or
    /// another sweeper is mid-pass): this pass deferred and touched nothing.
    Deferred,
    /// The pass ran under the lock; `msgs` are the human-readable notices of
    /// what was removed (empty = nothing was there).
    Cleaned(Vec<String>),
}

/// Background sweep for the `demo-ghostprovider-cleanup` systemd user timer.
///
/// This is the only entry point allowed to kill ghost transient units: it runs
/// exclusively while holding the deploy lock, which guarantees no deploy is
/// live in this user session, so every `ghost-build-*` / `ghost-egress-*` unit
/// it finds is an orphan of an interrupted deploy. Ghost units are stopped
/// BEFORE the journal reconciliation removes their project trees, so a
/// still-running build process cannot keep the directory (or its caches)
/// busy. A `Deferred` pass is silent: the timer simply runs again later.
pub fn sweep_stale() -> SweepOutcome {
    let Some(_lock) = super::lock::try_lock_exclusive() else {
        return SweepOutcome::Deferred;
    };
    let killed = stop_ghost_units();
    let mut msgs = reconcile_stale_with_basis(false, ReconcileBasis::Sweep);
    if killed > 0 {
        let line = format!("cleanup: stopped {killed} orphaned ghost build/probe unit(s)");
        crate::tui::workers::append_deploy_log(&line);
        msgs.insert(0, line);
        crate::crashlog::ghost_stopped(killed);
    }
    SweepOutcome::Cleaned(msgs)
}

/// Top-level handler for the `__cleanup` subcommand (cleanup timer / manual
/// run): runs a lock-guarded sweep and reports the outcome on stdout (captured
/// by journald for the unit).
pub fn cleanup_cmd() -> anyhow::Result<()> {
    use std::io::Write;
    match sweep_stale() {
        SweepOutcome::Deferred => {
            let _ = write!(
                std::io::stdout(),
                "cleanup: deferred — a deployment is in progress\n"
            );
        }
        SweepOutcome::Cleaned(msgs) => {
            if msgs.is_empty() {
                let _ = write!(std::io::stdout(), "cleanup: nothing to remove\n");
            } else {
                for m in &msgs {
                    let _ = write!(std::io::stdout(), "{m}\n");
                }
            }
        }
    }
    Ok(())
}

fn short(s: &str) -> String {
    s.chars().take(300).collect()
}

/// The last few lines of a step's stdout, so a `pnpm`/`go` failure that
/// printed to stdout (progress/error lines) is visible in the report even
/// when stderr only carried the systemd-run status block.
fn tail(s: &str) -> String {
    let mut lines: Vec<&str> = s.lines().rev().take(12).collect();
    lines.reverse();
    let tail = lines.join("\n");
    let tail = tail.chars().take(600).collect::<String>();
    if tail.trim().is_empty() {
        String::new()
    } else {
        format!("\n--- stdout (tail) ---\n{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_line_keeps_verdicts_and_warnings_only() {
        let kept = [
            "! pre-flight failed, aborting",
            "sandbox: FULL",
            "! sandbox: ALMOST — GHOSTPROVIDER_BUILD_USER set but unusable; refusing to deploy without full isolation",
            "! sandbox: NO — refusing to build without isolation (the sandbox is mandatory)",
            "listening on http://localhost:8888",
            "! public-test-token leaked in output",
            "provision: bun 1.4.2 (glibc) → .ghost-cache/toolbox/bin",
        ];
        for line in kept {
            assert!(screen_line(line), "expected to keep: {line}");
        }
        let dropped = [
            "pre-flight checks...",
            "cloning repository...",
            "build...",
            "build: seeded Go module cache (193 module(s) ready)",
            "proceeding without pinned tools (host bun reaches the registry)",
            "installing systemd unit demo-memos...",
            "probing runtime egress...",
            "starting service...",
            "source tree download complete",
        ];
        for line in dropped {
            assert!(!screen_line(line), "expected to drop: {line}");
        }
    }

    /// README promise: deleting a service wipes the clone together with its
    /// caches — but only inside services_dir.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
    fn wipe_removes_clone_inside_services_dir_only() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "dgp-wipe-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }

        // 1) A clone inside services_dir is removed, caches included.
        let base = crate::paths::services_dir();
        let project = base.join("memos");
        std::fs::create_dir_all(project.join(".ghost-cache/npm")).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        assert!(wipe_project_dir(&project.to_string_lossy()));
        assert!(!project.exists(), "clone must be gone, caches included");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
    fn wipe_refuses_paths_outside_services_dir() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-wipe-guard-{}", std::process::id()));
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }
        let outside = tmp.join("precious");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.me"), "do not touch").unwrap();

        assert!(!wipe_project_dir(&outside.to_string_lossy()));
        assert!(outside.exists(), "paths outside services_dir must survive");

        // A bare services_dir itself is not a project clone either.
        assert!(!wipe_project_dir(tmp.to_string_lossy().as_ref()));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// README promise extended to failed deploys: when a deployment fails the
    /// rollback wipes the project tree (caches included), leaves no unit, and
    /// keeps the original error — nothing of the failed attempt is left behind.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
    fn rollback_failed_wipes_project_tree_on_failed_deploy() {
        let _env = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "dgp-rollback-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }

        let project = crate::paths::services_dir().join("memos");
        std::fs::create_dir_all(project.join(".ghost-cache/npm")).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        let mut result = HostResult {
            errors: vec!["Build step failed".into()],
            ..Default::default()
        };
        let notes = std::cell::RefCell::new(Vec::new());
        rollback_failed(&mut result, "demo-memos", &project, None, &|m| {
            notes.borrow_mut().push(m.to_string())
        });

        assert!(
            !project.exists(),
            "failed deploy must wipe the project tree"
        );
        assert_eq!(
            result.errors,
            vec!["Build step failed".to_string()],
            "rollback must not swallow the original error"
        );
        assert!(notes.borrow().is_empty(), "no cleanup warnings on success");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn released_port_is_detected_immediately() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(wait_port_released(port, std::time::Duration::from_secs(2)));
    }

    #[test]
    fn occupied_port_times_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!wait_port_released(
            port,
            std::time::Duration::from_millis(300)
        ));
    }

    /// A wildcard or LAN-IP listener must classify as exposed; loopback must
    /// not. This is the classification behind the deploy-time `warn:`.
    #[test]
    fn non_loopback_classification() {
        assert!(address_is_non_loopback("*:23920"));
        assert!(address_is_non_loopback("[::]:23920"));
        assert!(address_is_non_loopback("0.0.0.0:5222"));
        assert!(address_is_non_loopback("192.168.0.5:8080"));
        assert!(!address_is_non_loopback("127.0.0.1:8080"));
        assert!(!address_is_non_loopback("[::1]:8080"));
        assert!(!address_is_non_loopback("localhost:8080"));
    }

    /// Reconciliation must clean only genuinely unfinished deploys; a finished
    /// or already-registered service is never torn down.
    #[test]
    fn stale_action_cleans_unfinished_but_preserves_live_services() {
        // Registered: deploy finished; only forget the journal entry.
        assert!(!stale_action(DeployState::Registered, true));
        assert!(!stale_action(DeployState::Registered, false));
        // Registering with the registry slot present: service is live.
        assert!(!stale_action(DeployState::Registering, true));
        // Registering without the slot: registration never landed → clean.
        assert!(stale_action(DeployState::Registering, false));
        // Still cloning/building: always clean.
        assert!(stale_action(DeployState::Deploying, true));
        assert!(stale_action(DeployState::Deploying, false));
    }

    /// Point every XDG root at a fresh temp dir so a reconcile pass can run
    /// against isolated journal/registry/clone/unit paths (real systemctl
    /// calls still fail harmlessly because the unit does not exist).
    #[allow(unsafe_code)] // test-only env mutation (XDG roots)
    fn isolated_env(tag: &str) -> (std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
        let lock = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "dgp-reconcile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        unsafe {
            std::env::set_var("XDG_DATA_HOME", tmp.join("data"));
            std::env::set_var("XDG_STATE_HOME", tmp.join("state"));
            std::env::set_var("XDG_CONFIG_HOME", tmp.join("config"));
        }
        (tmp, lock)
    }

    /// Leftovers wiped + entry cleared when a deploy finished unwinding.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn reconcile_wipes_leftovers_and_clears_entry() {
        let (tmp, _env) = isolated_env("wipes");
        journal::begin("demo-memos", "https://github.com/usememos/memos");
        let project = crate::paths::services_dir().join("memos");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        let msgs = reconcile_stale(false);

        assert!(!project.exists(), "clone tree must be removed");
        assert!(journal::entries().is_empty(), "entry settled after removal");
        assert!(
            msgs.iter()
                .any(|m| m.contains("demo-memos") && m.contains("removed")),
            "notices must report the removal: {msgs:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Nothing left behind → the entry is settled without claiming a removal,
    /// but with a visible closure line so the deferred flow stays traceable.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn reconcile_settles_empty_leftover_with_closure_line() {
        let (tmp, _env) = isolated_env("settle");
        journal::begin("demo-memos", "https://github.com/usememos/memos");

        let msgs = reconcile_stale(false);

        assert!(journal::entries().is_empty(), "silent entries are settled");
        assert_eq!(msgs.len(), 1, "one closure line: {msgs:?}");
        assert!(
            msgs[0].contains("settled") && msgs[0].contains("no leftovers"),
            "closure must not claim a removal: {msgs:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Early exit while the deploy worker is still alive must keep the journal
    /// entry so the next launch re-verifies instead of leaving re-created
    /// artifacts as permanent leftovers.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation + in-flight flag
    fn reconcile_keeps_entry_while_deploy_in_flight() {
        let (tmp, _env) = isolated_env("inflight");
        journal::begin("demo-memos", "https://github.com/usememos/memos");
        let project = crate::paths::services_dir().join("memos");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        DEPLOY_IN_FLIGHT.store(true, Ordering::Relaxed);
        let keep = reconcile_stale(true);
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);

        assert!(
            keep.iter().any(|m| m.contains("finalizing on next launch")),
            "exit path must announce deferred finalization: {keep:?}"
        );
        assert_eq!(
            journal::entries().len(),
            1,
            "entry retained for next launch"
        );

        let settle = reconcile_stale(false);
        assert!(
            journal::entries().is_empty(),
            "next launch settles the entry"
        );
        assert!(!project.exists(), "and finishes wiping the tree");
        let _ = std::fs::remove_dir_all(&tmp);
        // The first (deferred) pass already wiped everything, so the next
        // launch has nothing left to remove — it settles the entry with one
        // closure line instead of a duplicate removal claim.
        assert_eq!(settle.len(), 1, "one closure line: {settle:?}");
        assert!(
            settle[0].contains("settled") && settle[0].contains("no leftovers"),
            "closure must not claim a removal: {settle:?}"
        );
    }

    /// Synthetic `systemctl list-units --plain --no-legend` rows: only the
    /// ghost build/egress units survive the filter, in sorted order.
    #[test]
    fn parse_ghost_units_picks_only_ghost_units() {
        let output = "\
demo-vert.service                        loaded active running   demo: VERT
ghost-build-1a2b.service                 loaded active running   (transient)
demo-searxng.service                     loaded inactive dead    demo: SearXNG
ghost-egress-9c0d.service                loaded active running   (transient)
run-user-1000.service                    loaded active exited    (transient)
ghost-build-1a2b.service                 loaded active running   (dup row)
";
        assert_eq!(
            parse_ghost_units(output),
            vec![
                "ghost-build-1a2b.service".to_string(),
                "ghost-egress-9c0d.service".to_string(),
            ]
        );
        assert!(parse_ghost_units("demo-vert.service\nrun-abc.service\n").is_empty());
        assert!(parse_ghost_units("").is_empty());
    }

    /// A sweep must never run while the deploy lock is held — that is the
    /// invariant that keeps the background timer from tearing down a live
    /// deploy in another process.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn sweep_defers_while_lock_held() {
        let (tmp, _env) = isolated_env("sweepdef");
        let _lock = super::super::lock::try_lock_exclusive().expect("hold the deploy lock");
        assert_eq!(sweep_stale(), SweepOutcome::Deferred);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A full sweep under a free lock cleans a stale journal entry and reports
    /// the removal notice; `ghost_units()` runs against the live user manager
    /// but may only ever stop units this same binary would create, and the
    /// real manager has none during the isolated test.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn sweep_cleans_interrupted_deploy_when_lock_free() {
        let (tmp, _env) = isolated_env("sweepclean");
        journal::begin("demo-memos", "https://github.com/usememos/memos");
        let project = crate::paths::services_dir().join("memos");
        std::fs::create_dir_all(project.join(".ghost-cache")).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        let outcome = sweep_stale();
        let SweepOutcome::Cleaned(msgs) = outcome else {
            panic!("lock is free in this test, sweep must run, got {outcome:?}");
        };
        assert!(!project.exists(), "stale tree must be removed");
        assert!(journal::entries().is_empty(), "entry settled");
        assert!(
            msgs.iter()
                .any(|m| m.contains("demo-memos") && m.contains("removed")),
            "notices must report the removal: {msgs:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
