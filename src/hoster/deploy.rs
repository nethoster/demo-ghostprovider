//! Deploy sequence for service manifests (user `service.yaml` files — the
//! built-in URL catalog and the shipped reference examples were removed in
//! v0.0.44).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

use super::gitclone;
use super::journal::{self, DeployState};
use super::models::{HostResult, RepoAnalysis};
use super::port::{find_free_port, wait_until_port_open};
use super::recipes::DemoRecipe;
use super::sandbox::run_build_cmd;
use super::secrets::write_env_file;
use super::units::{
    StartOutcome, UnitSpec, create_unit, remove_unit, service_logs, start_unit, wait_until_active,
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
) -> Option<(PathBuf, bool)> {
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
    // Fresh = the materializer just wrote every blob from the pin (the
    // worktree is pristine upstream content); a reuse may carry the
    // previous build's output.
    let fresh = status.last_message == "source tree download complete";
    Some((dir, fresh))
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

/// Placeholders in `run.env` values: `{port}` is the deploy's chosen port
/// and `{secret}` the deploy's generated hex (same value for every entry —
/// if two vars must match, they do). Validation guarantees no other tokens.
fn resolve_env_value(value: &str, port: u16, secret: &str) -> String {
    value
        .replace("{port}", &port.to_string())
        .replace("{secret}", secret)
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
    // The netns deny-all companion socket holds the host-facing port; it
    // must go too or the next bind (redeploy, other apps) fails.
    let socket = crate::paths::user_unit_dir().join(format!("{service_name}.socket"));
    if socket.is_file() {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &format!("{service_name}.socket")])
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
/// the deploy subject (`source:`, always first), verification and warning
/// lines plus the final reachable URL. Pure progress chatter — pre-flight,
/// build steps, unit install, service start — is dropped; the final verdict
/// line is what matters.
fn screen_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('!')
        || t.starts_with("warn: ")
        || t.starts_with("auto-repair: ")
        || t.starts_with("sandbox: ")
        || t.starts_with("source: ")
        || t.starts_with("provision: ")
        || t.starts_with("egress: ")
        || t.contains("listening on ")
}

/// One-line deploy subject for the laconic output: what is being deployed.
/// Printed before any gate verdict so `sandbox: FULL` reads in context
/// instead of hanging as the unexplained first line.
fn source_line(manifest: &super::manifest::ServiceManifest) -> String {
    let what = manifest
        .owner_name()
        .map(|(o, n)| format!("{o}/{n}"))
        .unwrap_or_else(|| manifest.service.id.clone());
    let pin_display = if super::manifest::is_full_sha(&manifest.source.commit) {
        manifest.source.commit.chars().take(7).collect::<String>()
    } else {
        format!("{} (branch)", manifest.source.commit)
    };
    format!(
        "source: {what} @ {pin_display} (profile {}, tools [{}])",
        manifest.build.profile,
        manifest.tools.join(", ")
    )
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

/// Deploy one validated user manifest (`service.yaml`).
///
/// The only scripted/interactive deploy entry left (v0.0.44, demo-declutter:
/// the built-in URL catalog is gone): sandbox FULL gate, preflight,
/// deploy lock + journal, [`deploy_service`], journal settle. The manifest
/// MUST already be validated (`ServiceManifest::load_from_file` does that);
/// this reuses the audited pipeline verbatim via
/// [`super::manifest::to_leaked_recipe`].
pub fn run_manifest_deployment(
    mut manifest: super::manifest::ServiceManifest,
    patch_path: Option<&Path>,
    log: &dyn Fn(String),
) -> DeployOutcome {
    let screen = |line: String| {
        if screen_line(&line) {
            log(line);
        }
    };
    // Subject-first order: the `source:` line, then gate verdicts.
    screen(source_line(&manifest));
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
    // The initial recipe serves the gates (preflight, journal, analysis
    // language); the loop below re-derives it per attempt so an applied
    // auto-repair takes effect. The retry deliberately skips preflight:
    // tools a repair just derived are provisioned by the toolbox inside
    // the deploy.
    let recipe = super::manifest::to_leaked_recipe(&manifest);
    let url = manifest.source.git.clone();
    let (owner, name) = manifest
        .owner_name()
        .unwrap_or_else(|| ("user".to_string(), manifest.service.id.clone()));

    let issues = super::preflight::preflight_check(recipe.tools);
    if !issues.is_empty() {
        for i in issues {
            screen(format!("! {i}"));
        }
        screen("! pre-flight failed, aborting".into());
        return DeployOutcome::Rejected("preflight");
    }

    let language: String = recipe.language.into();
    let analysis = RepoAnalysis {
        url: url.clone(),
        owner,
        name,
        language,
        exists: true,
        clone_path: None,
        errors: vec![],
    };
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
    journal::begin(recipe.service_name, &url);
    if super::cancel::is_exiting() {
        journal::clear(recipe.service_name);
        DEPLOY_IN_FLIGHT.store(false, Ordering::Relaxed);
        return DeployOutcome::Rejected("exiting");
    }

    // ── deploy, with ONE auto-repair retry ──
    // A failed attempt may return a repair instead of errors ("the tree
    // declares frontend build steps this manifest lacks"): patch the
    // manifest on disk and run the whole deployment again. A second
    // repair request, or a patch that will not persist, is a failure —
    // never a success.
    let mut repaired = false;
    let result = loop {
        let recipe = super::manifest::to_leaked_recipe(&manifest);
        let result = deploy_service(
            &analysis,
            &recipe,
            None,
            DeployHooks {
                on_status: Some(&|line| screen(line.to_string())),
            },
        );
        if let Some(repair) = result.repair.clone() {
            if !repaired {
                repaired = true;
                apply_repair(&mut manifest, &repair);
                match persist_manifest(&manifest, patch_path, "auto-repair") {
                    Ok(()) => {
                        screen("auto-repair: manifest patched — retrying the deploy once".into());
                        continue;
                    }
                    Err(e) => {
                        let mut result = result;
                        result
                            .errors
                            .push(format!("auto-repair: cannot patch the manifest: {e:#}"));
                        break result;
                    }
                }
            }
            let mut result = result;
            result
                .errors
                .push("auto-repair: repair budget exhausted — manual fix required".into());
            break result;
        }
        break result;
    };

    // ── auto-egress: the deploy opened hosts the tree declared ──
    // Persist them into the manifest (allow + auto=Some(true)) so the unit
    // renders them from now on and a redeploy keeps the same list even
    // without re-detecting. Only on a clean success and only when the
    // manifest's allow is still empty — a concurrent manual edit wins.
    if result.ok() && !result.egress.is_empty() && manifest.egress.allow.is_empty() {
        manifest.egress.allow = result.egress.clone();
        manifest.egress.auto = Some(true);
        match persist_manifest(&manifest, patch_path, "auto-egress") {
            Ok(()) => {
                screen(format!(
                    "egress: auto-detected {} host(s) — saved to the manifest (editable in the Egress menu)",
                    result.egress.len()
                ));
            }
            Err(e) => {
                screen(format!(
                    "warn: egress: cannot save the auto-detected list: {e:#}"
                ));
            }
        }
    }

    for u in &result.urls {
        screen(format!("listening on {u}"));
    }
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

/// Load `service.yaml` from disk and deploy it (used by `__deploy --manifest`).
pub fn run_manifest_file(path: &Path, log: &dyn Fn(String)) -> DeployOutcome {
    match super::manifest::ServiceManifest::load_from_file(path) {
        Ok(m) => {
            log(format!("manifest: {} ({})", m.service.id, path.display()));
            for line in m.plan_text().lines() {
                log(line.to_string());
            }
            run_manifest_deployment(m, Some(path), log)
        }
        Err(e) => {
            let msg = format!("! invalid manifest {}: {e:#}", path.display());
            // Emit through the screen filter path manually: callers of
            // run_manifest_file already forward everything, so push directly.
            log(msg);
            DeployOutcome::Rejected("bad-manifest")
        }
    }
}

/// Build, install, and start one service from a validated manifest/recipe.
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

    // ── pin resolution ──
    // recipe.commit is either an exact 40-hex pin or a ref name (branch
    // tracking). A ref is resolved to the tip SHA right now; the deploy then
    // proceeds exactly as if that SHA had been pinned — the materializer and
    // the anti-TOFU check below only ever see the resolved commit.
    let pin: String = if super::manifest::is_full_sha(recipe.commit) {
        recipe.commit.to_string()
    } else {
        let url = format!(
            "https://github.com/{}/{}.git",
            analysis.owner, analysis.name
        );
        match gitclone::resolve_ref(&url, recipe.commit) {
            Ok(sha) => {
                emit(&format!(
                    "source: branch {} resolved to {}",
                    recipe.commit,
                    &sha[..7]
                ));
                sha
            }
            Err(e) => {
                let refname = recipe.commit;
                report_err(
                    &mut result,
                    format!(
                        "cannot resolve '{refname}' of {}/{}: {e:#}",
                        analysis.owner, analysis.name
                    ),
                );
                return result;
            }
        }
    };

    emit("cloning repository...");
    let Some((project_dir, fresh_clone)) = clone_repo(analysis, work_dir, Some(&pin)) else {
        result
            .errors
            .push("git clone failed after retries (check network connection)".into());
        return result;
    };

    // ── pinned commit (anti-TOFU) ──
    // The recipe named one specific commit — either pinned directly or
    // resolved from a tracked branch just above — and a deployment must
    // build exactly that, never whichever tip downloads at build time.
    // `clone_repo` was asked for the resolved pin, so the tree in
    // `project_dir` was materialized blob-by-blob from that SHA — verify the
    // recorded marker matches, then refuse to build anything else.
    match super::gitclone::pinned_sha(&project_dir) {
        Some(have) if have == pin => {}
        Some(have) => {
            report_err(
                &mut result,
                format!(
                    "checkout is pinned to {have}, deploy resolved {pin} (anti-TOFU); refusing to build an unpinned tree."
                ),
            );
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
        None => {
            report_err(
                &mut result,
                format!(
                    "checkout carries no pin marker, deploy resolved {pin} (anti-TOFU); refusing to build an unpinned tree."
                ),
            );
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    }

    // ── go:embed placeholder snapshot (content honesty) ──
    // A go:embed binary whose frontend build never ran serves the git-
    // shipped placeholder page with a happy HTTP 200 — a port/HTTP
    // healthcheck alone calls that success. Snapshot the placeholder
    // pages NOW, before the build can rewrite them; the post-start probe
    // compares the live response against these.
    let placeholder_pages = if recipe.language == "Go" {
        git_placeholder_pages(&project_dir, fresh_clone)
    } else {
        Vec::new()
    };
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
    // Python: after a fully successful prefetch, mark the wheelhouse
    // complete so the offline build's pip is forced onto it
    // (`pip_offline_env` keys on this marker). Without it the sandboxed
    // `pip install` probes pypi.org under PrivateNetwork=yes and dies on
    // DNS resolution after minutes of retries — the prefetch step itself
    // already failed closed above, so a reached marker means full wheels.
    if recipe.language == "Python"
        && let Err(e) = super::prefetch::mark_pip_wheelhouse(&project_dir)
    {
        report_err(&mut result, format!("pip wheelhouse marker failed: {e:#}"));
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
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
    // Manifest-declared build-time env (e.g. SvelteKit's PUB_* public env):
    // must land before PATH pinning below so a hostile manifest can never
    // shadow the pinned toolbox PATH.
    for (k, v) in recipe.build_env {
        build_env.push((k.to_string(), v.to_string()));
    }
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
    // The sandbox engages here: every step below runs inside a transient
    // systemd unit with PrivateNetwork=yes (no network). All downloads
    // (clone, toolbox, prefetch, seeds) are done on the host above.
    emit("sandbox: offline build — no network from here");
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
                        "Build step failed ({resolved}):\nstatus: {}\n{}{}",
                        r.status,
                        section("stderr (tail)", &short(&r.stderr)),
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
    let mut port = match find_free_port(recipe.port, 50) {
        Ok(p) => p,
        Err(e) => {
            report_err(&mut result, e.to_string());
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    };
    let exec_start = resolve_start(recipe, &project_dir, port);

    emit(&format!(
        "installing systemd unit {}...",
        recipe.service_name
    ));

    // Runtime env from `run.env`: values resolve here — `{port}` is the
    // chosen port and `{secret}` one fresh 16-byte hex for the whole deploy
    // (shared by every entry, never written to the manifest — only to the
    // 0600 EnvironmentFile). An empty map resolves to Ok(None) and the unit
    // gets no EnvironmentFile line.
    let need_secret = recipe.run_env.iter().any(|(_, v)| v.contains("{secret}"));
    let secret = if need_secret {
        match crate::atomic::random_hex(16) {
            Ok(s) => s,
            Err(e) => {
                report_err(
                    &mut result,
                    format!("run.env secret generation failed: {e}"),
                );
                rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
                return result;
            }
        }
    } else {
        String::new()
    };
    let env_map: BTreeMap<String, String> = recipe
        .run_env
        .iter()
        .map(|(k, v)| (k.to_string(), resolve_env_value(v, port, &secret)))
        .collect();
    let env_file = write_env_file(recipe.service_name, &env_map).ok().flatten();

    // IPAddressAllow= takes bare addresses only — hostnames would refuse
    // the whole unit — so the manifest's egress hosts resolve here, before
    // any unit file is written (fail closed: one unresolvable name aborts
    // the deploy and rolls the project back; a redeploy re-resolves, which
    // is also how DNS drift is corrected).
    //
    // When the manifest never chose a list (allow empty AND auto still
    // None), the tree's own declaration may suggest one — detect it from
    // the cloned project, resolve each host individually (an unreachable
    // suggestion is dropped with a warn, never fails the deploy: an
    // auto-suggestion is best-effort), and open what survived.
    let mut autofilled: Vec<String> = Vec::new();
    let egress_hosts: Vec<String> = if recipe.egress_may_autofill {
        match crate::hoster::egress_detect::detect_egress(&project_dir) {
            Some(plan) => {
                let mut kept: Vec<String> = Vec::new();
                for h in &plan.hosts {
                    match crate::hoster::egress::resolve_egress_hosts(&[h.as_str()]) {
                        Ok(_) => kept.push(h.clone()),
                        Err(_) => emit(&format!("warn: egress: {h} does not resolve — skipped")),
                    }
                }
                if !kept.is_empty() {
                    emit(&format!(
                        "egress: auto-detected {} host(s) — editable in the Egress menu",
                        kept.len()
                    ));
                }
                if let Some(note) = &plan.note {
                    emit(&format!("egress: {note}"));
                }
                autofilled = kept;
                autofilled.clone()
            }
            None => recipe.egress_allow.iter().map(|s| s.to_string()).collect(),
        }
    } else {
        recipe.egress_allow.iter().map(|s| s.to_string()).collect()
    };
    let egress_strs: Vec<&str> = egress_hosts.iter().map(String::as_str).collect();
    let egress_ips = match crate::hoster::egress::resolve_egress_hosts(&egress_strs) {
        Ok(ips) => ips,
        Err(e) => {
            // Manual lists stay fail-closed; the auto path only ever
            // contains pre-resolved hosts, so this Err is the manual case.
            report_err(&mut result, format!("egress host resolution failed: {e}"));
            rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
            return result;
        }
    };
    let egress_refs: Vec<&str> = egress_ips.iter().map(String::as_str).collect();
    result.egress = autofilled;
    // Empty allowlist → the unit gets a real deny-all (private network
    // namespace + socket-activation shim); non-empty keeps the IP filter,
    // which this kernel may or may not enforce (see the emit below).
    let netns_mode = egress_ips.is_empty();

    let spec = UnitSpec {
        service_name: recipe.service_name,
        working_dir: &project_dir,
        exec_start: &exec_start,
        description: &format!("demo: {}", recipe.description),
        env_file: env_file.as_deref(),
        extra_env: &[],
        res: recipe.res,
        egress_allow: &egress_refs,
        port,
    };
    if let Err(e) = create_unit(&spec) {
        report_err(&mut result, format!("unit creation failed: {e:#}"));
        rollback_failed(&mut result, recipe.service_name, &project_dir, None, &emit);
        return result;
    }
    if netns_mode {
        emit(
            "egress: REAL deny-all — private network namespace (no outbound route; loopback only via socket activation)",
        );
    } else if !super::egress::kernel_enforces_ip_filter() {
        emit(
            "warn: egress: allowlist is best-effort on this host (unprivileged eBPF disabled) — the kernel does not enforce the unit IP filter; a host firewall is needed for a hard deny",
        );
    }

    // ── start + verify (polling; see units.rs / FINDINGS.md) ──
    // start_unit activates the .socket companion first when one exists
    // (netns deny-all mode — systemd only passes the listening fd when the
    // socket is already up), then starts the service --no-block. A non-zero
    // exit means the unit/job was rejected outright (bad unit, dead user
    // manager), not merely slow to activate — fail closed (same discipline
    // as selftest.rs). wait_until_active budgets a grace period for the
    // queued async job, so a healthy unit whose first is-active poll wins
    // the race is not miscounted as a crash.
    emit("starting service...");
    if let Err(e) = start_unit(recipe.service_name) {
        report_err(&mut result, format!("{e:#}"));
        rollback_failed(
            &mut result,
            recipe.service_name,
            &project_dir,
            Some(port),
            &emit,
        );
        return result;
    }

    match wait_until_active(recipe.service_name) {
        StartOutcome::Active => {
            // `is-active` alone can catch a crash-looping unit (Restart=always)
            // inside a brief active window between restarts. Only report the
            // service as up when its port really accepts connections, so
            // `done: ok` / `listening on` never print for a dead port.
            // Netns deny-all mode binds the host port via the .socket
            // companion immediately — a plain port probe would false-positive;
            // the tunnel probe goes through the shim to the app inside the
            // namespace instead.
            let port_ok = if netns_mode {
                super::port::wait_until_tunnel_open(port, super::units::START_BUDGET)
            } else {
                wait_until_port_open(port, super::units::START_BUDGET)
            };
            if !port_ok {
                if netns_mode {
                    // Port adoption (ss scan) cannot see inside the private
                    // network namespace — an honest failure, not a guess.
                    let logs = service_logs(recipe.service_name, 20);
                    report_err(
                        &mut result,
                        format!(
                            "Service became active but the tunnel never reached the app inside its namespace on 127.0.0.1:{port} (crash-loop? wrong port? recent logs):\n{}",
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
                // The app ignored the assigned port and bound one of its
                // own (hardcoded ListenAndServe, its own config): instead
                // of killing a live service, adopt where it actually went.
                // Attribution is PID-strict — only this unit's processes
                // count — and the port must answer a real connect.
                if let Some(actual) = super::port::discover_unit_port(recipe.service_name, port) {
                    emit(&format!(
                        "note: the service binds port {actual} (not the assigned {port}) — healthcheck adopted it; manifest records {actual} for next deploy"
                    ));
                    if let Err(e) =
                        crate::hoster::library::set_run_port(recipe.service_name, actual)
                    {
                        emit(&format!(
                            "note: could not record port {actual} in the library manifest: {e}"
                        ));
                    }
                    port = actual;
                } else {
                    let logs = service_logs(recipe.service_name, 20);
                    report_err(
                        &mut result,
                        format!(
                            "Service became active but never accepted connections on 127.0.0.1:{port} (crash-loop? recent logs):\n{}",
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
            }
        }
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

    // ── content honesty (go:embed placeholder) ──
    // Port open + HTTP 200 is not enough: the embedded git placeholder
    // page answers exactly that way. Compare the served body with the
    // snapshot taken from the fresh clone.
    if let Some(diag) = placeholder_probe(port, &placeholder_pages) {
        // ── auto-repair ──
        // The manifest may predate frontend detection (hand-written, or
        // written by an older generator): re-detect from the clone, and
        // when the tree declares frontend build steps the manifest
        // lacks, ask the caller to patch the manifest and run ONE retry.
        // The tree stays on disk for the retry's clone reuse.
        match super::detect::detect_tree(&project_dir) {
            Ok(detected) => {
                if let Some(repair) = plan_repair(&detected, recipe.build_steps) {
                    emit(&format!("auto-repair: {}", repair.summary));
                    result.repair = Some(repair);
                    return result;
                }
                // The tree ships an embed dir with NO frontend build
                // script: those committed assets ARE the app (no build
                // could ever change them) — serving them unchanged is by
                // design, not a failed build. Honest warning, keep going.
                if detected
                    .notes
                    .iter()
                    .any(|n| n.contains("no frontend build script"))
                {
                    emit(&format!(
                        "warn: {diag} — but the tree declares no frontend build script, so the committed embed content is the product; starting on it as-is"
                    ));
                } else {
                    report_err(&mut result, diag);
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
            Err(_) => {
                report_err(&mut result, diag);
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

/// Snapshot the text files inside a freshly cloned tree's go:embed
/// directories as (repo-relative path, trimmed content): the pages a
/// go:embed binary serves WITHOUT a working frontend build.
///
/// Three sources, in trust order:
/// * fresh clone — the materializer just wrote every blob from the pin,
///   so the worktree IS the upstream content. HEAD is not usable here:
///   embed dirs are often gitignored (`.gitignore: dist/`), so the local
///   `git add -A` never stages the placeholder.
/// * reuse — the worktree may hold the previous build's output; the side
///   file written by the fresh deploy's snapshot is the truth.
/// * legacy reuse without a side file — HEAD, for trees that tracked
///   their embed dir (ignored elsewhere → empty → probe inert, which is
///   the safe default).
const PLACEHOLDER_SIDE_FILE: &str = ".ghost-placeholder.json";

fn git_placeholder_pages(project_dir: &Path, fresh_clone: bool) -> Vec<(String, String)> {
    let embeds = super::detect::go_embed_dirs(project_dir);
    if embeds.is_empty() {
        return Vec::new();
    }
    let mut pages: Vec<(String, String)> = Vec::new();
    if fresh_clone {
        for rel in &embeds {
            collect_text_pages(&project_dir.join(rel), rel, &mut pages);
        }
        persist_pages(project_dir, &pages);
        return pages;
    }
    if let Some(saved) = load_pages(project_dir) {
        return saved;
    }
    for rel in &embeds {
        collect_pristine_pages(project_dir, rel, &mut pages);
    }
    pages
}

/// Side file: the fresh deploy's snapshot, reusable by later redeploys
/// whose worktree no longer holds the pristine content.
fn persist_pages(project_dir: &Path, pages: &[(String, String)]) {
    let entries: Vec<serde_json::Value> = pages
        .iter()
        .map(|(p, c)| serde_json::json!({ "path": p, "content": c }))
        .collect();
    let _ = std::fs::write(
        project_dir.join(PLACEHOLDER_SIDE_FILE),
        serde_json::Value::Array(entries).to_string(),
    );
}

fn load_pages(project_dir: &Path) -> Option<Vec<(String, String)>> {
    let text = std::fs::read_to_string(project_dir.join(PLACEHOLDER_SIDE_FILE)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let arr = value.as_array()?;
    let mut pages = Vec::new();
    for item in arr {
        let p = item.get("path")?.as_str()?.to_string();
        let c = item.get("content")?.as_str()?.to_string();
        pages.push((p, c));
    }
    Some(pages)
}

fn collect_pristine_pages(project_dir: &Path, rel: &str, out: &mut Vec<(String, String)>) {
    const MAX_FILES: usize = 16;
    const MAX_BYTES: u64 = 16 * 1024;
    if !project_dir.join(".git").is_dir() {
        // No git at all (tarball fallback): the working tree is the only
        // source there is.
        collect_text_pages(&project_dir.join(rel), rel, out);
        return;
    }
    let root = project_dir.to_string_lossy();
    let listed = Command::new("git")
        .args([
            "-C",
            &root,
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "--",
            rel,
        ])
        .output();
    let Ok(listed) = listed else {
        return;
    };
    if !listed.status.success() {
        return;
    }
    let Ok(names) = String::from_utf8(listed.stdout) else {
        return;
    };
    for path in names.lines().take(MAX_FILES) {
        if out.len() >= MAX_FILES {
            return;
        }
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        let Ok(blob) = Command::new("git")
            .args(["-C", &root, "show", &format!("HEAD:{path}")])
            .output()
        else {
            continue;
        };
        if !blob.status.success() || blob.stdout.len() as u64 > MAX_BYTES {
            continue;
        }
        let Ok(text) = String::from_utf8(blob.stdout) else {
            continue;
        };
        let text = text.trim();
        // Tiny files ("<html></html>") are too generic to be a signature.
        if text.chars().count() < 24 {
            continue;
        }
        out.push((path.to_string(), text.to_string()));
    }
}

fn collect_text_pages(dir: &Path, rel: &str, out: &mut Vec<(String, String)>) {
    const SKIP: &[&str] = &["node_modules", ".git", "vendor"];
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(|e| e.ok()) {
        if out.len() >= 16 {
            return;
        }
        let name = e.file_name().to_string_lossy().to_string();
        let path = e.path();
        if path.is_dir() {
            if !name.starts_with('.') && !SKIP.contains(&name.as_str()) {
                collect_text_pages(&path, &format!("{rel}/{name}"), out);
            }
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() == 0 || meta.len() > 16 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let text = text.trim();
        // Tiny files ("<html></html>") are too generic to be a signature.
        if text.chars().count() < 24 {
            continue;
        }
        out.push((format!("{rel}/{name}"), text.to_string()));
    }
}

/// GET `path` over loopback HTTP/1.0 and return the response body.
/// `None` = the probe could not run (nothing to judge); the port being
/// open is already proven by the caller.
fn http_get_body(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    // Chunked reads: a read timeout AFTER the response arrived must keep
    // the bytes — `read_to_end` would discard them with its Err.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 256 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8(buf).ok()?;
    let (_head, body) = text.split_once("\r\n\r\n")?;
    Some(body.to_string())
}

/// The served `/` must not BE the git placeholder page: a go:embed binary
/// whose frontend build never took effect answers HTTP 200 with exactly
/// the file the fresh clone shipped. Returns the diagnosis on a hit.
fn placeholder_probe(port: u16, pages: &[(String, String)]) -> Option<String> {
    if pages.is_empty() {
        return None;
    }
    let body = http_get_body(port, "/")?;
    let body = body.trim();
    if body.chars().count() < 24 {
        return None;
    }
    let (rel, _) = pages.iter().find(|(_, c)| body.contains(c.as_str()))?;
    Some(format!(
        "HTTP 200 but the server is serving the git placeholder page {rel} — the frontend build did not take effect (the binary embedded the placeholder). Fix the build steps, then redeploy."
    ))
}

/// The wizard's rule, restated here: tool interpreters are derived from
/// step heads, never hand-maintained.
const KNOWN_TOOLS: &[&str] = &["bun", "pnpm", "go", "python3", "node"];

/// Is the source tree's detected plan worth a patched retry? Only when
/// the manifest LACKS frontend build steps the tree declares — retrying a
/// plan that already contains every detected step cannot fix a
/// placeholder, so that failure stays an honest one.
fn plan_repair(
    detected: &super::detect::Detected,
    current_steps: &[&str],
) -> Option<super::models::ManifestRepair> {
    let missing_frontend = detected.build.iter().any(|s| {
        (s.starts_with("pnpm ") || s.starts_with("bun ")) && !current_steps.contains(&s.as_str())
    });
    if !missing_frontend {
        return None;
    }
    Some(super::models::ManifestRepair {
        summary: format!(
            "the manifest's build plan misses the frontend build — re-detected {} step(s), patching the manifest and redeploying once",
            detected.prefetch.len() + detected.build.len()
        ),
        prefetch: detected.prefetch.clone(),
        build_steps: detected.build.clone(),
    })
}

/// Fold a repair into the manifest: new build plan, tools re-derived from
/// the step heads (the wizard's rule).
fn apply_repair(m: &mut super::manifest::ServiceManifest, r: &super::models::ManifestRepair) {
    m.prefetch = r
        .prefetch
        .iter()
        .map(|s| super::manifest::Step::Shell(s.clone()))
        .collect();
    m.build.steps = r
        .build_steps
        .iter()
        .map(|s| super::manifest::Step::Shell(s.clone()))
        .collect();
    let mut tools: Vec<String> = Vec::new();
    for step in m.prefetch.iter().chain(m.build.steps.iter()) {
        let shell = step.to_shell();
        let head = shell
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");
        if KNOWN_TOOLS.contains(&head) && !tools.iter().any(|t| t == head) {
            tools.push(head.to_string());
        }
    }
    m.tools = tools;
}

/// Write the patched manifest back: the file the deploy was started from,
/// plus the library's copy when that is a different file (the panel
/// redeploys from the library). Used for both auto-repair patches and the
/// auto-egress fill.
fn persist_manifest(
    m: &super::manifest::ServiceManifest,
    patch_path: Option<&Path>,
    context: &str,
) -> anyhow::Result<()> {
    m.validate(context)?;
    let yaml = serde_yaml::to_string(m).map_err(|e| anyhow::anyhow!("cannot render YAML: {e}"))?;
    if let Some(p) = patch_path {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::atomic::write_atomic(p, yaml.as_bytes())?;
    }
    if let Ok(lib) = super::library::file_path(&m.service.id)
        && Some(lib.as_path()) != patch_path
    {
        if let Some(dir) = lib.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::atomic::write_atomic(&lib, yaml.as_bytes())?;
    }
    Ok(())
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
/// the service. Used by "Self-Hosting" → delete.
///
/// GhostProvider cleans up the resources it manages; applications may still
/// leave their own state (databases, external sockets) elsewhere.
pub fn remove_unit_and_state(service_name: &str) {
    crate::networks::supervisor::stop(service_name);
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
    // Deletion is complete: the shelf manifest goes too, so no screen
    // (My Services, Edit Service) keeps a row for a service that is gone.
    let _ = super::library::remove(service_name);
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
    crate::networks::supervisor::stop(service);
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

/// The single entry-point reconciliation for processes that do not hold the
/// deploy lock themselves: panel startup, panel exit, the scripted
/// `__deploy` watchdog, the `tui_v2` exit paths. The journal is the only
/// "there might be leftovers" signal, and the flock is the only "is the
/// deploy behind them still alive" signal (see [`crate::hoster::lock`]) —
/// asking both here means no caller can forget either: entries untouched
/// while the lock is held (that tree belongs to a live deploy — sweeping
/// it is how a running clone dies with `opening part
/// …/.ghost-materialize/…: No such file or directory`), settled once it is
/// free. Quiet when the journal is empty, so a healthy parallel deploy
/// prints nothing.
///
/// The background timer ([`sweep_stale`]) and unit tests use the private
/// `reconcile_stale_inner` — they already hold the lock, and a second
/// flock in the same process would self-defer.
pub fn reconcile_stale_locked(basis: ReconcileBasis) -> Vec<String> {
    if crate::hoster::journal::entries().is_empty() {
        return Vec::new();
    }
    let Some(_lock) = super::lock::try_lock_exclusive() else {
        return vec!["cleanup: deferred — a deployment is live (deploy.lock held)".to_string()];
    };
    reconcile_stale_inner(false, basis)
}

/// Sweep leftover deploy-journal entries and clean their artifacts with a
/// full "clean removal" (unit + env file + project tree + registry slot).
///
/// Called on the next launch (TUI and `__deploy`) and on exit while a deploy
/// was in flight — but only *after* [`quiesce`] has stopped and waited for the
/// in-process worker, so this removal is final rather than racing a writer.
/// It never touches finished (`Registered`) or live (`Registering` with a
/// registry slot) services. Returns human-readable notice lines for
/// the deploy log so the panel surfaces what it cleaned.
///
/// Every entry this pass actually settles is appended to the Crash screen's
/// history (`crash.log`), tagged by [`basis`](ReconcileBasis): an `Exit` pass
/// records the deploy as aborted at exit; `Startup`/`Sweep` passes record it
/// as recovered leftovers.
fn reconcile_stale_inner(keep_if_inflight: bool, basis: ReconcileBasis) -> Vec<String> {
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

/// The URL of the live/leftover journaled deploy, if any. The exit path reads
/// it *before* reconciling so it can write the terminal "done: interrupted"
/// marker even after the reconcile clears the journal.
pub fn in_flight_url() -> Option<String> {
    journal::entries()
        .first()
        .map(|(_, entry)| entry.url.clone())
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
/// tree that the reconcile pass is about to wipe.
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
    let mut msgs = reconcile_stale_inner(false, ReconcileBasis::Sweep);
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
    let mut out = std::io::stdout();
    match sweep_stale() {
        SweepOutcome::Deferred => {
            writeln!(out, "cleanup: deferred — a deployment is in progress")?;
        }
        SweepOutcome::Cleaned(msgs) => {
            if msgs.is_empty() {
                writeln!(out, "cleanup: nothing to remove")?;
            } else {
                for m in &msgs {
                    writeln!(out, "{m}")?;
                }
            }
        }
    }
    Ok(())
}

/// The END of a step's output — that is where the actual failure reason
/// lives. The head is dominated by the command echo and early chatter (a
/// paraglide CDN warning once ate the first 300 chars and hid the vite
/// error behind it, leaving the deploy reason-less). The window is sized
/// for a rollup/vite stack trace: the error message sits ~12 frames above
/// the bun exit line, so 15 lines once cut it off.
fn short(s: &str) -> String {
    let mut lines: Vec<&str> = s.lines().rev().take(30).collect();
    lines.reverse();
    let joined = lines.join("\n");
    let skip = joined.chars().count().saturating_sub(3000);
    joined.chars().skip(skip).collect()
}

/// A labeled output section for failure reports; an empty body adds nothing.
fn section(name: &str, body: &str) -> String {
    let body = body.trim_end();
    if body.is_empty() {
        String::new()
    } else {
        format!("\n--- {name} ---\n{body}")
    }
}

/// The last few lines of a step's stdout, so a `pnpm`/`go` failure that
/// printed to stdout (progress/error lines) is visible in the report even
/// when stderr only carried the systemd-run status block.
fn tail(s: &str) -> String {
    let mut lines: Vec<&str> = s.lines().rev().take(12).collect();
    lines.reverse();
    let joined = lines.join("\n");
    let skip = joined.chars().count().saturating_sub(600);
    let tail: String = joined.chars().skip(skip).collect();
    section("stdout (tail)", &tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Failure reports quote the END of a step's output: the head is echo
    /// and early chatter, the reason (e.g. the real vite error behind a
    /// long paraglide CDN warning) is at the tail.
    #[test]
    fn short_keeps_the_tail_where_the_error_lives() {
        let mut out = String::new();
        for i in 0..40 {
            out.push_str(&format!("noise line {i}\n"));
        }
        out.push_str("real vite error\n");
        let s = short(&out);
        assert!(s.ends_with("real vite error"), "tail kept: {s:?}");
        assert!(!s.contains("noise line 0"), "head dropped: {s:?}");
        // A short body is returned whole.
        assert_eq!(short("only line\n"), "only line");
    }

    /// A rollup/vite failure prints the error message ~12 stack frames above
    /// the bun exit line; the window must be deep enough to keep the message
    /// itself, not just the frames.
    #[test]
    fn short_keeps_a_vite_error_above_its_stack_frames() {
        let mut out = String::new();
        for i in 0..20 {
            out.push_str(&format!("early chatter line {i}\n"));
        }
        out.push_str(
            "src/lib/util/consts.ts (1:44): \"PUB_ENV\" is not exported by \"virtual:env/static/public\"\n",
        );
        for i in 0..14 {
            out.push_str(&format!("    at Frame.bind (rollup/node-entry.js:{i})\n"));
        }
        out.push_str("error: script \"build\" exited with code 1\n");
        let s = short(&out);
        assert!(
            s.contains("PUB_ENV\" is not exported"),
            "error message survives the stack frames: {s:?}"
        );
        assert!(!s.contains("early chatter line 0"), "head dropped: {s:?}");
    }

    /// An empty section must add no header; a non-empty one is labeled.
    #[test]
    fn section_labels_non_empty_bodies_only() {
        assert_eq!(section("stderr (tail)", ""), "");
        assert_eq!(section("stderr (tail)", " \n"), "");
        assert_eq!(
            section("stderr (tail)", "boom\n"),
            "\n--- stderr (tail) ---\nboom"
        );
    }

    #[test]
    fn screen_line_keeps_verdicts_and_warnings_only() {
        let kept = [
            "! pre-flight failed, aborting",
            "auto-repair: the manifest's build plan misses the frontend build — re-detected 4 step(s), patching the manifest and redeploying once",
            "auto-repair: manifest patched — retrying the deploy once",
            "source: usememos/memos @ 245e5e3 (profile go, tools [pnpm, go])",
            "sandbox: FULL",
            "sandbox: offline build — no network from here",
            "! sandbox: ALMOST — GHOSTPROVIDER_BUILD_USER set but unusable; refusing to deploy without full isolation",
            "! sandbox: NO — refusing to build without isolation (the sandbox is mandatory)",
            "egress: auto-detected 4 host(s) — editable in the Egress menu",
            "egress: truncated to 8 of 12 detected host(s) — extend the list in the Egress menu",
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

    /// The laconic output names the subject first: `source:` passes the
    /// filter so the sandbox verdict below it reads in context.
    #[test]
    fn source_line_names_subject_and_passes_filter() {
        let m = crate::hoster::manifest::ServiceManifest::load_from_str(
            crate::hoster::fixtures::MEMOS_YAML,
            "demo-memos",
        )
        .expect("memos fixture must validate");
        let line = source_line(&m);
        assert!(
            line.starts_with("source: usememos/memos @ "),
            "unexpected: {line}"
        );
        assert!(line.contains("(profile go, tools [pnpm, go])"), "{line}");
        assert!(screen_line(&line));
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

    /// `run.env` value placeholders: `{port}` is the chosen port, `{secret}`
    /// the deploy's shared hex, anything else passes through untouched
    /// (validation rejects other tokens before we ever get here).
    #[test]
    fn resolve_env_value_fills_port_and_secret() {
        assert_eq!(resolve_env_value("{port}", 8888, "abc"), "8888");
        assert_eq!(resolve_env_value("prefix-{secret}", 1, "s3c"), "prefix-s3c");
        assert_eq!(
            resolve_env_value("p={port}&s={secret}", 4242, "hx"),
            "p=4242&s=hx"
        );
        assert_eq!(resolve_env_value("literal", 7, "x"), "literal");
        // Same secret for every entry of one deploy: pure substitution.
        assert_eq!(
            resolve_env_value("{secret}", 9, "same"),
            resolve_env_value("{secret}", 9, "same")
        );
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

        let msgs = reconcile_stale_inner(false, ReconcileBasis::Startup);

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

        let msgs = reconcile_stale_inner(false, ReconcileBasis::Startup);

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
        let keep = reconcile_stale_inner(true, ReconcileBasis::Startup);
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

        let settle = reconcile_stale_inner(false, ReconcileBasis::Startup);
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

    /// The entry-point reconcile (panel startup / panel exit) must defer the
    /// same way the sweep does: with the deploy lock held, the journal entry
    /// belongs to a live deploy in another process and its tree is not a
    /// leftover — sweeping it is what makes a running clone die with
    /// `opening part …/.ghost-materialize/…: No such file or directory`.
    /// Freeing the lock lets the next pass settle it normally.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn reconcile_stale_locked_defers_while_lock_held() {
        let (tmp, _env) = isolated_env("lockeddefer");
        journal::begin("demo-memos", "https://github.com/usememos/memos");
        let project = crate::paths::services_dir().join("memos");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("file.txt"), "clone").unwrap();

        let held = super::super::lock::try_lock_exclusive().expect("hold the deploy lock");
        let msgs = reconcile_stale_locked(ReconcileBasis::Startup);
        assert!(project.exists(), "a live tree must survive the deferral");
        assert_eq!(journal::entries().len(), 1, "entry kept for a later pass");
        assert!(msgs.iter().any(|m| m.contains("deferred")), "{msgs:?}");
        drop(held);

        let msgs = reconcile_stale_locked(ReconcileBasis::Startup);
        assert!(!project.exists(), "swept once the lock is free");
        assert!(journal::entries().is_empty(), "entry settled");
        assert!(
            !msgs.iter().any(|m| m.contains("deferred")),
            "no deferral line with a free lock: {msgs:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Nothing to settle → the guarded pass prints nothing at all: a healthy
    /// parallel deploy must not produce cleanup noise at panel startup.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation
    fn reconcile_stale_locked_is_silent_without_entries() {
        let (tmp, _env) = isolated_env("lockedsilent");
        let _held = super::super::lock::try_lock_exclusive().expect("hold the deploy lock");
        let msgs = reconcile_stale_locked(ReconcileBasis::Startup);
        assert!(msgs.is_empty(), "no journal, no notices: {msgs:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// One-shot loopback HTTP server: reads the request, serves `body`,
    /// closes. Returns the port it listens on.
    fn serve_once(body: &str) -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(resp.as_bytes());
            }
        });
        port
    }

    /// The probe's whole point: a live server answering HTTP 200 with the
    /// git placeholder page is a FAILED deploy, not a success.
    #[test]
    fn placeholder_probe_flags_served_git_page() {
        let page = "<html><body>No embeddable frontend found.</body></html>";
        let port = serve_once(page);
        let pages = vec![(
            "server/frontend/dist/index.html".to_string(),
            page.to_string(),
        )];
        let diag = placeholder_probe(port, &pages).expect("placeholder must be flagged");
        assert!(
            diag.contains("server/frontend/dist/index.html")
                && diag.contains("frontend build did not take effect"),
            "{diag}"
        );
    }

    /// A real UI (different body) passes the probe untouched.
    #[test]
    fn placeholder_probe_passes_a_real_ui() {
        let port = serve_once(
            "<!doctype html><html><head><title>Memos</title></head><body>app shell with real assets</body></html>",
        );
        let pages = vec![(
            "server/frontend/dist/index.html".to_string(),
            "<html><body>No embeddable frontend found.</body></html>".to_string(),
        )];
        assert_eq!(placeholder_probe(port, &pages), None);
    }

    /// No snapshot (no embed dirs, non-Go profile) → the probe is inert.
    #[test]
    fn placeholder_probe_without_pages_is_inert() {
        assert_eq!(placeholder_probe(1, &[]), None);
    }

    /// The snapshot walks the go:embed directories of a fresh clone and
    /// keeps the trimmed text files big enough to be a signature.
    #[test]
    fn git_placeholder_pages_reads_embed_dirs() {
        let dir =
            std::env::temp_dir().join(format!("dgp-ph-{}-{}", std::process::id(), "embedsnap"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("server/frontend/dist")).unwrap();
        std::fs::write(
            dir.join("main.go"),
            "package main\n\nimport \"embed\"\n\n//go:embed server/frontend/dist/*\nvar ui embed.FS\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("server/frontend/dist/index.html"),
            "<html><body>No embeddable frontend found.</body></html>\n",
        )
        .unwrap();
        std::fs::write(dir.join("server/frontend/dist/tiny"), "x").unwrap();
        let pages = git_placeholder_pages(&dir, true);
        assert_eq!(
            pages,
            vec![(
                "server/frontend/dist/index.html".to_string(),
                "<html><body>No embeddable frontend found.</body></html>".to_string(),
            )],
            "tiny files are too generic to be signatures: {pages:?}"
        );
        assert!(
            dir.join(".ghost-placeholder.json").is_file(),
            "a fresh snapshot is persisted for later redeploys"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reuse never trusts the worktree (it holds the previous build's
    /// output) — the fresh deploy's side file is the source of truth.
    #[test]
    fn side_file_beats_a_dirty_worktree_on_reuse() {
        let dir = std::env::temp_dir().join(format!("dgp-ph-{}-side", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("server/frontend/dist")).unwrap();
        std::fs::write(
            dir.join("main.go"),
            "package main\n\nimport \"embed\"\n\n//go:embed server/frontend/dist/*\nvar ui embed.FS\n",
        )
        .unwrap();
        let placeholder = "<html><body>No embeddable frontend found.</body></html>";
        std::fs::write(dir.join("server/frontend/dist/index.html"), placeholder).unwrap();
        // Fresh: snapshot from the pristine worktree, side file written.
        let fresh_pages = git_placeholder_pages(&dir, true);
        assert_eq!(fresh_pages.len(), 1);
        // The previous build rewrote the tree...
        std::fs::write(
            dir.join("server/frontend/dist/index.html"),
            "<!doctype html><html><head><title>Real UI</title></head><body>built</body></html>",
        )
        .unwrap();
        // ...but reuse reads the side file, not the dirty file.
        let reuse_pages = git_placeholder_pages(&dir, false);
        assert_eq!(
            reuse_pages, fresh_pages,
            "reuse must serve the fresh snapshot, not the build output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reused checkout's embed dir holds the PREVIOUS build's output,
    /// not the placeholder: the snapshot must read HEAD, or every healthy
    /// redeploy would be flagged as serving a placeholder.
    #[test]
    fn snapshot_prefers_head_over_a_dirty_worktree() {
        let dir = std::env::temp_dir().join(format!("dgp-ph-{}-dirty", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("server/frontend/dist")).unwrap();
        std::fs::write(
            dir.join("main.go"),
            "package main\n\nimport \"embed\"\n\n//go:embed server/frontend/dist/*\nvar ui embed.FS\n",
        )
        .unwrap();
        let placeholder = "<html><body>No embeddable frontend found.</body></html>";
        std::fs::write(dir.join("server/frontend/dist/index.html"), placeholder).unwrap();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .args(["-C", &dir.to_string_lossy()])
                .args(args)
                .env_remove("GIT_ASKPASS")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        run(&["init", "-q"]);
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "pin",
        ]);
        // The previous deploy's build rewrote the working tree.
        std::fs::write(
            dir.join("server/frontend/dist/index.html"),
            "<!doctype html><html><head><title>Real UI</title></head><body>built shell</body></html>",
        )
        .unwrap();
        let pages = git_placeholder_pages(&dir, false);
        assert_eq!(
            pages,
            vec![(
                "server/frontend/dist/index.html".to_string(),
                placeholder.to_string(),
            )],
            "HEAD content, not the dirty working tree: {pages:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn detected_frontend_plan() -> crate::hoster::detect::Detected {
        crate::hoster::detect::Detected {
            profile: "go".into(),
            prefetch: vec!["pnpm --dir web fetch --store-dir {project}/.ghost-cache/pnpm".into()],
            build: vec![
                "pnpm --dir web install --offline --store-dir {project}/.ghost-cache/pnpm".into(),
                "pnpm --dir web run release".into(),
                "go build -o ghost-server ./cmd/memos".into(),
            ],
            run_cmd: "{bin} --addr 127.0.0.1 --port {port}".into(),
            port: "0".into(),
            memory_max: "1024M".into(),
            tasks_max: "512".into(),
            build_env: vec![],
            plugins: vec![],
            notes: vec![],
            confident: true,
            run_env: vec![],
        }
    }

    /// A manifest that lacks frontend steps the tree declares justifies one
    /// patched retry; the repaired plan itself must NOT request another —
    /// that is what keeps the retry budget at exactly one.
    #[test]
    fn plan_repair_only_when_frontend_steps_are_missing() {
        let d = detected_frontend_plan();
        let bare = &["go build -o ghost-server ./cmd/memos"];
        let repair = plan_repair(&d, bare).expect("missing frontend steps → repair");
        assert!(repair.summary.contains("frontend"), "{}", repair.summary);
        assert_eq!(repair.build_steps, d.build);
        assert_eq!(repair.prefetch, d.prefetch);
        let now: Vec<&str> = d.build.iter().map(|s| s.as_str()).collect();
        assert!(
            plan_repair(&d, &now).is_none(),
            "an already-complete plan fails honestly, no loop"
        );
        let no_frontend = crate::hoster::detect::Detected {
            build: vec!["go build -o ghost-server .".into()],
            prefetch: vec![],
            ..detected_frontend_plan()
        };
        assert!(
            plan_repair(&no_frontend, bare).is_none(),
            "no frontend in the plan → honest failure, nothing to patch"
        );
    }

    /// The patch lands in the manifest: new build plan, tools re-derived
    /// from the step heads, still valid.
    #[test]
    fn apply_repair_rewrites_plan_and_derives_tools() {
        let mut m = super::super::manifest::ServiceManifest::load_from_str(
            super::super::fixtures::MEMOS_YAML,
            "demo-memos",
        )
        .unwrap_or_else(|e| panic!("fixture must load: {e}"));
        // Simulate the hand-written, frontend-blind manifest.
        m.prefetch = vec![];
        m.build.steps = vec![super::super::manifest::Step::Shell(
            "go build -o ghost-server ./cmd/memos".into(),
        )];
        m.tools = vec!["go".into()];
        let d = detected_frontend_plan();
        let repair = plan_repair(&d, &["go build -o ghost-server ./cmd/memos"])
            .expect("fixture requests repair");
        apply_repair(&mut m, &repair);
        assert_eq!(m.prefetch.len(), 1);
        assert_eq!(m.build.steps.len(), 3);
        assert_eq!(
            m.tools,
            vec!["pnpm".to_string(), "go".to_string()],
            "tools follow the step heads: {:?}",
            m.tools
        );
        m.validate("repair-test")
            .expect("patched manifest must validate");
    }

    /// The patched plan is written where the deploy came from, loadable,
    /// and the library copy (different file) receives it too.
    #[test]
    fn persist_repair_writes_both_copies() {
        let (tmp, _env) = isolated_env("repairpatch");
        let mut m = super::super::manifest::ServiceManifest::load_from_str(
            super::super::fixtures::MEMOS_YAML,
            "demo-memos",
        )
        .unwrap();
        let patch_path = tmp.join("manifests/usememos-memos.yaml");
        std::fs::create_dir_all(patch_path.parent().unwrap()).unwrap();
        std::fs::write(&patch_path, "placeholder").unwrap();
        let repair = plan_repair(&detected_frontend_plan(), &["go build"]).unwrap();
        apply_repair(&mut m, &repair);
        persist_manifest(&m, Some(&patch_path), "auto-repair").unwrap();
        let reloaded =
            super::super::manifest::ServiceManifest::load_from_file(&patch_path).unwrap();
        assert_eq!(reloaded.build.steps.len(), 3, "patched file reloads");
        let lib = super::super::library::file_path(&m.service.id).unwrap();
        assert_ne!(lib, patch_path, "fixture must exercise the second copy");
        let lib_m = super::super::manifest::ServiceManifest::load_from_file(&lib).unwrap();
        assert_eq!(lib_m.tools, vec!["pnpm".to_string(), "go".to_string()]);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
