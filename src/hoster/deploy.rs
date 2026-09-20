//! Deploy sequence for the curated demo services.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Stop and delete a previously deployed unit so it can be replaced cleanly.
fn stop_existing(service_name: &str) {
    let unit = crate::paths::user_unit_dir().join(format!("{service_name}.service"));
    if unit.is_file() {
        remove_unit(service_name);
        super::secrets::remove_env_file(service_name);
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
fn toolbox_needs(recipe: &DemoRecipe, project_dir: &Path) -> Vec<(super::toolcheck::Tool, Option<super::toolcheck::Ver>)> {
    use super::toolcheck::{Tool, is_auto_provisionable, installed_version, manifest_requirements, tool_from_bin};
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
        screen("warn: GHOSTPROVIDER_NO_NETLOG — outbound requests are not written to net.log".into());
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
    journal::begin(recipe.service_name, url);

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
    // entry so the next launch does not re-clean a finished deploy.
    journal::clear(recipe.service_name);
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
        let resolved = resolve_project_step(step, &project_dir);
        if let Err(e) = super::prefetch::run_host_step(&resolved, &project_dir, &path_prefix, &emit) {
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
    if recipe.searxng && let Err(e) = prepare_searxng_config(&project_dir, port) {
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
            rollback_failed(&mut result, recipe.service_name, &project_dir, Some(port), &emit);
            return result;
        }
        Err(_) => {
            report_err(&mut result, "failed to invoke systemctl start".into());
            rollback_failed(&mut result, recipe.service_name, &project_dir, Some(port), &emit);
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
            rollback_failed(&mut result, recipe.service_name, &project_dir, Some(port), &emit);
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
            rollback_failed(&mut result, recipe.service_name, &project_dir, Some(port), &emit);
            return result;
        }
        StartOutcome::SystemdUnavailable => {
            report_err(&mut result, "systemd user manager unavailable".into());
            rollback_failed(&mut result, recipe.service_name, &project_dir, Some(port), &emit);
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

/// Remove everything a *single* in-flight deploy recorded in the journal may
/// have left behind, whether or not `state.json` mentions the service.
///
/// Idempotent: safe to run repeatedly, and to run while the tail of an
/// interrupted deploy worker is still winding down (both sides touch the same
/// paths and tolerate already-absent files). Returns `true` when the project
/// tree is gone (or never existed) — i.e. full removal; `false` keeps the
/// journal entry so the next launch retries.
fn cleanup_stale(service: &str, url: &str) -> bool {
    remove_unit(service);
    super::secrets::remove_env_file(service);

    // The journal may outlive the registry entry (state.json is written last,
    // during `Registering`): derive the clone dir from the repository URL,
    // exactly as `clone_repo` would name it. The services_dir parent guard in
    // `wipe_project_dir` still applies.
    let mut removed = true;
    if let Some((_, repo)) = super::github::parse_github_url(url) {
        let dir = crate::paths::services_dir().join(safe_dirname(&repo));
        if dir.is_dir() {
            removed = wipe_project_dir(&dir.to_string_lossy());
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
    removed
}

/// Sweep leftover deploy-journal entries and clean their artifacts with a
/// full "clean removal" (unit + env file + project tree + registry slot).
///
/// Called on the next launch (TUI and `__deploy`) and on a deliberate early
/// exit while a deploy is in flight (Ctrl+C / q / Esc, SIGTERM, SIGHUP). It
/// never touches finished (`Registered`) or live (`Registering` with a
/// registry slot) services. Returns human-readable notice lines for the
/// deploy log so the panel surfaces what it cleaned.
pub fn reconcile_stale() -> Vec<String> {
    let mut msgs = Vec::new();
    for (service, entry) in journal::entries() {
        if !stale_action(entry.state, crate::state::get(&service).is_some()) {
            journal::clear(&service);
            continue;
        }
        msgs.push(format!(
            "cleanup: interrupted deploy of {service} ({}) — removing leftover unit, env file and project tree",
            entry.url
        ));
        if cleanup_stale(&service, &entry.url) {
            msgs.push(format!("cleanup: {service}: removed"));
            journal::clear(&service);
        } else {
            msgs.push(format!(
                "cleanup: {service}: project tree still in use, retrying on next launch"
            ));
        }
    }
    for m in &msgs {
        crate::tui::workers::append_deploy_log(m);
    }
    msgs
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

    /// Serializes tests that mutate the process-global XDG_DATA_HOME.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// README promise: deleting a service wipes the clone together with its
    /// caches — but only inside services_dir.
    #[test]
    #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
    fn wipe_removes_clone_inside_services_dir_only() {
        let _env = ENV_LOCK.lock().unwrap();
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
        let _env = ENV_LOCK.lock().unwrap();
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
        let _env = ENV_LOCK.lock().unwrap();
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
        rollback_failed(
            &mut result,
            "demo-memos",
            &project,
            None,
            &|m| notes.borrow_mut().push(m.to_string()),
        );

        assert!(!project.exists(), "failed deploy must wipe the project tree");
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
}
