//! Validated engine shape for one deployable service.
//!
//! Services are authored as `service.yaml` manifests — the three built-ins
//! in `manifests/*.yaml`, user services as files anywhere — and converted
//! into this shape (`manifest::to_leaked_recipe`) before the pipeline runs,
//! so every manifest shares every security gate below. `tools` lists the
//! executables the recipe's build steps require; preflight refuses to start
//! a deployment when any of them is missing (lesson from the audit: the old
//! preflight was green while `bun install` would fail with ENOENT).

/// A validated deploy recipe for a single service.
#[derive(Debug, Clone)]
pub struct DemoRecipe {
    pub owner: &'static str,
    pub name: &'static str,
    pub language: &'static str,
    pub service_name: &'static str,
    pub description: &'static str,
    pub display_name: &'static str,
    /// Pinned commit SHA that a deployment checks out after cloning, so a
    /// recipe never silently tracks whatever `main`/`master` moved to at
    /// build time (anti-TOFU). Bumped consciously when a recipe is updated.
    pub commit: &'static str,
    pub pre_build: &'static [&'static str],
    pub build_steps: &'static [&'static str],
    /// Host-phase dependency pre-fetch steps, run BEFORE the sandboxed build
    /// with network available (see `prefetch.rs`). These fill the tool caches
    /// so each sandboxed build step below runs fully offline. They are
    /// *downloader* commands, never the project's build code — a hostile
    /// `setup.py`/`postinstall` is not executed on the host (see the security
    /// invariant at the top of `prefetch.rs`).
    pub prefetch_steps: &'static [&'static str],
    /// Host-phase pinned paraglide-js plugin seeds (VERT recipe only; empty
    /// for the others). Each entry is `(jsdelivr module URL as written in
    /// `project.inlang/settings.json`, lowercase-hex SHA-256 of the file
    /// jsdelivr must serve at that URL)`. Fetched through the allowlisted
    /// client (`cdn.jsdelivr.net` — a permitted, net.log-visible host) and
    /// content-pinned so a silent version lift under the same `@N` major tag
    /// fails the deploy instead of feeding changed third-party code into the
    /// offline build.
    pub plugins: &'static [(&'static str, &'static str)],
    /// Placeholders: {bin} {venv} {python} {project} {port} {self}
    /// {self} expands to this binary — used by the built-in static server.
    pub start_cmd: &'static str,
    /// 0 = pick a random free port.
    pub port: u16,
    pub searxng: bool,
    /// Executables required on PATH for the build steps to succeed.
    pub tools: &'static [&'static str],
    /// Runtime egress exceptions: hostnames/IPv4 the unit may reach besides
    /// loopback (empty = historic deny-all). Converted from the manifest's
    /// `egress.allow`, normalized there.
    pub egress_allow: &'static [&'static str],
    /// systemd resource caps for the deployed unit (cgroup memory/tasks
    /// bounds): a runaway demo service must never grind the whole user
    /// session. See `units.rs::ResourceLimits`.
    pub res: crate::hoster::units::ResourceLimits,
}
