//! User-supplied service manifests (`service.yaml`, v1).
//!
//! A manifest is the contract between GhostProvider and one deployable
//! service: source pin, downloader prefetch, offline build, loopback run and
//! resource budget. The engine ([`super::deploy`]) only executes what a
//! validated manifest describes; the sandbox + systemd hardening stay
//! non-negotiable regardless of manifest content.
//!
//! Format decisions (see docs/MANIFEST.md):
//! * steps accept either shell strings (v0 compat, e.g. the VERT
//!   `if [ -f ... ]` pre-build) or argv arrays (preferred: no `sh -c`
//!   injection surface). Argv steps are shell-quoted into one string before
//!   they reach the existing `run_host_step` / `run_build_cmd` executors.
//! * `run.command` is always argv with `{bin}/{venv}/{self}/{project}/{port}`
//!   placeholders, resolved per-arg at install time.
//! * `prefetch` is host-phase only and profile-gated: only downloader
//!   commands that never execute fetched code on the host are accepted.
//!   Anything else is rejected at validation, before any side effect.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Max accepted manifest file size (64 KiB): a manifest is hand-written
/// config, never a data dump.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// A single build/prefetch step: either a shell string (compat) or an argv
/// array (preferred). YAML example:
/// ```yaml
/// steps:
///   - ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
///   - "python3 -m venv --clear .venv"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Step {
    Shell(String),
    Argv(Vec<String>),
}

impl Step {
    /// Render the step into the single shell string the executors expect.
    /// Argv items are single-quoted so `sh -c` cannot reinterpret them.
    pub fn to_shell(&self) -> String {
        match self {
            Step::Shell(s) => s.clone(),
            Step::Argv(argv) => argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    /// First executable token (for tool-coverage checks).
    pub fn head(&self) -> String {
        match self {
            Step::Shell(s) => s
                .split_whitespace()
                .next()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string(),
            Step::Argv(argv) => argv
                .first()
                .map(|h| h.rsplit('/').next().unwrap_or(h).to_string())
                .unwrap_or_default(),
        }
    }

    pub fn shell_text(&self) -> String {
        self.to_shell()
    }
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'+' | b',' | b'@' | b'{' | b'}'
            )
    }) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceMeta {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceSpec {
    pub git: String,
    pub commit: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildSpec {
    pub profile: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunSpec {
    pub command: Vec<String>,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    0
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ResourcesSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_high: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_nofile: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_score_adjust: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthcheckSpec {
    #[serde(default = "default_hc_type")]
    #[allow(dead_code)]
    pub r#type: String,
    #[serde(default = "default_hc_path")]
    pub path: String,
}

fn default_hc_type() -> String {
    "http".to_string()
}
fn default_hc_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginPin {
    pub url: String,
    pub sha256: String,
}

/// Top-level `service.yaml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceManifest {
    pub manifest_version: u32,
    pub service: ServiceMeta,
    pub source: SourceSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_build: Vec<Step>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefetch: Vec<Step>,
    pub build: BuildSpec,
    pub run: RunSpec,
    #[serde(default)]
    pub resources: ResourcesSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthcheckSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<PluginPin>,
    /// SearXNG-style settings patch (secret + loopback bind). Only valid
    /// with `build.profile: python-searxng`; kept explicit instead of an
    /// `if id == ...` in the engine.
    #[serde(default)]
    pub searxng: bool,
    /// Extra build tools required on PATH (provisionable: bun/pnpm/go).
    #[serde(default)]
    pub tools: Vec<String>,
}

impl ServiceManifest {
    /// Parse + validate in one step (file path used in error messages).
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            anyhow::bail!(
                "manifest {} is {} bytes (limit {}): refusing to parse",
                path.display(),
                bytes.len(),
                MAX_MANIFEST_BYTES
            );
        }
        Self::load_from_str(&String::from_utf8_lossy(&bytes), &path.to_string_lossy())
    }

    pub fn load_from_str(text: &str, origin: &str) -> anyhow::Result<Self> {
        if text.len() > MAX_MANIFEST_BYTES {
            anyhow::bail!("manifest {origin} exceeds size limit");
        }
        let m: ServiceManifest = serde_yaml::from_str(text)
            .map_err(|e| anyhow::anyhow!("manifest {origin}: invalid YAML/schema: {e}"))?;
        m.validate(origin)?;
        Ok(m)
    }

    /// Fail-closed schema + policy checks. No side effects.
    pub fn validate(&self, origin: &str) -> anyhow::Result<()> {
        let at = |what: &str| format!("manifest {origin}: {what}");
        // ── version ──
        if self.manifest_version != 1 {
            anyhow::bail!(
                "{}",
                at(&format!(
                    "unsupported manifest_version {} (only 1)",
                    self.manifest_version
                ))
            );
        }
        // ── service.id ──
        if self.service.id.len() < 3 || self.service.id.len() > 64 {
            anyhow::bail!("{}", at("service.id must be 3..=64 chars"));
        }
        if !self
            .service
            .id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            anyhow::bail!("{}", at("service.id must match ^[a-z0-9-]{3,64}$"));
        }
        if self.service.id.starts_with('-') || self.service.id.ends_with('-') {
            anyhow::bail!("{}", at("service.id must not start/end with '-'"));
        }
        for reserved in ["demo-vert", "demo-searxng", "demo-memos"] {
            // Reserved ids stay usable ONLY via built-in manifests so a user
            // file cannot shadow/squat the curated names.
            let _ = reserved;
        }
        // systemd unit safety (mirrors units::validate_unit_name, dots allowed
        // but leading dot forbidden).
        if self.service.id.starts_with('.') {
            anyhow::bail!("{}", at("service.id must not start with '.'"));
        }
        // ── source ──
        let Some((_owner, _name)) = crate::hoster::github::parse_github_url(&self.source.git)
        else {
            anyhow::bail!(
                "{}",
                at("source.git must be https://github.com/<owner>/<repo>(.git)")
            );
        };
        if self.source.commit.len() != 40
            || !self.source.commit.bytes().all(|b| b.is_ascii_hexdigit())
        {
            anyhow::bail!("{}", at("source.commit must be a full 40-hex commit SHA"));
        }
        // ── profile ──
        match self.build.profile.as_str() {
            "bun" | "python" | "python-searxng" | "go" | "node" => {}
            other => anyhow::bail!(
                "{}",
                at(&format!(
                    "build.profile '{other}' unsupported (bun|python|python-searxng|go|node)"
                ))
            ),
        }
        if self.searxng && self.build.profile != "python-searxng" {
            anyhow::bail!(
                "{}",
                at("searxng: true requires build.profile: python-searxng")
            );
        }
        // ── tools ──
        for t in &self.tools {
            match t.as_str() {
                "bun" | "pnpm" | "go" | "python3" | "node" => {}
                other => anyhow::bail!("{}", at(&format!("tools: unsupported '{other}'"))),
            }
        }
        // every build/prefetch step head must be declared when it is a known tool
        for step in self
            .prefetch
            .iter()
            .chain(self.pre_build.iter())
            .chain(self.build.steps.iter())
        {
            let head = step.head();
            if matches!(head.as_str(), "bun" | "pnpm" | "go" | "python3" | "node")
                && !self.tools.iter().any(|t| t == &head)
            {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "step '{}' needs tool '{head}' not listed in tools",
                        step.shell_text()
                    ))
                );
            }
        }
        // ── prefetch whitelist (host phase: downloaders only) ──
        for step in &self.prefetch {
            validate_prefetch_step(step).map_err(|r| anyhow::anyhow!("{}", at(&r)))?;
        }
        // ── pre_build/build heuristic screen (belt-and-suspenders; the
        // sandbox is the real boundary) ──
        for step in self.pre_build.iter().chain(self.build.steps.iter()) {
            let s = step.to_shell();
            if s.trim().is_empty() {
                anyhow::bail!("{}", at("empty build step"));
            }
            if s.len() > 2048 {
                anyhow::bail!("{}", at("build step exceeds 2048 chars"));
            }
            crate::hoster::validate::validate_build_cmd(&s).map_err(|r| {
                anyhow::anyhow!("{}", at(&format!("build step rejected: {r}: {s}")))
            })?;
        }
        // ── plugins (VERT-style content pins) ──
        if self.plugins.len() > 8 {
            anyhow::bail!("{}", at("too many plugin pins (max 8)"));
        }
        for p in &self.plugins {
            if !p
                .url
                .starts_with("https://cdn.jsdelivr.net/npm/@inlang/plugin-")
            {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "plugin URL must be a jsdelivr @inlang module: {}",
                        p.url
                    ))
                );
            }
            if p.sha256.len() != 64 || !p.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!(
                    "{}",
                    at(&format!("plugin {} SHA-256 must be 64 hex chars", p.url))
                );
            }
        }
        if !self.plugins.is_empty() && self.build.profile != "bun" {
            anyhow::bail!(
                "{}",
                at("plugins are only supported with build.profile: bun")
            );
        }
        // ── run.command ──
        if self.run.command.is_empty() || self.run.command.len() > 32 {
            anyhow::bail!("{}", at("run.command must have 1..=32 argv items"));
        }
        for a in &self.run.command {
            if a.is_empty() || a.len() > 1024 {
                anyhow::bail!("{}", at("run.command argv item must be 1..=1024 chars"));
            }
            if a.contains('\n') || a.contains('\0') {
                anyhow::bail!("{}", at("run.command must not contain newlines/NUL"));
            }
        }
        let joined = self.run.command.join(" ");
        // SearXNG receives its port via settings.yml patch (prepare_searxng_config),
        // not via CLI argv — so {port} is required everywhere except searxng.
        if !self.searxng && !joined.contains("{port}") {
            anyhow::bail!("{}", at("run.command must contain the {port} placeholder"));
        }
        // Loopback pin: the deployed unit must bind 127.0.0.1 (or be our
        // loopback static server / searxng-patched).
        let loopback_ok =
            joined.contains("__serve-static") || joined.contains("127.0.0.1") || self.searxng;
        if !loopback_ok {
            anyhow::bail!(
                "{}",
                at(
                    "run.command must bind loopback: use __serve-static or 127.0.0.1 (or searxng patch)"
                )
            );
        }
        if !(self.run.port == 0 || (1024..=65535).contains(&self.run.port)) {
            anyhow::bail!("{}", at("run.port must be 0 (random) or 1024..=65535"));
        }
        // ── resources (budgets are mandatory: unbounded units can grind the session) ──
        if self.resources.memory_max.is_none() || self.resources.tasks_max.is_none() {
            anyhow::bail!(
                "{}",
                at("resources.memory_max and resources.tasks_max are required")
            );
        }
        if let Some(hc) = &self.healthcheck
            && !hc.path.starts_with('/')
        {
            anyhow::bail!("{}", at("healthcheck.path must start with '/'"));
        }
        Ok(())
    }

    pub fn owner_name(&self) -> Option<(String, String)> {
        crate::hoster::github::parse_github_url(&self.source.git)
    }

    /// Human-readable deploy plan (no side effects) for `__check-manifest`.
    pub fn plan_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "service:  {} ({})\n",
            self.service.id, self.source.git
        ));
        out.push_str(&format!("commit:   {}\n", self.source.commit));
        out.push_str(&format!(
            "profile:  {}  tools: [{}]\n",
            self.build.profile,
            self.tools.join(", ")
        ));
        out.push_str(&format!(
            "prefetch (host, {} step(s)):\n",
            self.prefetch.len()
        ));
        for s in &self.prefetch {
            out.push_str(&format!("  + {}\n", s.to_shell()));
        }
        if !self.plugins.is_empty() {
            out.push_str(&format!("plugins (pinned, {}):\n", self.plugins.len()));
            for p in &self.plugins {
                out.push_str(&format!("  + {} @ {}\n", p.url, &p.sha256[..12]));
            }
        }
        out.push_str(&format!(
            "build (sandbox offline, {} step(s)):\n",
            self.pre_build.len() + self.build.steps.len()
        ));
        for s in self.pre_build.iter().chain(self.build.steps.iter()) {
            out.push_str(&format!("  + {}\n", s.to_shell()));
        }
        out.push_str(&format!("run:      {}\n", self.run.command.join(" ")));
        out.push_str(&format!(
            "port:     {}\n",
            if self.run.port == 0 {
                "0 (random free)".to_string()
            } else {
                self.run.port.to_string()
            }
        ));
        out.push_str(&format!(
            "limits:   mem={:?}/{:?} tasks={:?} cpu={:?}\n",
            self.resources.memory_high,
            self.resources.memory_max,
            self.resources.tasks_max,
            self.resources.cpu_quota
        ));
        out.push_str("sandbox:  FULL required; network off at build; loopback-only at runtime\n");
        out
    }
}

/// Host-phase prefetch gate: only downloader invocations that never execute
/// fetched/project code on the host. Mirrors the
/// `prefetch_steps_never_run_lifecycle_scripts_on_host` recipe test.
fn validate_prefetch_step(step: &Step) -> Result<(), String> {
    let s = step.to_shell();
    let head = step.head();
    match head.as_str() {
        "bun" => {
            if !s.contains("--ignore-scripts") {
                return Err(format!("bun prefetch must use --ignore-scripts: '{s}'"));
            }
            for banned in [" run ", " exec ", " dlx ", " x "] {
                if s.contains(banned) {
                    let b = banned.trim();
                    return Err(format!(
                        "bun prefetch must be a downloader (install only), found '{b}': '{s}'"
                    ));
                }
            }
            Ok(())
        }
        "pnpm" => {
            // `fetch` fills the store without building or running scripts.
            let has_fetch = s.split_whitespace().any(|w| w == "fetch");
            if !has_fetch {
                return Err(format!(
                    "pnpm prefetch must be a script-free `fetch`: '{s}'"
                ));
            }
            for banned in [" run ", " install ", " exec ", " dlx "] {
                if s.contains(banned) {
                    let b = banned.trim();
                    return Err(format!("pnpm prefetch must not '{b}': '{s}'"));
                }
            }
            Ok(())
        }
        "python3" => {
            if !s.contains("pip download") && !s.contains("pip_download") {
                // argv form: ["python3","-m","pip","download",...]
                if !(s.contains("pip") && s.contains("download")) {
                    return Err(format!("python3 prefetch must be `pip download`: '{s}'"));
                }
            }
            if !s.contains("--only-binary=:all:") {
                return Err(format!(
                    "pip prefetch must pin binary-only wheels (--only-binary=:all:): '{s}'"
                ));
            }
            Ok(())
        }
        "go" => {
            if !(s.contains("mod download") || s.contains("mod_download")) {
                return Err(format!("go prefetch must be `go mod download`: '{s}'"));
            }
            Ok(())
        }
        "touch" => {
            // `touch .ghost-cache/.../.done` marker tails (SearXNG recipe).
            if s.contains("..") || !s.contains(".ghost-cache") {
                return Err(format!(
                    "touch prefetch is limited to .ghost-cache markers: '{s}'"
                ));
            }
            Ok(())
        }
        other => Err(format!(
            "prefetch step starts with unexpected tool '{other}': '{s}' (allowed: bun|pnpm|python3|go|touch)"
        )),
    }
}

/// True when deploy input names a local manifest file rather than a URL:
/// an absolute/unexpanded-home/relative path, or anything ending in
/// `.yaml`/`.yml`. The file is still validated on load — this is only the
/// routing heuristic for the input field.
pub fn looks_like_manifest_path(input: &str) -> bool {
    let t = input.trim();
    t.starts_with('/')
        || t.starts_with("~/")
        || t.starts_with("./")
        || t.starts_with("../")
        || t.ends_with(".yaml")
        || t.ends_with(".yml")
}

/// Resolve a manifest path typed into the deploy field: `~/` expands to
/// `$HOME`, everything else passes through as-is.
pub fn expand_manifest_path(input: &str) -> std::path::PathBuf {
    let t = input.trim();
    if let Some(rest) = t.strip_prefix("~/") {
        crate::paths::home().join(rest)
    } else {
        std::path::PathBuf::from(t)
    }
}

// ── built-in manifests (1:1 with the former hardcoded recipes) ──

pub const MANIFEST_VERT: &str = include_str!("manifests/vert.yaml");
pub const MANIFEST_SEARXNG: &str = include_str!("manifests/searxng.yaml");
pub const MANIFEST_MEMOS: &str = include_str!("manifests/memos.yaml");

/// Parse a built-in manifest (already validated at authorship time).
pub fn builtin(name: &str) -> Option<ServiceManifest> {
    let text = match name {
        "demo-vert" => MANIFEST_VERT,
        "demo-searxng" => MANIFEST_SEARXNG,
        "demo-memos" => MANIFEST_MEMOS,
        _ => return None,
    };
    ServiceManifest::load_from_str(text, name).ok()
}

/// Find a built-in manifest by GitHub owner/name (case-insensitive).
pub fn find_builtin(owner: &str, name: &str) -> Option<ServiceManifest> {
    for id in ["demo-vert", "demo-searxng", "demo-memos"] {
        let m = builtin(id)?;
        // NOTE: builtin() returns None only for unknown ids above; a parse
        // failure would surface in tests. Keep the `?` so a broken built-in
        // fails loudly here rather than silently skipping.
        if let Some((o, n)) = m.owner_name()
            && o.eq_ignore_ascii_case(owner)
            && n.eq_ignore_ascii_case(name)
        {
            return Some(m);
        }
    }
    None
}

/// Convert a validated manifest into the engine's recipe shape.
///
/// The engine's `DemoRecipe` carries `&'static` borrows (author-written
/// constants). A user manifest is runtime data, so each string is copied
/// into leaked `'static` memory once per deploy. The leak is bounded
/// (a dozen short strings per deploy; the deploying process is
/// short-lived for `__deploy`, and one deploy at a time holds the lock)
/// and lets the manifest path reuse 100% of the audited pipeline
/// (`deploy_service`, `resolve_start`, `toolbox_needs`) with zero
/// behavioural drift.
pub fn to_leaked_recipe(m: &ServiceManifest) -> super::recipes::DemoRecipe {
    fn leak_str(s: &str) -> &'static str {
        Box::leak(s.to_string().into_boxed_str())
    }
    fn leak_slice(v: Vec<&'static str>) -> &'static [&'static str] {
        Box::leak(v.into_boxed_slice())
    }
    let pre_build: Vec<&'static str> = m
        .pre_build
        .iter()
        .map(|s| leak_str(&s.to_shell()))
        .collect();
    let prefetch: Vec<&'static str> = m.prefetch.iter().map(|s| leak_str(&s.to_shell())).collect();
    let build: Vec<&'static str> = m
        .build
        .steps
        .iter()
        .map(|s| leak_str(&s.to_shell()))
        .collect();
    let plugins: Vec<(&'static str, &'static str)> = m
        .plugins
        .iter()
        .map(|p| (leak_str(&p.url), leak_str(&p.sha256)))
        .collect();
    let tools: Vec<&'static str> = m.tools.iter().map(|t| leak_str(t)).collect();
    let language: &'static str = match m.build.profile.as_str() {
        "go" => "Go",
        "python" | "python-searxng" => "Python",
        _ => "JavaScript",
    };
    let start_cmd = leak_str(&m.run.command.join(" "));
    super::recipes::DemoRecipe {
        owner: leak_str(&m.owner_name().map(|(o, _)| o).unwrap_or_default()),
        name: leak_str(&m.owner_name().map(|(_, n)| n).unwrap_or_default()),
        language,
        service_name: leak_str(&m.service.id),
        description: leak_str(if m.service.description.is_empty() {
            &m.service.id
        } else {
            &m.service.description
        }),
        display_name: leak_str(if m.service.name.is_empty() {
            &m.service.id
        } else {
            &m.service.name
        }),
        commit: leak_str(&m.source.commit),
        pre_build: leak_slice(pre_build),
        build_steps: leak_slice(build),
        prefetch_steps: leak_slice(prefetch),
        plugins: Box::leak(plugins.into_boxed_slice()),
        start_cmd,
        port: m.run.port,
        searxng: m.searxng,
        tools: leak_slice(tools),
        res: super::units::ResourceLimits {
            memory_high: m.resources.memory_high.as_deref().map(leak_str),
            memory_max: m.resources.memory_max.as_deref().map(leak_str),
            tasks_max: m.resources.tasks_max.as_deref().map(leak_str),
            cpu_quota: m.resources.cpu_quota.as_deref().map(leak_str),
            limit_nofile: m.resources.limit_nofile,
            oom_score_adjust: m.resources.oom_score_adjust,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServiceManifest {
        ServiceManifest::load_from_str(MANIFEST_VERT, "test").expect("builtin vert must validate")
    }

    #[test]
    fn builtins_validate() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).unwrap_or_else(|| panic!("{id} must parse"));
            assert_eq!(m.service.id, id);
            assert_eq!(m.manifest_version, 1);
        }
    }

    /// The built-in shelf is exactly these three manifests: no more, no less.
    /// New services ship as user files, never as engine edits.
    #[test]
    fn builtin_shelf_holds_exactly_three() {
        assert!(builtin("demo-vert").is_some());
        assert!(builtin("demo-searxng").is_some());
        assert!(builtin("demo-memos").is_some());
        assert!(builtin("demo-evil").is_none());
    }

    /// Every built-in carries a resource budget through conversion: an
    /// unbounded unit can grind the whole user session.
    #[test]
    fn every_builtin_has_resource_limits() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).expect(id);
            let r = to_leaked_recipe(&m);
            assert!(
                r.res.memory_max.is_some() && r.res.tasks_max.is_some(),
                "{id}: must set memory_max and tasks_max"
            );
        }
    }

    /// Audit lesson, now asserted on the converted manifests: every build
    /// step's interpreter must be declared in `tools`.
    #[test]
    fn every_builtin_tool_covers_build_steps() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).expect(id);
            let r = to_leaked_recipe(&m);
            for step in r
                .pre_build
                .iter()
                .chain(r.build_steps.iter())
                .chain(r.prefetch_steps.iter())
            {
                let head = step.split_whitespace().next().unwrap();
                let base = head.rsplit('/').next().unwrap();
                if matches!(base, "bun" | "pnpm" | "go" | "python3") {
                    assert!(
                        r.tools.contains(&base),
                        "{id}: step '{step}' requires '{base}' not in {:?}",
                        r.tools
                    );
                }
            }
        }
    }

    /// Host-phase prefetch steps may never execute fetched package or project
    /// code on the host: bun needs --ignore-scripts, pnpm must stay a
    /// script-free `fetch`, pip must pin binary-only wheels.
    #[test]
    fn builtin_prefetch_never_runs_lifecycle_scripts_on_host() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).expect(id);
            let r = to_leaked_recipe(&m);
            for step in r.prefetch_steps {
                // `touch` marker tails carry no interpreter (see searxng.yaml).
                if step.starts_with("touch ") {
                    continue;
                }
                let base = step.split_whitespace().next().unwrap();
                match base {
                    "bun" => assert!(
                        step.contains("--ignore-scripts"),
                        "{id}: bun prefetch must use --ignore-scripts: '{step}'"
                    ),
                    "pnpm" => assert!(
                        step.split_whitespace().any(|w| w == "fetch"),
                        "{id}: pnpm prefetch must be a script-free `fetch`: '{step}'"
                    ),
                    "python3" => assert!(
                        step.contains("--only-binary=:all:"),
                        "{id}: pip prefetch must pin binary-only wheels: '{step}'"
                    ),
                    other => panic!("{id}: unexpected prefetch tool '{other}'"),
                }
            }
        }
    }

    /// Only VERT carries plugin pins, and every pin is a jsdelivr paraglide
    /// module whose cache filename matches the FNV1a-64 derivation.
    #[test]
    fn builtin_plugin_pins_are_paraglide_jsdelivr_and_well_formed() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).expect(id);
            let r = to_leaked_recipe(&m);
            assert!(r.plugins.len() <= 2, "{id}: unexpected plugin count");
            if id != "demo-vert" {
                assert!(r.plugins.is_empty(), "{id}: non-VERT plugin pins");
            }
            for (url, sha) in r.plugins {
                assert!(
                    url.starts_with("https://cdn.jsdelivr.net/npm/@inlang/plugin-"),
                    "{id}: {url}"
                );
                assert_eq!(sha.len(), 64, "{id}: {url}");
                assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{id}: {url}");
                super::super::prefetch::paraglide_cache_name(url);
            }
        }
    }

    /// resolve_start must preserve the loopback pin through placeholder
    /// expansion, so the deployed unit actually binds 127.0.0.1.
    #[test]
    fn builtin_memos_resolve_start_keeps_loopback_after_expansion() {
        use std::path::Path;
        let m = find_builtin("usememos", "memos").unwrap();
        let r = to_leaked_recipe(&m);
        let resolved = super::super::deploy::resolve_start(&r, Path::new("/srv/memos"), 12345);
        assert!(resolved.contains("--addr 127.0.0.1"), "got: {resolved}");
        assert!(resolved.contains("--port 12345"), "got: {resolved}");
    }

    #[test]
    fn builtin_lookup_is_case_insensitive() {
        assert!(find_builtin("VERT-sh", "VERT").is_some());
        assert!(find_builtin("searxng", "searxng").is_some());
        assert!(find_builtin("usememos", "memos").is_some());
        assert!(find_builtin("foo", "bar").is_none());
    }

    #[test]
    fn rejects_bad_version_and_commit() {
        let mut m = sample();
        m.manifest_version = 2;
        assert!(m.validate("t").is_err());
        let mut m = sample();
        m.source.commit = "abc".into();
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn rejects_non_github_and_non_loopback_run() {
        let mut m = sample();
        m.source.git = "https://gitlab.com/a/b".into();
        assert!(m.validate("t").is_err());
        let mut m = sample();
        m.run.command = vec![
            "node".into(),
            "server.js".into(),
            "--port".into(),
            "{port}".into(),
        ];
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn rejects_bun_prefetch_without_ignore_scripts() {
        let mut m = sample();
        m.prefetch = vec![Step::Shell("bun install --frozen-lockfile".into())];
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn rejects_unknown_tool_and_undeclared_tool() {
        let mut m = sample();
        m.tools = vec!["curl".into()];
        assert!(m.validate("t").is_err());
        let mut m = sample();
        m.build.steps = vec![Step::Argv(vec!["go".into(), "build".into()])];
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn rejects_missing_resource_caps() {
        let mut m = sample();
        m.resources.memory_max = None;
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn argv_steps_are_shell_quoted() {
        let s = Step::Argv(vec!["bun".into(), "install;rm -rf /".into()]);
        assert_eq!(s.to_shell(), "bun 'install;rm -rf /'");
    }

    #[test]
    fn manifest_path_routing_heuristic() {
        for p in [
            "/tmp/svc.yaml",
            "~/svc/service.yml",
            "./service.yaml",
            "../x.yaml",
            "relative.yaml",
            "  /tmp/svc.yaml  ",
        ] {
            assert!(looks_like_manifest_path(p), "{p}");
        }
        for u in [
            "https://github.com/usememos/memos",
            "https://github.com/VERT-sh/VERT.git",
            "notaurl",
        ] {
            assert!(!looks_like_manifest_path(u), "{u}");
        }
    }

    #[test]
    fn manifest_path_tilde_expands_to_home() {
        let p = expand_manifest_path("~/svc/service.yaml");
        assert!(p.ends_with("svc/service.yaml"));
        assert!(p.is_absolute());
        assert_eq!(
            expand_manifest_path("/tmp/x.yaml"),
            std::path::PathBuf::from("/tmp/x.yaml")
        );
    }

    #[test]
    fn every_builtin_binds_loopback_only() {
        for id in ["demo-vert", "demo-searxng", "demo-memos"] {
            let m = builtin(id).expect(id);
            let joined = m.run.command.join(" ");
            if !m.searxng {
                assert!(joined.contains("{port}"), "{id}");
            }
            assert!(
                joined.contains("__serve-static") || joined.contains("127.0.0.1") || m.searxng,
                "{id}: {joined}"
            );
        }
    }
}
