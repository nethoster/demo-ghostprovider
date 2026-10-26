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

use std::collections::BTreeMap;
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

/// True for a full 40-hex commit SHA (an exact pin).
pub fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A ref name safe to hand to the materializer and `git ls-remote`: no
/// shell/URL hazards, no traversal shapes, no empty segments. Mirrors git's
/// own ref-format rules closely enough for branches and tags.
pub fn valid_ref_name(s: &str) -> anyhow::Result<()> {
    if s.is_empty() {
        anyhow::bail!("ref name is empty");
    }
    if s == "HEAD" {
        anyhow::bail!("HEAD is not a stable ref — use the branch name (e.g. main)");
    }
    if s.len() > 100 {
        anyhow::bail!("ref name too long (max 100)");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
    {
        anyhow::bail!("ref name may only contain letters, digits, '.', '_', '/', '-'");
    }
    if s.starts_with('-') || s.starts_with('/') || s.starts_with('.') {
        anyhow::bail!("ref name must not start with '-', '/' or '.'");
    }
    if s.ends_with('/') || s.ends_with('.') {
        anyhow::bail!("ref name must not end with '/' or '.'");
    }
    if s.contains("..") || s.contains("//") || s.contains("@{") {
        anyhow::bail!("ref name must not contain '..', '//' or '@{{'");
    }
    if s.split('/')
        .any(|seg| seg.is_empty() || seg.starts_with('.') || seg.ends_with(".lock"))
    {
        anyhow::bail!("ref name must not contain empty, leading-'.' or '.lock' path segments");
    }
    Ok(())
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
    /// Either a full 40-hex commit SHA (exact pin — the deploy builds
    /// exactly that commit) or a safe ref name such as `main` (branch
    /// tracking — the tip is resolved to a SHA at the start of each deploy
    /// and the build proceeds pin-exact against that resolution; for
    /// upstreams that force-push, where a static pin would go stale).
    pub commit: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildSpec {
    pub profile: String,
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Build-time environment variables (e.g. SvelteKit's `PUB_*` public
    /// env, without which `$env/static/public` imports fail the offline
    /// vite build). Injected into every sandboxed build step; runtime
    /// units never see these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunSpec {
    pub command: Vec<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Runtime environment variables, written to a per-service 0600
    /// EnvironmentFile. Values may use the `{port}` placeholder and
    /// `{secret}` (fresh 16-byte hex per deploy) — e.g. an app config that
    /// documents an env override for a committed placeholder secret.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
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

/// Per-service runtime egress exceptions. Empty (the default) means the
/// historic deny-all: the unit may only talk to loopback. Each entry opens
/// exactly one hostname/IPv4 for that service's unit — a conscious trust
/// decision recorded in the manifest, never a global allowlist. Hostnames
/// resolve to literal addresses at deploy time (`egress::resolve_egress_hosts`,
/// fail closed) because systemd's `IPAddressAllow=` rejects names.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EgressSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Auto-fill policy: `None` = untouched (deploy may fill `allow` from
    /// what the tree declares, when it declares anything); `Some(true)` =
    /// the deploy already filled it; `Some(false)` = the user edited the
    /// list (even to empty) and the deploy must never touch it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<bool>,
}

/// Max allowed egress hosts per service (v1): keeps the unit line and the
/// live verification probe (one beat per host) bounded.
pub const MAX_EGRESS_HOSTS: usize = 8;

/// Validate one egress host; returns it normalized (trimmed, lowercased).
pub(crate) fn validate_egress_host(host: &str) -> Result<String, String> {
    let t = host.trim().to_lowercase();
    if t.is_empty() || t.len() > 253 {
        return Err(format!("egress host must be 1..=253 chars: '{host}'"));
    }
    if t == "localhost" {
        return Err("egress host 'localhost' is redundant (loopback is always allowed)".into());
    }
    if t.contains('/') || t.contains(':') || t.contains(' ') || t.contains('*') || t.contains('?') {
        return Err(format!(
            "egress host must be a bare hostname or IPv4, no ranges/ports/wildcards: '{host}'"
        ));
    }
    if is_ipv4(&t) {
        return Ok(t);
    }
    let labels: Vec<&str> = t.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("egress host needs at least two labels: '{host}'"));
    }
    // All-numeric TLDs are IP typos (256.1.1.1), not hostnames.
    if !labels
        .last()
        .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()))
    {
        return Err(format!("egress hostname needs a lettered TLD: '{host}'"));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(format!("bad egress hostname label in '{host}'"));
        }
    }
    Ok(t)
}

fn is_ipv4(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u8>().is_ok()
        })
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
    /// Extra build tools required on PATH (provisionable: bun/pnpm/go).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Runtime egress exceptions (default: loopback only).
    #[serde(default)]
    pub egress: EgressSpec,
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
        // Legacy ids `demo-vert`/`demo-searxng`/`demo-memos` stay valid on
        // purpose: they name already-deployed units and the test fixtures
        // (`crate::hoster::fixtures`) — a redeploy of those must keep
        // working. There is no curated catalog left to squat.
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
        // commit: a full 40-hex SHA (exact pin) or a safe ref name (branch
        // tracking — the tip is resolved to a SHA at each deploy).
        if !is_full_sha(&self.source.commit) && valid_ref_name(&self.source.commit).is_err() {
            anyhow::bail!(
                "{}",
                at("source.commit must be a full 40-hex commit SHA or a branch name (e.g. main)")
            );
        }
        // ── profile ──
        match self.build.profile.as_str() {
            "bun" | "python" | "go" | "node" => {}
            other => anyhow::bail!(
                "{}",
                at(&format!(
                    "build.profile '{other}' unsupported (bun|python|go|node)"
                ))
            ),
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
        // ── build.env: names are POSIX-ish (no '=', no NUL/newlines in
        // values — systemd Environment= lines would break) ──
        if self.build.env.len() > 64 {
            anyhow::bail!("{}", at("build.env holds at most 64 variables"));
        }
        for (k, v) in &self.build.env {
            if k.is_empty()
                || k.len() > 128
                || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || k.starts_with(|c: char| c.is_ascii_digit())
            {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "build.env key must be [A-Za-z_][A-Za-z0-9_] (got {k:?})"
                    ))
                );
            }
            if v.len() > 4096 || v.contains('\0') || v.contains('\n') {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "build.env value for {k} must be ≤4096 chars without NUL/newlines"
                    ))
                );
            }
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
        // The assigned port must reach the app somewhere: argv (`--port
        // {port}`) or the environment (`PORT: '{port}'` — the convention the
        // recipe also exports by default). Command-only would reject every
        // env-binding app.
        let env_has_port = self.run.env.values().any(|v| v.contains("{port}"));
        if !joined.contains("{port}") && !env_has_port {
            anyhow::bail!(
                "{}",
                at("run.command or run.env must contain the {port} placeholder")
            );
        }
        // Loopback pin: the deployed unit must bind 127.0.0.1 (or be our
        // loopback static server).
        if !(joined.contains("__serve-static") || joined.contains("127.0.0.1")) {
            anyhow::bail!(
                "{}",
                at("run.command must bind loopback: use __serve-static or 127.0.0.1")
            );
        }
        if !(self.run.port == 0 || (1024..=65535).contains(&self.run.port)) {
            anyhow::bail!("{}", at("run.port must be 0 (random) or 1024..=65535"));
        }
        // ── run.env: same shape rules as build.env, plus placeholder check
        // so a typo like {secert} fails validation instead of shipping the
        // literal braces to the unit ──
        if self.run.env.len() > 64 {
            anyhow::bail!("{}", at("run.env holds at most 64 variables"));
        }
        for (k, v) in &self.run.env {
            if k.is_empty()
                || k.len() > 128
                || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || k.starts_with(|c: char| c.is_ascii_digit())
            {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "run.env key must be [A-Za-z_][A-Za-z0-9_] (got {k:?})"
                    ))
                );
            }
            if v.len() > 4096 || v.contains('\0') || v.contains('\n') {
                anyhow::bail!(
                    "{}",
                    at(&format!(
                        "run.env value for {k} must be ≤4096 chars without NUL/newlines"
                    ))
                );
            }
            let mut rest = v.as_str();
            while let Some(open) = rest.find('{') {
                if rest[..open].contains('}') {
                    anyhow::bail!("{}", at(&format!("run.env value for {k} has a stray }}")));
                }
                let Some(close) = rest[open + 1..].find('}') else {
                    anyhow::bail!(
                        "{}",
                        at(&format!(
                            "run.env value for {k} has an unclosed {{placeholder"
                        ))
                    );
                };
                let token = &rest[open + 1..open + 1 + close];
                if token != "port" && token != "secret" {
                    anyhow::bail!(
                        "{}",
                        at(&format!(
                            "run.env value for {k} has unknown placeholder {{{token}}} (port|secret)"
                        ))
                    );
                }
                rest = &rest[open + 1 + close + 1..];
            }
            if rest.contains('}') {
                anyhow::bail!("{}", at(&format!("run.env value for {k} has a stray }}")));
            }
        }
        // ── resources (budgets are mandatory: unbounded units can grind the session) ──
        if self.resources.memory_max.is_none() || self.resources.tasks_max.is_none() {
            anyhow::bail!(
                "{}",
                at("resources.memory_max and resources.tasks_max are required")
            );
        }
        // ── egress allowlist (empty = historic deny-all) ──
        if self.egress.allow.len() > MAX_EGRESS_HOSTS {
            anyhow::bail!(
                "{}",
                at(&format!(
                    "egress.allow holds at most {MAX_EGRESS_HOSTS} hosts"
                ))
            );
        }
        if self.egress.auto == Some(true) && self.egress.allow.is_empty() {
            anyhow::bail!(
                "{}",
                at(
                    "egress.auto=true requires a non-empty egress.allow (a filled list is the point)"
                )
            );
        }
        {
            let mut seen = std::collections::BTreeSet::new();
            for h in &self.egress.allow {
                let norm = validate_egress_host(h).map_err(|r| anyhow::anyhow!("{}", at(&r)))?;
                if !seen.insert(norm.clone()) {
                    anyhow::bail!("{}", at(&format!("egress.allow lists '{norm}' twice")));
                }
            }
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
        if is_full_sha(&self.source.commit) {
            out.push_str(&format!("commit:   {} (exact pin)\n", self.source.commit));
        } else {
            out.push_str(&format!(
                "branch:   {} (tip resolved at each deploy)\n",
                self.source.commit
            ));
        }
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
        if !self.build.env.is_empty() {
            out.push_str(&format!("build env ({} var(s)):\n", self.build.env.len()));
            for (k, v) in &self.build.env {
                out.push_str(&format!("  + {k}={v}\n"));
            }
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
        if self.egress.allow.is_empty() {
            out.push_str("egress:   loopback only (deny-all — private network namespace)\n");
        } else {
            let auto = if self.egress.auto == Some(true) {
                " (auto)"
            } else {
                ""
            };
            out.push_str(&format!(
                "egress:   loopback + {}{auto}\n",
                self.egress.allow.join(", ")
            ));
        }
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

// ── built-in manifests were removed in v0.0.44 (demo-declutter): the former
// reference examples now live as cfg(test) string fixtures
// (`crate::hoster::fixtures`) — validated by the tests below, never embedded
// into the binary. Every deploy goes through a user-provided `service.yaml`;
// a GitHub URL is input for stack detection (Add Service → Detect /
// `__deploy URL`), never a deployable on its own.

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
    let build_env: Vec<(&'static str, &'static str)> = m
        .build
        .env
        .iter()
        .map(|(k, v)| (leak_str(k), leak_str(v)))
        .collect();
    let mut run_env: Vec<(&'static str, &'static str)> = m
        .run
        .env
        .iter()
        .map(|(k, v)| (leak_str(k), leak_str(v)))
        .collect();
    // PORT={port} on every deploy unless the manifest sets PORT itself: the
    // industry-standard convention — next/nuxt/express/uvicorn-with-env and
    // hundreds more bind exactly where the healthcheck probes. Harmless for
    // servers that ignore it.
    if !m.run.env.contains_key("PORT") {
        run_env.push(("PORT", "{port}"));
    }
    let tools: Vec<&'static str> = m.tools.iter().map(|t| leak_str(t)).collect();
    let egress: Vec<&'static str> = m
        .egress
        .allow
        .iter()
        .map(|h| leak_str(&h.trim().to_lowercase()))
        .collect();
    let egress_may_autofill = m.egress.allow.is_empty() && m.egress.auto.is_none();
    let language: &'static str = match m.build.profile.as_str() {
        "go" => "Go",
        "python" => "Python",
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
        build_env: Box::leak(build_env.into_boxed_slice()),
        run_env: Box::leak(run_env.into_boxed_slice()),
        prefetch_steps: leak_slice(prefetch),
        plugins: Box::leak(plugins.into_boxed_slice()),
        start_cmd,
        port: m.run.port,
        tools: leak_slice(tools),
        egress_allow: leak_slice(egress),
        egress_may_autofill,
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

    /// Fixture dispatch — formerly `docs/examples/<name>.yaml`, now inline
    /// test data (see `super::super::fixtures`), never embedded into the
    /// binary.
    fn example(id: &str) -> ServiceManifest {
        let yaml = match id {
            "demo-vert" => super::super::fixtures::VERT_YAML,
            "demo-searxng" => super::super::fixtures::SEARXNG_YAML,
            "demo-memos" => super::super::fixtures::MEMOS_YAML,
            other => panic!("unknown fixture {other}"),
        };
        ServiceManifest::load_from_str(yaml, id)
            .unwrap_or_else(|e| panic!("{id} fixture must validate: {e}"))
    }

    fn example_ids() -> [&'static str; 3] {
        ["demo-vert", "demo-searxng", "demo-memos"]
    }

    fn sample() -> ServiceManifest {
        example("demo-vert")
    }

    #[test]
    fn examples_validate() {
        for id in example_ids() {
            let m = example(id);
            assert_eq!(m.service.id, id);
            assert_eq!(m.manifest_version, 1);
        }
    }

    /// Every example carries a resource budget through conversion: an
    /// unbounded unit can grind the whole user session.
    #[test]
    fn every_example_has_resource_limits() {
        for id in example_ids() {
            let m = example(id);
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
    fn every_example_tool_covers_build_steps() {
        for id in example_ids() {
            let m = example(id);
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
    fn example_prefetch_never_runs_lifecycle_scripts_on_host() {
        for id in example_ids() {
            let m = example(id);
            let r = to_leaked_recipe(&m);
            for step in r.prefetch_steps {
                // `touch` marker tails carry no interpreter (searxng fixture).
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
    fn example_plugin_pins_are_paraglide_jsdelivr_and_well_formed() {
        for id in example_ids() {
            let m = example(id);
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
    fn egress_hosts_validate_and_normalize() {
        assert_eq!(
            validate_egress_host("Api.Telegram.Org").unwrap(),
            "api.telegram.org"
        );
        assert_eq!(validate_egress_host("1.1.1.1").unwrap(), "1.1.1.1");
        for bad in [
            "",
            "localhost",
            "no-dot",
            "a..b.com",
            "-lead.com",
            "trail-.com",
            "has space.com",
            "10.0.0.0/8",
            "example.com:443",
            "*.example.com",
            "256.1.1.1",
            "1.2.3",
        ] {
            assert!(validate_egress_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn egress_allowlist_rejects_overflow_and_duplicates() {
        let mut m = sample();
        m.egress.allow = (0..=MAX_EGRESS_HOSTS)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        assert!(m.validate("t").is_err());
        let mut m = sample();
        m.egress.allow = vec!["a.example.com".into(), "A.EXAMPLE.COM".into()];
        assert!(m.validate("t").is_err());
        // Empty (default) stays valid and converts to no exceptions.
        let m = sample();
        assert!(m.egress.allow.is_empty());
        assert!(to_leaked_recipe(&m).egress_allow.is_empty());
        // Untouched (auto=None, allow empty) is autofill-eligible.
        assert!(to_leaked_recipe(&m).egress_may_autofill);
    }

    #[test]
    fn egress_auto_true_requires_a_filled_list() {
        let mut m = sample();
        m.egress.auto = Some(true);
        m.egress.allow = vec!["duckduckgo.com".into()];
        m.validate("t").unwrap();
        let mut m = sample();
        m.egress.auto = Some(true);
        assert!(m.validate("t").is_err());
        // auto=false with an empty list is the "user emptied it" state — valid,
        // and never autofill-eligible.
        let mut m = sample();
        m.egress.auto = Some(false);
        m.validate("t").unwrap();
        assert!(!to_leaked_recipe(&m).egress_may_autofill);
        // auto=true with a filled list converts, but is not autofill-eligible.
        let mut m = sample();
        m.egress.auto = Some(true);
        m.egress.allow = vec!["duckduckgo.com".into()];
        assert!(!to_leaked_recipe(&m).egress_may_autofill);
        assert_eq!(to_leaked_recipe(&m).egress_allow, ["duckduckgo.com"]);
        // plan_text marks an auto-filled list.
        assert!(
            m.plan_text()
                .contains("egress:   loopback + duckduckgo.com (auto)")
        );
        // serde round-trip keeps the tri-state.
        let yaml = serde_yaml::to_string(&m).unwrap();
        assert!(yaml.contains("auto: true"), "{yaml}");
        let back: ServiceManifest = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.egress.auto, Some(true));
    }

    #[test]
    fn memos_example_resolve_start_keeps_loopback_after_expansion() {
        use std::path::Path;
        let m = example("demo-memos");
        let r = to_leaked_recipe(&m);
        let resolved = super::super::deploy::resolve_start(&r, Path::new("/srv/memos"), 12345);
        assert!(resolved.contains("--addr 127.0.0.1"), "got: {resolved}");
        assert!(resolved.contains("--port 12345"), "got: {resolved}");
    }

    #[test]
    fn rejects_bad_version_and_commit() {
        let mut m = sample();
        m.manifest_version = 2;
        assert!(m.validate("t").is_err());
        // Neither a 40-hex SHA nor a safe ref name (space).
        let mut m = sample();
        m.source.commit = "a b".into();
        assert!(m.validate("t").is_err());
    }

    #[test]
    fn accepts_branch_tracking_source() {
        let mut m = sample();
        m.source.commit = "main".into();
        m.validate("t").unwrap();
        let mut m = sample();
        m.source.commit = "release/1.2".into();
        m.validate("t").unwrap();
    }

    #[test]
    fn rejects_hazardous_ref_names() {
        for bad in [
            "",
            "HEAD",
            "a b",
            "-x",
            "/x",
            "x/",
            ".x",
            "x.",
            "a..b",
            "a//b",
            "x@{y}",
            "feature/.hidden",
            "a.lock",
            "a.lock/b",
            &"a".repeat(101),
        ] {
            assert!(valid_ref_name(bad).is_err(), "{bad:?} must be rejected");
        }
        for ok in ["main", "release/1.2", "feat_x.y", "v1.2.3"] {
            valid_ref_name(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
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
    fn every_example_binds_loopback_only() {
        for id in example_ids() {
            let m = example(id);
            let joined = m.run.command.join(" ");
            assert!(joined.contains("{port}"), "{id}");
            assert!(
                joined.contains("__serve-static") || joined.contains("127.0.0.1"),
                "{id}: {joined}"
            );
        }
    }

    /// `build.env` travels from the manifest into the recipe (and from there
    /// into every sandboxed build step); keys/values are validated up front.
    #[test]
    fn build_env_validates_keys_and_reaches_the_recipe() {
        let mut m = sample();
        m.build.env.insert("PUB_ENV".into(), "production".into());
        m.build
            .env
            .insert("PUB_DISABLE_ALL_EXTERNAL_REQUESTS".into(), "true".into());
        m.validate("t").expect("valid build.env");
        let r = to_leaked_recipe(&m);
        assert!(r.build_env.contains(&("PUB_ENV", "production")));
        assert!(
            r.build_env
                .contains(&("PUB_DISABLE_ALL_EXTERNAL_REQUESTS", "true"))
        );

        // Bad keys: digits first, dashes, empty.
        for bad in ["1PUBLIC", "PUB-ENV", ""] {
            let mut m = sample();
            m.build.env.insert(bad.into(), "x".into());
            assert!(m.validate("t").is_err(), "key {bad:?} must be rejected");
        }
        // Newlines would break the unit's Environment= line.
        let mut m = sample();
        m.build.env.insert("PUB_ENV".into(), "a\nb".into());
        assert!(m.validate("t").is_err());
        // The built-in VERT example carries the eight PUB_* imports VERT
        // needs for its offline vite build.
        let vert = example("demo-vert");
        assert!(
            vert.build.env.contains_key("PUB_ENV"),
            "vert example must set PUB_ENV"
        );
    }

    /// `run.env`: valid entries reach the leaked recipe, bad keys/values/
    /// placeholders fail validation before any deploy sees them.
    #[test]
    fn run_env_validates_and_reaches_the_recipe() {
        let mut m = sample();
        m.run.env.insert("SEARXNG_SECRET".into(), "{secret}".into());
        m.run.env.insert("APP_PORT".into(), "listen {port}".into());
        m.validate("t").expect("valid run.env");
        let r = to_leaked_recipe(&m);
        assert!(r.run_env.contains(&("SEARXNG_SECRET", "{secret}")));
        assert!(r.run_env.contains(&("APP_PORT", "listen {port}")));

        // Unknown placeholder (typo) must not ship literal braces.
        let mut m = sample();
        m.run.env.insert("X".into(), "{secert}".into());
        assert!(m.validate("t").is_err(), "typo placeholder rejected");
        // Stray / unclosed braces.
        let mut m = sample();
        m.run.env.insert("X".into(), "abc}".into());
        assert!(m.validate("t").is_err(), "stray brace rejected");
        let mut m = sample();
        m.run.env.insert("X".into(), "{port".into());
        assert!(m.validate("t").is_err(), "unclosed brace rejected");
        // Same shape rules as build.env.
        let mut m = sample();
        m.run.env.insert("1BAD".into(), "x".into());
        assert!(m.validate("t").is_err(), "bad key rejected");
        let mut m = sample();
        m.run.env.insert("GOOD_KEY".into(), "a\nb".into());
        assert!(m.validate("t").is_err(), "newline value rejected");
    }

    /// Every recipe exports PORT={port} (the universal convention aid) —
    /// unless the manifest pins PORT itself, which must win.
    #[test]
    fn recipe_exports_port_unless_manifest_pins_it() {
        let m = sample();
        let r = to_leaked_recipe(&m);
        assert!(
            r.run_env.contains(&("PORT", "{port}")),
            "PORT exported by default: {:?}",
            r.run_env
        );

        let mut pinned = sample();
        pinned.run.env.insert("PORT".into(), "9999".into());
        let r = to_leaked_recipe(&pinned);
        assert!(r.run_env.contains(&("PORT", "9999")), "{:?}", r.run_env);
        assert!(
            !r.run_env.contains(&("PORT", "{port}")),
            "pinned PORT not overridden: {:?}",
            r.run_env
        );
    }
}
