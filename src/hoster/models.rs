//! Shared data types for the deploy pipeline.

/// Resolved owner/name/language facts about the GitHub URL a manifest points
/// at (resolved from the manifest itself — no catalog lookup exists).
#[derive(Debug, Default, Clone)]
pub struct RepoAnalysis {
    pub url: String,
    pub owner: String,
    pub name: String,
    pub language: String,
    pub exists: bool,
    pub clone_path: Option<String>,
    pub errors: Vec<String>,
}

/// Auto-repair request from a failed deploy: the source tree declares a
/// build plan richer than the manifest's (frontend steps missing) — the
/// caller patches the manifest and runs ONE retry instead of dying.
#[derive(Debug, Clone, Default)]
pub struct ManifestRepair {
    /// Human line for the deploy screen ("what was wrong and what now").
    pub summary: String,
    pub prefetch: Vec<String>,
    pub build_steps: Vec<String>,
}

/// Outcome of a deployment attempt.
#[derive(Debug, Default)]
pub struct HostResult {
    pub service_names: Vec<String>,
    pub urls: Vec<String>,
    pub errors: Vec<String>,
    /// Hosts the deploy auto-detected from the source tree's own
    /// declaration and opened in the unit (empty when the list came from
    /// the manifest as-is). The caller persists them into the manifest
    /// with `egress.auto = Some(true)` on success.
    pub egress: Vec<String>,
    /// Set instead of failing when a patched manifest could fix the
    /// failure — the caller owns the one-retry loop. Never a success.
    pub repair: Option<ManifestRepair>,
}

impl HostResult {
    pub fn ok(&self) -> bool {
        !self.service_names.is_empty() && self.errors.is_empty()
    }
}
