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

/// Outcome of a deployment attempt.
#[derive(Debug, Default)]
pub struct HostResult {
    pub service_names: Vec<String>,
    pub urls: Vec<String>,
    pub errors: Vec<String>,
}

impl HostResult {
    pub fn ok(&self) -> bool {
        !self.service_names.is_empty() && self.errors.is_empty()
    }
}
