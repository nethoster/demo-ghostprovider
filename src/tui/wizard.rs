//! New-service wizard: draft, profile defaults, validation.
//!
//! Pure logic (no widgets): the step screens, keys and drawing live in
//! `super`. Every transition builds a [`ServiceManifest`] from the
//! [`Draft`] and runs the real schema validation, so the wizard can only
//! produce files the engine accepts.

use crate::hoster::manifest::{ServiceManifest, Step};

/// Profiles the wizard offers: (id, one-line explanation).
pub const PROFILES: &[(&str, &str)] = &[
    ("bun", "JavaScript with Bun (e.g. SvelteKit / Vite apps)"),
    ("python", "Python with pip (venv, binary wheels)"),
    (
        "python-searxng",
        "Python, SearXNG-style (settings patch + loopback bind)",
    ),
    ("go", "Go (modules seeded on host, offline build)"),
];

/// Tools the engine can auto-provision; anything else must be installed.
const KNOWN_TOOLS: &[&str] = &["bun", "pnpm", "go", "python3", "node"];

/// Everything the wizard asks, in step order.
#[derive(Clone, Default, Debug)]
pub struct Draft {
    pub id: String,
    pub git: String,
    pub commit: String,
    pub profile: String,
    pub prefetch: Vec<String>,
    pub build_steps: Vec<String>,
    pub run_cmd: String,
    pub port: String,
    pub memory_max: String,
    pub tasks_max: String,
    /// Build-time env vars (name, value) carried into `build.env` —
    /// auto-detected from `$env/static/public` imports for SvelteKit apps.
    pub build_env: Vec<(String, String)>,
    /// Remote inlang/paraglide modules pinned by content hash
    /// (url, sha256) — auto-detected so the offline build compiles real
    /// messages instead of an empty (broken) module.
    pub plugins: Vec<(String, String)>,
    /// True when steps came from stack detection (not profile defaults):
    /// the profile step keeps them unless the user picks another profile.
    pub detected: bool,
    /// Why detection guessed what it guessed; shown on the profile step.
    pub notes: Vec<String>,
}

/// Preset answers for a profile: the user edits them on later steps.
pub struct ProfileDefaults {
    pub prefetch: Vec<String>,
    pub build: Vec<String>,
    pub run_cmd: String,
    pub port: String,
    pub memory_max: String,
    pub tasks_max: String,
}

pub fn defaults_for_profile(profile: &str) -> Option<ProfileDefaults> {
    match profile {
        | "bun" => Some(ProfileDefaults {
            prefetch: vec!["bun install --frozen-lockfile --ignore-scripts".into()],
            build: vec!["bun run build".into()],
            run_cmd: "{self} __serve-static {project}/build {port}".into(),
            port: "0".into(),
            memory_max: "384M".into(),
            tasks_max: "300".into(),
        }),
        | "python" => Some(ProfileDefaults {
            prefetch: vec![
                "python3 -m pip download -r requirements.txt -d .ghost-cache/pip-wheelhouse --only-binary=:all:"
                    .into(),
            ],
            build: vec![
                "python3 -m venv --clear .venv".into(),
                ".venv/bin/pip install --no-cache-dir -r requirements.txt".into(),
            ],
            run_cmd: "{venv} -m http.server {port} --bind 127.0.0.1".into(),
            port: "8000".into(),
            memory_max: "1024M".into(),
            tasks_max: "512".into(),
        }),
        | "python-searxng" => Some(ProfileDefaults {
            prefetch: vec![
                "python3 -m pip download -r requirements.txt -d .ghost-cache/pip-wheelhouse --only-binary=:all:"
                    .into(),
            ],
            build: vec![
                "python3 -m venv --clear .venv".into(),
                ".venv/bin/pip install --no-cache-dir -r requirements.txt".into(),
            ],
            run_cmd: "{venv} -m searx.webapp".into(),
            port: "8888".into(),
            memory_max: "1536M".into(),
            tasks_max: "512".into(),
        }),
        | "go" => Some(ProfileDefaults {
            prefetch: vec![],
            build: vec!["go build -o ghost-server ./...".into()],
            run_cmd: "{bin} --addr 127.0.0.1 --port {port}".into(),
            port: "0".into(),
            memory_max: "1024M".into(),
            tasks_max: "512".into(),
        }),
        | _ => None,
    }
}

/// Apply a profile's presets to the draft (steps, run, port, budgets).
/// Clears the detection flag: from here the answers are profile defaults
/// the user edits, not detector guesses.
pub fn apply_profile_defaults(draft: &mut Draft, profile: &str) -> bool {
    match defaults_for_profile(profile) {
        Some(d) => {
            draft.profile = profile.to_string();
            draft.prefetch = d.prefetch;
            draft.build_steps = d.build;
            draft.run_cmd = d.run_cmd;
            draft.port = d.port;
            draft.memory_max = d.memory_max;
            draft.tasks_max = d.tasks_max;
            draft.detected = false;
            draft.notes.clear();
            // Plugin pins are a bun/paraglide concept (the schema rejects
            // them elsewhere); drop them on a profile switch so the user
            // never hits a confusing validation error later.
            if profile != "bun" {
                draft.plugins.clear();
            }
            true
        }
        None => false,
    }
}

/// First executable token of a shell step (mirrors `Step::head`).
fn step_head(step: &str) -> &str {
    step.split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
}

/// Per-field checks: same rules as the schema, but callable after a single
/// wizard step (the full [`build_manifest`] runs at Review).
pub fn check_id(id: &str) -> Result<(), String> {
    let t = id.trim();
    if t.len() < 3 || t.len() > 64 {
        return Err("id must be 3..=64 characters (lowercase letters, digits, dashes)".into());
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || t.starts_with('-')
        || t.ends_with('-')
    {
        return Err("id must match ^[a-z0-9-]{3,64}$ and not start/end with '-'".into());
    }
    Ok(())
}

pub fn check_git(git: &str) -> Result<(), String> {
    match crate::hoster::github::parse_github_url(git.trim()) {
        Some(_) => Ok(()),
        None => Err("must be https://github.com/<owner>/<repo> (optional .git)".into()),
    }
}

pub fn check_commit(commit: &str) -> Result<(), String> {
    let t = commit.trim();
    if crate::hoster::manifest::is_full_sha(t) {
        return Ok(());
    }
    if crate::hoster::manifest::valid_ref_name(t).is_ok() {
        return Ok(());
    }
    Err("must be a full 40-hex commit SHA or a branch name (e.g. main)".into())
}

pub fn check_port(port: &str) -> Result<u16, String> {
    let p: u16 = port
        .trim()
        .parse()
        .map_err(|_| "port must be a number: 0 (random free port) or 1024..=65535".to_string())?;
    if p == 0 || (1024..=65535).contains(&p) {
        Ok(p)
    } else {
        Err("port must be 0 (random free port) or 1024..=65535".to_string())
    }
}

pub fn check_memory(memory: &str) -> Result<(), String> {
    if is_memory(memory) {
        Ok(())
    } else {
        Err("memory limit must look like 256M or 1G (e.g. 384M)".to_string())
    }
}

pub fn check_tasks(tasks: &str) -> Result<(), String> {
    let t = tasks.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err("task limit must be a number (e.g. 300)".to_string())
    }
}

/// Build the validated manifest for a draft, or a human-readable reason.
/// This is the single chokepoint every wizard step goes through.
pub fn build_manifest(draft: &Draft) -> Result<ServiceManifest, String> {
    if PROFILES.iter().all(|(id, _)| *id != draft.profile) {
        return Err(format!(
            "unknown profile '{}' (pick one of: bun, python, python-searxng, go)",
            draft.profile
        ));
    }
    let port = check_port(&draft.port)?;
    check_memory(&draft.memory_max)?;
    check_tasks(&draft.tasks_max)?;
    for step in draft.prefetch.iter().chain(draft.build_steps.iter()) {
        if step.trim().is_empty() {
            return Err("build steps must not contain empty lines".to_string());
        }
        if step.len() > 2048 {
            return Err("one build step exceeds 2048 characters".to_string());
        }
    }
    let run_argv: Vec<String> = draft
        .run_cmd
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if run_argv.is_empty() {
        return Err("run command must not be empty".to_string());
    }
    // Tools the steps need: auto-derived from first tokens so the user never
    // hand-maintains this list.
    let mut tools: Vec<String> = Vec::new();
    for step in draft.prefetch.iter().chain(draft.build_steps.iter()) {
        let head = step_head(step);
        if KNOWN_TOOLS.contains(&head) && !tools.iter().any(|t| t == head) {
            tools.push(head.to_string());
        }
    }
    let m = ServiceManifest {
        manifest_version: 1,
        service: crate::hoster::manifest::ServiceMeta {
            id: draft.id.trim().to_string(),
            name: String::new(),
            description: String::new(),
        },
        source: crate::hoster::manifest::SourceSpec {
            git: draft.git.trim().to_string(),
            commit: draft.commit.trim().to_string(),
        },
        pre_build: vec![],
        prefetch: draft
            .prefetch
            .iter()
            .map(|s| Step::Shell(s.clone()))
            .collect(),
        build: crate::hoster::manifest::BuildSpec {
            profile: draft.profile.clone(),
            steps: draft
                .build_steps
                .iter()
                .map(|s| Step::Shell(s.clone()))
                .collect(),
            env: draft.build_env.iter().cloned().collect(),
        },
        run: crate::hoster::manifest::RunSpec {
            command: run_argv,
            port,
        },
        resources: crate::hoster::manifest::ResourcesSpec {
            memory_high: None,
            memory_max: Some(draft.memory_max.trim().to_string()),
            tasks_max: Some(draft.tasks_max.trim().to_string()),
            cpu_quota: None,
            limit_nofile: None,
            oom_score_adjust: None,
        },
        healthcheck: None,
        plugins: draft
            .plugins
            .iter()
            .map(|(url, sha256)| crate::hoster::manifest::PluginPin {
                url: url.clone(),
                sha256: sha256.clone(),
            })
            .collect(),
        searxng: draft.profile == "python-searxng",
        tools,
        egress: Default::default(),
    };
    m.validate("wizard").map_err(|e| format!("{e:#}"))?;
    Ok(m)
}

/// Rendered `service.yaml` preview, or the reason it is not valid yet.
pub fn preview_yaml(draft: &Draft) -> Result<String, String> {
    let m = build_manifest(draft)?;
    serde_yaml::to_string(&m).map_err(|e| format!("cannot render YAML: {e}"))
}

fn is_memory(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 2
        && t[..t.len() - 1].bytes().all(|b| b.is_ascii_digit())
        && matches!(t.as_bytes().last(), Some(b'M' | b'G'))
}

/// One editable command list (prefetch or build steps).
#[derive(Default)]
pub struct StepEditor {
    pub lines: Vec<String>,
    pub selected: usize,
    /// Inline edit buffer for the selected line (None = navigating).
    pub editing: Option<String>,
    pub message: Option<String>,
}

impl StepEditor {
    pub fn new(lines: Vec<String>) -> Self {
        Self {
            lines,
            selected: 0,
            editing: None,
            message: None,
        }
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        if !self.lines.is_empty() {
            self.selected = (self.selected + 1).min(self.lines.len() - 1);
        }
    }

    pub fn start_edit(&mut self) {
        if let Some(line) = self.lines.get(self.selected).cloned() {
            self.editing = Some(line);
            self.message = None;
        }
    }

    pub fn cancel_edit(&mut self) {
        self.editing = None;
    }

    /// Commit the inline buffer into the selected line.
    pub fn commit_edit(&mut self) {
        if let Some(buf) = self.editing.take() {
            if buf.trim().is_empty() {
                self.message = Some("empty lines are not allowed — d deletes the line".into());
                return;
            }
            if let Some(line) = self.lines.get_mut(self.selected) {
                *line = buf;
            }
            self.message = None;
        }
    }

    /// Insert a blank line below the selection and edit it.
    pub fn add_line(&mut self) {
        let at = (self.selected + 1).min(self.lines.len());
        self.lines.insert(at, String::new());
        self.selected = at;
        self.editing = Some(String::new());
        self.message = None;
    }

    /// Delete the selected line (draft-only: nothing is saved yet).
    pub fn delete_line(&mut self) {
        if self.selected < self.lines.len() {
            self.lines.remove(self.selected);
            self.selected = self.selected.min(self.lines.len().saturating_sub(1));
            self.message = Some("line deleted (nothing saved yet)".into());
        }
    }

    pub fn take_lines(self) -> Vec<String> {
        self.lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(profile: &str) -> Draft {
        let mut d = Draft {
            id: "wz-demo".into(),
            git: "https://github.com/example/wz-demo.git".into(),
            commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ..Default::default()
        };
        assert!(apply_profile_defaults(&mut d, profile), "{profile}");
        d
    }

    #[test]
    fn every_profile_default_builds_a_valid_manifest() {
        for (id, _) in PROFILES {
            let d = filled(id);
            build_manifest(&d).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
    }

    #[test]
    fn unknown_profile_is_rejected() {
        let mut d = filled("bun");
        d.profile = "docker".into();
        assert!(build_manifest(&d).is_err());
    }

    #[test]
    fn bad_port_memory_tasks_are_rejected_with_hints() {
        let mut d = filled("go");
        d.port = "80".into();
        assert!(build_manifest(&d).unwrap_err().contains("1024"));
        d.port = "abc".into();
        assert!(build_manifest(&d).is_err());
        d.port = "0".into();
        d.memory_max = "lots".into();
        assert!(build_manifest(&d).unwrap_err().contains("256M"));
        d.memory_max = "512M".into();
        d.tasks_max = "many".into();
        assert!(build_manifest(&d).is_err());
    }

    #[test]
    fn field_checks_agree_with_schema() {
        assert!(check_id("my-svc").is_ok());
        for bad in ["ab", "UPPER", "a/b", "-x-", "", "a..b"] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
        assert!(check_git("https://github.com/o/n.git").is_ok());
        assert!(check_git("http://github.com/o/n").is_err());
        assert!(check_commit(&"a".repeat(40)).is_ok());
        assert!(check_commit("main").is_ok());
        assert!(check_commit("a b").is_err());
        assert!(check_commit("").is_err());
        assert_eq!(check_port("0"), Ok(0));
        assert!(check_port("80").is_err());
        assert!(check_memory("1G").is_ok());
        assert!(check_memory("big").is_err());
        assert!(check_tasks("512").is_ok());
        assert!(check_tasks("").is_err());
    }

    #[test]
    fn applying_profile_clears_detection_flag() {
        let mut d = filled("go");
        d.detected = true;
        d.notes = vec!["guessed".into()];
        assert!(apply_profile_defaults(&mut d, "go"));
        assert!(!d.detected);
        assert!(d.notes.is_empty());
    }

    #[test]
    fn preview_roundtrips_through_the_schema() {
        let d = filled("bun");
        let yaml = preview_yaml(&d).unwrap();
        assert!(yaml.contains("wz-demo"));
        ServiceManifest::load_from_str(&yaml, "preview").unwrap();
    }

    #[test]
    fn detected_plugins_flow_into_the_manifest() {
        let mut d = filled("bun");
        d.plugins = vec![(
            "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js"
                .to_string(),
            "85a5ce9d714530f6e0b5f3f2a1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2".to_string(),
        )];
        let m = build_manifest(&d).unwrap();
        assert_eq!(m.plugins.len(), 1);
        assert_eq!(m.plugins[0].url, d.plugins[0].0);
        let yaml = preview_yaml(&d).unwrap();
        assert!(yaml.contains("plugin-message-format"), "{yaml}");
        ServiceManifest::load_from_str(&yaml, "preview").unwrap();
        // Switching away from bun drops the pins (the schema rejects them
        // with any other profile) instead of failing validation later.
        assert!(apply_profile_defaults(&mut d, "python"));
        assert!(d.plugins.is_empty());
    }

    #[test]
    fn step_editor_edits_adds_deletes() {
        let mut e = StepEditor::new(vec!["a".into(), "b".into()]);
        e.move_down();
        e.start_edit();
        e.editing = Some("B".into());
        e.commit_edit();
        assert_eq!(e.lines, vec!["a".to_string(), "B".to_string()]);
        e.add_line();
        assert_eq!(e.lines.len(), 3);
        e.cancel_edit();
        e.delete_line();
        assert_eq!(e.lines.len(), 2);
        let mut empty = StepEditor::new(vec![]);
        empty.move_down();
        empty.delete_line();
    }
}
