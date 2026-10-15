//! Post-clone toolchain doctor.
//!
//! Preflight verifies tool *presence* before cloning; this module runs right
//! after the clone and cross-checks *versions* declared by the project's own
//! manifests (go.mod / package.json / pyproject.toml) against the installed
//! tools. Every gap becomes one plain-language line with a copy-pasteable fix
//! command for the detected distro.
//!
//! POLICY: this software never upgrades system packages by itself — sudo
//! stays a human decision. It names the command and stops.

use std::path::Path;
use std::process::Command;

pub(crate) type Ver = (u32, u32, u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tool {
    Go,
    Bun,
    Pnpm,
    Node,
    Python,
}

impl Tool {
    fn bin(self) -> &'static str {
        match self {
            Tool::Go => "go",
            Tool::Bun => "bun",
            Tool::Pnpm => "pnpm",
            Tool::Node => "node",
            Tool::Python => "python3",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Tool::Go => "Go",
            Tool::Bun => "Bun",
            Tool::Pnpm => "pnpm",
            Tool::Node => "Node.js",
            Tool::Python => "Python",
        }
    }

    /// User-level tools manage their own updates without sudo.
    fn user_managed(self) -> bool {
        matches!(self, Tool::Bun | Tool::Pnpm)
    }
}

/// The [`Tool`] whose release binary is named `bin`, if any.
pub fn tool_from_bin(bin: &str) -> Option<Tool> {
    match bin {
        "go" => Some(Tool::Go),
        "bun" => Some(Tool::Bun),
        "pnpm" => Some(Tool::Pnpm),
        "node" => Some(Tool::Node),
        "python3" => Some(Tool::Python),
        _ => None,
    }
}

/// Tools the toolbox can provision into the project cache (`toolbox.rs`):
/// their official releases are pure downloads, so a missing/outdated install
/// never blocks a deploy. Everything else (python3, node) stays a system
/// requirement. Go is provisionable only for the *baseline* (missing `go`):
/// an installed-but-old `go` under `GOTOOLCHAIN=auto` still self-heals via the
/// seeded file:// toolchain proxy, exactly as before.
pub fn is_auto_provisionable(tool: Tool) -> bool {
    matches!(tool, Tool::Bun | Tool::Pnpm | Tool::Go)
}

pub(crate) fn v_str(v: Ver) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Extract the leading dotted-number version from free-form probe output:
/// "1.27.0", "go1.26.6", "v26.7.0", "Python 3.14.7", ">=3.12", "^20.1.2".
pub(crate) fn parse_version(input: &str) -> Option<Ver> {
    let mut cur = String::new();
    for c in input.chars() {
        if c.is_ascii_digit() || c == '.' {
            cur.push(c);
        } else if !cur.is_empty() {
            break;
        }
    }
    let cur = cur.trim_matches('.');
    if cur.is_empty() || !cur.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut parts = cur.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    Some((
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    ))
}

/// Highest requirement found among `go` / `toolchain` directives.
pub fn go_mod_requirement(text: &str) -> Option<Ver> {
    let mut best: Option<Ver> = None;
    for line in text.lines() {
        let t = line.trim();
        let rest = if let Some(r) = t.strip_prefix("toolchain") {
            r.trim()
        } else if let Some(r) = t.strip_prefix("go ") {
            r.trim()
        } else {
            continue;
        };
        let Some(v) = parse_version(rest) else {
            continue;
        };
        best = Some(best.map_or(v, |b: Ver| b.max(v)));
    }
    best
}

/// Requirements from package.json `engines` (lowest bound wins for ranges)
/// and `packageManager`.
pub fn package_json_requirements(text: &str) -> Vec<(Tool, Ver)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(Some(pm)) = v
        .get("packageManager")
        .and_then(|x| x.as_str())
        .map(|s| s.split_once('@').map(|(_, ver)| ver))
        && let Some(ver) = parse_version(pm)
    {
        out.push((Tool::Pnpm, ver));
    }
    if let Some(engines) = v.get("engines").and_then(|x| x.as_object()) {
        for (key, val) in engines {
            let tool = match key.as_str() {
                "node" => Tool::Node,
                "bun" => Tool::Bun,
                "pnpm" => Tool::Pnpm,
                _ => continue,
            };
            let Some(spec) = val.as_str() else { continue };
            // Range specifiers ("^20.1.2", ">=18 <21"): the lowest mentioned
            // version is the effective floor.
            if let Some(min) = spec.split_whitespace().filter_map(parse_version).min() {
                out.push((tool, min));
            }
        }
    }
    out.sort_by_key(|(t, _)| *t);
    out.dedup_by_key(|(t, _)| *t);
    out
}

/// `requires-python = ">=3.12"` from pyproject.toml.
pub fn pyproject_requirement(text: &str) -> Option<Ver> {
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("requires-python") else {
            continue;
        };
        let quoted = rest.split('"').nth(1).or_else(|| rest.split('\'').nth(1));
        if let Some(v) = parse_version(quoted.unwrap_or(rest)) {
            return Some(v);
        }
    }
    None
}

fn probe_output(mut cmd: Command) -> Option<Ver> {
    let out = cmd.stderr(std::process::Stdio::piped()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = if text.trim().is_empty() {
        String::from_utf8_lossy(&out.stderr)
    } else {
        text
    };
    let mut s = text.trim();
    s = s.strip_prefix("Python ").unwrap_or(s);
    s = s.strip_prefix("go").unwrap_or(s);
    s = s.strip_prefix('v').unwrap_or(s);
    parse_version(s)
}

pub fn installed_version(tool: Tool) -> Option<Ver> {
    match tool {
        Tool::Go => probe_output({
            let mut c = Command::new("go");
            c.args(["env", "GOVERSION"]);
            c
        }),
        Tool::Bun => probe_output({
            let mut c = Command::new("bun");
            c.arg("--version");
            c
        }),
        Tool::Pnpm => probe_output({
            let mut c = Command::new("pnpm");
            c.arg("--version");
            c
        }),
        Tool::Node => probe_output({
            let mut c = Command::new("node");
            c.arg("--version");
            c
        }),
        Tool::Python => probe_output({
            let mut c = Command::new("python3");
            c.arg("--version");
            c
        }),
    }
}

fn distro() -> &'static str {
    for (path, name) in [
        ("/usr/bin/pacman", "arch"),
        ("/usr/bin/apt", "debian"),
        ("/usr/bin/dnf", "fedora"),
        ("/usr/bin/zypper", "suse"),
    ] {
        if Path::new(path).exists() {
            return name;
        }
    }
    "unknown"
}

fn system_install_cmd(tool: Tool) -> &'static str {
    match (distro(), tool) {
        ("arch", Tool::Go) => "sudo pacman -S --needed go",
        ("arch", Tool::Python) => "sudo pacman -S --needed python",
        ("arch", Tool::Node) => "sudo pacman -S --needed nodejs npm",
        ("debian", Tool::Go) => "sudo apt install golang-go",
        ("debian", Tool::Python) => "sudo apt install python3",
        ("debian", Tool::Node) => "sudo apt install nodejs npm",
        ("fedora", Tool::Go) => "sudo dnf install golang",
        ("fedora", Tool::Python) => "sudo dnf install python3",
        ("fedora", Tool::Node) => "sudo dnf install nodejs npm",
        ("suse", Tool::Go) => "sudo zypper install go",
        ("suse", Tool::Python) => "sudo zypper install python3",
        ("suse", Tool::Node) => "sudo zypper install nodejs20",
        (_, Tool::Go) => "install from https://go.dev/dl/",
        (_, Tool::Python) => "install Python >= 3.10 from your package manager",
        (_, Tool::Node) => "install from https://nodejs.org",
        _ => "install it with your package manager",
    }
}

fn install_cmd(tool: Tool) -> &'static str {
    match tool {
        Tool::Bun => "curl -fsSL https://bun.sh/install | bash",
        Tool::Pnpm => "corepack enable pnpm  OR  npm install -g pnpm",
        _ => system_install_cmd(tool),
    }
}

fn update_cmd(tool: Tool) -> &'static str {
    match tool {
        Tool::Bun => "bun upgrade",
        Tool::Pnpm => "corepack install -g pnpm@latest  OR  npm install -g pnpm@latest",
        _ => system_install_cmd(tool),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gap {
    Missing,
    Outdated { have: Ver },
}

fn gaps<F>(reqs: &[(Tool, Ver)], probe: F) -> Vec<(Tool, Ver, Gap)>
where
    F: Fn(Tool) -> Option<Ver>,
{
    let mut out = Vec::new();
    for (tool, min) in reqs {
        match probe(*tool) {
            None => out.push((*tool, *min, Gap::Missing)),
            Some(have) if have < *min => out.push((*tool, *min, Gap::Outdated { have })),
            _ => {}
        }
    }
    out
}

fn message(service: &str, tool: Tool, min: Ver, gap: &Gap) -> String {
    match gap {
        Gap::Missing => format!(
            "{service} needs {} >= {} but '{}' is not installed — install: {}",
            tool.label(),
            v_str(min),
            tool.bin(),
            install_cmd(tool)
        ),
        Gap::Outdated { have } => format!(
            "{service} needs {} >= {}, found {} — update first: {}{}",
            tool.label(),
            v_str(min),
            v_str(*have),
            update_cmd(tool),
            if tool.user_managed() {
                ""
            } else {
                "  (this software never runs sudo commands by itself)"
            },
        ),
    }
}

/// Is an outdated `go` binary still able to satisfy a newer go.mod directive
/// on its own? With the default `GOTOOLCHAIN=auto` (Go >= 1.21) the go command
/// downloads the required toolchain during the build, so an old system package
/// is not fatal. `GOTOOLCHAIN=local` disables that and keeps the block.
fn toolchain_auto_fetch() -> bool {
    Command::new("go")
        .args(["env", "GOTOOLCHAIN"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() != "local")
        .unwrap_or(false)
}

/// Doctor line for an outdated Go under auto-toolchain mode: informational,
/// deliberately NOT prefixed with "! " so neither renderer treats it as a
/// blocker, and phrased without the "update first:" marker of a hard gap.
fn go_auto_note(service: &str, min: Ver, have: Ver) -> String {
    format!(
        "{service} needs Go >= {min}, found {have} — ok: GOTOOLCHAIN=auto fetches \
         toolchain {min} automatically during the build",
        min = v_str(min),
        have = v_str(have)
    )
}

/// One doctor finding: a hard blocker (missing/ancient tool) or an
/// informational note (deploy may proceed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub blocking: bool,
    pub text: String,
}

/// One human-readable line per unmet manifest requirement; empty = green.
pub fn check_versions(project_dir: &Path, service: &str) -> Vec<String> {
    check_findings(project_dir, service)
        .into_iter()
        .map(|f| f.text)
        .collect()
}

/// Structured variant of [`check_versions`] used by the deploy pipeline to
/// distinguish "abort" from "mention and continue".
/// Every version the project's own manifests demand, as the doctor sees them:
/// package.json `engines`/`packageManager` (root + `web/`), go.mod
/// `go`/`toolchain` directives and pyproject.toml `requires-python`. Same tool
/// demanded by several manifests keeps the highest bar. Empty when no manifest
/// exists or pins nothing.
pub fn manifest_requirements(project_dir: &Path) -> Vec<(Tool, Ver)> {
    let mut reqs: Vec<(Tool, Ver)> = Vec::new();
    for rel in ["package.json", "web/package.json"] {
        if let Ok(t) = std::fs::read_to_string(project_dir.join(rel)) {
            reqs.extend(package_json_requirements(&t));
        }
    }
    if let Ok(t) = std::fs::read_to_string(project_dir.join("go.mod"))
        && let Some(v) = go_mod_requirement(&t)
    {
        reqs.push((Tool::Go, v));
    }
    if let Ok(t) = std::fs::read_to_string(project_dir.join("pyproject.toml"))
        && let Some(v) = pyproject_requirement(&t)
    {
        reqs.push((Tool::Python, v));
    }
    reqs.sort_by_key(|(t, _)| *t);
    reqs.dedup_by_key(|(t, _)| *t);
    // Same tool demanded twice (root + subdir manifests): keep the highest bar.
    let mut merged: Vec<(Tool, Ver)> = Vec::new();
    for (t, v) in reqs {
        match merged.iter_mut().find(|(mt, _)| mt == &t) {
            Some(e) => e.1 = e.1.max(v),
            None => merged.push((t, v)),
        }
    }
    merged
}

/// Doctor line for a provisionable tool gap: informational (never prefixed
/// with `!`), because the deploy provisions the pinned build into the project
/// cache instead of aborting. Deliberately keeps none of the "update
/// first:"/"install:" markers, so neither renderer treats it as a hard issue.
fn provision_note(service: &str, tool: Tool, min: Ver, gap: &Gap) -> String {
    let name = tool.label();
    let bin = tool.bin();
    let suffix = " — a pinned, SHA-256-verified build will be provisioned into this project's \
         .ghost-cache for the deploy (this software never installs system packages)";
    match gap {
        Gap::Missing => format!(
            "{service} needs {name} >= {} but '{bin}' is not installed{suffix}",
            v_str(min),
        ),
        Gap::Outdated { have } => format!(
            "{service} needs {name} >= {}, found {}{suffix}",
            v_str(min),
            v_str(*have),
        ),
    }
}

/// Structured variant of [`check_versions`] used by the deploy pipeline to
/// distinguish "abort" from "mention and continue".
pub fn check_findings(project_dir: &Path, service: &str) -> Vec<Finding> {
    let merged = manifest_requirements(project_dir);
    gaps(&merged, installed_version)
        .iter()
        .map(|(t, m, g)| {
            // Provisionable tools (bun/pnpm/go) never block: the toolbox
            // provisions a pinned build into the project cache instead. Go's
            // installed-but-old self-heal (GOTOOLCHAIN=auto) stays untouched.
            if is_auto_provisionable(*t)
                && !(matches!((t, g), (Tool::Go, Gap::Outdated { .. })) && toolchain_auto_fetch())
            {
                Finding {
                    blocking: false,
                    text: provision_note(service, *t, *m, g),
                }
            } else if matches!((t, g), (Tool::Go, Gap::Outdated { .. })) && toolchain_auto_fetch() {
                // Installable-but-old Go under auto-toolchain mode: the
                // existing informational note (toolchain fetched from the
                // seeded file:// proxy during the build).
                let Gap::Outdated { have } = g else {
                    unreachable!("guarded above")
                };
                Finding {
                    blocking: false,
                    text: go_auto_note(service, *m, *have),
                }
            } else {
                Finding {
                    blocking: true,
                    text: message(service, *t, *m, g),
                }
            }
        })
        .collect()
}

/// Does this log line carry a doctor issue (problem + explicit fix command)?
/// Shared by the TUI and the scripted-CLI renderer.
pub fn is_issue_line(s: &str) -> bool {
    s.contains(" — update first: ") || s.contains(" — install: ")
}

/// Split a doctor issue body into (problem, fix command, optional note).
pub fn split_issue(body: &str) -> Option<(&str, &str, Option<&str>)> {
    let mut hit = None;
    for m in [" — update first: ", " — install: "] {
        if let Some(p) = body.find(m) {
            hit = Some((p, m));
            break;
        }
    }
    let (pos, marker) = hit?;
    let problem = &body[..pos];
    let rest = &body[pos + marker.len()..];
    let (cmd, note) = match rest.rfind("  (") {
        Some(i) if rest.ends_with(')') => (rest[..i].trim_end(), Some(&rest[i + 2..])),
        _ => (rest, None),
    };
    Some((problem, cmd, note))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_handles_common_outputs() {
        assert_eq!(parse_version("1.27.0"), Some((1, 27, 0)));
        assert_eq!(parse_version("go1.26.6"), Some((1, 26, 6)));
        assert_eq!(parse_version("v26.7.0"), Some((26, 7, 0)));
        assert_eq!(parse_version("Python 3.14.7"), Some((3, 14, 7)));
        assert_eq!(parse_version(">=3.12"), Some((3, 12, 0)));
        assert_eq!(parse_version("^20.1.2"), Some((20, 1, 2)));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("none"), None);
    }

    #[test]
    fn go_mod_takes_max_of_go_and_toolchain() {
        let m = "\nmodule example\n\ngo 1.24.0\n\ntoolchain go1.27.0\n";
        assert_eq!(go_mod_requirement(m), Some((1, 27, 0)));
        assert_eq!(go_mod_requirement("go 1.16\n"), Some((1, 16, 0)));
        assert_eq!(go_mod_requirement("module x\n"), None);
    }

    #[test]
    fn package_json_reads_engines_and_package_manager() {
        let pj = r#"{
            "name": "x",
            "engines": { "node": ">=20 <23", "bun": "^1.1.0" },
            "packageManager": "pnpm@11.17.0"
        }"#;
        let mut reqs = package_json_requirements(pj);
        reqs.sort();
        assert_eq!(
            reqs,
            vec![
                (Tool::Bun, (1, 1, 0)),
                (Tool::Pnpm, (11, 17, 0)),
                (Tool::Node, (20, 0, 0)),
            ]
        );
        assert!(package_json_requirements("{broken").is_empty());
    }

    #[test]
    fn pyproject_reads_requires_python() {
        assert_eq!(
            pyproject_requirement("requires-python = \">=3.12\"\n"),
            Some((3, 12, 0))
        );
        assert_eq!(pyproject_requirement("[project]\nname='x'\n"), None);
    }

    #[test]
    fn gaps_report_missing_and_outdated() {
        let reqs = vec![(Tool::Go, (1, 27, 0)), (Tool::Bun, (1, 0, 0))];
        let found = gaps(&reqs, |t| match t {
            Tool::Go => Some((1, 26, 6)),
            Tool::Bun => Some((1, 3, 14)),
            _ => None,
        });
        assert_eq!(
            found,
            vec![(Tool::Go, (1, 27, 0), Gap::Outdated { have: (1, 26, 6) })]
        );

        let missing = gaps(&reqs, |_| None);
        assert_eq!(
            missing,
            vec![
                (Tool::Go, (1, 27, 0), Gap::Missing),
                (Tool::Bun, (1, 0, 0), Gap::Missing),
            ]
        );
    }

    #[test]
    fn messages_are_human_readable_with_fix_command() {
        let m = message(
            "Memos",
            Tool::Go,
            (1, 27, 0),
            &Gap::Outdated { have: (1, 26, 6) },
        );
        assert!(m.contains("Memos needs Go >= 1.27.0, found 1.26.6"), "{m}");
        assert!(m.contains("update first:"), "{m}");

        let mi = message("X", Tool::Bun, (1, 0, 0), &Gap::Missing);
        assert!(mi.contains("bun.sh/install"), "{mi}");
    }

    /// Auto-toolchain mode turns the Go gap into a non-blocking note that
    /// neither renderer classifies as a doctor issue.
    #[test]
    fn go_auto_note_is_informational_not_a_blocker() {
        let note = go_auto_note("Memos", (1, 27, 0), (1, 26, 6));
        assert!(!note.starts_with('!'), "{note}");
        assert!(!crate::hoster::toolcheck::is_issue_line(&note), "{note}");
        assert!(note.contains(">= 1.27.0"), "{note}");
        assert!(note.contains("GOTOOLCHAIN=auto"), "{note}");
    }

    /// Provisionable tool gaps (bun/pnpm/go) read as inform-and-continue, not
    /// an issue: no `!` prefix, no fix-command marker, and explicitly "will be
    /// provisioned".
    #[test]
    fn provisionable_gaps_are_non_blocking_notes() {
        for (tool, gap) in [
            (Tool::Bun, Gap::Missing),
            (Tool::Pnpm, Gap::Outdated { have: (11, 0, 0) }),
            (Tool::Go, Gap::Missing),
        ] {
            let note = provision_note("Memos", tool, (11, 0, 1), &gap);
            assert!(!note.starts_with('!'), "{tool:?}: {note}");
            assert!(!is_issue_line(&note), "{tool:?}: {note}");
            assert!(note.contains("provisioned"), "{tool:?}: {note}");
        }
        // python3 (not provisionable) must keep the hard message form.
        let py = message("SearXNG", Tool::Python, (3, 10, 0), &Gap::Missing);
        assert!(py.contains(" — install: "), "{py}");
        assert!(is_issue_line(&py), "{py}");
    }
}
