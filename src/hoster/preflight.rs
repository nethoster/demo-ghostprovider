//! Pre-flight environment checks before deployment.
//!
//! Audit lesson applied: besides systemd/nspawn/network this now verifies
//! that the *selected recipe's build tools* are installed — the old check
//! stayed green and then failed deep inside `bun install` / `go build`.

use std::path::Path;
use std::process::Command;

/// One human-readable issue per failed check; empty slice = green light.
pub fn preflight_check(tools: &[&str]) -> Vec<String> {
    let mut issues = Vec::new();

    // ── systemd (user manager) ──
    match Command::new("systemctl")
        .args(["--user", "is-system-running"])
        .output()
    {
        Err(_) => issues.push("systemd not found".into()),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() && !stdout.contains("degraded") {
                issues.push(
                    "systemd user manager is not reachable from this shell \
                     (systemctl --user is-system-running failed) — run from a logged-in session, \
                     or `loginctl enable-linger $USER` so units outlive the login"
                        .into(),
                );
            }
        }
    }

    // ── systemd-nspawn ──
    // Deliberately not a check any more. Nothing in the deploy path launches
    // nspawn: builds run in `systemd-run --user` (see `sandbox.rs`) and the
    // binary only ever mentioned it as a label. Requiring it rejected
    // Debian/Ubuntu hosts — where nspawn is a separate package — while their
    // deploys worked perfectly.

    // ── cgroup v2 ──
    // Resource caps (MemoryMax/TasksMax) and the egress IP filters attach to
    // the unified hierarchy; on v1 hosts they silently degrade.
    if !cgroup_v2() {
        issues.push(
            "cgroup v2 unified hierarchy not found (/sys/fs/cgroup/cgroup.controllers is missing) \
             — memory/task caps and egress filters need it: boot with \
             systemd.unified_cgroup_hierarchy=1"
                .into(),
        );
    }

    // ── network: github.com is what we actually need for clone/API.
    // HEAD probe (no body to read), recorded in the local net log. ──
    if !super::httpclient::head_ok("https://github.com/") {
        issues.push("No network connectivity (https://github.com unreachable)".into());
    }

    // ── per-recipe build tools ──
    // bun/pnpm/go are auto-provisioned into the project cache later this
    // deploy (see `toolbox.rs`); a missing system install is not a blocker.
    // Everything else (python3, node) stays a hard requirement.
    for tool in tools {
        if !which(tool) {
            if is_provisionable(tool) {
                continue;
            }
            issues.push(format!(
                "'{tool}' not found on PATH — required by this service's build (install hint: {})",
                install_hint(tool)
            ));
        }
    }

    issues
}

/// True for the tools the toolbox can provision into the project cache; see
/// `toolcheck::is_auto_provisionable`. Preflight skips these so a missing bun/
/// pnpm/go can be provisioned instead of aborting the deploy.
fn is_provisionable(tool: &str) -> bool {
    super::toolcheck::tool_from_bin(tool).is_some_and(super::toolcheck::is_auto_provisionable)
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// Unified cgroup hierarchy: the file exists exactly when v2 is mounted.
fn cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
}

#[cfg(test)]
mod nspawn_is_not_a_gate {
    use super::*;

    #[test]
    fn missing_nspawn_never_blocks_a_deploy() {
        // nspawn is not used by the deploy path (builds run in
        // `systemd-run --user`); its absence on Debian/Ubuntu must never be
        // reported as an issue.
        let issues = preflight_check(&[]);
        assert!(
            !issues.iter().any(|i| i.to_lowercase().contains("nspawn")),
            "{issues:?}"
        );
    }
}

fn install_hint(tool: &str) -> &'static str {
    match tool {
        "bun" => "see https://bun.sh (curl -fsSL https://bun.sh/install | bash)",
        "pnpm" => "corepack enable pnpm  OR  npm install -g pnpm",
        "go" => "install Go from your package manager or https://go.dev/dl/",
        "python3" => "install Python >= 3.10 from your package manager",
        "node" => "install Node.js from your package manager or https://nodejs.org",
        _ => "install it with your package manager",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_is_reported_with_hint() {
        // Network/systemd checks depend on the host; assert only the tool one.
        let issues = preflight_check(&["definitely-not-a-real-binary-xyz"]);
        let tool_issue = issues
            .iter()
            .find(|i| i.contains("definitely-not-a-real-binary-xyz"));
        assert!(
            tool_issue.is_some_and(|i| i.contains("install hint")),
            "{issues:?}"
        );
    }

    #[test]
    fn present_tool_passes_that_check() {
        // `sh` exists everywhere this program runs; only tool checks are
        // asserted here because systemd/network depend on the host env.
        assert!(which("sh"));
    }
}
