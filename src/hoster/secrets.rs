//! Per-service EnvironmentFile handling (mode 0600).
//!
//! Escaping rules below are **empirically verified** against systemd 261
//! (see FINDINGS.md in the repo root):
//!
//! | written   | value seen by service |
//! |-----------|-----------------------|
//! | `$x`      | `$x`   (no expansion in env files) |
//! | `\$x`     | `$x`   |
//! | `$$x`     | `$$x`  (`$$` is NOT an escape here) |
//! | `%`/`%%`  | verbatim (%-specifiers do not apply) |
//! | `\\` → `\`, `\"` → `"`, `\n` stays literal, unknown escapes preserved |
//! | trailing bare `\` corrupts parsing and leaks into following lines    |
//!
//! Therefore: escape only `\` and `"`; leave `$` and `%` untouched; reject
//! values containing newlines. (The Python version's `%→%%` doubling was a
//! real bug that corrupted such secrets.)
//!
//! DORMANT IN THE DEMO (by design): no shipped manifest (user files aside)
//! carries secrets (`deploy.rs` passes an empty env map),
//! so no EnvironmentFile is
//! ever written for a demo deployment. The writer stays because it is
//! regression-tested here against the empirically verified systemd 261
//! rules above and is the exact code path the full GhostProvider uses.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;

/// Escape a value for a double-quoted EnvironmentFile assignment.
pub fn escape_env_value(value: &str) -> anyhow::Result<String> {
    if value.contains('\n') || value.contains('\r') {
        anyhow::bail!("secret values must not contain newlines");
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    Ok(out)
}

fn secrets_dir() -> PathBuf {
    // ~/.local/state/demo-ghostprovider/secrets
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::paths::home().join(".local/state"));
    base.join("demo-ghostprovider/secrets")
}

/// Create the secrets directory and force mode 0700 so sibling users can
/// never list or open per-service EnvironmentFiles.
fn ensure_secrets_dir() -> anyhow::Result<()> {
    let dir = secrets_dir();
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protecting {}", dir.display()))?;
    }
    Ok(())
}

pub fn env_file_for(service_name: &str) -> PathBuf {
    secrets_dir().join(format!("{service_name}.env"))
}

/// Write env vars to a per-service EnvironmentFile with mode 0600 inside a
/// 0700 directory. Returns the path, or `Ok(None)` when `env` is empty.
pub fn write_env_file(
    service_name: &str,
    env: &BTreeMap<String, String>,
) -> anyhow::Result<Option<PathBuf>> {
    if env.is_empty() {
        return Ok(None);
    }
    ensure_secrets_dir()?;

    let mut lines = Vec::new();
    for (key, value) in env {
        let safe_key: String = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if safe_key.is_empty() || safe_key.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        lines.push(format!("{safe_key}=\"{}\"", escape_env_value(value)?));
    }
    // Atomic write (temp + rename): the secret file is mode 0600 from its
    // first byte and a pre-planted symlink at the final name is replaced,
    // never followed (write-then-chmod TOCTOU and symlink follow are both
    // audit findings).
    let path = env_file_for(service_name);
    crate::atomic::write_atomic(&path, (lines.join("\n") + "\n").as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(Some(path))
}

/// Remove the EnvironmentFile for a service (idempotent).
pub fn remove_env_file(service_name: &str) {
    let _ = std::fs::remove_file(env_file_for(service_name));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(written: &str) -> String {
        escape_env_value(written).unwrap()
    }

    /// Mirrors FINDINGS.md: what systemd does to our escaped output.
    /// This simulates systemd's unquoting rules as measured on v261.
    fn systemd_unquote(escaped: &str) -> String {
        assert!(escaped.starts_with('"') && escaped.ends_with('"'));
        let inner = &escaped[1..escaped.len() - 1];
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some(other) => {
                        // Unknown escape: backslash kept verbatim (measured).
                        out.push('\\');
                        out.push(other);
                    }
                    None => panic!("trailing backslash would corrupt parsing"),
                }
            } else if c == '$' && chars.clone().next() == Some('$') {
                // NOT collapsed in env files (measured): keep both.
                out.push_str("$$");
                chars.next();
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn dollar_round_trips_verbatim() {
        // $ needs no escaping and survives unchanged.
        assert_eq!(
            systemd_unquote(&format!("\"{}\"", round_trip("plain$dollar"))),
            "plain$dollar"
        );
    }

    #[test]
    fn percent_not_doubled_regression() {
        // Regression: Python version wrote %% which systemd kept doubled.
        assert_eq!(
            systemd_unquote(&format!("\"{}\"", round_trip("p%ss"))),
            "p%ss"
        );
    }

    #[test]
    fn quote_and_backslash_round_trip() {
        assert_eq!(
            systemd_unquote(&format!("\"{}\"", round_trip("dq\"q"))),
            "dq\"q"
        );
        assert_eq!(
            systemd_unquote(&format!("\"{}\"", round_trip("bs\\s"))),
            "bs\\s"
        );
        assert_eq!(
            systemd_unquote(&format!("\"{}\"", round_trip("tricky\\\"$%mix"))),
            "tricky\\\"$%mix"
        );
    }

    #[test]
    fn rejects_newlines() {
        assert!(escape_env_value("line1\nline2").is_err());
        assert!(escape_env_value("cr\r").is_err());
    }
}
