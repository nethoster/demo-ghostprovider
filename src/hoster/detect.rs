//! Stack detection: guess a deploy draft from a source tree.
//!
//! Given a freshly cloned tree (before anything is stored), inspect its
//! dependency markers (`package.json` + lockfiles, `requirements.txt` /
//! `pyproject.toml`, `go.mod`) and propose profile, prefetch/build steps,
//! run command and port. Every guess is returned alongside plain-language
//! notes; the TUI shows them as "detected — verify" and the schema
//! validation still has the final word. An unrecognized tree is an honest
//! error, never a fabricated draft.
//!
//! Clean-room note: the *idea* (detect → draft → user review) mirrors
//! berthpanel's wizard; every line here is original. berthpanel is GPL-3.0
//! and none of its code is used or referenced.

use std::path::Path;

/// A draft proposal: mirrors the wizard `Draft` fields without depending on
/// the TUI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub profile: String,
    pub prefetch: Vec<String>,
    pub build: Vec<String>,
    pub run_cmd: String,
    pub port: String,
    pub memory_max: String,
    pub tasks_max: String,
    /// Why each guess was made / what must be verified by a human.
    pub notes: Vec<String>,
}

/// Inspect `dir` and propose a deploy draft, or explain why nothing fits.
pub fn detect_tree(dir: &Path) -> Result<Detected, String> {
    if dir.join("package.json").is_file() {
        return detect_node(dir);
    }
    if dir.join("requirements.txt").is_file() || dir.join("pyproject.toml").is_file() {
        return detect_python(dir);
    }
    if dir.join("go.mod").is_file() {
        return Ok(detect_go());
    }
    Err("no supported stack markers found (looked for package.json, requirements.txt, pyproject.toml, go.mod)".into())
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

fn scripts_of(pkg: &serde_json::Value) -> Vec<String> {
    pkg.get("scripts")
        .and_then(|s| s.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn has_dep(pkg: &serde_json::Value, name: &str) -> bool {
    for section in ["dependencies", "devDependencies", "peerDependencies"] {
        if pkg
            .get(section)
            .and_then(|s| s.as_object())
            .is_some_and(|m| m.contains_key(name))
        {
            return true;
        }
    }
    false
}

fn detect_node(dir: &Path) -> Result<Detected, String> {
    let pkg = read_json(&dir.join("package.json")).unwrap_or(serde_json::Value::Null);
    let scripts = scripts_of(&pkg);
    // Manager: lockfiles win, packageManager field breaks ties. npm-locked
    // projects build with bun (its installer reads any package.json);
    // npm-the-binary never runs here, so the schema whitelist
    // (bun|pnpm|python3|go|touch) and the provisionable toolbox cover
    // everything emitted below with zero new trusted tools.
    let manager = if dir.join("bun.lockb").is_file() || dir.join("bun.lock").is_file() {
        "bun"
    } else if dir.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else {
        pkg.get("packageManager")
            .and_then(|v| v.as_str())
            .and_then(|pm| {
                if pm.starts_with("pnpm") {
                    Some("pnpm")
                } else {
                    None
                }
            })
            .unwrap_or("bun")
    };
    let frozen = match manager {
        "bun" => {
            if dir.join("bun.lockb").is_file() || dir.join("bun.lock").is_file() {
                " --frozen-lockfile"
            } else {
                ""
            }
        }
        _ => {
            if dir.join("pnpm-lock.yaml").is_file() {
                " --frozen-lockfile"
            } else {
                ""
            }
        }
    };
    let (prefetch, build) = match manager {
        "pnpm" => (
            vec!["pnpm fetch --store-dir {project}/.ghost-cache/pnpm".to_string()],
            {
                let mut steps = vec![
                    "pnpm install --offline --store-dir {project}/.ghost-cache/pnpm".to_string(),
                ];
                if scripts.iter().any(|s| s == "build") {
                    steps.push("pnpm run build".to_string());
                }
                steps
            },
        ),
        // bun installs any package.json (npm-locked projects included); the
        // --ignore-scripts flag keeps the host phase script-free.
        _ => (
            vec![format!("bun install{frozen} --ignore-scripts")],
            if scripts.iter().any(|s| s == "build") {
                vec!["bun run build".to_string()]
            } else {
                vec![]
            },
        ),
    };
    // Framework hints for the run command and port (all marked as guesses).
    let framework = if has_dep(&pkg, "next") {
        Some(("next", "3000"))
    } else if has_dep(&pkg, "nuxt") {
        Some(("nuxt", "3000"))
    } else if has_dep(&pkg, "astro") {
        Some(("astro", "4321"))
    } else if has_dep(&pkg, "@sveltejs/kit") {
        Some(("svelte-kit", "4173"))
    } else if has_dep(&pkg, "vite") {
        Some(("vite", "5173"))
    } else {
        None
    };
    let mut notes = vec![format!("node stack via {manager}")];
    let (run_cmd, port) = if scripts.iter().any(|s| s == "start") {
        notes.push("run uses your `start` script — add {port} where your app takes it".into());
        (
            if manager == "pnpm" {
                "pnpm run start".into()
            } else {
                "bun run start".into()
            },
            framework
                .map(|(_, p)| p.to_string())
                .unwrap_or_else(|| "3000".into()),
        )
    } else if framework.is_some() || !build.is_empty() {
        notes.push(
            "static guess: serves {project}/build — change it if your app is a server".into(),
        );
        (
            "{self} __serve-static {project}/build {port}".into(),
            framework
                .map(|(_, p)| p.to_string())
                .unwrap_or_else(|| "3000".into()),
        )
    } else {
        notes.push("no build/start scripts found — fill in how this app runs".into());
        (
            "{self} __serve-static {project}/build {port}".into(),
            "3000".into(),
        )
    };
    if let Some((fw, _)) = framework {
        notes.push(format!("{fw} detected — port is a guess, verify it"));
    }
    Ok(Detected {
        profile: "bun".into(),
        prefetch,
        build,
        run_cmd,
        port,
        memory_max: "384M".into(),
        tasks_max: "300".into(),
        notes,
    })
}

fn detect_python(dir: &Path) -> Result<Detected, String> {
    let reqs = std::fs::read_to_string(dir.join("requirements.txt")).unwrap_or_default();
    let reqs_lc = reqs.to_lowercase();
    let has = |name: &str| reqs_lc.contains(name);
    let mut notes = vec!["python stack".to_string()];
    if !dir.join("requirements.txt").is_file() {
        notes.push(
            "no requirements.txt — pip prefetch below may fail; add one or vendor wheels".into(),
        );
    }
    let (run_cmd, port) = if has("gunicorn") {
        notes.push("gunicorn seen — module `app:app` is a guess, fix it to yours".into());
        (
            "{venv} -m gunicorn app:app --bind 127.0.0.1:{port}".into(),
            "8000".into(),
        )
    } else if has("uvicorn") {
        notes.push("uvicorn seen — module `main:app` is a guess, fix it to yours".into());
        (
            "{venv} -m uvicorn main:app --host 127.0.0.1 --port {port}".into(),
            "8000".into(),
        )
    } else if has("flask") {
        notes.push("flask seen — `flask run` serves the app found in the tree".into());
        (
            "{venv} -m flask run --host 127.0.0.1 --port {port}".into(),
            "8000".into(),
        )
    } else if has("django") {
        notes.push("django seen — project name `config` is a guess, fix it to yours".into());
        (
            "{venv} -m gunicorn config.wsgi --bind 127.0.0.1:{port}".into(),
            "8000".into(),
        )
    } else {
        notes.push("no known server found — placeholder serves static files, change it".into());
        (
            "{venv} -m http.server {port} --bind 127.0.0.1".into(),
            "8000".into(),
        )
    };
    Ok(Detected {
        profile: "python".into(),
        prefetch: vec![
            "python3 -m pip download -r requirements.txt -d .ghost-cache/pip-wheelhouse --only-binary=:all:"
                .into(),
        ],
        build: vec![
            "python3 -m venv --clear .venv".into(),
            ".venv/bin/pip install --no-cache-dir -r requirements.txt".into(),
        ],
        run_cmd,
        port,
        memory_max: "1024M".into(),
        tasks_max: "512".into(),
        notes,
    })
}

fn detect_go() -> Detected {
    Detected {
        profile: "go".into(),
        // Empty: the Go toolchain + module cache are seeded on the host by
        // goenv before the offline build, no registry fetch needed here.
        prefetch: vec![],
        build: vec!["go build -o ghost-server ./...".into()],
        run_cmd: "{bin} --addr 127.0.0.1 --port {port}".into(),
        port: "0".into(),
        memory_max: "1024M".into(),
        tasks_max: "512".into(),
        notes: vec![
            "go modules detected — binary is built as ghost-server; change -o if yours differs"
                .into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dgp-detect-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn detects_bun_next_app() {
        let dir = tree(
            "next",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"next":"14.0.0"},"scripts":{"build":"next build","start":"next start"}}"#,
                ),
                ("bun.lockb", "x"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "bun");
        assert!(
            d.prefetch[0].contains("--frozen-lockfile --ignore-scripts"),
            "{:?}",
            d.prefetch
        );
        assert_eq!(d.build, vec!["bun run build".to_string()]);
        assert_eq!(d.run_cmd, "bun run start");
        assert_eq!(d.port, "3000");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_pnpm_without_build_script() {
        let dir = tree(
            "pnpm",
            &[
                ("package.json", r#"{"scripts":{"start":"node server.js"}}"#),
                ("pnpm-lock.yaml", "x"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert!(d.prefetch[0].contains("pnpm fetch"), "{:?}", d.prefetch);
        assert!(d.build[0].contains("--offline"), "{:?}", d.build);
        assert!(!d.notes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_npm_locked_project_via_bun() {
        // npm-the-binary never runs in our pipeline: npm-locked trees build
        // with bun, keeping the schema whitelist and toolbox coverage intact.
        let dir = tree(
            "npm",
            &[
                (
                    "package.json",
                    r#"{"scripts":{"build":"tsc","start":"node dist/index.js"}}"#,
                ),
                ("package-lock.json", "{}"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert!(d.prefetch[0].starts_with("bun install"), "{:?}", d.prefetch);
        assert!(
            !d.prefetch[0].contains("--frozen-lockfile"),
            "{:?}",
            d.prefetch
        );
        assert!(
            d.prefetch[0].contains("--ignore-scripts"),
            "{:?}",
            d.prefetch
        );
        assert_eq!(d.run_cmd, "bun run start");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_python_gunicorn() {
        let dir = tree(
            "py",
            &[("requirements.txt", "gunicorn==21.2.0\nflask==3.0.0\n")],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "python");
        assert!(
            d.prefetch[0].contains("--only-binary=:all:"),
            "{:?}",
            d.prefetch
        );
        assert!(
            d.run_cmd.contains("gunicorn") && d.run_cmd.contains("127.0.0.1"),
            "{}",
            d.run_cmd
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_go_module() {
        let dir = tree("go", &[("go.mod", "module example.com/x\n\ngo 1.21\n")]);
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "go");
        assert!(d.prefetch.is_empty());
        assert!(d.run_cmd.contains("127.0.0.1"), "{}", d.run_cmd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_tree_is_an_honest_error() {
        let dir = tree("unknown", &[("README.md", "hi"), ("Dockerfile", "FROM x")]);
        let err = detect_tree(&dir).unwrap_err();
        assert!(err.contains("no supported stack markers"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_package_json_does_not_panic() {
        let dir = tree("broken", &[("package.json", "{not json")]);
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "bun");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
