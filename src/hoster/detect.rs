//! Stack detection: propose a deploy draft from a source tree.
//!
//! The stack (bun / python / go) comes from dependency markers that carry
//! real evidence; the run command and the port come from what the
//! repository itself declares about running the app — Procfile, container
//! command / entrypoint script, packaging entry points, manage scripts,
//! config files. Nothing app-specific is hard-coded here: an unknown app
//! that writes down how to start is detected like any other. When nothing
//! is declared, python falls back to an explicitly-marked low-confidence
//! guess and the autopilot opens the wizard for review instead of
//! deploying blind. An unrecognized tree is an honest error, never a
//! fabricated draft.
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
    /// Build-time env vars auto-detected from `$env/static/public` imports
    /// (SvelteKit): names from the source tree, values from the repo's own
    /// env files. Empty for stacks without such imports.
    pub build_env: Vec<(String, String)>,
    /// Remote inlang/paraglide modules pinned by content hash
    /// (url, sha256) so the offline build can compile real messages
    /// without reaching the CDN. Empty for stacks without paraglide.
    pub plugins: Vec<(String, String)>,
    /// Why each guess was made / what must be verified by a human.
    pub notes: Vec<String>,
    /// True when the run command came from the repository's own
    /// declarations (or a located app object); false for guesses — the
    /// autopilot then opens the wizard for review instead of deploying
    /// blind.
    pub confident: bool,
    /// Runtime env vars the repository itself declares: Dockerfile `ENV`
    /// entries plus `${VAR}` overrides documented next to a flagged
    /// placeholder secret. Carried into `run.env`; empty for trees without
    /// such declarations.
    pub run_env: Vec<(String, String)>,
}

/// Inspect `dir` and propose a deploy draft, or explain why nothing fits.
pub fn detect_tree(dir: &Path) -> Result<Detected, String> {
    // A package.json alone proves nothing: devtools-only manifests (no
    // deps, no build script, no lockfile) sit inside python/go repos. Each
    // stack probe demands its own evidence, so a polyglot tree falls
    // through to the stack that actually carries weight.
    let mut d = if dir.join("package.json").is_file() && node_evidence(dir) {
        detect_node(dir)?
    } else if dir.join("requirements.txt").is_file() || dir.join("pyproject.toml").is_file() {
        detect_python(dir)?
    } else if dir.join("go.mod").is_file() {
        detect_go(dir)
    } else {
        return Err("no supported stack markers found (looked for package.json, requirements.txt, pyproject.toml, go.mod)".into());
    };
    // Repo-declared runtime env: `${VAR}` overrides documented beside a
    // flagged placeholder secret win; Dockerfile `ENV` fills the rest.
    let (warns, secret_envs) = placeholder_secret_findings(dir);
    d.run_env = secret_envs;
    for (k, v) in container_env(dir) {
        if !d.run_env.iter().any(|(ek, _)| *ek == k) {
            d.run_env.push((k, v));
        }
    }
    d.notes.extend(warns);
    if !d.run_env.is_empty() {
        let names: Vec<&str> = d.run_env.iter().map(|(k, _)| k.as_str()).collect();
        d.notes
            .push(format!("runtime env from the repo: {}", names.join(", ")));
    }
    Ok(d)
}

/// Evidence that a package.json describes an actual node app: a lockfile,
/// a build/start script, or dependencies. A bare devtools manifest fails
/// this and the tree falls through to the next stack.
fn node_evidence(dir: &Path) -> bool {
    let has_lock = [
        "bun.lockb",
        "bun.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ]
    .iter()
    .any(|l| dir.join(l).is_file());
    if has_lock {
        return true;
    }
    let Some(pkg) = read_json(&dir.join("package.json")) else {
        // Unparseable: absence of evidence cannot be proven — treat it as
        // a (broken) node app, the same tolerance `detect_node` has.
        return true;
    };
    let non_empty = |k: &str| {
        pkg.get(k)
            .and_then(|v| v.as_object())
            .is_some_and(|m| !m.is_empty())
    };
    non_empty("dependencies")
        || non_empty("devDependencies")
        || pkg
            .get("scripts")
            .and_then(|v| v.as_object())
            .is_some_and(|m| m.contains_key("build") || m.contains_key("start"))
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
    let (run_cmd, port, confident) = if scripts.iter().any(|s| s == "start") {
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
            true,
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
            true,
        )
    } else {
        // Nothing declares how the app runs — no build, no start: the
        // wizard must ask, exactly like the python guess path. Never a
        // blind static deploy of a directory nothing ever builds.
        notes.push("no build/start scripts found — fill in how this app runs".into());
        (
            "{self} __serve-static {project}/build {port}".into(),
            "3000".into(),
            false,
        )
    };
    if let Some((fw, _)) = framework {
        notes.push(format!("{fw} detected — port is a guess, verify it"));
    }
    // SvelteKit apps import PUB_* from $env/static/public; the offline vite
    // build fails when any of them is unset. Collect the names from the
    // source tree and values from the repo's own env files.
    let (build_env, env_notes) = detect_public_env(dir);
    notes.extend(env_notes);
    // paraglide apps declare remote inlang modules in project.inlang; the
    // offline build needs them content-pinned on local disk or it silently
    // compiles an empty messages module (see prefetch::pin_remote_paraglide_modules).
    let (plugins, plugin_notes) = crate::hoster::prefetch::pin_remote_paraglide_modules(dir);
    if !plugins.is_empty() {
        notes.push(format!(
            "pinned {} inlang plugin(s) by content hash — offline build stays reproducible",
            plugins.len()
        ));
    }
    notes.extend(plugin_notes);
    Ok(Detected {
        profile: "bun".into(),
        prefetch,
        build,
        run_cmd,
        port,
        memory_max: "384M".into(),
        tasks_max: "300".into(),
        build_env,
        plugins,
        notes,
        confident,
        run_env: vec![],
    })
}

/// Python: all non-dev `requirements*.txt` feed the offline wheelhouse
/// (runtime servers often live in a companion list), and the run command
/// comes from the repository's own declarations — a located app object
/// next, an explicitly-marked guess last.
fn detect_python(dir: &Path) -> Result<Detected, String> {
    let req_files = requirements_files(dir);
    let mut notes = vec!["python stack".to_string()];
    if !dir.join("requirements.txt").is_file() {
        notes.push(
            "no requirements.txt — pip prefetch below may fail; add one or vendor wheels".into(),
        );
    }
    let reqs_lc = req_files
        .iter()
        .filter_map(|f| std::fs::read_to_string(dir.join(f)).ok())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let (run_cmd, port, confident, run_notes) = synthesise_python_run(dir, &reqs_lc);
    notes.extend(run_notes);
    let rflags = if req_files.is_empty() {
        "-r requirements.txt".to_string()
    } else {
        req_files
            .iter()
            .map(|f| format!("-r {f}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    Ok(Detected {
        profile: "python".into(),
        prefetch: vec![format!(
            "python3 -m pip download {rflags} -d .ghost-cache/pip-wheelhouse --only-binary=:all:"
        )],
        build: vec![
            "python3 -m venv --clear .venv".into(),
            format!(".venv/bin/pip install --no-cache-dir {rflags}"),
        ],
        run_cmd,
        port,
        memory_max: "1024M".into(),
        tasks_max: "512".into(),
        build_env: vec![],
        plugins: vec![],
        notes,
        confident,
        run_env: vec![],
    })
}

/// Root-level `requirements*.txt` that are not dev-only: the main list plus
/// companion lists (e.g. `requirements-server.txt`) that carry the runtime
/// servers.
fn requirements_files(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.starts_with("requirements") && n.ends_with(".txt") && !n.contains("dev"))
        .collect();
    files.sort();
    if let Some(i) = files.iter().position(|f| f == "requirements.txt") {
        let main = files.remove(i);
        files.insert(0, main);
    }
    files
}

/// A run command the repository itself declares.
struct RunDecl {
    cmd: String,
    source: &'static str,
}

/// Declared full commands, most production-authoritative first: Procfile,
/// container assets (entrypoint exec / compose command / Dockerfile CMD),
/// Makefile run target. Packaging entry points are handled separately —
/// they name an app target, not a server command.
fn read_run_decls(dir: &Path) -> Vec<RunDecl> {
    let mut out = Vec::new();
    if let Some(cmd) = procfile_web(dir) {
        out.push(RunDecl {
            cmd,
            source: "Procfile",
        });
    }
    if let Some(cmd) = container_command(dir) {
        out.push(RunDecl {
            cmd,
            source: "container command",
        });
    }
    if let Some(cmd) = makefile_run(dir) {
        out.push(RunDecl {
            cmd,
            source: "Makefile",
        });
    }
    out
}

fn procfile_web(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("Procfile")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("web:"))
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// Production command from the container assets: entrypoint script exec
/// line, compose `command:`, else Dockerfile CMD (then ENTRYPOINT).
fn container_command(dir: &Path) -> Option<String> {
    for script in [
        "container/entrypoint.sh",
        "entrypoint.sh",
        "dockerfiles/docker-entrypoint.sh",
        "utils/dockerfiles/docker-entrypoint.sh",
    ] {
        if let Some(cmd) = exec_line(&dir.join(script)) {
            return Some(cmd);
        }
    }
    for compose in [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ] {
        if let Some(cmd) = scalar_key(&dir.join(compose), "command") {
            return Some(cmd);
        }
    }
    dockerfile_cmd(&dir.join("Dockerfile"))
}

/// Last `exec …` line of an entrypoint script — how the container really
/// starts. Env assignments (`FOO=bar`) before the binary are dropped.
fn exec_line(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("exec ").map(str::trim))?;
    let cmd = line
        .split_whitespace()
        .filter(|t| !t.contains('=') || t.contains('/'))
        .collect::<Vec<_>>()
        .join(" ");
    (!cmd.is_empty()).then_some(cmd)
}

/// First `command:` scalar in a compose file (line scan — enough for the
/// common `command: ./x y` shape).
fn scalar_key(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let pat = format!("{key}:");
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix(&pat)
            .map(|v| {
                v.trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string()
            })
            .filter(|v| !v.is_empty() && !v.starts_with('[') && !v.starts_with('&'))
    })
}

/// Dockerfile CMD (exec or shell form); ENTRYPOINT as fallback.
fn dockerfile_cmd(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut cmd: Option<String> = None;
    let mut entry: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("CMD") {
            let rest = rest.trim_start();
            if rest.starts_with('[') || rest.starts_with(char::is_whitespace) {
                let val = bracket_args(rest).unwrap_or_else(|| rest.trim().to_string());
                if !val.is_empty() {
                    cmd = Some(val);
                }
            }
        } else if let Some(rest) = t.strip_prefix("ENTRYPOINT") {
            let rest = rest.trim_start();
            if rest.starts_with('[') || rest.starts_with(char::is_whitespace) {
                let val = bracket_args(rest).unwrap_or_else(|| rest.trim().to_string());
                if !val.is_empty() {
                    entry = Some(val);
                }
            }
        }
    }
    cmd.or(entry)
}

/// `["a","b c"]` → `a b c`.
fn bracket_args(s: &str) -> Option<String> {
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    let parts: Vec<String> = inner
        .split(',')
        .filter_map(|p| {
            let p = p.trim().trim_matches('"').trim_matches('\'');
            (!p.is_empty()).then(|| p.to_string())
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Packaging entry point as an app target `module:func`: the first
/// console_scripts pair in setup.py or `[project.scripts]` in pyproject.
fn console_scripts(dir: &Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(dir.join("setup.py"))
        && let Some(pos) = text.find("console_scripts")
    {
        let after = &text[pos + "console_scripts".len()..];
        // Inline dict (`entry_points={'console_scripts': [...]}`) has the
        // first entry on the same line; multi-line blocks start on the next.
        let mut lines = after.lines();
        if let Some(first) = lines.next()
            && let Some((_, target)) = parse_script_line(first)
        {
            return Some(target);
        }
        for line in lines {
            let t = line.trim();
            if t.starts_with(']') || t.starts_with('}') || t.starts_with(')') {
                break;
            }
            if let Some((_, target)) = parse_script_line(t) {
                return Some(target);
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(dir.join("pyproject.toml")) {
        let mut in_scripts = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_scripts = t == "[project.scripts]";
                continue;
            }
            if in_scripts && let Some((_, target)) = parse_script_line(t) {
                return Some(target);
            }
        }
    }
    None
}

/// `name = module:func` (setup.py quoting or toml quoting).
fn parse_script_line(line: &str) -> Option<(String, String)> {
    let t = line.trim().trim_end_matches([',', ']', '}', ')']).trim();
    let (name, rest) = t.split_once('=')?;
    let name = name.trim().trim_matches(['\'', '"']).to_string();
    let target = rest.trim().trim_matches(['\'', '"']).trim();
    if name.is_empty() || !target.contains(':') {
        return None;
    }
    let (module, func) = target.split_once(':')?;
    if module.is_empty() || !func.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((name, format!("{module}:{func}")))
}

/// First Makefile `run:`/`start:`/`serve:` recipe line.
fn makefile_run(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("Makefile")).ok()?;
    let mut collecting = false;
    for line in text.lines() {
        if line.starts_with("run:") || line.starts_with("start:") || line.starts_with("serve:") {
            collecting = true;
            continue;
        }
        if collecting {
            if let Some(rest) = line.strip_prefix('\t') {
                let rest = rest.trim();
                if !rest.is_empty() && !rest.starts_with('#') {
                    return Some(rest.to_string());
                }
            } else if !line.trim().is_empty() {
                collecting = false;
            }
        }
    }
    None
}

/// Synthesise the python run command: declared commands first, then a
/// packaging entry point (or a located app object) paired with a server
/// from the requirements, then django's manage.py, then an honest guess.
/// Returns (run command, port, confident, notes).
fn synthesise_python_run(dir: &Path, reqs_lc: &str) -> (String, String, bool, Vec<String>) {
    let mut notes = Vec::new();
    let port = match config_port(dir) {
        Some((p, src)) => {
            notes.push(format!("port {p} from {src}"));
            p
        }
        None => "8000".to_string(),
    };
    // 1. Declared full commands the renderer recognises.
    for decl in read_run_decls(dir) {
        if let Some((run, server, app)) = render_python_server(&decl.cmd) {
            notes.push(format!(
                "run command from {}: `{}` (server `{server}`, app `{app}`)",
                decl.source, decl.cmd
            ));
            return (run, port, true, notes);
        }
    }
    // 2. Packaging entry point + a server from the requirements.
    if let Some(app) = console_scripts(dir)
        && let Some(server) = first_server(reqs_lc)
        && let Some(run) = server_run(server, &app)
    {
        notes.push(format!(
            "run target `{app}` from console_scripts; server `{server}` from the requirements"
        ));
        return (run, port, true, notes);
    }
    // 3. django: manage.py is the declaration.
    if dir.join("manage.py").is_file() && reqs_lc.contains("django") {
        notes.push(
            "run command from manage.py — django's dev server; swap for gunicorn in production"
                .to_string(),
        );
        return (
            "{venv} manage.py runserver 127.0.0.1:{port}".into(),
            port,
            true,
            notes,
        );
    }
    // 4. App object located in the code + a server from the requirements.
    if let Some((module, obj)) = python_app_object(dir) {
        let app = format!("{module}:{obj}");
        if let Some(server) = first_server(reqs_lc)
            && let Some(run) = server_run(server, &app)
        {
            notes.push(format!(
                "app object `{obj}` found in {module}.py; server `{server}` from the requirements"
            ));
            return (run, port, true, notes);
        }
        if reqs_lc.contains("flask") {
            notes.push(format!(
                "app object `{obj}` found in {module}.py; serving it with flask"
            ));
            return (
                format!("{{venv}} -m flask --app {app} run --host 127.0.0.1 --port {{port}}"),
                port,
                true,
                notes,
            );
        }
    }
    // 5. Guess — low confidence: the autopilot opens the wizard instead
    // of deploying this blind.
    let (run, guess) = guess_python_run(reqs_lc);
    notes.push(guess);
    (run, port, false, notes)
}

/// First known python ASGI/WSGI server mentioned in the requirements text.
fn first_server(reqs_lc: &str) -> Option<&'static str> {
    ["granian", "gunicorn", "uvicorn", "hypercorn", "daphne"]
        .into_iter()
        .find(|s| reqs_lc.contains(s))
}

/// Bind a known python server to loopback `{port}` around the app target.
/// Servers only — never per-app knowledge.
fn server_run(server: &str, app: &str) -> Option<String> {
    Some(match server {
        "granian" => format!("{{venv}} -m granian {app} --host 127.0.0.1 --port {{port}}"),
        "gunicorn" => format!("{{venv}} -m gunicorn {app} --bind 127.0.0.1:{{port}}"),
        "uvicorn" => format!("{{venv}} -m uvicorn {app} --host 127.0.0.1 --port {{port}}"),
        "hypercorn" => format!("{{venv}} -m hypercorn {app} --bind 127.0.0.1:{{port}}"),
        "daphne" => format!("{{venv}} -m daphne -b 127.0.0.1 -p {{port}} {app}"),
        _ => return None,
    })
}

/// Recognise a declared command as a known python server invocation and
/// re-render it bound to loopback `{port}`. Returns (run, server, app).
fn render_python_server(cmd: &str) -> Option<(String, String, String)> {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        let stem = tok.rsplit('/').next().unwrap_or(tok);
        if matches!(
            stem,
            "granian" | "gunicorn" | "uvicorn" | "hypercorn" | "daphne"
        ) {
            let app = toks[i + 1..]
                .iter()
                .find(|t| t.contains(':') && !t.starts_with('-'))?;
            let run = server_run(stem, app)?;
            return Some((run, stem.to_string(), app.to_string()));
        }
        if (matches!(stem, "python" | "python3") || stem.starts_with("python3."))
            && toks.get(i + 1) == Some(&"-m")
            && let Some(module) = toks.get(i + 2)
            && matches!(
                *module,
                "granian" | "gunicorn" | "uvicorn" | "hypercorn" | "daphne"
            )
        {
            let app = toks[i + 3..]
                .iter()
                .find(|t| t.contains(':') && !t.starts_with('-'))?;
            let run = server_run(module, app)?;
            return Some((run, module.to_string(), app.to_string()));
        }
    }
    // `flask [--app X] run` — flask finds the app itself when unnamed.
    if toks.iter().any(|t| t.rsplit('/').next() == Some("flask")) && toks.contains(&"run") {
        let app = toks
            .iter()
            .find_map(|t| t.strip_prefix("--app="))
            .unwrap_or("");
        let run = if app.is_empty() {
            "{venv} -m flask run --host 127.0.0.1 --port {port}".to_string()
        } else {
            format!("{{venv}} -m flask --app {app} run --host 127.0.0.1 --port {{port}}")
        };
        return Some((run, "flask".into(), app.into()));
    }
    None
}

/// Locate the module that defines the app object (`app = Flask(...)`,
/// `app = FastAPI(...)`, `application = get_wsgi_application()`) — the
/// real module:obj instead of a guessed `app:app`.
fn python_app_object(dir: &Path) -> Option<(String, String)> {
    const SKIP: &[&str] = &[
        "node_modules",
        ".venv",
        "venv",
        ".git",
        "tests",
        "test",
        "build",
        "dist",
        "docs",
        "static",
        "scripts",
        "migrations",
        "__pycache__",
    ];
    let mut found: Option<(String, String)> = None;
    fn visit(
        dir: &Path,
        root: &Path,
        depth: usize,
        budget: &mut usize,
        found: &mut Option<(String, String)>,
    ) {
        if depth > 5 || *budget == 0 || found.is_some() {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if *budget == 0 || found.is_some() {
                return;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIP.contains(&name.as_ref()) {
                continue;
            }
            let path = e.path();
            if path.is_dir() {
                visit(&path, root, depth + 1, budget, found);
                continue;
            }
            *budget -= 1;
            if path.extension() != Some(std::ffi::OsStr::new("py")) {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.len() > 512 * 1024 {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                let Some((lhs, rhs)) = line.split_once('=') else {
                    continue;
                };
                let obj = lhs.trim();
                let rhs = rhs.trim();
                let is_app = (rhs.starts_with("Flask(") || rhs.starts_with("FastAPI("))
                    && !obj.is_empty()
                    && obj.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                let is_wsgi = rhs.starts_with("get_wsgi_application(") && !obj.is_empty();
                if is_app || is_wsgi {
                    let rel = path.strip_prefix(root).unwrap_or(&path);
                    let module = rel
                        .to_string_lossy()
                        .trim_end_matches(".py")
                        .replace('/', ".")
                        .replace(".__init__", "");
                    *found = Some((module, obj.to_string()));
                    return;
                }
            }
        }
    }
    let mut budget = 500usize;
    visit(dir, dir, 0, &mut budget, &mut found);
    found
}

/// Port from the app's own config: well-known config files (root or one
/// directory deep) with a `port:`/`PORT=` value, else the Dockerfile
/// EXPOSE (a container port — weaker). Returns (port, human source).
fn config_port(dir: &Path) -> Option<(String, &'static str)> {
    const NAMES: &[&str] = &[
        "settings.yml",
        "settings.yaml",
        "config.yml",
        "config.yaml",
        "application.yml",
        ".env",
    ];
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    for name in NAMES {
        let p = dir.join(name);
        if p.is_file() {
            candidates.push(p);
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        {
            for name in NAMES {
                let p = e.path().join(name);
                if p.is_file() {
                    candidates.push(p);
                }
            }
        }
    }
    for path in &candidates {
        if let Some(p) = port_from_file(path) {
            return Some((p, "the app's config file"));
        }
    }
    if let Some(p) = expose_port(&dir.join("Dockerfile")) {
        return Some((p, "Dockerfile EXPOSE (container port — verify)"));
    }
    None
}

fn port_from_file(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let v = if let Some(v) = t.strip_prefix("port:") {
            v.trim().trim_matches('"').trim_matches('\'')
        } else if let Some((_, v)) = t.rsplit_once("PORT=") {
            v.trim().trim_matches('"')
        } else {
            continue;
        };
        if let Ok(n) = v.parse::<u16>()
            && (1024..=65535).contains(&n)
        {
            return Some(n.to_string());
        }
    }
    None
}

fn expose_port(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .rev()
        .find_map(|l| {
            let t = l.trim();
            let rest = t.strip_prefix("EXPOSE")?.trim_start();
            rest.split_whitespace().next()?.parse::<u16>().ok()
        })
        .map(|n| n.to_string())
}

/// Notes about config files that ship a known placeholder secret instead of
/// a real value (the app will usually refuse to boot or is insecure). Pure
/// pattern reading — no app knowledge: the key must look secret-ish and the
/// value must be exactly a well-known placeholder. When the same line
/// documents its `${ENV}` override (configs often say so in a comment), the
/// finding also yields a `run.env` pair — `{secret}` is fresh per deploy —
/// because the repo itself declares the wiring. Returns (notes, env pairs).
fn placeholder_secret_findings(dir: &Path) -> (Vec<String>, Vec<(String, String)>) {
    const KEYS: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "passphrase",
        "token",
        "apikey",
        "api_key",
        "private_key",
    ];
    const PLACEHOLDERS: &[&str] = &[
        "ultrasecretkey",
        "changeme",
        "change_me",
        "change-me",
        "changeit",
        "mysecret",
        "password",
        "passw0rd",
        "secret123",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "unset",
    ];
    const SKIP: &[&str] = &[
        "node_modules",
        ".venv",
        "venv",
        ".git",
        "tests",
        "test",
        "docs",
        "static",
        "dist",
        "build",
        "target",
        "__pycache__",
        "templates",
        "template",
        "locales",
        "locale",
        "i18n",
        "translations",
    ];
    const EXT: &[&str] = &[
        "yml",
        "yaml",
        "ini",
        "conf",
        "cfg",
        "toml",
        "json",
        "properties",
    ];
    let mut notes: Vec<String> = Vec::new();
    let mut envs: Vec<(String, String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let path = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if !name.starts_with('.') && !SKIP.contains(&name.as_ref()) && dirs.len() < 8 {
                    dirs.push(path);
                }
            } else if name.starts_with(".env")
                || (path
                    .extension()
                    .is_some_and(|x| EXT.contains(&x.to_str().unwrap_or("")))
                    && !name.starts_with('.')
                    // Template/example configs are boilerplate, not the
                    // running config — no placeholder warnings from them.
                    && !name.contains("template")
                    && !name.contains("example")
                    && !name.contains("sample")
                    && !name.contains(".tmpl")
                    && !name.contains(".dist"))
            {
                files.push(path);
            }
        }
    }
    files.truncate(60);
    for path in files {
        if notes.len() >= 4 {
            break;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.len() > 512 * 1024 {
            continue;
        }
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        for line in text.lines() {
            if notes.len() >= 4 {
                break;
            }
            let code = match line.find('#') {
                Some(h) => &line[..h],
                None => line,
            };
            let sep = code.find([':', '=']).unwrap_or(usize::MAX);
            if sep == usize::MAX || sep == 0 {
                continue;
            }
            let key = code[..sep].trim().trim_matches(['"', '\'']).to_lowercase();
            if !KEYS.iter().any(|k| key.contains(k)) {
                continue;
            }
            let raw = code[sep + 1..].trim();
            let val = raw
                .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
                .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
                .to_lowercase();
            if val.is_empty() || !PLACEHOLDERS.contains(&val.as_str()) {
                continue;
            }
            let dedup = format!("{rel}:{key}");
            if seen.contains(&dedup) {
                continue;
            }
            seen.push(dedup);
            // The same line's comment often documents the env override
            // (`secret_key: "ultrasecretkey"  # Is overwritten by ${APP_SECRET}`).
            let env_hint = line.find("${").and_then(|i| {
                let rest = &line[i + 2..];
                rest.split('}').next().filter(|v| {
                    !v.is_empty()
                        && v.len() <= 64
                        && v.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
                        && v.chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                        && env_name_allowed(v)
                })
            });
            match env_hint {
                Some(env) => {
                    if !envs.iter().any(|(k, _)| k == env) {
                        envs.push((env.to_string(), "{secret}".into()));
                    }
                    // Already fixed for the user (run.env auto-set to a fresh
                    // {secret}): informational, not a blocking warn — the
                    // autopilot deploys over it.
                    notes.push(format!(
                        "config {rel}: `{key}` placeholder `{val}` auto-overridden via ${{{env}}}={{secret}}"
                    ));
                }
                None => notes.push(format!(
                    "warn: config {rel}: `{key}` holds the placeholder `{val}` — replace it or override via run.env"
                )),
            }
        }
    }
    (notes, envs)
}

/// Env names a repo declaration may never set for us: shell/interpreter
/// plumbing that would break the unit itself. OS-level denylist — never
/// app-specific.
fn env_name_allowed(name: &str) -> bool {
    const DENY_EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "USERNAME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "TERM",
        "TMPDIR",
        "IFS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ];
    const DENY_PREFIX: &[&str] = &["LC_", "PYTHON", "LD_"];
    !DENY_EXACT.contains(&name) && !DENY_PREFIX.iter().any(|p| name.starts_with(p))
}

/// Runtime env declared by the repo's Dockerfiles (`ENV KEY=value`): the
/// container's own view of how the app should run (a WSGI-interface flag,
/// worker counts, …), read generically. Values with shell expansion
/// (`$VAR`), unbalanced quotes and OS-critical names are skipped.
fn container_env(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for rel in [
        "Dockerfile",
        "container/Dockerfile",
        "dockerfiles/Dockerfile",
    ] {
        let Ok(text) = std::fs::read_to_string(dir.join(rel)) else {
            continue;
        };
        // Logical ENV statements: `ENV \` blocks and trailing `\`
        // continuations join their lines before parsing pairs.
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if out.len() >= 16 {
                return out;
            }
            let t = line.trim_start();
            if !t.starts_with("ENV") {
                continue;
            }
            let after = &t[3..];
            if !after.is_empty() && !after.starts_with(char::is_whitespace) {
                continue;
            }
            let mut stmt = after.trim().to_string();
            while stmt.ends_with('\\') {
                stmt.pop();
                let Some(next) = lines.next() else {
                    break;
                };
                stmt.push(' ');
                stmt.push_str(next.trim());
            }
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = stmt.split_whitespace().collect();
            let pairs: Vec<(&str, &str)> = if tokens.iter().any(|t| t.contains('=')) {
                let mut v = Vec::new();
                for tok in &tokens {
                    match tok.split_once('=') {
                        Some((k, val)) => v.push((k, val)),
                        None => break,
                    }
                }
                v
            } else {
                vec![(tokens[0], stmt[tokens[0].len()..].trim())]
            };
            for (rawk, rawv) in pairs {
                let key = rawk.trim_matches(['"', '\'']);
                let val = rawv.trim_matches(['"', '\'']);
                if key.is_empty()
                    || key.len() > 128
                    || !key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || !env_name_allowed(key)
                {
                    continue;
                }
                if val.is_empty()
                    || val.len() > 4096
                    || val.contains(['\n', '\0', '$'])
                    || rawv.matches('"').count() % 2 != 0
                    || rawv.matches('\'').count() % 2 != 0
                {
                    continue;
                }
                if out.iter().any(|(k, _)| k == key) {
                    continue;
                }
                out.push((key.to_string(), val.to_string()));
            }
        }
    }
    out
}

/// Last-resort python run guess from the requirements text — always
/// returned with a note that says it is a guess (low confidence).
fn guess_python_run(reqs_lc: &str) -> (String, String) {
    let has = |name: &str| reqs_lc.contains(name);
    if has("gunicorn") {
        (
            "{venv} -m gunicorn app:app --bind 127.0.0.1:{port}".into(),
            "guess: gunicorn seen — module `app:app` is a guess, fix it in the wizard".into(),
        )
    } else if has("uvicorn") {
        (
            "{venv} -m uvicorn main:app --host 127.0.0.1 --port {port}".into(),
            "guess: uvicorn seen — module `main:app` is a guess, fix it in the wizard".into(),
        )
    } else if has("flask") {
        (
            "{venv} -m flask run --host 127.0.0.1 --port {port}".into(),
            "guess: flask seen — `flask run` may not find the app, verify in the wizard".into(),
        )
    } else if has("django") {
        (
            "{venv} -m gunicorn config.wsgi --bind 127.0.0.1:{port}".into(),
            "guess: django seen — project name `config` is a guess, fix it in the wizard".into(),
        )
    } else {
        (
            "{venv} -m http.server {port} --bind 127.0.0.1".into(),
            "guess: nothing declares how this app runs — placeholder serves static files, fix it in the wizard".into(),
        )
    }
}

fn detect_go(dir: &Path) -> Detected {
    // `go build -o <file>` accepts exactly one package; `./...` breaks the
    // moment the repo has any second package (cmd/, internal/, pkg/…):
    // "cannot write multiple packages to non-directory". Locate the main
    // package and build just that path.
    let pkg = locate_go_main(dir);
    let build_cmd = match &pkg {
        Some(p) if p == "." => "go build -o ghost-server .".to_string(),
        Some(p) => format!("go build -o ghost-server ./{p}"),
        // No package main anywhere: the root path at least builds whatever
        // the module root holds, and the note tells the user to fix it.
        None => "go build -o ghost-server .".to_string(),
    };
    let mut notes = vec![
        "go modules detected — binary is built as ghost-server; change -o if yours differs".into(),
    ];
    match pkg.as_deref() {
        Some(".") => {}
        Some(p) => notes.push(format!("main package at ./{p}")),
        None => notes.push(
            "no package main found — build step likely needs the real path, fix it in the wizard"
                .into(),
        ),
    }

    // Go has no Procfile-class declaration standard: the run command comes
    // from the main package's own source — flag definitions, a PORT env
    // read, a hardcoded listen address. Nothing found = an honest guess-
    // free refusal, not a fabricated `--addr --port` pair.
    let pkg_dir = pkg.as_deref().map(|p| {
        if p == "." {
            dir.to_path_buf()
        } else {
            dir.join(p)
        }
    });
    let sig = pkg_dir.as_deref().and_then(go_run_signals);
    let cfg_port = config_port(dir).map(|(p, _)| p);
    let (run_cmd, port, mut confident) = match sig {
        Some(s) => {
            let port = s
                .listen_port
                .map(|n| n.to_string())
                .or(cfg_port)
                .unwrap_or_else(|| "0".into());
            if let Some(lp) = s.listen_port {
                // The code hardcodes its bind address — flags would be
                // ignored or fatal; run the binary plain.
                notes.push(format!(
                    "run: binds :{lp} from the code itself — healthcheck probes that port"
                ));
                ("{bin}".to_string(), port, true)
            } else if let Some(pf) = &s.port_flag {
                let mut cmd = "{bin}".to_string();
                if let Some(af) = &s.addr_flag {
                    cmd.push_str(&format!(" --{af} 127.0.0.1"));
                }
                cmd.push_str(&format!(" --{pf} {{port}}"));
                notes.push(format!(
                    "run from the main package's flags ({}) — port passed as the panel's free choice",
                    [
                        s.addr_flag.as_deref(),
                        Some(pf.as_str())
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ")
                ));
                (cmd, port, true)
            } else if s.env_port {
                notes.push(
                    "run: the code reads PORT from the environment — PORT={port} is exported"
                        .into(),
                );
                ("{bin}".to_string(), port, true)
            } else {
                // An addr/host flag proves the process takes arguments but
                // says nothing about its port: run with the loopback flag,
                // let the healthcheck adopt whatever it binds.
                let cmd = match &s.addr_flag {
                    Some(af) => format!("{{bin}} --{af} 127.0.0.1"),
                    None => "{bin}".to_string(),
                };
                notes.push(
                    "run from the main package's flags — port not declared; healthcheck adopts the live port"
                        .into(),
                );
                (cmd, port, true)
            }
        }
        None => {
            if pkg.is_some() {
                notes.push(
                    "no run/port declaration found in the main package — set the command in the wizard"
                        .into(),
                );
            }
            (
                "{bin}".to_string(),
                cfg_port.unwrap_or_else(|| "0".into()),
                false,
            )
        }
    };

    // go:embed freezes the frontend build into the binary. When the repo
    // wires a UI that way, build it BEFORE go build: the git tree often
    // ships only a placeholder dist (its index.html says the real UI is
    // missing) and the embedded placeholder still answers HTTP 200, so a
    // "successful" deploy would serve the fallback page forever.
    let embeds = go_embed_dirs(dir);
    let mut prefetch: Vec<String> = vec![];
    let mut build = vec![build_cmd];
    if !embeds.is_empty() {
        match frontend_build_for(dir, &embeds) {
            Some(fe) => {
                let fe_dir: &str = if fe.dir.is_empty() { "." } else { &fe.dir };
                let run_step = match fe.manager.as_str() {
                    "bun" => {
                        prefetch.push(format!(
                            "bun install --cwd {{project}}/{fe_dir} --frozen-lockfile --ignore-scripts"
                        ));
                        let s = format!("bun run --cwd {fe_dir} {}", fe.script);
                        build.insert(0, s.clone());
                        s
                    }
                    _ => {
                        prefetch.push(format!(
                            "pnpm --dir {fe_dir} fetch --store-dir {{project}}/.ghost-cache/pnpm"
                        ));
                        let s = format!("pnpm --dir {fe_dir} run {}", fe.script);
                        build.insert(0, s.clone());
                        build.insert(
                            0,
                            format!("pnpm --dir {fe_dir} install --offline --store-dir {{project}}/.ghost-cache/pnpm"),
                        );
                        s
                    }
                };
                notes.push(format!(
                    "frontend: `{run_step}` → {} (go:embed target) — built before go",
                    fe.target
                ));
            }
            None => {
                notes.push(format!(
                    "go:embed {}: no frontend build script found — the binary would embed whatever is in that directory; review the build steps in the wizard",
                    embeds[0]
                ));
                confident = false;
            }
        }
    }

    Detected {
        profile: "go".into(),
        prefetch,
        build,
        run_cmd,
        port,
        memory_max: "1024M".into(),
        tasks_max: "512".into(),
        build_env: vec![],
        plugins: vec![],
        notes,
        confident,
        run_env: vec![],
    }
}

/// A web UI that go:embed freezes into the binary: the package.json build
/// script whose output lands inside an embed directory.
struct GoFrontend {
    /// Script directory relative to the repo root ("" = repo root).
    dir: String,
    /// The npm-style script that produces the embedded assets.
    script: String,
    /// Package manager implied by the lockfile beside package.json.
    manager: String,
    /// The embed directory the script writes into (repo-relative).
    target: String,
}

/// Join `base/` + `token` into a normalized repo-relative path: ".." is
/// applied, an escape above the root rejects the token.
fn normalize_rel(base: &str, token: &str) -> Option<String> {
    let mut parts: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    for seg in token.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Directories that `//go:embed` directives pull into the binary — for a UI
/// compiled into the executable, the frontend dist. Existing directories
/// only, repo-relative. `deploy` reuses this to snapshot the placeholder
/// pages a fresh clone ships, for the post-start content probe.
pub(crate) fn go_embed_dirs(dir: &Path) -> Vec<String> {
    const SKIP: &[&str] = &["vendor", ".git", "node_modules", "testdata"];
    let mut found: Vec<String> = Vec::new();
    fn visit(d: &Path, root: &Path, depth: usize, budget: &mut usize, found: &mut Vec<String>) {
        if depth > 4 || *budget == 0 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if *budget == 0 {
                return;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIP.contains(&name.as_ref()) {
                continue;
            }
            let path = e.path();
            if path.is_dir() {
                visit(&path, root, depth + 1, budget, found);
                continue;
            }
            *budget -= 1;
            if path.extension() != Some(std::ffi::OsStr::new("go")) || name.ends_with("_test.go") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let base = path
                .parent()
                .and_then(|p| p.strip_prefix(root).ok())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let base = if base == "." { String::new() } else { base };
            for line in text.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("//go:embed") else {
                    continue;
                };
                for tok in rest.split_whitespace() {
                    let tok = tok.trim_matches('"');
                    let tok = tok.strip_prefix("all:").unwrap_or(tok);
                    let tok = tok.trim_end_matches('*').trim_end_matches('/');
                    if tok.is_empty() {
                        continue;
                    }
                    let Some(rel) = normalize_rel(&base, tok) else {
                        continue;
                    };
                    if !found.contains(&rel) && root.join(&rel).is_dir() {
                        found.push(rel);
                    }
                }
            }
        }
    }
    let mut budget = 2000usize;
    visit(dir, dir, 0, &mut budget, &mut found);
    found
}

/// `--outDir=PATH` / `--outDir PATH` from a vite-style build command.
fn script_outdir(cmd: &str) -> Option<&str> {
    let i = cmd.find("--outDir")?;
    let rest = &cmd[i + "--outDir".len()..];
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let val = &rest[..end];
    (!val.is_empty() && !val.starts_with('$')).then_some(val)
}

/// The package.json build script whose outDir lands inside one of the
/// go:embed directories — the frontend that must be built before go build.
fn frontend_build_for(dir: &Path, embeds: &[String]) -> Option<GoFrontend> {
    const SKIP: &[&str] = &[
        "node_modules",
        ".git",
        "vendor",
        "testdata",
        "dist",
        "build",
        "target",
        ".venv",
        "venv",
        "__pycache__",
    ];
    let mut pkgs: Vec<std::path::PathBuf> = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            let path = e.path();
            if path.is_dir() {
                if !name.starts_with('.') && !SKIP.contains(&name.as_str()) && dirs.len() < 16 {
                    dirs.push(path);
                }
            } else if name == "package.json" {
                pkgs.push(path);
            }
        }
    }
    pkgs.sort();
    let mut best: Option<(u8, GoFrontend)> = None;
    for pkg_path in &pkgs {
        let Ok(text) = std::fs::read_to_string(pkg_path) else {
            continue;
        };
        let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(scripts) = pkg.get("scripts").and_then(|s| s.as_object()) else {
            continue;
        };
        let pkg_dir = pkg_path
            .parent()
            .and_then(|p| p.strip_prefix(dir).ok())
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let pkg_dir = if pkg_dir == "." {
            String::new()
        } else {
            pkg_dir
        };
        for (name, cmd) in scripts {
            let Some(cmd) = cmd.as_str() else { continue };
            // vite-style `--outDir` wins; any other script that names the
            // embed path verbatim (cp, --output-path, --dest, …) counts
            // too — the path is specific enough to be proof.
            let exact = script_outdir(cmd)
                .and_then(|out| normalize_rel(&pkg_dir, out))
                .filter(|t| embeds.contains(t));
            let (target, strong) = match exact {
                Some(t) => (t, true),
                None => match embeds.iter().find(|e| cmd.contains(e.as_str())) {
                    Some(e) => (e.clone(), false),
                    None => continue,
                },
            };
            let manager = if pkg_path
                .parent()
                .is_some_and(|p| p.join("pnpm-lock.yaml").exists())
            {
                "pnpm"
            } else if pkg_path
                .parent()
                .is_some_and(|p| p.join("bun.lockb").exists() || p.join("bun.lock").exists())
            {
                "bun"
            } else {
                // npm's binary never runs; the node detector defaults
                // the same way.
                "pnpm"
            };
            let prio = match name.as_str() {
                "release" => 0,
                "build" => 1,
                _ => 2,
            } + if strong { 0 } else { 1 };
            let fe = GoFrontend {
                dir: pkg_dir.clone(),
                script: name.clone(),
                manager: manager.into(),
                target,
            };
            if best.as_ref().is_none_or(|(p, _)| prio < *p) {
                best = Some((prio, fe));
            }
        }
    }
    best.map(|(_, fe)| fe)
}

/// How the main package takes its port/addr: CLI flags, a PORT env read, or
/// a hardcoded listen literal. Extracted from the package's own `.go` files
/// (non-test) — declarations, not conventions.
#[derive(Debug, Default)]
struct GoRunSignals {
    addr_flag: Option<String>,
    port_flag: Option<String>,
    env_port: bool,
    listen_port: Option<u16>,
}

fn go_run_signals(pkg_dir: &Path) -> Option<GoRunSignals> {
    let mut sig = GoRunSignals::default();
    let mut any = false;
    let Ok(rd) = std::fs::read_dir(pkg_dir) else {
        return None;
    };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.extension().is_none_or(|x| x != "go") || name.ends_with("_test.go") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        any = true;
        for line in text.lines() {
            // flag.Int("name" …), flag.String("name" …), flag.Int64/Uint/
            // Int32 — the stdlib constructor family with a string name first.
            for ctor in [
                "flag.Int(\"",
                "flag.String(\"",
                "flag.Int64(\"",
                "flag.Int32(\"",
                "flag.Uint(\"",
                "flag.Uint64(\"",
            ] {
                if let Some(name) = after_token(line, ctor) {
                    classify_go_flag(&mut sig, name);
                }
            }
            // cobra/pflag: .Flags().Int("name" / .PersistentFlags().String(
            for ctor in [
                "Flags().Int(\"",
                "Flags().String(\"",
                "Flags().Int64(\"",
                "Flags().Uint(\"",
            ] {
                if let Some(name) = after_token(line, ctor) {
                    classify_go_flag(&mut sig, name);
                }
            }
            // The standard convention: os.Getenv("PORT") / LookupEnv.
            if (line.contains("os.Getenv(\"PORT\"") || line.contains("os.LookupEnv(\"PORT\""))
                && !sig.env_port
            {
                sig.env_port = true;
            }
            // Hardcoded bind: ListenAndServe(":8080"), net.Listen("tcp",
            // ":8080"), r.Run(":8080"), e.Start(":8080") — a ":digits"
            // literal on a listen-ish line.
            if (line.contains("Listen") || line.contains(".Run(") || line.contains(".Start("))
                && sig.listen_port.is_none()
                && let Some(p) = quoted_port(line)
            {
                sig.listen_port = Some(p);
            }
        }
    }
    (any && (sig.addr_flag.is_some()
        || sig.port_flag.is_some()
        || sig.env_port
        || sig.listen_port.is_some()))
    .then_some(sig)
}

/// Everything after `token` up to the next quote — the flag's name.
fn after_token<'a>(line: &'a str, token: &str) -> Option<&'a str> {
    let i = line.find(token)? + token.len();
    let rest = &line[i..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    (!name.is_empty() && name.len() <= 40).then_some(name)
}

fn classify_go_flag(sig: &mut GoRunSignals, name: &str) {
    let lower = name.to_lowercase();
    if lower.contains("port") {
        sig.port_flag.get_or_insert(lower);
    } else if lower.contains("addr") || lower.contains("host") {
        sig.addr_flag.get_or_insert(lower);
    }
}

/// `":8080"` / `"127.0.0.1:8080"` literal → the port digits.
fn quoted_port(line: &str) -> Option<u16> {
    let mut rest = line;
    while let Some(i) = rest.find("\":") {
        rest = &rest[i + 2..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        if rest[digits.len()..].starts_with('"')
            && let Ok(n) = digits.parse::<u16>()
            && n > 0
        {
            return Some(n);
        }
    }
    None
}

/// Find the `package main` directory relative to the repo root.
///
/// Checks the root first, then the conventional `cmd/<name>/` layout, then a
/// shallow scan (depth ≤ 2, skipping vendor/.git and friends). Returns None
/// when no main package exists anywhere.
fn locate_go_main(dir: &Path) -> Option<String> {
    const SKIP: &[&str] = &["vendor", ".git", "node_modules", "testdata"];
    fn is_main_pkg(d: &Path) -> bool {
        let Ok(rd) = std::fs::read_dir(d) else {
            return false;
        };
        rd.filter_map(|e| e.ok()).any(|e| {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "go") {
                return false;
            }
            std::fs::read_to_string(&p).is_ok_and(|t| t.contains("package main"))
        })
    }
    if is_main_pkg(dir) {
        return Some(".".into());
    }
    if let Ok(rd) = std::fs::read_dir(dir.join("cmd")) {
        let mut mains: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| is_main_pkg(&e.path()))
            .map(|e| format!("cmd/{}", e.file_name().to_string_lossy()))
            .collect();
        if mains.len() == 1 {
            return mains.pop();
        }
        // Several cmd/ mains (multi-binary repo): no single -o target —
        // None keeps the honest "fix it" note.
        if mains.len() > 1 {
            return None;
        }
    }
    // Shallow scan: one level of subdirs, then one more (pkg/, internal/…).
    fn scan(base: &Path, depth: u8) -> Option<String> {
        if depth == 0 {
            return None;
        }
        let Ok(rd) = std::fs::read_dir(base) else {
            return None;
        };
        let mut subs: Vec<_> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                !n.starts_with('.') && !SKIP.contains(&n.as_ref())
            })
            .collect();
        subs.sort_by_key(|e| e.file_name());
        for sub in subs {
            let path = sub.path();
            let name = sub.file_name().to_string_lossy().into_owned();
            if is_main_pkg(&path) {
                return Some(name);
            }
            if let Some(found) = scan(&path, depth - 1) {
                return Some(format!("{name}/{found}"));
            }
        }
        None
    }
    scan(dir, 2)
}

/// Build-time env vars for SvelteKit-style `$env/static/public` imports.
///
/// The offline vite build fails when any imported `PUB_*` name is unset, so
/// detection scans the source tree for the imports and fills values from the
/// repo's own env files (`.env.example` is the common template; real env
/// files override it). Imported names with no value anywhere get an empty
/// string plus a note — the review screen shows the result for editing.
fn detect_public_env(dir: &Path) -> (Vec<(String, String)>, Vec<String>) {
    const MAX_VARS: usize = 32;
    /// Directories that never contain first-party source worth scanning.
    const SKIP_DIRS: &[&str] = &[
        "node_modules",
        ".git",
        "build",
        "dist",
        ".svelte-kit",
        ".ghost-cache",
        ".venv",
        "target",
        ".next",
        ".nuxt",
        ".output",
        "vendor",
    ];
    let mut names = std::collections::BTreeSet::new();
    collect_source_env_names(dir, SKIP_DIRS, &mut names, MAX_VARS);
    // Values: .env.example is the template; .env.production and .env (when
    // committed) override it, matching dotenv precedence. Their PUB_*
    // keys are names too: apps read those vars dynamically (or through
    // defineEnvVars) and the offline build still needs them set.
    let mut values = std::collections::BTreeMap::new();
    for file in [".env.example", ".env.production", ".env"] {
        let path = dir.join(file);
        merge_env_file(&path, &mut values);
        collect_env_file_keys(&path, &mut names, MAX_VARS);
    }
    if names.is_empty() {
        return (vec![], vec![]);
    }
    let mut notes = vec![];
    let mut missing = vec![];
    let mut out = Vec::new();
    for name in names {
        match values.get(&name) {
            Some(v) => out.push((name, v.clone())),
            None => {
                missing.push(name.clone());
                out.push((name, String::new()));
            }
        }
    }
    notes.push(format!(
        "detected {} PUB_* build env var(s) from source declarations and env files — review them on the last step",
        out.len()
    ));
    if !missing.is_empty() {
        notes.push(format!(
            "no committed value for {} — set {} before deploying",
            missing.len(),
            missing.join(", ")
        ));
    }
    (out, notes)
}

/// Recursively collect `PUB_*` env var names that the source declares:
/// literal `$env/static/public` imports and `defineEnvVars({...})` keys
/// (SvelteKit v2 declares vars without any import).
fn collect_source_env_names(
    dir: &Path,
    skip_dirs: &[&str],
    out: &mut std::collections::BTreeSet<String>,
    max: usize,
) {
    if out.len() >= max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= max {
            return;
        }
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !skip_dirs.contains(&name.as_ref()) {
                collect_source_env_names(&path, skip_dirs, out, max);
            }
        } else if ft.is_file() && is_source_file(&path) {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            collect_import_names(&content, out, max);
            collect_define_env_names(&content, out, max);
        }
    }
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ts" | "js" | "mjs" | "cjs" | "svelte" | "tsx" | "jsx")
    )
}

/// Extract `PUB_*` names from `import { A, B } from "$env/static/public"`
/// statements in `content`. Multi-line imports are handled by scanning
/// backwards from each marker occurrence to the enclosing braces.
fn collect_import_names(content: &str, out: &mut std::collections::BTreeSet<String>, max: usize) {
    const MARKER: &str = "$env/static/public";
    let mut rest = content;
    while let Some(pos) = rest.find(MARKER) {
        if out.len() >= max {
            return;
        }
        let before = &rest[..pos];
        if let Some(import_pos) = before.rfind("import") {
            let stmt = &before[import_pos..];
            if let (Some(open), Some(close)) = (stmt.rfind('{'), stmt.rfind('}'))
                && open < close
            {
                for tok in stmt[open + 1..close].split(|c: char| c == ',' || c.is_whitespace()) {
                    if out.len() >= max {
                        return;
                    }
                    if tok.starts_with("PUB_")
                        && tok.len() > 4
                        && tok
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                    {
                        out.insert(tok.to_string());
                    }
                }
            }
        }
        rest = &rest[pos + MARKER.len()..];
    }
}

/// `defineEnvVars({ PUB_X: {...} })` (SvelteKit v2's env declaration) never
/// mentions `$env/static/public` — take every `PUB_*:` key from files that
/// use it. Key-shaped tokens only (name followed by a colon).
fn collect_define_env_names(
    content: &str,
    out: &mut std::collections::BTreeSet<String>,
    max: usize,
) {
    if out.len() >= max || !content.contains("defineEnvVars") {
        return;
    }
    let bytes = content.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if out.len() >= max {
            return;
        }
        if &bytes[i..i + 4] != b"PUB_" {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < bytes.len()
            && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == b'_')
        {
            j += 1;
        }
        let mut k = j;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t' || bytes[k] == b'\n') {
            k += 1;
        }
        if j - i > 4 && k < bytes.len() && bytes[k] == b':' {
            // The walked token is pure ascii, so this cannot fail.
            if let Ok(tok) = std::str::from_utf8(&bytes[i..j]) {
                out.insert(tok.to_string());
            }
        }
        i = j;
    }
}

/// `PUB_*` keys declared by one env file (template or committed env).
/// Only `PUB_*` is taken: SvelteKit exposes exactly that prefix as public,
/// so a committed `.env` can never smuggle a secret key into build.env.
fn collect_env_file_keys(path: &Path, out: &mut std::collections::BTreeSet<String>, max: usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        if out.len() >= max {
            return;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.starts_with("PUB_")
            && key.len() > 4
            && key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            out.insert(key.to_string());
        }
    }
}

/// Parse `KEY=value` lines of one env file into `map` (later files
/// override). Comments, blank lines, and malformed keys are skipped;
/// surrounding quotes on values are stripped.
fn merge_env_file(path: &Path, map: &mut std::collections::BTreeMap<String, String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        let value = value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if value.len() <= 4096 && !value.contains('\n') {
            map.insert(key.to_string(), value.to_string());
        }
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
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, body).unwrap();
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

    /// A polyglot tree (devtools package.json + python deps) is recognised
    /// by evidence, and the run command/port come from what the repo
    /// itself declares — the entrypoint exec line and the config file.
    /// Zero app-specific code is involved.
    #[test]
    fn declared_container_command_wins_end_to_end() {
        let dir = tree(
            "decl",
            &[
                // Real shape of a polyglot repo: node manifest carries no
                // evidence, python deps do.
                (
                    "package.json",
                    r#"{"name":"devtools","dependencies":{},"scripts":{"clean":"rm -Rf node_modules"}}"#,
                ),
                ("requirements.txt", "flask==3.1.3\n"),
                // The runtime server lives in a companion requirements list.
                ("requirements-server.txt", "granian==2.8.4\n"),
                // The container entrypoint declares the real command.
                (
                    "container/entrypoint.sh",
                    "#!/bin/sh\nexport APP_PORT=\"${PORT:-}\"\nexec /usr/local/app/.venv/bin/granian searx.webapp:app\n",
                ),
                (
                    "pkgmain.py",
                    "from flask import Flask\napp = Flask(__name__)\n",
                ),
                // The config file carries the port.
                (
                    "settings.yml",
                    "server:\n  port: 8888\n  bind_address: \"127.0.0.1\"\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert_eq!(d.profile, "python");
        assert!(
            d.confident,
            "a declared command is high confidence: {:?}",
            d.notes
        );
        assert_eq!(
            d.run_cmd,
            "{venv} -m granian searx.webapp:app --host 127.0.0.1 --port {port}"
        );
        assert_eq!(d.port, "8888");
        assert!(
            d.prefetch[0].contains("-r requirements-server.txt"),
            "companion requirements feed the wheelhouse: {:?}",
            d.prefetch
        );
        assert!(
            d.build[1].contains("-r requirements-server.txt"),
            "{:?}",
            d.build
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No declarations anywhere: the code itself shows the app object, and
    /// the requirements carry the server — still high confidence.
    #[test]
    fn app_object_plus_server_beats_the_guess() {
        let dir = tree(
            "appobj",
            &[
                ("requirements.txt", "uvicorn==0.30.0\nfastapi==0.111.0\n"),
                ("main.py", "from fastapi import FastAPI\napp = FastAPI()\n"),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(d.confident, "{:?}", d.notes);
        assert_eq!(
            d.run_cmd,
            "{venv} -m uvicorn main:app --host 127.0.0.1 --port {port}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Procfile `web:` line is a first-class declaration.
    #[test]
    fn procfile_web_line_is_a_declaration() {
        let dir = tree(
            "procfile",
            &[
                ("requirements.txt", "gunicorn==21.2.0\n"),
                (
                    "Procfile",
                    "web: gunicorn myapp.wsgi:application --bind 127.0.0.1:8000\n",
                ),
                ("myapp/wsgi.py", "application = get_wsgi_application()\n"),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(d.confident, "{:?}", d.notes);
        assert!(
            d.run_cmd.contains("gunicorn")
                && d.run_cmd.contains("myapp.wsgi:application")
                && d.run_cmd.contains("{port}"),
            "{}",
            d.run_cmd
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A packaging entry point names the app target; the server comes from
    /// the requirements — no container assets needed.
    #[test]
    fn console_scripts_plus_server_dependency() {
        let dir = tree(
            "scripts",
            &[
                ("requirements.txt", "granian==2.8.4\n"),
                (
                    "setup.py",
                    "from setuptools import setup\nsetup(name='x', entry_points={'console_scripts': ['xrun = mypkg.main:run']})\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(d.confident, "{:?}", d.notes);
        assert!(
            d.run_cmd.contains("granian") && d.run_cmd.contains("mypkg.main:run"),
            "{}",
            d.run_cmd
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The config file outranks a container EXPOSE: the app's own port
    /// wins over the container's published one.
    #[test]
    fn config_port_beats_dockerfile_expose() {
        let dir = tree(
            "ports",
            &[
                ("requirements.txt", "flask\n"),
                ("app.py", "app = 1\n"),
                ("settings.yml", "server:\n  port: 8888\n"),
                ("Dockerfile", "FROM x\nEXPOSE 8080\n"),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert_eq!(d.port, "8888", "{:?}", d.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A shipped placeholder secret is flagged as a warn note, and when the
    /// config line documents its `${ENV}` override, the note hands the user
    /// the exact run.env entry to add. Read from the repo — no app names.
    #[test]
    fn placeholder_secret_with_env_hint_is_flagged() {
        let dir = tree(
            "phint",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "searx/settings.yml",
                    "server:\n  secret_key: \"ultrasecretkey\"  # Is overwritten by ${SEARXNG_SECRET}\n  port: 8888\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        let note = d
            .notes
            .iter()
            .find(|n| n.contains("auto-overridden"))
            .expect("placeholder secret must be reported");
        assert!(
            !note.starts_with("warn: "),
            "already fixed = not a warn: {note}"
        );
        assert!(note.contains("searx/settings.yml"), "{note}");
        assert!(note.contains("SEARXNG_SECRET"), "{note}");
        assert!(
            d.run_env
                .contains(&("SEARXNG_SECRET".to_string(), "{secret}".to_string())),
            "{:?}",
            d.run_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An auto-fixed placeholder must not block the autopilot: the draft is
    /// both confident and free of `warn:` notes.
    #[test]
    fn auto_fixed_placeholder_does_not_warn() {
        let dir = tree(
            "phauto",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "settings.yml",
                    "server:\n  secret_key: \"ultrasecretkey\"  # Is overwritten by ${APP_TOKEN}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(
            d.notes.iter().all(|n| !n.starts_with("warn: ")),
            "{:?}",
            d.notes
        );
        assert!(
            d.run_env
                .contains(&("APP_TOKEN".to_string(), "{secret}".to_string())),
            "{:?}",
            d.run_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A value that only looks like a secret (real random hex) is not a
    /// placeholder — no false alarm.
    #[test]
    fn a_real_looking_secret_is_not_flagged() {
        let dir = tree(
            "phreal",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "settings.yml",
                    "server:\n  secret_key: \"9f2c7a1e4b8d3c6f0a5b2e9d7c1f4a8e\"\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(
            d.notes.iter().all(|n| !n.starts_with("warn: ")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No `${ENV}` documentation in the file: the note still points at the
    /// generic fix (override via run.env), with no auto-set.
    #[test]
    fn placeholder_secret_without_hint_mentions_run_env() {
        let dir = tree(
            "phnohint",
            &[
                ("requirements.txt", "flask\n"),
                ("config.ini", "[db]\npassword = changeme\n"),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        let note = d
            .notes
            .iter()
            .find(|n| n.starts_with("warn: "))
            .expect("placeholder must be flagged");
        assert!(note.contains("run.env"), "{note}");
        assert!(note.contains("password"), "{note}");
        assert!(
            d.run_env.is_empty(),
            "no hint means no auto-set: {:?}",
            d.run_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The documented `${VAR}` override becomes a run.env pair with the
    /// fresh-secret placeholder — declared by the repo itself.
    #[test]
    fn placeholder_env_hint_auto_sets_run_env() {
        let dir = tree(
            "phset",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "settings.yml",
                    "server:\n  secret_key: \"ultrasecretkey\"  # Is overwritten by ${SEARXNG_SECRET}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(
            d.run_env
                .contains(&("SEARXNG_SECRET".to_string(), "{secret}".to_string())),
            "{:?}",
            d.run_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hostile/broken `${PATH}`-style hint must never become run.env
    /// (OS-level denylist — would break the unit itself).
    #[test]
    fn denied_env_names_are_never_auto_set() {
        let dir = tree(
            "phdeny",
            &[
                ("requirements.txt", "flask\n"),
                ("settings.yml", "server:\n  password: changeme  # ${PATH}\n"),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(
            d.run_env.is_empty(),
            "PATH must not be auto-set: {:?}",
            d.run_env
        );
        assert!(
            d.notes.iter().any(|n| n.starts_with("warn: ")),
            "still flagged: {:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dockerfile `ENV` declarations flow into run.env: the container's own
    /// runtime settings (interface flags & co) survive detection, while
    /// OS-critical and shell-expanding entries are dropped.
    #[test]
    fn dockerfile_env_declarations_reach_run_env() {
        let dir = tree(
            "denv",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "Dockerfile",
                    "FROM python:3\nENV GRANIAN_INTERFACE=\"wsgi\" GRANIAN_PORT=\"8080\"\nENV PATH=$PATH:/opt/x\nENV PYTHONPATH=/x\nENV EXPAND=\"pre-$HOME\"\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        assert!(
            d.run_env
                .contains(&("GRANIAN_INTERFACE".to_string(), "wsgi".to_string())),
            "{:?}",
            d.run_env
        );
        assert!(
            d.run_env
                .contains(&("GRANIAN_PORT".to_string(), "8080".to_string())),
            "{:?}",
            d.run_env
        );
        assert!(
            !d.run_env
                .iter()
                .any(|(k, _)| { matches!(k.as_str(), "PATH" | "PYTHONPATH" | "EXPAND") }),
            "denied/expanding values must be dropped: {:?}",
            d.run_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The multi-line `ENV \` block form (how real Dockerfiles declare a
    /// group of runtime vars) parses too.
    #[test]
    fn dockerfile_env_continuation_blocks_parse() {
        let dir = tree(
            "denv2",
            &[
                ("requirements.txt", "flask\n"),
                (
                    "container/Dockerfile",
                    "FROM python:3\nENV \\\n    GRANIAN_INTERFACE=\"wsgi\" \\\n    GRANIAN_HOST=\"::\" \\\n    GRANIAN_PORT=\"8080\"\n",
                ),
            ],
        );
        let d = detect_tree(&dir).expect("detected");
        for (k, v) in [("GRANIAN_INTERFACE", "wsgi"), ("GRANIAN_HOST", "::")] {
            assert!(
                d.run_env.contains(&(k.to_string(), v.to_string())),
                "{k} missing: {:?}",
                d.run_env
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The evidence gate is generic, not app-specific: any tree whose only
    /// node marker is a bare devtools package.json falls through to the
    /// next stack carrying real weight.
    #[test]
    fn bare_package_json_falls_through_to_python() {
        let dir = tree(
            "barepkg",
            &[
                (
                    "package.json",
                    r#"{"name":"tools","dependencies":{},"scripts":{"clean":"rm -Rf node_modules"}}"#,
                ),
                ("requirements.txt", "flask\n"),
            ],
        );
        let d = detect_tree(&dir).expect("python detected");
        assert_eq!(d.profile, "python", "{:?}", d.notes);
        assert!(
            !d.confident,
            "an undeclared app is a guess — the wizard must review it: {:?}",
            d.notes
        );
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
        assert!(
            !d.confident,
            "nothing declares the module — the wizard must review it: {:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_go_module() {
        let dir = tree(
            "go",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\n\nimport \"flag\"\n\nfunc main() {\n\tflag.String(\"addr\", \"\", \"\")\n\tflag.Int(\"port\", 8080, \"\")\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "go");
        assert!(d.prefetch.is_empty());
        assert_eq!(
            d.build[0], "go build -o ghost-server .",
            "root main builds the root package"
        );
        assert_eq!(d.run_cmd, "{bin} --addr 127.0.0.1 --port {port}");
        assert!(d.confident, "{:?}", d.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A main package with no flags/env/listen declarations: honest refusal
    /// (not confident) instead of a fabricated --addr/--port pair.
    #[test]
    fn go_without_declarations_is_not_confident() {
        let dir = tree(
            "gobare",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                ("main.go", "package main\n\nfunc main() {}\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert!(!d.confident, "{:?}", d.notes);
        assert_eq!(d.run_cmd, "{bin}");
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("no run/port declaration")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cobra-style flags (the layout real CLIs use): run command mirrors
    /// the declared names.
    #[test]
    fn go_cobra_flags_are_read_from_source() {
        let dir = tree(
            "gocobra",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\n\nimport \"github.com/spf13/cobra\"\n\nfunc main() {\n\trootCmd.Flags().String(\"addr\", \"\", \"address of server\")\n\trootCmd.Flags().Int(\"port\", 8081, \"port of server\")\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.run_cmd, "{bin} --addr 127.0.0.1 --port {port}");
        assert!(d.confident, "{:?}", d.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The code reads PORT from the environment: run plain, the exported
    /// PORT={port} does the binding.
    #[test]
    fn go_port_env_declaration_is_confident() {
        let dir = tree(
            "goenvport",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\n\nimport \"os\"\n\nfunc main() {\n\t_ = os.Getenv(\"PORT\")\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.run_cmd, "{bin}");
        assert!(d.confident, "{:?}", d.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hardcoded bind address is the port declaration: plain run, that
    /// exact port, no invented flags.
    #[test]
    fn go_hardcoded_listen_port_is_adopted() {
        let dir = tree(
            "golisten",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\n\nimport \"net/http\"\n\nfunc main() {\n\thttp.ListenAndServe(\":9123\", nil)\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.run_cmd, "{bin}");
        assert_eq!(d.port, "9123");
        assert!(d.confident, "{:?}", d.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A repo with subpackages must not build via `./...` (multi-package
    /// output error) — the cmd/<name> main package is located and built.
    #[test]
    fn go_cmd_layout_builds_only_the_main_package() {
        let dir = tree(
            "gocmd",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                ("pkg/lib/lib.go", "package lib\n"),
                (
                    "cmd/server/main.go",
                    "package main\n\nimport \"flag\"\n\nfunc main() {\n\tflag.Int(\"port\", 8080, \"\")\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.build[0], "go build -o ghost-server ./cmd/server");
        assert!(d.confident, "{:?}", d.notes);
        assert_eq!(d.run_cmd, "{bin} --port {port}");
        assert!(
            d.notes.iter().any(|n| n.contains("cmd/server")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Main deeper than cmd/ (pkg/server) is found by the shallow scan.
    #[test]
    fn go_nested_main_package_is_located() {
        let dir = tree(
            "gonest",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                (
                    "pkg/server/main.go",
                    "package main\n\nimport \"flag\"\n\nfunc main() {\n\tflag.Int(\"port\", 8080, \"\")\n}\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.build[0], "go build -o ghost-server ./pkg/server");
        assert!(d.confident);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Several cmd/ mains (multi-binary repo): no single -o target —
    /// honest note, not confident, wizard review.
    #[test]
    fn go_multi_main_is_not_confident() {
        let dir = tree(
            "gomulti",
            &[
                ("go.mod", "module example.com/x\n\ngo 1.21\n"),
                ("cmd/a/main.go", "package main\n"),
                ("cmd/b/main.go", "package main\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert!(!d.confident, "{:?}", d.notes);
        assert!(
            d.notes.iter().any(|n| n.contains("no package main")),
            "{:?}",
            d.notes
        );
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

    #[test]
    fn sveltekit_public_env_imports_are_detected_with_values() {
        let dir = tree(
            "svelte-env",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/lib/util/consts.ts",
                    r#"import { PUB_ENV, PUB_HOSTNAME } from "$env/static/public";
export const X = PUB_ENV;"#,
                ),
                (
                    "src/routes/+layout.svelte",
                    r#"<script>
import { PUB_PLAUSIBLE_URL } from "$env/static/public";
</script>"#,
                ),
                (
                    ".env.example",
                    "PUB_ENV=production\nPUB_HOSTNAME=localhost\nPUB_PLAUSIBLE_URL=\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        let env: std::collections::BTreeMap<&str, &str> = d
            .build_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(env.len(), 3, "{:?}", d.build_env);
        assert_eq!(env["PUB_ENV"], "production");
        assert_eq!(env["PUB_HOSTNAME"], "localhost");
        assert_eq!(env["PUB_PLAUSIBLE_URL"], "");
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("PUB_") && n.contains("env")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_env_import_without_committed_value_gets_empty_and_note() {
        let dir = tree(
            "svelte-missing",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/app.ts",
                    "import { PUB_SECRET_THING } from \"$env/static/public\";\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.build_env.len(), 1, "{:?}", d.build_env);
        assert_eq!(d.build_env[0].0, "PUB_SECRET_THING");
        assert_eq!(d.build_env[0].1, "");
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("PUB_SECRET_THING") && n.contains("no committed value")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The VERT shape: SvelteKit v2 declares vars via defineEnvVars (no
    /// `$env/static/public` imports anywhere) and the values live in the
    /// committed .env.example — the offline build needs every one of them.
    #[test]
    fn define_env_vars_and_env_template_supply_build_env() {
        let dir = tree(
            "svelte-define",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/env.ts",
                    "import { defineEnvVars } from \"@sveltejs/kit/env\";\n\
                     export const vars = defineEnvVars({\n\
                     \x20 PUB_VERTD_URL: { public: true, static: true },\n\
                     \x20 PUB_ENV: { public: true, static: true },\n\
                     });\n",
                ),
                (
                    ".env.example",
                    "PUB_VERTD_URL=https://vertd.vert.sh\n\
                     PUB_ENV=production\n\
                     PUB_DONATION_URL=https://donations.vert.sh\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        let env: std::collections::BTreeMap<&str, &str> = d
            .build_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // Two declared keys + one template-only key, all with values.
        assert_eq!(env.len(), 3, "{:?}", d.build_env);
        assert_eq!(env["PUB_VERTD_URL"], "https://vertd.vert.sh");
        assert_eq!(env["PUB_ENV"], "production");
        assert_eq!(env["PUB_DONATION_URL"], "https://donations.vert.sh");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_bun_app_has_no_detected_build_env() {
        let dir = tree(
            "plain-bun",
            &[
                ("package.json", r#"{"scripts":{"build":"tsc"}}"#),
                ("bun.lock", "x"),
                ("src/index.ts", "console.log('hi');\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert!(d.build_env.is_empty(), "{:?}", d.build_env);
        assert!(
            !d.notes.iter().any(|n| n.contains("build env")),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_precedence_production_over_example() {
        let dir = tree(
            "svelte-precedence",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/a.ts",
                    "import { PUB_ENV } from \"$env/static/public\";\n",
                ),
                (".env.example", "PUB_ENV=development\n"),
                (".env.production", "PUB_ENV=production\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.build_env, vec![("PUB_ENV".into(), "production".into())]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiline_import_and_quoted_env_values() {
        let dir = tree(
            "svelte-multiline",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/b.ts",
                    "import {\n  PUB_ALPHA,\n  PUB_BETA,\n} from \"$env/static/public\";\n",
                ),
                (
                    ".env.example",
                    "PUB_ALPHA='hello world'\nPUB_BETA=\"quoted\"\n# comment\nBAD LINE\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        let env: std::collections::BTreeMap<&str, &str> = d
            .build_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(env["PUB_ALPHA"], "hello world");
        assert_eq!(env["PUB_BETA"], "quoted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_modules_are_not_scanned_for_imports() {
        let dir = tree(
            "svelte-skip",
            &[
                (
                    "package.json",
                    r#"{"dependencies":{"@sveltejs/kit":"2.0.0"},"scripts":{"build":"vite build"}}"#,
                ),
                ("bun.lock", "x"),
                (
                    "src/real.ts",
                    "import { PUB_REAL } from \"$env/static/public\";\n",
                ),
                (
                    "node_modules/dep/index.js",
                    "import { PUB_FROM_DEP } from \"$env/static/public\";\n",
                ),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(
            d.build_env,
            vec![("PUB_REAL".into(), String::new())],
            "{:?}",
            d.build_env
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Go app that embeds its web UI (vite build into the go:embed dir)
    /// must build the frontend BEFORE go build — otherwise the binary
    /// freezes the git-shipped placeholder page and "succeeds" while
    /// serving the fallback.
    #[test]
    fn go_embed_frontend_builds_before_go() {
        let dir = tree(
            "go-embed-fe",
            &[
                ("go.mod", "module example.com/app\n\ngo 1.22\n"),
                (
                    "cmd/app/main.go",
                    "package main\nimport (\"flag\"; \"fmt\")\nfunc main() {\n    addr := flag.String(\"addr\", \"0.0.0.0\", \"\")\n    port := flag.String(\"port\", \"0\", \"\")\n    flag.Parse()\n    fmt.Println(*addr, *port)\n}\n",
                ),
                (
                    "server/frontend/frontend.go",
                    "package frontend\n\nimport \"embed\"\n\n//go:embed dist/*\nvar dist embed.FS\n",
                ),
                (
                    "server/frontend/dist/index.html",
                    "<html><body>No embeddable frontend found.</body></html>\n",
                ),
                (
                    "web/package.json",
                    r#"{"scripts":{"release":"vite build --mode release --outDir=../server/frontend/dist --emptyOutDir","build":"vite build"}}"#,
                ),
                ("web/pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "go");
        assert_eq!(
            d.prefetch,
            vec!["pnpm --dir web fetch --store-dir {project}/.ghost-cache/pnpm".to_string()],
            "{:?}",
            d.prefetch
        );
        assert_eq!(
            d.build,
            vec![
                "pnpm --dir web install --offline --store-dir {project}/.ghost-cache/pnpm"
                    .to_string(),
                "pnpm --dir web run release".to_string(),
                "go build -o ghost-server ./cmd/app".to_string(),
            ],
            "{:?}",
            d.build
        );
        assert_eq!(d.run_cmd, "{bin} --addr 127.0.0.1 --port {port}");
        assert!(d.confident, "flags are declared: {:?}", d.notes);
        assert!(
            d.notes.iter().any(
                |n| n.contains("frontend: `pnpm --dir web run release` → server/frontend/dist")
            ),
            "{:?}",
            d.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// go:embed without any build script pointing into the embedded dir is
    /// an unknown: the binary would freeze whatever sits there (often a
    /// placeholder), so autopilot must yield to a wizard review.
    #[test]
    fn go_embed_without_script_opens_wizard() {
        let dir = tree(
            "go-embed-raw",
            &[
                ("go.mod", "module example.com/app\n\ngo 1.22\n"),
                (
                    "main.go",
                    "package main\nimport \"flag\"\nfunc main() {\n    port := flag.String(\"port\", \"0\", \"\")\n    _ = port\n}\n",
                ),
                (
                    "static/index.go",
                    "package static\n\nimport \"embed\"\n\n//go:embed dist/*\nvar dist embed.FS\n",
                ),
                ("static/dist/index.html", "<html>placeholder</html>\n"),
            ],
        );
        let d = detect_tree(&dir).unwrap();
        assert_eq!(d.profile, "go");
        assert!(!d.confident);
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains("go:embed static/dist: no frontend build script")),
            "{:?}",
            d.notes
        );
        assert_eq!(d.build, vec!["go build -o ghost-server .".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_outdir_parsing() {
        assert_eq!(
            script_outdir(
                "vite build --mode release --outDir=../server/frontend/dist --emptyOutDir"
            ),
            Some("../server/frontend/dist")
        );
        assert_eq!(
            script_outdir("next build --outDir ../ui/dist"),
            Some("../ui/dist")
        );
        assert_eq!(script_outdir("vite build"), None);
        assert_eq!(script_outdir("build --outDir=$DIST"), None);
    }
}
