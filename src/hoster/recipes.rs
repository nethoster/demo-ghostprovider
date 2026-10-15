//! Curated demo catalog — a small set of supported services.
//!
//! demo_ghostprovider does not host arbitrary repositories. Each entry is a
//! hardcoded deploy recipe for one specific public service. `tools` lists the
//! executables the recipe's build steps require; preflight refuses to start
//! a deployment when any of them is missing (lesson from the audit: the old
//! preflight was green while `bun install` would fail with ENOENT).

/// A hardcoded deploy recipe for a single supported demo service.
#[derive(Debug, Clone)]
pub struct DemoRecipe {
    pub owner: &'static str,
    pub name: &'static str,
    pub language: &'static str,
    pub service_name: &'static str,
    pub description: &'static str,
    pub display_name: &'static str,
    /// Pinned commit SHA that a deployment checks out after cloning, so a
    /// recipe never silently tracks whatever `main`/`master` moved to at
    /// build time (anti-TOFU). Bumped consciously when a recipe is updated.
    pub commit: &'static str,
    pub pre_build: &'static [&'static str],
    pub build_steps: &'static [&'static str],
    /// Host-phase dependency pre-fetch steps, run BEFORE the sandboxed build
    /// with network available (see `prefetch.rs`). These fill the tool caches
    /// so each sandboxed build step below runs fully offline. They are
    /// *downloader* commands, never the project's build code — a hostile
    /// `setup.py`/`postinstall` is not executed on the host (see the security
    /// invariant at the top of `prefetch.rs`).
    pub prefetch_steps: &'static [&'static str],
    /// Host-phase pinned paraglide-js plugin seeds (VERT recipe only; empty
    /// for the others). Each entry is `(jsdelivr module URL as written in
    /// `project.inlang/settings.json`, lowercase-hex SHA-256 of the file
    /// jsdelivr must serve at that URL)`. Fetched through the allowlisted
    /// client (`cdn.jsdelivr.net` — a permitted, net.log-visible host) and
    /// content-pinned so a silent version lift under the same `@N` major tag
    /// fails the deploy instead of feeding changed third-party code into the
    /// offline build.
    pub plugins: &'static [(&'static str, &'static str)],
    /// Placeholders: {bin} {venv} {python} {project} {port} {self}
    /// {self} expands to this binary — used by the built-in static server.
    pub start_cmd: &'static str,
    /// 0 = pick a random free port.
    pub port: u16,
    pub searxng: bool,
    /// Executables required on PATH for the build steps to succeed.
    pub tools: &'static [&'static str],
    /// systemd resource caps for the deployed unit (cgroup memory/tasks
    /// bounds): a runaway demo service must never grind the whole user
    /// session. See `units.rs::ResourceLimits`.
    pub res: crate::hoster::units::ResourceLimits,
}

pub const DEMO_SERVICES: &[DemoRecipe] = &[
    DemoRecipe {
        owner: "VERT-sh",
        name: "VERT",
        language: "JavaScript",
        service_name: "demo-vert",
        description: "VERT — next-generation file converter (Svelte)",
        display_name: "VERT",
        commit: "cc7b5a54d5e9c797b377db47b9bdfbb561707783",
        pre_build: &["if [ -f .env.example ] && [ ! -f .env ]; then cp .env.example .env; fi"],
        // bun install fills node_modules/caches; the two paraglide-js plugin
        // modules are seeded separately (see `plugins` below and
        // `prefetch.rs::seed_paraglide_plugins`). Both the shell prefetch and
        // the Rust plugin seed run before the sandboxed build, which itself
        // must be fully offline (PrivateNetwork=yes — see sandbox.rs).
        prefetch_steps: &[
            // --ignore-scripts: keep the host-phase prefetch script-free. bun
            // does not run dependency lifecycle scripts by default, but it DOES
            // run the root project's pre/postinstall/prepare scripts and any
            // packages named in this repo's trustedDependencies — both would
            // execute on the host, outside the sandbox. The flag blocks all of
            // them; VERT's build needs no postinstall (verified offline).
            "bun install --frozen-lockfile --ignore-scripts",
        ],
        // Pinned (url, sha256) paraglide-js plugin modules.  Fetched through
        // the allowlisted client (net.log-visible) and verified against these
        // digests *before* any file is placed — a CDN content drift under the
        // same `@N` major tag fails the deploy instead of feeding silently
        // changed code into the offline build. The URLs are identical to
        // project.inlang/settings.json so the FNV1a-64 filenames match (see
        // prefetch.rs::paraglide_cache_name and the guard tests there).
        plugins: &[
            (
                "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js",
                "765b487bbe95a20c7f83a940a3fba81bacef18bce0bbe916df6807f7ddd512ca",
            ),
            (
                "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js",
                "a7e6c41307afc64b3f34116f220e925f0ad3aca47231e849f080051a2fb459a8",
            ),
        ],
        // PrivateNetwork is enforced: deps come ONLY from the host prefetch
        // (bun install + the pinned plugin seed above). The sandboxed build
        // itself is fully offline.
        build_steps: &["bun run build"],
        // Served by THIS binary (built-in static server) instead of shelling
        // out to `python -m http.server`: one less host dependency.
        start_cmd: "{self} __serve-static {project}/build {port}",
        port: 0,
        searxng: false,
        tools: &["bun"],
        res: crate::hoster::units::ResourceLimits {
            memory_high: Some("256M"),
            memory_max: Some("384M"),
            tasks_max: Some("300"),
            cpu_quota: Some("100%"),
            limit_nofile: Some(65536),
            oom_score_adjust: Some(0),
        },
    },
    DemoRecipe {
        owner: "searxng",
        name: "searxng",
        language: "Python",
        service_name: "demo-searxng",
        description: "SearXNG — privacy-friendly metasearch engine (Python)",
        display_name: "SearXNG",
        commit: "18af21159bd7b84880cd7265b184825493322232",
        pre_build: &[],
        prefetch_steps: &[
            "python3 -m pip download -r requirements.txt -d .ghost-cache/pip-wheelhouse --only-binary=:all: && touch .ghost-cache/pip-wheelhouse/.done",
        ],
        build_steps: &[
            "python3 -m venv --clear .venv",
            ".venv/bin/pip install --no-cache-dir -r requirements.txt",
        ],
        start_cmd: "{venv} -m searx.webapp",
        port: 8888,
        searxng: true,
        plugins: &[],
        tools: &["python3"],
        res: crate::hoster::units::ResourceLimits {
            memory_high: Some("768M"),
            memory_max: Some("1536M"),
            tasks_max: Some("512"),
            cpu_quota: Some("100%"),
            limit_nofile: Some(65536),
            oom_score_adjust: Some(-100),
        },
    },
    DemoRecipe {
        owner: "usememos",
        name: "memos",
        language: "Go",
        service_name: "demo-memos",
        description: "Memos — self-hosted, open-source knowledge base (Go)",
        display_name: "Memos",
        commit: "245e5e3a3e95cd3648fd66a696e0970e5eef1254",
        pre_build: &[],
        // pnpm fetch fills the virtual store from the lockfile WITHOUT
        // building node_modules or running any lifecycle script; the sandboxed
        // install links node_modules from that warm store, offline.
        //
        // Flag discipline (keep these exact):
        //   * `fetch` NOT `install` — install would build the tree and could
        //     run the repo's lifecycle scripts on the host, outside the sandbox.
        //   * `--store-dir` pins the store to the project cache directory.
        // The offline install below must never drop `--offline`: the sandbox
        // has PrivateNetwork=yes and would fail (or, worse, a future network
        // change could let it fall back to the registry mid-build).
        prefetch_steps: &["pnpm --dir web fetch --store-dir {project}/.ghost-cache/pnpm"],
        build_steps: &[
            // PrivateNetwork is enforced: --offline is required since the
            // store was filled by the prefetch (never reach the registry).
            "pnpm --dir web install --offline --store-dir {project}/.ghost-cache/pnpm",
            "pnpm --dir web release",
            "go build -o ghost-server ./cmd/memos",
        ],
        // --addr 127.0.0.1 is mandatory: Memos' default bind (empty --addr) is
        // the wildcard `:port`, which would put the service on the LAN/VPN.
        // Loopback keeps the announced `http://localhost:PORT` honest and
        // matches the egress model (units.rs: IPAddressAllow=127.0.0.1 ::1).
        start_cmd: "{bin} --addr 127.0.0.1 --port {port}",
        port: 0,
        searxng: false,
        plugins: &[],
        tools: &["pnpm", "go"],
        res: crate::hoster::units::ResourceLimits {
            memory_high: Some("512M"),
            memory_max: Some("1024M"),
            tasks_max: Some("512"),
            cpu_quota: Some("100%"),
            limit_nofile: Some(65536),
            oom_score_adjust: Some(0),
        },
    },
];

/// Find a recipe by GitHub owner/name (case-insensitive).
pub fn find_recipe(owner: &str, name: &str) -> Option<&'static DemoRecipe> {
    DEMO_SERVICES
        .iter()
        .find(|r| r.owner.eq_ignore_ascii_case(owner) && r.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn catalog_has_three_services() {
        assert_eq!(DEMO_SERVICES.len(), 3);
        assert_eq!(
            DEMO_SERVICES
                .iter()
                .map(|r| r.service_name)
                .collect::<Vec<_>>(),
            vec!["demo-vert", "demo-searxng", "demo-memos"]
        );
    }

    #[test]
    fn find_recipe_is_case_insensitive_and_total_for_catalog() {
        assert!(find_recipe("VERT-sh", "VERT").is_some());
        assert!(find_recipe("vert-sh", "vert").is_some());
        assert!(find_recipe("usememos", "memos").is_some());
        assert!(find_recipe("searxng", "searxng").is_some());
        assert!(find_recipe("foo", "bar").is_none());
    }

    /// A deployed service must carry a resource budget: `none()` is only for
    /// the selftest unit, never for a catalog service. A service with no
    /// memory/tasks cap can exhaust the user session.
    #[test]
    fn every_catalog_service_has_resource_limits() {
        for r in DEMO_SERVICES {
            let res = r.res;
            assert!(
                res.memory_max.is_some() && res.tasks_max.is_some(),
                "{}: recipe must set memory_max and tasks_max (got {:?})",
                r.service_name,
                res
            );
        }
    }

    /// Audit lesson: every build step's interpreter must be declared in
    /// `tools`, otherwise preflight passes while the build cannot run.
    #[test]
    fn every_declared_tool_covers_build_steps() {
        for r in DEMO_SERVICES {
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
                        "{}: build step '{step}' requires '{base}' but it is not in tools {:?}",
                        r.service_name,
                        r.tools
                    );
                }
            }
        }
    }

    /// Every catalog service must end up bound to loopback only: an announced
    /// `http://localhost:PORT` while the port is reachable from the LAN is a
    /// real leak (Memos' default --addr is the wildcard `:port`). This guards
    /// against a recipe change silently re-exposing a service on every
    /// interface; `deploy.rs` additionally warns live via `ss` if a change
    /// slips through.
    #[test]
    fn every_service_binds_loopback_only() {
        for r in DEMO_SERVICES {
            match r.service_name {
                // Serve: our static server hard-binds Ipv4Addr::LOCALHOST.
                "demo-vert" => assert!(
                    r.start_cmd.contains("__serve-static"),
                    "demo-vert must be served by our loopback static server, got: {}",
                    r.start_cmd
                ),
                // SearXNG: deploy.rs patches bind_address to 127.0.0.1.
                "demo-searxng" => assert_eq!(r.start_cmd, "{venv} -m searx.webapp"),
                // Memos: --addr 127.0.0.1 is mandatory (default is wildcard).
                "demo-memos" => assert!(
                    r.start_cmd.contains("--addr 127.0.0.1"),
                    "demo-memos must bind loopback explicitly, got: {}",
                    r.start_cmd
                ),
                other => panic!("unexpected service {other} in catalog"),
            }
        }
    }

    /// resolve_start must preserve the loopback pin through placeholder
    /// expansion, so the deployed unit actually binds 127.0.0.1.
    #[test]
    fn memos_resolve_start_keeps_loopback_after_expansion() {
        let recipe = find_recipe("usememos", "memos").unwrap();
        let resolved = super::super::deploy::resolve_start(recipe, Path::new("/srv/memos"), 12345);
        assert!(resolved.contains("--addr 127.0.0.1"), "got: {resolved}");
        assert!(resolved.contains("--port 12345"), "got: {resolved}");
    }
    /// Prefetch steps are downloaders, never executed in the sandbox; every
    /// one of them references a tool the recipe declares.
    #[test]
    fn prefetch_steps_are_downloaders_and_covered() {
        for r in DEMO_SERVICES {
            for step in r.prefetch_steps {
                let head = step.split_whitespace().next().unwrap();
                let base = head.rsplit('/').next().unwrap();
                assert!(
                    r.tools.contains(&base),
                    "{}: prefetch step '{step}' needs tool '{base}' not declared in {:?}",
                    r.service_name,
                    r.tools
                );
            }
        }
    }

    /// Host-phase prefetch steps may never execute fetched package or project
    /// code on the host. bun install runs the root project's lifecycle scripts
    /// and any packages named in the repo's trustedDependencies, so it must be
    /// pinned with --ignore-scripts; pnpm/fetch does not run lifecycle scripts
    /// by design; pip must be pinned to binary-only wheels (inert archives).
    #[test]
    fn prefetch_steps_never_run_lifecycle_scripts_on_host() {
        for r in DEMO_SERVICES {
            for step in r.prefetch_steps {
                let base = step.split_whitespace().next().unwrap();
                match base {
                    "bun" => assert!(
                        step.contains("--ignore-scripts"),
                        "{}: bun prefetch must use --ignore-scripts, found: '{step}'",
                        r.service_name
                    ),
                    "pnpm" => assert!(
                        step.split_whitespace().any(|w| w == "fetch"),
                        "{}: pnpm prefetch must be a script-free `fetch`, found: '{step}'",
                        r.service_name
                    ),
                    "python3" => assert!(
                        step.contains("--only-binary=:all:"),
                        "{}: pip prefetch must pin binary-only wheels, found: '{step}'",
                        r.service_name
                    ),
                    other => panic!(
                        "{}: prefetch step starts with unexpected tool '{other}'",
                        r.service_name
                    ),
                }
            }
        }
    }

    /// Only VERT may carry plugin pins (the others have none), and every pin
    /// must be a jsdelivr paraglide module whose cache filename matches the
    /// FNV1a-64 derivation and whose SHA-256 is well-formed hex. This is the
    /// guard that keeps a recipe plugin bump honest.
    #[test]
    fn plugin_pins_are_paraglide_jsdelivr_and_well_formed() {
        for r in DEMO_SERVICES {
            assert!(
                r.plugins.len() <= 2,
                "{}: unexpected plugin count {}",
                r.service_name,
                r.plugins.len()
            );
            if r.service_name != "demo-vert" {
                assert!(
                    r.plugins.is_empty(),
                    "{}: non-VERT plugin pins",
                    r.service_name
                );
            }
            for (url, sha) in r.plugins {
                assert!(
                    url.starts_with("https://cdn.jsdelivr.net/npm/@inlang/plugin-"),
                    "{}: plugin URL must be a jsdelivr @inlang module: {url}",
                    r.service_name
                );
                assert_eq!(
                    sha.len(),
                    64,
                    "{}: plugin {url} SHA-256 must be 64 hex chars",
                    r.service_name
                );
                assert!(
                    sha.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{}: plugin {url} SHA-256 is not hex",
                    r.service_name
                );
                // Cache filename must match the URL's FNV1a-64 base36 name.
                super::super::prefetch::paraglide_cache_name(url);
            }
        }
    }
}
