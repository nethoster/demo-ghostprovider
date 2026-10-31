//! demo-ghostprovider — local-first demo hosting panel.
//!
//! CLI surface:
//!   (no args)            launch the TUI
//!   --show-endpoints     print the compiled-in endpoint allowlist plus this
//!                        session's request counters, then exit
//!   --version | -V       print version
//!   --selftest           E2E check against the live systemd user manager:
//!                        installs a real unit running the static server,
//!                        polls activation, health-checks it, cleans up
//!   --verify-sandbox     audit the hardened build sandbox under strace:
//!                        no outbound connects, no code-loading exec's
//!   __serve-static DIR PORT   internal: static server used by deployed units
//!   __egress-probe [--hosts a,b]  internal: probe beats for egress checks
//!   __egress-shim PORT -- CMD...  internal: netns deny-all front — adopts the
//!                        socket-unit listener (fd 3) and bridges it to CMD
//!                        inside the private network namespace
//!   __check-manifest PATH   validate a service.yaml and print the plan
//!   __recipe-edit ID        edit a stored service.yaml in $EDITOR (re-validated)
//!   __deploy URL            detect the stack of a GitHub URL and print a
//!                            service.yaml to stdout (review, then deploy
//!                            with --manifest — a URL never deploys itself)
//!   __deploy --manifest PATH scripted deploy of one service.yaml

#![deny(unsafe_code)]

use anyhow::Context;

use demo_ghostprovider::{netlog, selftest, serve, verify};

/// Write to stdout, tolerating closed pipes (`| head`) without panicking.
fn write_stdout(s: &str) {
    use std::io::Write;
    let _ = std::io::stdout().lock().write_all(s.as_bytes());
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            // Ignore write errors (e.g. closed pipe from `| head`) instead of panicking.
            write_stdout(&format!(
                "demo-ghostprovider {}\n",
                env!("CARGO_PKG_VERSION")
            ));
        }
        Some("--show-endpoints") => {
            let mut out = String::from("Compiled-in remote allowlist:\n");
            for h in netlog::ALLOWED_ENDPOINTS {
                out.push_str(&format!("  {h}\n"));
            }
            out.push_str("Local health-check hosts (never used for API calls):\n");
            for h in netlog::LOCAL_ENDPOINTS {
                out.push_str(&format!("  {h}\n"));
            }
            let summary = netlog::session_summary();
            if summary.is_empty() {
                out.push_str("\nNo outbound requests made this session.\n");
            } else {
                out.push_str("\nThis session:\n");
                for (host, (total, errors)) in &summary {
                    out.push_str(&format!(
                        "  {host}: {total} request(s), {errors} with errors\n"
                    ));
                }
            }
            write_stdout(&out);
        }
        Some("--selftest") => {
            selftest::run()?;
        }
        Some("--verify-sandbox") => {
            verify::run()?;
        }
        // Internal subcommand used by generated systemd units. Not advertised.
        Some("__egress-probe") => {
            let hosts: Vec<String> = match args.iter().position(|a| a == "--hosts") {
                Some(i) => args
                    .get(i + 1)
                    .map(|s| s.split(',').map(str::to_string).collect())
                    .unwrap_or_default(),
                None => vec!["api.github.com".into()],
            };
            demo_ghostprovider::hoster::egress::run_probe_cmd(&hosts)?;
        }
        Some("__serve-static") => {
            let dir = args.get(1).context("usage: __serve-static DIR PORT")?;
            let port: u16 = args
                .get(2)
                .context("usage: __serve-static DIR PORT")?
                .parse()?;
            serve::serve_static(std::path::Path::new(dir), port)?;
        }
        // Internal subcommand used by netns deny-all units. Not advertised.
        Some("__egress-shim") => {
            demo_ghostprovider::hoster::shim::run(&args[1..])?;
        }
        // Internal subcommand for scripted E2E: full pipeline without the TUI.
        // Internal subcommand for the demo-ghostprovider-cleanup systemd user
        // timer: sweep leftovers of deploys interrupted out-of-band (exit,
        // SIGKILL, shutdown/reboot) — but only while the deploy lock is free,
        // i.e. no deploy is genuinely live in this user session.
        Some("__cleanup") => {
            demo_ghostprovider::networks::supervisor::stop_all();
            demo_ghostprovider::hoster::deploy::cleanup_cmd()?;
        }
        Some("__networks-stop-all") => {
            demo_ghostprovider::networks::supervisor::stop_all();
            return Ok(());
        }
        Some("__check-manifest") => {
            let path = args.get(1).context("usage: __check-manifest PATH")?;
            match demo_ghostprovider::hoster::manifest::ServiceManifest::load_from_file(
                std::path::Path::new(path),
            ) {
                Ok(m) => {
                    println!("manifest OK: {}", m.service.id);
                    println!();
                    print!("{}", m.plan_text());
                }
                Err(e) => {
                    eprintln!("! invalid manifest {path}: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Some("__cloudflared-supervisor") => {
            demo_ghostprovider::networks::supervisor::run_cli(&args[1..])?;
            return Ok(());
        }
        Some("__recipe-edit") => {
            let id = args.get(1).context("usage: __recipe-edit SERVICE_ID")?;
            match demo_ghostprovider::hoster::library::edit_in_editor(id) {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("! {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Some("__deploy") => {
            reconcile_on_startup();
            use std::cell::RefCell;
            // v0.0.44 (demo-declutter): the built-in URL catalog is gone —
            // a deploy only ever runs from a `service.yaml`. Two modes:
            //   * `--manifest PATH` — the deploy pipeline itself, with the
            //     exit-signal watchdog armed (SIGINT cleans up mid-deploy);
            //   * `URL` — the smart path: clone to a temp dir, detect the
            //     stack, print the resulting service.yaml on stdout for
            //     review. Detection holds no deploy lock and starts no
            //     pipeline, so no watchdog is needed there.
            if args.get(1).map(String::as_str) == Some("--manifest") {
                arm_deploy_signal_watchdog();
                let path = args.get(2).context("usage: __deploy --manifest PATH")?;
                let painter = RefCell::new(demo_ghostprovider::output::Painter::new());
                println!();
                println!("{}", painter.borrow().header(path));
                let outcome = demo_ghostprovider::hoster::deploy::run_manifest_file(
                    std::path::Path::new(path),
                    &|line| {
                        for out in painter.borrow_mut().render(&line) {
                            println!("{out}");
                        }
                    },
                );
                match outcome {
                    demo_ghostprovider::hoster::deploy::DeployOutcome::Deployed => {}
                    other => {
                        eprintln!("{}", painter.borrow().summary(false));
                        eprintln!("  reason: {other:?}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            let url = args
                .get(1)
                .context("usage: __deploy GITHUB_URL | --manifest PATH")?;
            let ready = match demo_ghostprovider::tui::workers::detect_url(url) {
                Ok(ready) => ready,
                Err(e) => {
                    eprintln!("! detect failed: {e}");
                    std::process::exit(1);
                }
            };
            let mut draft = ready.draft;
            if draft.id.trim().is_empty() {
                draft.id = ready.suggested_id;
            }
            // Detection notes (why it guessed what it guessed) are part of
            // the review material — stderr keeps stdout a pure YAML stream,
            // so `__deploy URL > service.yaml` yields a ready file.
            for n in &draft.notes {
                eprintln!("note: {n}");
            }
            match demo_ghostprovider::tui::wizard::preview_yaml(&draft) {
                Ok(yaml) => {
                    write_stdout(&yaml);
                    eprintln!(
                        "detected profile '{}' — review the service.yaml above, then run:\n  \
                         demo-ghostprovider __deploy --manifest <path>",
                        draft.profile
                    );
                }
                Err(e) => {
                    eprintln!("! cannot build a manifest from detection: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("--help" | "-h") => print_help(),
        Some(other) if other.starts_with("--") => {
            eprintln!("unknown option: {other}\nsee --help");
            std::process::exit(2);
        }
        _ => {
            reconcile_on_startup();
            demo_ghostprovider::tui::run()?;
        }
    }
    Ok(())
}

/// Clean up artifacts left by deploys interrupted out-of-band (panel exit,
/// kill, shutdown/reboot) before the interactive/scripted entry starts, and
/// surface what was removed on stderr. Lock-guarded: while another process
/// is deploying, its live tree is left alone (deferred to the next launch
/// or the cleanup timer once the lock is free).
fn reconcile_on_startup() {
    for m in demo_ghostprovider::hoster::deploy::reconcile_stale_locked(
        demo_ghostprovider::hoster::deploy::ReconcileBasis::Startup,
    ) {
        eprintln!("{m}");
    }
}

/// Watchdog for scripted `__deploy` runs: the first SIGINT/SIGTERM/SIGHUP
/// triggers the interruption reconciliation (stop the in-flight unit, wipe the
/// tree, settle or retain the journal entry) and exits 128+signal. The TUI
/// routes the same signals through its event loop instead, so nothing here
/// applies to interactive runs.
fn arm_deploy_signal_watchdog() {
    let Ok(mut signals) = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) else {
        return;
    };
    std::thread::spawn(move || {
        let Some(sig) = signals.forever().next() else {
            return;
        };
        // Set EXITING (so the pipeline stops starting steps), tear down the
        // deploy's own writers (host clone/build children and ghost-* build
        // units) and wait for the worker to unwind, then reconcile with the
        // entry settled — the clone/build tree and journal entry go *now*, not
        // on the next launch.
        demo_ghostprovider::hoster::cancel::request_exit();
        demo_ghostprovider::hoster::deploy::quiesce(std::time::Duration::from_secs(3));
        // Lock-guarded: this process just released its own deploy lock, so
        // the sweep runs — unless a different session is deploying, whose
        // live tree must survive.
        for m in demo_ghostprovider::hoster::deploy::reconcile_stale_locked(
            demo_ghostprovider::hoster::deploy::ReconcileBasis::Exit,
        ) {
            eprintln!("{m}");
        }
        std::process::exit(128 + sig);
    });
}

fn print_help() {
    println!(
        "demo-ghostprovider {} — deploy service.yaml manifests as hardened systemd user units\n\
         \n\
         Usage:\n\
         \x20 demo-ghostprovider              launch the interactive panel\n\
         \x20 demo-ghostprovider --show-endpoints   transparency: allowlist + session counters\n\
         \x20 demo-ghostprovider --selftest           verify systemd integration on this machine\n\
         \x20 demo-ghostprovider --verify-sandbox       audit the build sandbox (needs strace)\n\
         \x20 demo-ghostprovider --version          version\n\
         \x20 demo-ghostprovider __check-manifest PATH   validate a service.yaml and print the plan\n\
         \x20 demo-ghostprovider __recipe-edit ID   edit a stored service.yaml in $EDITOR\n\
         \x20 demo-ghostprovider __deploy --manifest PATH  deploy one service.yaml\n\
         \x20 demo-ghostprovider __deploy GITHUB_URL  detect the stack, print service.yaml to stdout\n\
         \x20 demo-ghostprovider __egress-probe [--hosts a,b]  probe egress beats (reads only)",
        env!("CARGO_PKG_VERSION")
    );
}
