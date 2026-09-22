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
//!   __egress-probe       internal: probe beat for runtime egress checks

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
            demo_ghostprovider::hoster::egress::run_probe_cmd()?;
        }
        Some("__serve-static") => {
            let dir = args.get(1).context("usage: __serve-static DIR PORT")?;
            let port: u16 = args
                .get(2)
                .context("usage: __serve-static DIR PORT")?
                .parse()?;
            serve::serve_static(std::path::Path::new(dir), port)?;
        }
        // Internal subcommand for scripted E2E: full pipeline without the TUI.
        // Internal subcommand for the demo-ghostprovider-cleanup systemd user
        // timer: sweep leftovers of deploys interrupted out-of-band (exit,
        // SIGKILL, shutdown/reboot) — but only while the deploy lock is free,
        // i.e. no deploy is genuinely live in this user session.
        Some("__cleanup") => {
            demo_ghostprovider::hoster::deploy::cleanup_cmd()?;
        }
        Some("__deploy") => {
            reconcile_on_startup();
            // A scripted deploy gets the same clean-removal guarantee as the
            // panel: on SIGINT/SIGTERM/SIGHUP (Ctrl+C, systemd shutdown,
            // terminal close) a watchdog runs the removal-II reconciliation
            // path before exiting, so a half-finished clone/build tree and the
            // journal entry never survive the process. While the deploy is
            // running, this process itself holds the deploy lock, so the
            // watchdog has no concurrent live deploy to race.
            arm_deploy_signal_watchdog();
            use std::cell::RefCell;
            let url = args.get(1).context("usage: __deploy GITHUB_URL")?;
            let painter = RefCell::new(demo_ghostprovider::output::Painter::new());
            println!();
            println!("{}", painter.borrow().header(url));
            let outcome = demo_ghostprovider::hoster::deploy::run_deployment(url, &|line| {
                for out in painter.borrow_mut().render(&line) {
                    println!("{out}");
                }
            });
            match outcome {
                // The reachable URL is already printed above ("+ listening on
                // …"); no extra verdict line needed on success.
                demo_ghostprovider::hoster::deploy::DeployOutcome::Deployed => {}
                other => {
                    eprintln!("{}", painter.borrow().summary(false));
                    eprintln!("  reason: {other:?}");
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
/// surface what was removed on stderr.
fn reconcile_on_startup() {
    for m in demo_ghostprovider::hoster::deploy::reconcile_stale(false) {
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
        for m in demo_ghostprovider::hoster::deploy::reconcile_stale_with_basis(
            false,
            demo_ghostprovider::hoster::deploy::ReconcileBasis::Exit,
        ) {
            eprintln!("{m}");
        }
        std::process::exit(128 + sig);
    });
}

fn print_help() {
    println!(
        "demo-ghostprovider {} — deploy three curated services as hardened systemd user units\n\
         \n\
         Usage:\n\
         \x20 demo-ghostprovider              launch the interactive panel\n\
         \x20 demo-ghostprovider --show-endpoints   transparency: allowlist + session counters\n\
         \x20 demo-ghostprovider --selftest           verify systemd integration on this machine\n\
         \x20 demo-ghostprovider --verify-sandbox       audit the build sandbox (needs strace)\n\
         \x20 demo-ghostprovider --version          version",
        env!("CARGO_PKG_VERSION")
    );
}
