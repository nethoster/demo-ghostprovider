//! Interactive panel — ratatui port of the Textual UI.
//!
//! Screen flow mirrors the Python version:
//! Main menu → System Scan / Deploy (URL input) / Self-Hosting.
//! Long operations run on worker threads reporting through a channel.
//!
//! Visual language: neon-on-black maxicolor theme. Every data type owns a
//! hue (cyan chrome · magenta deploy · green success · amber input/warnings
//! · red errors · violet scan sections). The event loop ticks ~80ms; the
//! title gradient and busy spinners are driven off that tick.

pub mod wizard;
pub mod workers;

use std::collections::{HashMap, HashSet};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{
    Arc,
    mpsc::{self, Receiver, Sender},
};
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

// --- palette (truecolor; terminals without RGB get the nearest ANSI match) ---
pub(crate) const ACCENT: Color = Color::Rgb(64, 220, 255); // electric cyan — chrome/menu
pub(crate) const MAGENTA: Color = Color::Rgb(255, 92, 200); // deploy screen theme
pub(crate) const OK_GREEN: Color = Color::Rgb(80, 250, 123); // success / active units
pub(crate) const WARN_YELLOW: Color = Color::Rgb(255, 184, 0); // input / warnings
pub(crate) const ERR_RED: Color = Color::Rgb(255, 85, 85); // failures
pub(crate) const VIOLET: Color = Color::Rgb(171, 130, 255); // scan sections
pub(crate) const BLUE: Color = Color::Rgb(97, 143, 255); // services screen theme
pub(crate) const ORANGE: Color = Color::Rgb(255, 140, 60); // edit-service theme
const DIM: Color = Color::Rgb(110, 118, 129); // secondary text
const BODY: Color = Color::Rgb(205, 213, 224); // regular text
const BODY_ALT: Color = Color::Rgb(150, 160, 174); // zebra rows (no background)

/// Gradient ramp used by the animated title and spinners.
const RAMP: [Color; 3] = [ACCENT, MAGENTA, WARN_YELLOW];

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Main menu: (icon, title, description, hue). Navigation caps, activation
/// and the menu test derive from this, so adding an item cannot desync them.
pub(crate) const MAIN_MENU: &[(&str, &str, &str, Color)] = &[
    (
        "@",
        "System Scan",
        "probe interfaces and occupied ports",
        ACCENT,
    ),
    (
        "⊗",
        "Networks",
        "publish one service at a temporary https URL",
        MAGENTA,
    ),
    ("#", "Self-Hosting", "manage deployed units", OK_GREEN),
    (
        "^",
        "Deploy Service",
        "deploy via GitHub URL or service.yaml",
        MAGENTA,
    ),
    (
        "+",
        "Add Service",
        "import service.yaml into your library",
        VIOLET,
    ),
    ("♥", "My Services", "your added services", BLUE),
    (
        "✎",
        "Edit Service",
        "edit a deployed service — name, port",
        ORANGE,
    ),
    ("⇄", "Egress", "allowed outbound per service", ERR_RED),
    (
        "≡",
        "Logs",
        "deploy + software + crash logs (3 screens)",
        WARN_YELLOW,
    ),
];

/// Row labels of the Edit Service form — the six manifest knobs the field
/// editor exposes; [`edit_fields_of`] / [`apply_edit`] map rows ↔ manifest.
const EDIT_FIELDS: [&str; 6] = ["name", "description", "commit", "port", "memory", "tasks"];

/// Row indices into [`EDIT_FIELDS`].
const EDIT_NAME: usize = 0;
const EDIT_DESC: usize = 1;
const EDIT_COMMIT: usize = 2;
const EDIT_PORT: usize = 3;
const EDIT_MEMORY: usize = 4;
const EDIT_TASKS: usize = 5;

/// "GHOST PROVIDER" in the ANSI Shadow font — the exact six-line art the
/// user picked in ~/Documents/style. Rendered verbatim: the outline frame
/// (═║╔╗╚╝) is part of the glyph layout, never trim or reflow it.
const MAIN_ART: &[&str] = &[
    " ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗██████╗ ███████╗██████╗ ",
    "██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██║██╔══██╗██╔════╝██╔══██╗",
    "██║  ███╗███████║██║   ██║███████╗   ██║       ██████╔╝██████╔╝██║   ██║██║   ██║██║██║  ██║█████╗  ██████╔╝",
    "██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔═══╝ ██╔══██║██║   ██║╚██╗ ██╔╝██║██║  ██║██╔══╝  ██╔══██╗",
    "╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║     ██║  ██║╚██████╔╝ ╚████╔╝ ██║██████╔╝███████╗██║  ██║",
    " ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
];

/// The maximum art scale: 4× turns the 108-cell ANSI Shadow banner into
/// 432 columns, which fills an ultrawide terminal; narrower terminals
/// condense the art to the window width (see `art_scale`, `shrink_art`).
const ART_MAX_SCALE: u16 = 4;

/// Repeat each art cell into an n×n block — a nearest-neighbour zoom of
/// the exact style-file bitmap: every glyph cell (═║╔╗╚╝ outline frame
/// included) simply repeats n times, so the banner grows without ever
/// changing font or shape. At 1× the art is rendered verbatim.
fn expand_art(art: &[&str], n: u16) -> Vec<String> {
    let n = n.max(1);
    if n == 1 {
        return art.iter().map(|l| l.to_string()).collect();
    }
    let n = n as usize;
    let mut out = Vec::with_capacity(art.len() * n);
    for line in art {
        for _sub in 0..n {
            let scaled: String = line
                .chars()
                .flat_map(|c| std::iter::repeat_n(c, n))
                .collect();
            out.push(scaled);
        }
    }
    out
}

/// Condense the art to `dst_w` columns as a nearest-neighbour resample
/// of the same bitmap, width-only: every output cell COPIES one source
/// cell from the centre of its column span, and every glyph row is
/// kept — the letterforms and the outline frame (═║╔╗╚╝) stay the
/// same font, merely narrower. No pooling, no re-drawing, no
/// plain-text fallback, never a different typeface.
fn shrink_art(art: &[&str], dst_w: u16) -> Vec<String> {
    let src_w = art[0].chars().count();
    let dst_w = (dst_w as usize).clamp(1, src_w);
    let grid: Vec<Vec<char>> = art.iter().map(|l| l.chars().collect()).collect();
    grid.iter()
        .map(|row| {
            (0..dst_w)
                .map(|c| {
                    let sx = ((2 * c + 1) * src_w / (2 * dst_w)).min(src_w - 1);
                    row[sx]
                })
                .collect()
        })
        .collect()
}

/// Largest scale (1..=ART_MAX_SCALE) whose art fits the terminal both
/// ways: width must hold `108 × n`, and height must hold the whole
/// composition (art 6n + subtitle 3 + gap/menu 2+8 + gap/description
/// 2). The layout itself never changes with the window.
fn art_scale(area: ratatui::prelude::Rect) -> u16 {
    let base_w = MAIN_ART[0].chars().count() as u16;
    let mut n = (area.width / base_w).clamp(1, ART_MAX_SCALE);
    let content_h = |n: u16| MAIN_ART.len() as u16 * n + 3 + 2 + MAIN_MENU.len() as u16 + 2;
    while n > 1 && content_h(n) > area.height {
        n -= 1;
    }
    n
}

// Hard bound on the deploy log held in memory. A heavy build (a SvelteKit +
// wasm app, a large Python project) can emit tens of thousands of lines; the
// deploy screen re-wraps the entire buffer every ~80ms tick, so unbounded
// growth turns each frame into O(n) work and the TUI freezes. We keep only
// the newest tail — the screen shows the latest output, which is what a user
// watching a build wants — and drop the prefix once the cap is exceeded.
//
// The cap is chosen generously (a tall terminal re-renders ~thousands of
// wrapped lines at worst), high enough to never lose the meaningful build log
// but low enough to keep frames cheap on the widest builds.
const MAX_DEPLOY_LINES: usize = 2000;

/// Push one log line onto the bounded deploy buffer, trimming the oldest
/// lines once the cap is exceeded so the screen stays responsive on very
/// long builds.
fn push_deploy_line(lines: &mut Vec<String>, line: String) {
    lines.push(line);
    if lines.len() > MAX_DEPLOY_LINES {
        let overflow = lines.len() - MAX_DEPLOY_LINES;
        lines.drain(0..overflow);
    }
}

/// Once a deploy finishes, its output is compressed to the lines that matter:
/// warnings, verdicts, sandbox/provision notes and the reachable URL. The
/// full log already streamed past the user as it happened; keeping a compact
/// tail makes the finished state last, which is exactly what a brittle
/// terminal wants to preserve.
///
/// A failed deploy keeps one more thing: everything from the last `! …`
/// report to the end — that block IS the reason, and dropping it (which this
/// compression used to do) leaves the user staring at "deployment failed"
/// with no cause on screen.
fn compress_done(lines: &mut Vec<String>, ok: bool) {
    let failure_from = if ok {
        usize::MAX
    } else {
        lines
            .iter()
            .rposition(|l| l.trim_start().starts_with('!'))
            .unwrap_or(usize::MAX)
    };
    let mut kept: Vec<String> = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        let verdict = t.starts_with('!')
            || t.starts_with("warn: ")
            || t.starts_with("sandbox: ")
            || t.starts_with("provision: ")
            || t.starts_with("✔")
            || t.contains("listening on ")
            || t.contains("deployment failed")
            || t.is_empty();
        if i >= failure_from || verdict {
            kept.push(l.clone());
        }
    }
    *lines = kept;
}

pub(crate) enum Screen {
    Main {
        selected: usize,
    },
    Scan {
        report: Option<String>,
        running: bool,
        /// Generation of the scan this screen is waiting for. A late
        /// ScanDone from an abandoned run (user left and re-entered) carries
        /// a stale seq and is dropped instead of overwriting fresh data.
        seq: u64,
    },
    UrlInput {
        buffer: String,
        error: Option<String>,
        busy: bool,
    },
    /// YES/NO gate before hosting a service (see README "Security model").
    /// The target is either a GitHub URL (routes to stack detection — the
    /// wizard review, nothing deployed) or a local `service.yaml` manifest
    /// the user pointed at (deploys).
    Confirm {
        target: workers::DeployTarget,
        /// Which button the arrow keys currently highlight.
        yes_selected: bool,
    },
    Deploy {
        lines: Vec<String>,
        done: Option<bool>,
    },
    Services {
        rows: Vec<workers::ServiceRow>,
        selected: usize,
        message: Option<String>,
    },
    /// YES/NO gate before removing a service (unit, clone, caches).
    ConfirmDelete {
        name: String,
        /// Which button the arrow keys currently highlight (defaults to No).
        yes_selected: bool,
    },
    Logs {
        view: LogView,
        deploy_lines: Vec<String>,
        software_lines: Vec<String>,
        crash_lines: Vec<String>,
        scroll: usize,
    },
    /// YES/NO gate before clearing logs (deploy file + buffer, software buffer,
    /// or crash history file).
    ConfirmClear {
        target: LogView,
        yes_selected: bool,
    },
    /// Manifest library (menu "Add Service"): imported `service.yaml` files.
    AddService {
        files: Vec<crate::hoster::library::LibraryEntry>,
        selected: usize,
        message: Option<String>,
        /// Armed delete: first `d` arms for this id, second `d` deletes it.
        armed_delete: Option<String>,
    },
    /// Import prompt: path to a `service.yaml` file to copy into the library.
    Import {
        buffer: String,
        error: Option<String>,
    },
    /// Detect prompt: GitHub URL to clone shallowly and detect the stack
    /// for. The worker reports back via `Msg::DetectDone`; leaving the
    /// screen meanwhile drops the stale result.
    DetectInput {
        buffer: String,
        error: Option<String>,
        busy: bool,
    },
    /// New-service wizard: one question per screen, "Step n/9" in the title.
    /// Each screen carries the [`wizard::Draft`] built so far; Esc walks back.
    WzId {
        buffer: String,
        error: Option<String>,
        draft: wizard::Draft,
    },
    WzGit {
        buffer: String,
        error: Option<String>,
        draft: wizard::Draft,
    },
    WzCommit {
        buffer: String,
        error: Option<String>,
        draft: wizard::Draft,
    },
    WzProfile {
        selected: usize,
        draft: wizard::Draft,
    },
    WzPrefetch {
        editor: wizard::StepEditor,
        draft: wizard::Draft,
    },
    WzBuild {
        editor: wizard::StepEditor,
        draft: wizard::Draft,
    },
    WzRun {
        cmd: String,
        port: String,
        /// Tab switches between the two fields.
        focus_port: bool,
        error: Option<String>,
        draft: wizard::Draft,
    },
    WzRes {
        memory: String,
        tasks: String,
        /// Tab switches between the two fields.
        focus_tasks: bool,
        error: Option<String>,
        draft: wizard::Draft,
    },
    WzReview {
        draft: wizard::Draft,
        /// Rendered YAML, or None when the draft does not validate (error set).
        yaml: Option<String>,
        error: Option<String>,
    },
    /// Egress matrix (menu "Egress"): every library service with its allow
    /// list, deploy mark, traffic counters and last verification verdict.
    Egress {
        files: Vec<crate::hoster::library::LibraryEntry>,
        deployed: Vec<String>,
        /// (unit, out_bytes, in_bytes) for deployed units with accounting.
        counters: HashMap<String, (u64, u64)>,
        /// Latest verification verdicts by service id (this view only).
        verdicts: HashMap<String, String>,
        /// Service id a verification worker is running for right now.
        checking: Option<String>,
        selected: usize,
        message: Option<String>,
    },
    /// Allow-list editor for one library service: add/delete hostnames,
    /// saved validated on every change (applies on next deploy).
    EgressHosts {
        id: String,
        hosts: Vec<String>,
        selected: usize,
        buffer: String,
        editing: bool,
        armed: bool,
        error: Option<String>,
        message: Option<String>,
    },
    /// Overview of the user's own added services (menu "My Services"): the
    /// manifest library annotated with deploy status. Read-mostly: Enter
    /// deploys (or jumps to Self-Hosting when already deployed); managing
    /// (import/delete) stays in Add Service.
    UserServices {
        files: Vec<crate::hoster::library::LibraryEntry>,
        /// Ids currently deployed (from state.json), for the ●/○ marks.
        deployed: Vec<String>,
        selected: usize,
        message: Option<String>,
    },
    /// Deployed services ready for in-place manifest edits (menu
    /// "Edit Service"): every id from state.json annotated with the library
    /// manifest behind it — pick one to edit name, commit, port, limits.
    EditService {
        rows: Vec<EditRow>,
        selected: usize,
        message: Option<String>,
    },
    /// Field editor for one deployed manifest. Row order is [`EDIT_FIELDS`];
    /// Enter edits the selected row inline (seeded with its value), Enter
    /// commits it through the field check, `s` saves the whole manifest, `r`
    /// saves and redeploys, `e` opens the raw yaml in $EDITOR for everything
    /// beyond the six rows.
    EditServiceForm {
        id: String,
        fields: Vec<String>,
        sel: usize,
        buffer: String,
        editing: bool,
        error: Option<String>,
        message: Option<String>,
    },
    /// Public sharing via Cloudflare Quick Tunnel (`Networks` menu).
    Networks {
        rows: Vec<crate::networks::supervisor::NetworkRow>,
        selected: usize,
        message: Option<String>,
    },
}

/// One Edit Service list row: a deployed id with its live URL and the
/// library manifest behind it (`None` = deployed some other way, e.g. an
/// external path — such units cannot be edited here).
pub(crate) struct EditRow {
    pub id: String,
    /// `service.name` from the manifest, falling back to the id.
    pub name: String,
    pub url: String,
    pub path: Option<std::path::PathBuf>,
    /// The manifest file exists and parses.
    pub valid: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LogView {
    Deploy,
    Software,
    Crash,
}

/// Logs tab order: Deploy → Software → Crash → Deploy (Tab/→), reverse on ←.
fn logs_tab_next(view: LogView) -> LogView {
    match view {
        LogView::Deploy => LogView::Software,
        LogView::Software => LogView::Crash,
        LogView::Crash => LogView::Deploy,
    }
}

fn logs_tab_prev(view: LogView) -> LogView {
    match view {
        LogView::Deploy => LogView::Crash,
        LogView::Software => LogView::Deploy,
        LogView::Crash => LogView::Software,
    }
}

pub(crate) enum Msg {
    Log(String),
    ScanDone(u64, String),
    DeployDone(bool),
    SoftwareLog(String),
    TailLog(String),
    CrashLog(String),
    DeployLogsCleared,
    SoftwareLogsCleared,
    CrashLogsCleared,
    /// Stack detection finished (URL input → autopilot or wizard, Add
    /// Service → Detect): prefilled wizard draft on success, human-readable
    /// reason on failure, plus where the result must go. Boxed — the draft
    /// keeps `Msg` small (channel-backed enum).
    DetectDone {
        res: Result<Box<workers::DetectReady>, String>,
        route: workers::DetectRoute,
    },
    /// Egress live-check finished for one library service: rendered lines.
    EgressChecked {
        id: String,
        lines: Vec<String>,
    },
    /// Shutdown requested by a termination signal (SIGTERM/SIGHUP).
    Terminate,
}

pub(crate) struct App {
    pub screen: Screen,
    pub rx: Receiver<Msg>,
    pub tx: Sender<Msg>,
    /// Drives animations; incremented every loop iteration (~80ms).
    pub tick: u64,
    /// Incremented on every System Scan request; identifies the run.
    pub scan_seq: u64,
    pub deploy_history: Vec<String>,
    pub software_history: Vec<String>,
    pub crash_history: Vec<String>,
    deploy_tail_keep: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    software_tail_keep: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    crash_tail_keep: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Cleanup notices collected on early exit, printed after the terminal is
    /// restored so the user sees what was cleaned up.
    exit_notices: Vec<String>,
}

/// Progress counter for the stall watchdog: bumped once per event-loop
/// iteration. The loop wedges forever inside crossterm when the terminal
/// vanishes (see `tty_hangup`), and a wedged loop never drains the channel —
/// the watchdog thread is the only thing that can still notice and exit.
static LOOP_TICKS: AtomicU64 = AtomicU64::new(0);
/// Set while the loop is *legitimately* blocked (external $EDITOR session,
/// shutdown reconcile): the watchdog must not treat those as a stall.
static WATCHDOG_PAUSE: AtomicBool = AtomicBool::new(false);

/// Two consecutive frozen heartbeat windows fire the stall exit. Paused
/// windows re-baseline instead, so long legitimate blocks never trip it.
struct StallWatchdog {
    last: u64,
}

impl StallWatchdog {
    fn new() -> Self {
        Self { last: 0 }
    }

    /// Feed one heartbeat sample; true = the loop stalled, kill the process.
    /// Ticks of 0 are exempt: the very first iteration can sit in a 2s
    /// cursor-query wait (unanswered DSR), which is boot, not a stall.
    fn watch(&mut self, now: u64, paused: bool) -> bool {
        if paused || now == 0 {
            self.last = now;
            return false;
        }
        let fired = now == self.last;
        self.last = now;
        fired
    }
}

/// Entry point: sets up the terminal, runs the loop, restores the terminal.
pub fn run() -> anyhow::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // Best-effort: the first draw repaints everything anyway, so a slow
    // terminal answering the clear's cursor query late must not abort startup.
    clear_screen(&mut terminal);

    let (tx, rx) = mpsc::channel();
    // Termination signals (kill, terminal closed) are routed through the event
    // loop so the in-flight deploy (if any) gets its clean removal and the
    // terminal is restored, instead of the process just being dropped.
    let sig_tx = tx.clone();
    if let Ok(mut signals) = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGINT,
    ]) {
        std::thread::spawn(move || {
            // Consume one signal, ask the loop to shut down, then restore
            // default dispositions so a follow-up signal kills us normally.
            if signals.forever().next().is_some() {
                let _ = sig_tx.send(Msg::Terminate);
            }
        });
    }
    // Last-resort net: if the loop stops heartbeating (crossterm wedged on a
    // vanished tty — its read retries EIO forever, so Terminate is never
    // drained), restore what we can and die instead of pegging a core.
    std::thread::spawn(|| {
        let mut watchdog = StallWatchdog::new();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let ticks = LOOP_TICKS.load(Ordering::Relaxed);
            let paused = WATCHDOG_PAUSE.load(Ordering::Relaxed);
            if watchdog.watch(ticks, paused) {
                let _ = crossterm::terminal::disable_raw_mode();
                let _ = io::stdout().execute(crossterm::terminal::LeaveAlternateScreen);
                eprintln!("ghostprovider: event loop stalled (terminal gone?) — exiting");
                std::process::exit(1);
            }
        }
    });
    let mut app = App {
        screen: Screen::Main { selected: 0 },
        rx,
        tx,
        tick: 0,
        scan_seq: 0,
        deploy_history: Vec::new(),
        software_history: Vec::new(),
        crash_history: Vec::new(),
        deploy_tail_keep: None,
        software_tail_keep: None,
        crash_tail_keep: None,
        exit_notices: Vec::new(),
    };
    // A stale build that re-exec'ed here left its action in the handover
    // file: resume it before the first frame draws.
    resume_pending_action(&mut app);
    let res = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    for m in &app.exit_notices {
        if crate::tui::workers::stderr_capture_active() {
            // The deploy worker is still winding down with fd 2 rerouted into
            // deploy.log; printing now would round-trip these notices back
            // into the log a second time. They were already written there by
            // reconcile, so skip them.
            continue;
        }
        eprintln!("{m}");
    }
    res
}

/// True when there is no controlling terminal at all (nohup'd run, broken
/// session): /dev/tty fails to open. Note the *deleted pty* case does NOT
/// trip this — Linux keeps the ctty object openable while a session holds
/// it — that case wedges crossterm's read and is caught by the stall
/// watchdog instead.
fn tty_hangup() -> bool {
    std::fs::File::open("/dev/tty").is_err()
}

/// Minimum gap between expensive full repaints while the window is being
/// resized. Dragging an edge emits dozens of Resize events per second; the
/// 80ms draw loop already picks up the new size via autoresize, so one full
/// repaint per window is enough to drop stale glyphs.
const RESIZE_REPAINT_DEBOUNCE: Duration = Duration::from_millis(150);

/// Window below which the header/body/hint layout cannot breathe: render a
/// short notice instead of squeezing widgets into nothing.
const MIN_TERM_WIDTH: u16 = 30;
const MIN_TERM_HEIGHT: u16 = 8;

/// Best-effort full repaint. `Terminal::clear()` issues a cursor-position
/// (DSR) query over stdin; during resize storms the reply is routinely eaten
/// by the concurrent event reader and crossterm times out with "The cursor
/// position could not be read within a normal duration". That failure is
/// transient — the next repaint retries — so it must never kill the panel.
fn clear_screen(terminal: &mut Terminal<CrosstermBackend<Stdout>>) {
    let _ = terminal.clear();
}

/// True when a resize-driven full repaint is due: no repaint yet this run,
/// or the last one is older than the debounce window.
fn resize_repaint_due(last: Option<Instant>, now: Instant) -> bool {
    match last {
        None => true,
        Some(t) => now.duration_since(t) >= RESIZE_REPAINT_DEBOUNCE,
    }
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    // Last full repaint time (None = none yet this run).
    let mut last_repaint: Option<Instant> = None;
    loop {
        // The terminal may have vanished under us; entering crossterm's read
        // path on a dead tty pegs the CPU forever (see `tty_hangup`).
        if tty_hangup() {
            return exit_with_reconcile(app);
        }
        while let Ok(msg) = app.rx.try_recv() {
            match msg {
                Msg::ScanDone(seq, report) => {
                    if let Screen::Scan {
                        report: r,
                        running,
                        seq: cur,
                    } = &mut app.screen
                        && *cur == seq
                    {
                        *r = Some(report);
                        *running = false;
                    }
                }
                Msg::Log(line) => {
                    // deploy_history is the file's mirror when a tail is active —
                    // don't double-count the same line (Log + TailLog).
                    let tail_active = app.deploy_tail_keep.is_some();
                    if !tail_active {
                        for l in line.split('\n') {
                            push_deploy_line(&mut app.deploy_history, l.to_string());
                        }
                    }
                    if let Screen::Deploy { lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(lines, l.to_string());
                        }
                    }
                    // Logs → Deploy is file-tailed (TailLog), never fed from the
                    // in-process deploy channel — otherwise the deploying window
                    // would duplicate and other windows would never see it.
                }
                Msg::TailLog(line) => {
                    for l in line.split('\n') {
                        push_deploy_line(&mut app.deploy_history, l.to_string());
                    }
                    if let Screen::Logs { deploy_lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(deploy_lines, l.to_string());
                        }
                    }
                }
                Msg::DeployDone(ok) => {
                    if app.deploy_tail_keep.is_none() {
                        let l = format!("deploy done: {}", if ok { "ok" } else { "failed" });
                        push_deploy_line(&mut app.deploy_history, l);
                    }
                    if let Screen::Deploy { lines, done } = &mut app.screen {
                        // The reachable URL is already in the log ("✔ listening
                        // on …"); keep the final verdict laconic and only add a
                        // line when the deploy did NOT surface a URL.
                        if !ok {
                            push_deploy_line(lines, "deployment failed".into());
                        }
                        compress_done(lines, ok);
                        *done = Some(ok);
                    }
                    // Logs deploy view is file-tailed; file already contains "== deploy done ==".
                }
                Msg::SoftwareLog(line) => {
                    for l in line.split('\n') {
                        push_deploy_line(&mut app.software_history, l.to_string());
                    }
                    if let Screen::Logs { software_lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(software_lines, l.to_string());
                        }
                    }
                }
                Msg::DeployLogsCleared => {
                    app.deploy_history.clear();
                    if let Screen::Logs {
                        deploy_lines,
                        scroll,
                        ..
                    } = &mut app.screen
                    {
                        deploy_lines.clear();
                        deploy_lines.push("Logs cleared.".into());
                        *scroll = 0;
                    }
                }
                Msg::SoftwareLogsCleared => {
                    app.software_history.clear();
                    if let Screen::Logs {
                        software_lines,
                        scroll,
                        ..
                    } = &mut app.screen
                    {
                        software_lines.clear();
                        software_lines.push("Logs cleared.".into());
                        *scroll = 0;
                    }
                }
                Msg::CrashLog(line) => {
                    for l in line.split('\n') {
                        push_deploy_line(&mut app.crash_history, l.to_string());
                    }
                    if let Screen::Logs { crash_lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(crash_lines, l.to_string());
                        }
                    }
                }
                Msg::CrashLogsCleared => {
                    app.crash_history.clear();
                    if let Screen::Logs {
                        crash_lines,
                        scroll,
                        ..
                    } = &mut app.screen
                    {
                        crash_lines.clear();
                        crash_lines.push("Logs cleared.".into());
                        *scroll = 0;
                    }
                }
                Msg::DetectDone { res, route } => {
                    // Apply only while the Detect screen is still open: Esc
                    // meanwhile means the user cancelled — drop the stale result.
                    if matches!(app.screen, Screen::DetectInput { .. }) {
                        match res {
                            Ok(ready) => {
                                let mut ready = *ready;
                                match route {
                                    workers::DetectRoute::Wizard => {
                                        app.screen = Screen::WzId {
                                            buffer: ready.suggested_id,
                                            error: None,
                                            draft: ready.draft,
                                        };
                                    }
                                    workers::DetectRoute::Auto => {
                                        // Autopilot only when the detection is
                                        // both confident (the repo declared its
                                        // run command) and clean (no warn notes,
                                        // e.g. a shipped placeholder secret the
                                        // app will refuse to boot with). A known
                                        // problem goes to the wizard for review.
                                        let warned = ready
                                            .draft
                                            .notes
                                            .iter()
                                            .any(|n| n.starts_with("warn: "));
                                        if ready.confident && !warned {
                                            match auto_store(&mut ready.draft, &ready.suggested_id)
                                            {
                                                Ok(target) => start_deploy_screen(app, target),
                                                // Manifest would not validate:
                                                // open the wizard on the same
                                                // draft with the reason, so the
                                                // user fixes exactly what failed.
                                                Err(e) => {
                                                    app.screen = Screen::WzId {
                                                        buffer: ready.suggested_id,
                                                        error: Some(e),
                                                        draft: ready.draft,
                                                    }
                                                }
                                            }
                                        } else {
                                            // Nothing declared how this app runs,
                                            // or its config ships a placeholder
                                            // secret: never deploy that silently —
                                            // open the wizard so the user reviews
                                            // and confirms.
                                            if !ready.confident {
                                                ready.draft.notes.insert(
                                                    0,
                                                    "detected by guessing — review before deploying"
                                                        .into(),
                                                );
                                            }
                                            app.screen = Screen::WzId {
                                                buffer: ready.suggested_id,
                                                error: None,
                                                draft: ready.draft,
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if let Screen::DetectInput { error, busy, .. } = &mut app.screen {
                                    *error = Some(e);
                                    *busy = false;
                                }
                            }
                        }
                    }
                }
                Msg::EgressChecked { id, lines } => {
                    // Apply only while the matrix is still open; the verdict
                    // text joins with newlines for the row detail.
                    if let Screen::Egress {
                        verdicts,
                        checking,
                        message,
                        ..
                    } = &mut app.screen
                    {
                        verdicts.insert(id.clone(), lines.join("\n"));
                        if checking.as_deref() == Some(id.as_str()) {
                            *checking = None;
                        }
                        *message = Some(format!("checked {id}"));
                    }
                }
                Msg::Terminate => {
                    // Termination signal: leave exactly like a deliberate exit.
                    return exit_with_reconcile(app);
                }
            }
        }

        if app.tick.is_multiple_of(12)
            && let Screen::Networks { rows, selected, .. } = &mut app.screen
        {
            let fresh = crate::networks::supervisor::rows();
            if *selected >= fresh.len() && !fresh.is_empty() {
                *selected = fresh.len().saturating_sub(1);
            }
            *rows = fresh;
        }

        // Self-heal: any stray glyph left by terminal desync (resize races,
        // tmux quirks, font-width lies) must not outlive ~2s — force a full
        // repaint periodically instead of trusting cell-diff forever.
        // Best-effort: a failed repaint is retried on the next pass.
        if app.tick.is_multiple_of(25) {
            clear_screen(terminal);
            last_repaint = Some(Instant::now());
        }
        terminal.draw(|f| draw(f, app))?;
        app.tick = app.tick.wrapping_add(1);

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        let before = std::mem::discriminant(&app.screen);
                        match on_key(app, key.code, key.modifiers) {
                            Flow::Continue => {}
                            Flow::Exit => return exit_with_reconcile(app),
                            Flow::EditFile(path) => {
                                WATCHDOG_PAUSE.store(true, Ordering::Relaxed);
                                edit_file_suspended(terminal, app, &path);
                                WATCHDOG_PAUSE.store(false, Ordering::Relaxed);
                                // Prove progress immediately: the resume must
                                // not race the watchdog's next sample.
                                LOOP_TICKS.fetch_add(1, Ordering::Relaxed);
                                last_repaint = Some(Instant::now());
                            }
                        }
                        // Screen switched: ratatui's cell-diff would keep glyphs
                        // from the longer previous screen — force a full repaint.
                        if std::mem::discriminant(&app.screen) != before {
                            clear_screen(terminal);
                            last_repaint = Some(Instant::now());
                        }
                    }
                }
                Event::Resize(_, _) if resize_repaint_due(last_repaint, Instant::now()) => {
                    clear_screen(terminal);
                    last_repaint = Some(Instant::now());
                }
                _ => {}
            }
        }
        LOOP_TICKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Progress of one editor interaction: used by both step-list screens.
#[derive(Debug, PartialEq, Eq)]
enum WzStepsFlow {
    Next,
    Back,
    Stay,
}

/// Shared keys for the prefetch/build step editors: Enter/Tab = next screen
/// (same contract as every other wizard step — Enter must never look dead),
/// `e` inline-edits the selected line (Enter confirms, Esc cancels inside),
/// a/d add/delete lines, Esc/q = back. The draft is untouched until the
/// screen is left (lines are taken, never borrowed out).
fn wz_steps_key(editor: &mut wizard::StepEditor, key: KeyCode, cmd: Option<char>) -> WzStepsFlow {
    use WzStepsFlow as Flow;
    if editor.editing.is_some() {
        match key {
            KeyCode::Char(c) => {
                if let Some(buf) = editor.editing.as_mut() {
                    buf.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(buf) = editor.editing.as_mut() {
                    buf.pop();
                }
            }
            KeyCode::Enter => editor.commit_edit(),
            KeyCode::Esc => editor.cancel_edit(),
            _ => {}
        }
        return Flow::Stay;
    }
    match key {
        KeyCode::Up => editor.move_up(),
        KeyCode::Down => editor.move_down(),
        KeyCode::Tab | KeyCode::Enter => return Flow::Next,
        KeyCode::Esc => return Flow::Back,
        _ => match cmd {
            Some('k') => editor.move_up(),
            Some('j') => editor.move_down(),
            Some('e') => editor.start_edit(),
            Some('a') => editor.add_line(),
            Some('d') => editor.delete_line(),
            Some('q') => return Flow::Back,
            _ => {}
        },
    }
    Flow::Stay
}

enum Flow {
    Continue,
    Exit,
    /// Open a stored manifest in $EDITOR: the panel suspends (raw mode off,
    /// alternate screen left), the edit runs on the real terminal, then the
    /// panel resumes. Handled in `event_loop`, which owns the terminal.
    EditFile(PathBuf),
}

/// Positional mapping national-layout → QWERTY for *command* keys only.
/// Free-text input (the URL field) always receives the raw character.
const LAYOUT_MAP: &[(char, char)] = &[
    // Russian ЙЦУКЕН
    ('й', 'q'),
    ('ц', 'w'),
    ('у', 'e'),
    ('к', 'r'),
    ('е', 't'),
    ('н', 'y'),
    ('г', 'u'),
    ('ш', 'i'),
    ('щ', 'o'),
    ('з', 'p'),
    ('ф', 'a'),
    ('ы', 's'),
    ('в', 'd'),
    ('а', 'f'),
    ('п', 'g'),
    ('р', 'h'),
    ('о', 'j'),
    ('л', 'k'),
    ('д', 'l'),
    ('я', 'z'),
    ('ч', 'x'),
    ('с', 'c'),
    ('м', 'v'),
    ('и', 'b'),
    ('т', 'n'),
    ('ь', 'm'),
];

/// Normalize a key event to the QWERTY command letter it represents,
/// regardless of the active keyboard layout. Uppercase is folded; ASCII
/// passes through unchanged. Characters without a positional counterpart
/// (digits, punctuation, unmapped letters) yield None so they never fire
/// a command by accident.
fn command_char(key: KeyCode) -> Option<char> {
    let c = match key {
        KeyCode::Char(c) => c,
        _ => return None,
    };
    let lower = c.to_lowercase().next().unwrap_or(c);
    if lower.is_ascii() {
        return Some(lower);
    }
    LAYOUT_MAP
        .iter()
        .find(|(nat, _)| *nat == lower)
        .map(|(_, lat)| *lat)
}

/// Leave the loop after cleaning up anything a still-in-flight deploy left
/// behind. A deploy worker runs as a thread in this process, so on a graceful
/// exit it must be stopped *first*: [`crate::hoster::deploy::quiesce`] kills its
/// host-side descendants (a running `git clone`/build step) and stops its
/// `ghost-*` transient build units, then waits for the worker to unwind.
/// Otherwise the worker could re-create artifacts after the cleanup and leave
/// permanent junk. Once it has unwound, reconcile with `keep_if_inflight =
/// false` so the entry is *settled now* — the clone/build tree (the whole
/// `services/<name>` folder) is wiped and the journal entry removed, rather than
/// deferred to the next launch. Safe to call when no deploy is running —
/// `reconcile_stale_locked` is a no-op then.
fn exit_with_reconcile(app: &mut App) -> anyhow::Result<()> {
    crate::networks::supervisor::stop_all();
    // Reconcile may run systemctl commands for seconds — tell the stall
    // watchdog this block is legitimate (see `WATCHDOG_PAUSE`).
    WATCHDOG_PAUSE.store(true, Ordering::Relaxed);
    // A just-spawned worker may not have set `deploy_in_flight` yet; the Deploy
    // screen (still `done: None`) is the reliable "a worker exists" signal, and
    // it is set by the UI thread before any exit key can be read. Asking for an
    // exit first makes even a worker that starts mid-exit abort before its
    // first clone (see the race guard in `run_manifest_deployment`).
    let worker_live = crate::hoster::deploy::deploy_in_flight()
        || matches!(app.screen, Screen::Deploy { done: None, .. });
    // Captured before the reconcile settles the journal, so the terminal
    // "done: interrupted" marker below still has the URL to print.
    let in_flight_url = worker_live.then(crate::hoster::deploy::in_flight_url);
    if worker_live {
        crate::hoster::cancel::request_exit();
        crate::hoster::deploy::quiesce(std::time::Duration::from_secs(3));
        // `quiesce` returns the moment the in-flight flag clears, which is
        // just before the worker's final bookkeeping. Wait for that too: the
        // trailing "== deploy … done: failed ===" line lands in the log, and
        // fd 2 is restored — otherwise the exit notices printed below would be
        // captured as "still a deploy" lines and every cleanup notice would
        // appear twice in deploy.log.
        crate::tui::workers::wait_deploy_worker(std::time::Duration::from_secs(2));
    }
    let msgs =
        crate::hoster::deploy::reconcile_stale_locked(crate::hoster::deploy::ReconcileBasis::Exit);
    app.exit_notices.extend(msgs);
    if worker_live {
        // The worker suppresses its own done line when exiting, so this is the
        // single authoritative terminal marker for an interrupted deploy.
        let url = in_flight_url
            .flatten()
            .unwrap_or_else(|| "(unknown)".into());
        crate::tui::workers::append_deploy_log(&format!("== deploy {url} done: interrupted =="));
    }
    Ok(())
}

/// Suspend the panel, edit a stored manifest in $EDITOR on the real
/// terminal, then resume with a repaint. The file is validated before it is
/// swapped (see `library::edit_in_editor`); library screens showing it are
/// refreshed and carry the one-line outcome as their message.
fn edit_file_suspended(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    path: &std::path::Path,
) {
    let id = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let _ = io::stdout().execute(LeaveAlternateScreen);
    let _ = disable_raw_mode();
    let outcome = crate::hoster::library::edit_in_editor(&id).map_err(|e| format!("{e:#}"));
    let _ = enable_raw_mode();
    let _ = io::stdout().execute(EnterAlternateScreen);
    clear_screen(terminal);
    let msg = match outcome {
        Ok(s) => s,
        Err(e) => format!("! {e}"),
    };
    match &mut app.screen {
        Screen::AddService {
            files,
            selected,
            message,
            ..
        } => {
            *files = crate::hoster::library::list();
            let last = lib_row_count(files.len()).saturating_sub(1);
            if *selected > last {
                *selected = last;
            }
            *message = Some(msg);
        }
        Screen::UserServices {
            files,
            deployed,
            selected,
            message,
        } => {
            *files = crate::hoster::library::list();
            if *selected >= files.len() {
                *selected = files.len().saturating_sub(1);
            }
            *deployed = crate::state::list()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            *message = Some(msg);
        }
        Screen::EditServiceForm {
            id,
            fields,
            sel,
            error,
            message,
            ..
        } => {
            // The external editor just rewrote the yaml: refill the rows so
            // the form shows what is actually on disk now.
            match crate::hoster::library::load(id) {
                Ok(m) => {
                    *fields = edit_fields_of(&m);
                    *error = None;
                }
                Err(e) => *error = Some(workers::short_error_for(&e)),
            }
            if *sel >= fields.len() {
                *sel = fields.len().saturating_sub(1);
            }
            *message = Some(msg);
        }
        _ => {}
    }
}

fn on_key(app: &mut App, key: KeyCode, mods: KeyModifiers) -> Flow {
    if matches!(key, KeyCode::Char('c')) && mods.contains(KeyModifiers::CONTROL) {
        return Flow::Exit;
    }
    // Main-menu activation touches app.tx and app.screen at once; decide it
    // before the screen match takes its borrow.
    if let Screen::Main { selected } = app.screen
        && matches!(key, KeyCode::Enter | KeyCode::Char(' '))
    {
        return main_menu_activate(app, selected);
    }
    let cmd = command_char(key);
    match &mut app.screen {
        Screen::Main { selected } => match key {
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => {
                move_main_selection(selected, key)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {}
            KeyCode::Esc => return Flow::Exit,
            _ => match cmd {
                Some('k') | Some('h') => *selected = selected.saturating_sub(1),
                Some('j') | Some('l') => *selected = (*selected + 1).min(MAIN_MENU.len() - 1),
                Some('q') => return Flow::Exit,
                _ => {}
            },
        },
        Screen::Scan { .. } => {
            if matches!(key, KeyCode::Esc | KeyCode::Enter) || cmd == Some('q') {
                app.screen = Screen::Main { selected: 0 };
            }
        }
        Screen::UrlInput {
            buffer,
            error,
            busy,
        } => {
            if *busy {
                return Flow::Continue;
            }
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 3 },
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter | KeyCode::Tab => {
                    if buffer.trim().is_empty() {
                        *error = Some("enter a GitHub URL or a path to service.yaml".into());
                    } else {
                        let autopilot = key == KeyCode::Enter;
                        match workers::classify_deploy_input(buffer.trim()) {
                            // URL: Enter = autopilot (detect → store manifest
                            // → deploy, no gate to click through), Tab = the
                            // same detect landing in the wizard for
                            // step-by-step review.
                            Ok(workers::DeployTarget::Detect { url, .. }) => {
                                if crate::paths::binary_is_stale() {
                                    restart_with_pending(&crate::paths::PendingAction {
                                        payload: url.clone(),
                                        route: if autopilot {
                                            crate::paths::PendingRoute::Auto
                                        } else {
                                            crate::paths::PendingRoute::Wizard
                                        },
                                    });
                                }
                                app.screen = Screen::DetectInput {
                                    buffer: url.clone(),
                                    error: None,
                                    busy: true,
                                };
                                workers::spawn_detect(
                                    app.tx.clone(),
                                    url,
                                    if autopilot {
                                        workers::DetectRoute::Auto
                                    } else {
                                        workers::DetectRoute::Wizard
                                    },
                                );
                            }
                            // A local manifest still passes the gate: hosting
                            // a file needs the explicit Yes. An outdated build
                            // opens the gate on [N]o — and a Yes restarts onto
                            // the fresh build instead of deploying old code.
                            Ok(target @ workers::DeployTarget::Manifest { .. }) => {
                                app.screen = Screen::Confirm {
                                    target,
                                    yes_selected: !crate::paths::binary_is_stale(),
                                };
                            }
                            Err(e) => *error = Some(e),
                        }
                    }
                }
                // Raw char: URLs must be typed verbatim on any layout.
                KeyCode::Char(c) => buffer.push(c),
                _ => {}
            }
        }
        Screen::Confirm {
            target,
            yes_selected,
            ..
        } => {
            let mut decision: Option<bool> = None;
            match key {
                KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                    *yes_selected = !*yes_selected;
                }
                KeyCode::Esc => decision = Some(false),
                // The ONLY committing key: Enter accepts the highlighted choice.
                KeyCode::Enter => decision = Some(*yes_selected),
                _ => match cmd {
                    // Letters only move the highlight; nothing runs without
                    // an explicit Enter.
                    Some('y') => *yes_selected = true,
                    Some('n') => *yes_selected = false,
                    _ => {}
                },
            }
            match decision {
                Some(true) => match target {
                    // Legacy gate for a URL — the input now sends URLs
                    // straight to autopilot/wizard; this arm stays reachable
                    // only through older callers and still routes to wizard
                    // detection (with the stale-restart handshake first).
                    workers::DeployTarget::Detect { url, .. } => {
                        if crate::paths::binary_is_stale() {
                            restart_with_pending(&crate::paths::PendingAction {
                                payload: url.clone(),
                                route: crate::paths::PendingRoute::Wizard,
                            });
                        }
                        let url = url.clone();
                        app.screen = Screen::DetectInput {
                            buffer: url.clone(),
                            error: None,
                            busy: true,
                        };
                        workers::spawn_detect(app.tx.clone(), url, workers::DetectRoute::Wizard);
                    }
                    manifest @ workers::DeployTarget::Manifest { .. } => {
                        // Consent was just given by this Enter: an outdated
                        // build hands the exact target to the fresh process
                        // instead of deploying old code.
                        if crate::paths::binary_is_stale() {
                            restart_with_pending(&crate::paths::PendingAction {
                                payload: manifest.back_to_input(),
                                route: crate::paths::PendingRoute::PathDeploy,
                            });
                        }
                        let owned = manifest.clone();
                        start_deploy_screen(app, owned);
                    }
                },
                // Back to the input with the URL/path preserved.
                Some(false) => {
                    app.screen = Screen::UrlInput {
                        buffer: target.back_to_input(),
                        error: None,
                        busy: false,
                    }
                }
                None => {}
            }
        }
        Screen::Deploy { .. } => {
            let finished = matches!(app.screen, Screen::Deploy { done: Some(_), .. });
            if finished && (matches!(key, KeyCode::Enter | KeyCode::Esc) || cmd == Some('q')) {
                app.screen = Screen::Main { selected: 3 };
            }
        }
        Screen::Services {
            rows,
            selected,
            message,
        } => {
            let _ = message; // status messages surface via the actions below
            let count = rows.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 2 },
                KeyCode::Up if count > 0 => *selected = selected.saturating_sub(1),
                KeyCode::Down if count > 0 => *selected = (*selected + 1).min(count - 1),
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 2 },
                    Some('k') if count > 0 => *selected = selected.saturating_sub(1),
                    Some('j') if count > 0 => *selected = (*selected + 1).min(count - 1),
                    Some('r') if count > 0 => {
                        // [r] restarts the selected service and re-reads the
                        // rows so the status shown reflects the restart.
                        // The tailscale row is read-only status: refresh it
                        // instead of acting on it.
                        let selected_row = rows.get(*selected).map(|r| (r.managed, r.name.clone()));
                        if let Some((managed, name)) = selected_row {
                            if managed {
                                let msg = workers::service_action(&name, "restart");
                                *rows = workers::service_rows();
                                *message = Some(msg);
                            } else {
                                *rows = workers::service_rows();
                                *message = Some("tailscale is not managed by the panel".into());
                            }
                        }
                    }
                    Some('r') => {
                        *rows = workers::service_rows();
                        *message = Some("refreshed".into());
                    }
                    Some(action @ ('s' | 't' | 'd')) if count > 0 => {
                        let selected_row = rows.get(*selected).map(|r| (r.managed, r.name.clone()));
                        if let Some((managed, name)) = selected_row {
                            if !managed {
                                // Read-only status row (tailscale): no
                                // systemctl actions on it, ever.
                                *rows = workers::service_rows();
                                *message = Some("tailscale is not managed by the panel".into());
                            } else {
                                match action {
                                    's' => {
                                        let msg = workers::service_action(&name, "stop");
                                        *rows = workers::service_rows();
                                        *message = Some(msg);
                                    }
                                    't' => {
                                        let msg = workers::service_action(&name, "start");
                                        *rows = workers::service_rows();
                                        *message = Some(msg);
                                    }
                                    // Deletion is destructive (unit + clone +
                                    // caches): gate it behind an explicit YES/NO
                                    // that defaults to No.
                                    _ => {
                                        app.screen = Screen::ConfirmDelete {
                                            name,
                                            yes_selected: false,
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                },
            }
        }
        Screen::ConfirmDelete { name, yes_selected } => {
            let mut decision: Option<bool> = None;
            match key {
                KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                    *yes_selected = !*yes_selected;
                }
                KeyCode::Esc => decision = Some(false),
                // The ONLY committing key: Enter accepts the highlighted choice.
                KeyCode::Enter => decision = Some(*yes_selected),
                _ => match cmd {
                    // Letters only move the highlight; nothing runs without
                    // an explicit Enter.
                    Some('y') => *yes_selected = true,
                    Some('n') => *yes_selected = false,
                    _ => {}
                },
            }
            match decision {
                Some(true) => {
                    let msg = workers::service_action(name, "delete");
                    let rows = workers::service_rows();
                    app.screen = Screen::Services {
                        rows,
                        selected: 0,
                        message: Some(msg),
                    };
                }
                Some(false) => {
                    let rows = workers::service_rows();
                    app.screen = Screen::Services {
                        rows,
                        selected: 0,
                        message: None,
                    };
                }
                None => {}
            }
        }
        Screen::Logs {
            view,
            deploy_lines,
            software_lines,
            crash_lines,
            scroll,
        } => {
            let active_lines = match view {
                LogView::Deploy => deploy_lines.len(),
                LogView::Software => software_lines.len(),
                LogView::Crash => crash_lines.len(),
            };
            let mut exit = false;
            let mut clear_target: Option<LogView> = None;
            match key {
                KeyCode::Esc | KeyCode::Enter => exit = true,
                KeyCode::Tab | KeyCode::Right => {
                    *view = logs_tab_next(*view);
                    *scroll = 0;
                }
                KeyCode::Left => {
                    *view = logs_tab_prev(*view);
                    *scroll = 0;
                }
                KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::Down => {
                    if active_lines > 0 {
                        *scroll = (*scroll + 1).min(active_lines - 1);
                    }
                }
                KeyCode::PageUp => *scroll = scroll.saturating_sub(20),
                KeyCode::PageDown => {
                    *scroll = (*scroll + 20).min(active_lines.saturating_sub(1));
                }
                KeyCode::Home => *scroll = 0,
                KeyCode::End => *scroll = active_lines.saturating_sub(1),
                _ => match cmd {
                    Some('q') => exit = true,
                    Some('d') => clear_target = Some(*view),
                    _ => {}
                },
            }
            if let Some(target) = clear_target {
                app.screen = Screen::ConfirmClear {
                    target,
                    yes_selected: false,
                };
            } else if exit {
                stop_log_tailers(app);
                app.screen = Screen::Main { selected: 8 };
            }
        }
        Screen::ConfirmClear {
            target,
            yes_selected,
        } => {
            let mut decision: Option<bool> = None;
            match key {
                KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                    *yes_selected = !*yes_selected;
                }
                KeyCode::Esc => decision = Some(false),
                KeyCode::Enter => decision = Some(*yes_selected),
                _ => match cmd {
                    Some('y') => *yes_selected = true,
                    Some('n') => *yes_selected = false,
                    _ => {}
                },
            }
            match decision {
                Some(true) => {
                    let crash_seed = if app.crash_history.is_empty() {
                        crate::crashlog::read()
                    } else {
                        app.crash_history.clone()
                    };
                    match target {
                        LogView::Deploy => {
                            workers::clear_deploy_log();
                            app.deploy_history.clear();
                            let _ = app.tx.send(Msg::DeployLogsCleared);
                            app.screen = Screen::Logs {
                                view: LogView::Deploy,
                                deploy_lines: vec!["Logs cleared.".into()],
                                software_lines: std::mem::take(&mut app.software_history),
                                crash_lines: crash_seed,
                                scroll: 0,
                            };
                            // restore software_lines if it was taken empty
                            if let Screen::Logs { software_lines, .. } = &mut app.screen
                                && software_lines.is_empty()
                            {
                                *software_lines = workers::fetch_software_logs();
                                app.software_history.clone_from(software_lines);
                            }
                        }
                        LogView::Software => {
                            app.software_history.clear();
                            let _ = app.tx.send(Msg::SoftwareLogsCleared);
                            // Re-seed deploy_lines from file so deploy view stays coherent
                            let deploy_lines = {
                                let dl = workers::read_deploy_log();
                                if dl.is_empty() {
                                    vec!["No deploy logs.".into()]
                                } else {
                                    dl
                                }
                            };
                            app.deploy_history.clone_from(&deploy_lines);
                            app.screen = Screen::Logs {
                                view: LogView::Software,
                                deploy_lines,
                                software_lines: vec!["Logs cleared.".into()],
                                crash_lines: crash_seed,
                                scroll: 0,
                            };
                        }
                        LogView::Crash => {
                            crate::crashlog::clear();
                            app.crash_history.clear();
                            let _ = app.tx.send(Msg::CrashLogsCleared);
                            let deploy_lines = {
                                let dl = workers::read_deploy_log();
                                if dl.is_empty() {
                                    vec!["No deploy logs.".into()]
                                } else {
                                    dl
                                }
                            };
                            app.deploy_history.clone_from(&deploy_lines);
                            app.screen = Screen::Logs {
                                view: LogView::Crash,
                                deploy_lines,
                                software_lines: std::mem::take(&mut app.software_history),
                                crash_lines: vec!["Logs cleared.".into()],
                                scroll: 0,
                            };
                        }
                    }
                }
                Some(false) => {
                    // back to Logs, preserve buffers
                    let deploy_lines = if app.deploy_history.is_empty() {
                        let dl = workers::read_deploy_log();
                        if dl.is_empty() {
                            vec!["No deploy logs.".into()]
                        } else {
                            dl
                        }
                    } else {
                        app.deploy_history.clone()
                    };
                    let software_lines = if app.software_history.is_empty() {
                        workers::fetch_software_logs()
                    } else {
                        app.software_history.clone()
                    };
                    let crash_lines = if app.crash_history.is_empty() {
                        crate::crashlog::read()
                    } else {
                        app.crash_history.clone()
                    };
                    app.screen = Screen::Logs {
                        view: *target,
                        deploy_lines,
                        software_lines,
                        crash_lines,
                        scroll: 0,
                    };
                }
                None => {}
            }
        }
        Screen::AddService {
            files,
            selected,
            message,
            armed_delete,
        } => {
            // Selection spans the two action rows plus the files; any
            // navigation disarms a pending delete.
            let last = lib_row_count(files.len()).saturating_sub(1);
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 4 },
                KeyCode::Up => {
                    *selected = selected.saturating_sub(1);
                    *armed_delete = None;
                }
                KeyCode::Down => {
                    *selected = (*selected + 1).min(last);
                    *armed_delete = None;
                }
                KeyCode::Enter => match lib_row(files.len(), *selected) {
                    Some(LibRow::CreateNew) => {
                        app.screen = Screen::WzId {
                            buffer: String::new(),
                            error: None,
                            draft: wizard::Draft::default(),
                        };
                    }
                    Some(LibRow::ImportFile) => {
                        app.screen = Screen::Import {
                            buffer: String::new(),
                            error: None,
                        };
                    }
                    Some(LibRow::DetectUrl) => {
                        app.screen = Screen::DetectInput {
                            buffer: String::new(),
                            error: None,
                            busy: false,
                        };
                    }
                    Some(LibRow::Entry(i)) => {
                        if let Some(f) = files.get(i) {
                            let path = f.path.display().to_string();
                            match workers::classify_deploy_input(&path) {
                                Ok(target) => {
                                    app.screen = Screen::Confirm {
                                        target,
                                        yes_selected: true,
                                    };
                                }
                                Err(e) => *message = Some(e),
                            }
                        }
                    }
                    None => {}
                },
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 4 },
                    Some('k') => {
                        *selected = selected.saturating_sub(1);
                        *armed_delete = None;
                    }
                    Some('j') => {
                        *selected = (*selected + 1).min(last);
                        *armed_delete = None;
                    }
                    Some('n') => {
                        app.screen = Screen::WzId {
                            buffer: String::new(),
                            error: None,
                            draft: wizard::Draft::default(),
                        }
                    }
                    Some('a') | Some('i') => {
                        app.screen = Screen::Import {
                            buffer: String::new(),
                            error: None,
                        }
                    }
                    Some('r') => {
                        *files = crate::hoster::library::list();
                        let last = lib_row_count(files.len()).saturating_sub(1);
                        if *selected > last {
                            *selected = last;
                        }
                        *message = Some("refreshed".into());
                    }
                    Some('e') => {
                        if let Some(LibRow::Entry(i)) = lib_row(files.len(), *selected)
                            && let Some(f) = files.get(i).cloned()
                        {
                            return Flow::EditFile(f.path);
                        }
                    }
                    Some('d') => {
                        if let Some(LibRow::Entry(i)) = lib_row(files.len(), *selected)
                            && let Some(f) = files.get(i).cloned()
                        {
                            if armed_delete.as_deref() == Some(f.id.as_str()) {
                                // A delete is complete — unit, env file,
                                // clone, registry entry and this manifest:
                                // the service disappears from Logs, Edit
                                // Service and here alike.
                                *message = Some(workers::service_action(&f.id, "delete"));
                                *armed_delete = None;
                                *files = crate::hoster::library::list();
                                let last = lib_row_count(files.len()).saturating_sub(1);
                                if *selected > last {
                                    *selected = last;
                                }
                            } else {
                                *armed_delete = Some(f.id.clone());
                                *message = Some(format!("press d again to fully delete {}", f.id));
                            }
                        }
                    }
                    _ => {}
                },
            }
        }
        Screen::Import { buffer, error } => match key {
            KeyCode::Esc => {
                app.screen = Screen::AddService {
                    files: crate::hoster::library::list(),
                    selected: 0,
                    message: None,
                    armed_delete: None,
                }
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
                if buffer.trim().is_empty() {
                    *error = Some("enter a path to service.yaml".into());
                } else {
                    let path = crate::hoster::manifest::expand_manifest_path(buffer.trim());
                    match crate::hoster::library::import(&path) {
                        Ok(id) => {
                            let files = crate::hoster::library::list();
                            // Selection space has 3 action rows on top.
                            let selected = files
                                .iter()
                                .position(|f| f.id == id)
                                .map(|i| i + 3)
                                .unwrap_or(0);
                            app.screen = Screen::AddService {
                                files,
                                selected,
                                message: Some(format!("imported {id}")),
                                armed_delete: None,
                            };
                        }
                        Err(e) => *error = Some(workers::short_error_for(&e)),
                    }
                }
            }
            // Raw char: paths must be typed verbatim on any layout.
            KeyCode::Char(c) => buffer.push(c),
            _ => {}
        },
        Screen::DetectInput {
            buffer,
            error,
            busy,
        } => match key {
            KeyCode::Esc => {
                app.screen = Screen::AddService {
                    files: crate::hoster::library::list(),
                    selected: 0,
                    message: None,
                    armed_delete: None,
                }
            }
            _ if *busy => {}
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
                if buffer.trim().is_empty() {
                    *error = Some("enter a GitHub URL to detect".into());
                } else if crate::hoster::github::parse_github_url(buffer.trim()).is_none() {
                    *error =
                        Some("must be https://github.com/<owner>/<repo> (optional .git)".into());
                } else {
                    *error = None;
                    *busy = true;
                    workers::spawn_detect(
                        app.tx.clone(),
                        buffer.trim().to_string(),
                        workers::DetectRoute::Wizard,
                    );
                }
            }
            // Raw char: URLs must be typed verbatim on any layout.
            KeyCode::Char(c) => buffer.push(c),
            _ => {}
        },
        Screen::UserServices {
            files,
            deployed,
            selected,
            message,
        } => {
            let count = files.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 5 },
                KeyCode::Up if count > 0 => {
                    *selected = selected.saturating_sub(1);
                }
                KeyCode::Down if count > 0 => {
                    *selected = (*selected + 1).min(count - 1);
                }
                KeyCode::Enter if count > 0 => {
                    if let Some(f) = files.get(*selected) {
                        if !f.valid {
                            *message = f
                                .error
                                .clone()
                                .map(|e| format!("invalid manifest: {e}"))
                                .or_else(|| Some("invalid manifest".into()));
                        } else if deployed.iter().any(|d| d == &f.id) {
                            // Already deployed: jump to Self-Hosting with the
                            // cursor on this unit instead of redeploying.
                            let rows = workers::service_rows();
                            let at = rows.iter().position(|row| row.name == f.id).unwrap_or(0);
                            app.screen = Screen::Services {
                                rows,
                                selected: at,
                                message: None,
                            };
                        } else {
                            let path = f.path.display().to_string();
                            match workers::classify_deploy_input(&path) {
                                Ok(target) => {
                                    app.screen = Screen::Confirm {
                                        target,
                                        yes_selected: true,
                                    };
                                }
                                Err(e) => *message = Some(e),
                            }
                        }
                    }
                }
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 5 },
                    Some('k') if count > 0 => {
                        *selected = selected.saturating_sub(1);
                    }
                    Some('j') if count > 0 => {
                        *selected = (*selected + 1).min(count - 1);
                    }
                    Some('r') => {
                        *files = crate::hoster::library::list();
                        if *selected >= files.len() {
                            *selected = files.len().saturating_sub(1);
                        }
                        *deployed = crate::state::list()
                            .into_iter()
                            .map(|(name, _)| name)
                            .collect();
                        *message = Some("refreshed".into());
                    }
                    Some('e') if count > 0 => {
                        if let Some(f) = files.get(*selected).cloned() {
                            return Flow::EditFile(f.path);
                        }
                    }
                    _ => {}
                },
            }
        }
        Screen::EditService {
            rows,
            selected,
            message,
        } => {
            let count = rows.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 6 },
                KeyCode::Up if count > 0 => {
                    *selected = selected.saturating_sub(1);
                }
                KeyCode::Down if count > 0 => {
                    *selected = (*selected + 1).min(count - 1);
                }
                KeyCode::Enter if count > 0 => {
                    if let Some(row) = rows.get(*selected) {
                        match row.path.as_ref() {
                            None => {
                                *message = Some(format!(
                                    "{} has no library manifest — import it via Add Service",
                                    row.id
                                ))
                            }
                            Some(_) => match crate::hoster::library::load(&row.id) {
                                Ok(m) => {
                                    app.screen = Screen::EditServiceForm {
                                        id: row.id.clone(),
                                        fields: edit_fields_of(&m),
                                        sel: 0,
                                        buffer: String::new(),
                                        editing: false,
                                        error: None,
                                        message: None,
                                    };
                                }
                                Err(e) => *message = Some(workers::short_error_for(&e)),
                            },
                        }
                    }
                }
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 6 },
                    Some('k') if count > 0 => {
                        *selected = selected.saturating_sub(1);
                    }
                    Some('j') if count > 0 => {
                        *selected = (*selected + 1).min(count - 1);
                    }
                    Some('r') => {
                        *rows = edit_service_rows();
                        if *selected >= rows.len() {
                            *selected = rows.len().saturating_sub(1);
                        }
                        *message = Some("refreshed".into());
                    }
                    _ => {}
                },
            }
        }
        Screen::EditServiceForm {
            id,
            fields,
            sel,
            buffer,
            editing,
            error,
            message,
        } => match key {
            KeyCode::Esc if *editing => {
                *editing = false;
                *error = None;
            }
            KeyCode::Esc => {
                let rows = edit_service_rows();
                let at = rows.iter().position(|r| r.id == *id).unwrap_or(0);
                app.screen = Screen::EditService {
                    rows,
                    selected: at,
                    message: None,
                };
            }
            KeyCode::Up if !*editing => {
                *sel = sel.saturating_sub(1);
            }
            KeyCode::Down if !*editing => {
                *sel = (*sel + 1).min(fields.len().saturating_sub(1));
            }
            KeyCode::Tab if !*editing => {
                *sel = (*sel + 1) % fields.len();
            }
            KeyCode::Backspace if *editing => {
                buffer.pop();
            }
            KeyCode::Enter if *editing => match commit_edit_field(*sel, buffer) {
                Ok(v) => {
                    fields[*sel] = v;
                    *editing = false;
                    *error = None;
                }
                Err(e) => *error = Some(e),
            },
            // Enter on a browsing row starts editing it, seeded with the
            // current value (EgressHosts convention; saving is `s`, like
            // the wizard review's "s save only").
            KeyCode::Enter => {
                *buffer = fields[*sel].clone();
                *editing = true;
                *error = None;
            }
            KeyCode::Char(c) if *editing => buffer.push(c),
            _ => match cmd {
                Some('q') if !*editing => {
                    let rows = edit_service_rows();
                    let at = rows.iter().position(|r| r.id == *id).unwrap_or(0);
                    app.screen = Screen::EditService {
                        rows,
                        selected: at,
                        message: None,
                    };
                }
                Some('s') if !*editing => match save_edit(id, fields) {
                    Ok(_) => {
                        *message = Some("saved — applies on next deploy".into());
                        *error = None;
                    }
                    Err(e) => *error = Some(e),
                },
                Some('r') if !*editing => match save_edit(id, fields) {
                    Ok(path) => {
                        let input = path.display().to_string();
                        match workers::classify_deploy_input(&input) {
                            Ok(target) => {
                                // The explicit r is the consent to redeploy —
                                // same as the wizard's Enter save + deploy. An
                                // outdated build re-execs first and resumes
                                // this deploy on the fresh code.
                                if crate::paths::binary_is_stale() {
                                    restart_with_pending(&crate::paths::PendingAction {
                                        payload: input,
                                        route: crate::paths::PendingRoute::PathDeploy,
                                    });
                                }
                                start_deploy_screen(app, target);
                            }
                            Err(e) => *error = Some(e),
                        }
                    }
                    Err(e) => *error = Some(e),
                },
                Some('e') if !*editing => match crate::hoster::library::file_path(id) {
                    Ok(path) => return Flow::EditFile(path),
                    Err(e) => *error = Some(workers::short_error_for(&e)),
                },
                _ => {}
            },
        },
        Screen::Egress {
            files,
            deployed,
            counters,
            verdicts: _,
            checking,
            selected,
            message,
        } => {
            let count = files.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 7 },
                KeyCode::Up if count > 0 => {
                    *selected = selected.saturating_sub(1);
                }
                KeyCode::Down if count > 0 => {
                    *selected = (*selected + 1).min(count - 1);
                }
                KeyCode::Enter if count > 0 => {
                    if let Some(f) = files.get(*selected) {
                        match crate::hoster::library::load(&f.id) {
                            Ok(m) => {
                                let id = f.id.clone();
                                app.screen = Screen::EgressHosts {
                                    id,
                                    hosts: m.egress.allow,
                                    selected: 0,
                                    buffer: String::new(),
                                    editing: false,
                                    armed: false,
                                    error: None,
                                    message: None,
                                };
                            }
                            Err(e) => {
                                *message = Some(workers::short_error_for(&e));
                            }
                        }
                    }
                }
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 7 },
                    Some('k') if count > 0 => {
                        *selected = selected.saturating_sub(1);
                    }
                    Some('j') if count > 0 => {
                        *selected = (*selected + 1).min(count - 1);
                    }
                    Some('r') => {
                        let snap = workers::egress_snapshot();
                        *files = snap.files;
                        *deployed = snap.deployed;
                        *counters = snap.counters;
                        if *selected >= files.len() {
                            *selected = files.len().saturating_sub(1);
                        }
                        *message = Some("refreshed".into());
                    }
                    Some('v') => {
                        if checking.is_none()
                            && let Some(f) = files.get(*selected).cloned()
                        {
                            *checking = Some(f.id.clone());
                            *message = Some(format!("checking {}…", f.id));
                            workers::spawn_egress_check(app.tx.clone(), f.id);
                        }
                    }
                    _ => {}
                },
            }
        }
        Screen::EgressHosts {
            id,
            hosts,
            selected,
            buffer,
            editing,
            armed,
            error,
            message,
        } => match key {
            KeyCode::Esc if *editing => {
                *editing = false;
                *error = None;
            }
            KeyCode::Esc => {
                let snap = workers::egress_snapshot();
                app.screen = Screen::Egress {
                    files: snap.files,
                    deployed: snap.deployed,
                    counters: snap.counters,
                    verdicts: HashMap::new(),
                    checking: None,
                    selected: 0,
                    message: None,
                };
            }
            KeyCode::Up if !*editing && !hosts.is_empty() => {
                *selected = selected.saturating_sub(1);
                *armed = false;
            }
            KeyCode::Down if !*editing && !hosts.is_empty() => {
                *selected = (*selected + 1).min(hosts.len() - 1);
                *armed = false;
            }
            KeyCode::Backspace if *editing => {
                buffer.pop();
            }
            KeyCode::Enter if *editing => {
                if buffer.trim().is_empty() {
                    *error = Some("enter a hostname (e.g. api.telegram.org)".into());
                } else {
                    let mut next = hosts.clone();
                    next.push(buffer.trim().to_string());
                    match crate::hoster::library::set_egress_allow(id, &next) {
                        Ok(()) => {
                            *hosts = next;
                            buffer.clear();
                            *editing = false;
                            *error = None;
                            *message = Some("saved — applies on next deploy".into());
                        }
                        Err(e) => *error = Some(workers::short_error_for(&e)),
                    }
                }
            }
            KeyCode::Enter => {
                *editing = true;
                *error = None;
            }
            KeyCode::Char(c) if *editing => buffer.push(c),
            _ => match cmd {
                Some('q') => {
                    let snap = workers::egress_snapshot();
                    app.screen = Screen::Egress {
                        files: snap.files,
                        deployed: snap.deployed,
                        counters: snap.counters,
                        verdicts: HashMap::new(),
                        checking: None,
                        selected: 0,
                        message: None,
                    };
                }
                Some('a') => {
                    *editing = true;
                    *error = None;
                }
                Some('d') if !*editing && !hosts.is_empty() => {
                    if *armed {
                        let mut next = hosts.clone();
                        next.remove((*selected).min(hosts.len() - 1));
                        match crate::hoster::library::set_egress_allow(id, &next) {
                            Ok(()) => {
                                *hosts = next;
                                if *selected >= hosts.len() {
                                    *selected = hosts.len().saturating_sub(1);
                                }
                                *message = Some("saved — applies on next deploy".into());
                            }
                            Err(e) => *error = Some(workers::short_error_for(&e)),
                        }
                        *armed = false;
                    } else {
                        *armed = true;
                        *message = Some("press d again to delete this host".into());
                    }
                }
                _ => {}
            },
        },
        Screen::Networks {
            rows,
            selected,
            message,
        } => {
            let count = rows.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 1 },
                KeyCode::Up if count > 0 => *selected = selected.saturating_sub(1),
                KeyCode::Down if count > 0 => *selected = (*selected + 1).min(count - 1),
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 1 },
                    Some('k') if count > 0 => *selected = selected.saturating_sub(1),
                    Some('j') if count > 0 => *selected = (*selected + 1).min(count - 1),
                    Some('r') => {
                        *rows = crate::networks::supervisor::rows();
                        if *selected >= rows.len() && !rows.is_empty() {
                            *selected = rows.len().saturating_sub(1);
                        }
                        *message = Some("refreshed".into());
                    }
                    Some('s') if count > 0 => {
                        if let Some(row) = rows.get(*selected).cloned()
                            && row.can_start()
                        {
                            if let Err(e) = crate::networks::supervisor::start(
                                &row.service,
                                &row.unit_name,
                                &row.local_url,
                            ) {
                                *message = Some(format!("! {e}"));
                            } else {
                                *rows = crate::networks::supervisor::rows();
                                *message = Some(format!("started sharing {}", row.service));
                            }
                        }
                    }
                    Some('x') if count > 0 => {
                        if let Some(row) = rows.get(*selected).cloned() {
                            crate::networks::supervisor::stop(&row.service);
                            *rows = crate::networks::supervisor::rows();
                            *message = Some(format!("stopped sharing {}", row.service));
                        }
                    }
                    _ => {}
                },
            }
        }
        Screen::WzId {
            buffer,
            error,
            draft,
        } => match key {
            KeyCode::Esc => {
                app.screen = Screen::AddService {
                    files: crate::hoster::library::list(),
                    selected: 0,
                    message: None,
                    armed_delete: None,
                }
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
                let mut draft = std::mem::take(draft);
                match wizard::check_id(buffer) {
                    Ok(()) => {
                        draft.id = buffer.trim().to_string();
                        app.screen = Screen::WzGit {
                            buffer: draft.git.clone(),
                            error: None,
                            draft,
                        };
                    }
                    Err(e) => *error = Some(e),
                }
            }
            KeyCode::Char(c) => buffer.push(c),
            _ => {}
        },
        Screen::WzGit {
            buffer,
            error,
            draft,
        } => match key {
            KeyCode::Esc => {
                let mut draft = std::mem::take(draft);
                draft.git = std::mem::take(buffer);
                app.screen = Screen::WzId {
                    buffer: draft.id.clone(),
                    error: None,
                    draft,
                };
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
                let mut draft = std::mem::take(draft);
                match wizard::check_git(buffer) {
                    Ok(()) => {
                        draft.git = buffer.trim().to_string();
                        app.screen = Screen::WzCommit {
                            buffer: draft.commit.clone(),
                            error: None,
                            draft,
                        };
                    }
                    Err(e) => *error = Some(e),
                }
            }
            KeyCode::Char(c) => buffer.push(c),
            _ => {}
        },
        Screen::WzCommit {
            buffer,
            error,
            draft,
        } => match key {
            KeyCode::Esc => {
                let mut draft = std::mem::take(draft);
                draft.commit = std::mem::take(buffer);
                app.screen = Screen::WzGit {
                    buffer: draft.git.clone(),
                    error: None,
                    draft,
                };
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
                let mut draft = std::mem::take(draft);
                match wizard::check_commit(buffer) {
                    Ok(()) => {
                        draft.commit = buffer.trim().to_string();
                        // Detection pre-selects its profile; manual flow starts at 0.
                        let selected = wizard::PROFILES
                            .iter()
                            .position(|(id, _)| *id == draft.profile)
                            .filter(|_| draft.detected)
                            .unwrap_or(0);
                        app.screen = Screen::WzProfile { selected, draft };
                    }
                    Err(e) => *error = Some(e),
                }
            }
            KeyCode::Char(c) => buffer.push(c),
            _ => {}
        },
        Screen::WzProfile { selected, draft } => {
            let count = wizard::PROFILES.len();
            match key {
                KeyCode::Esc => {
                    let draft = std::mem::take(draft);
                    app.screen = Screen::WzCommit {
                        buffer: draft.commit.clone(),
                        error: None,
                        draft,
                    };
                }
                KeyCode::Up if count > 0 => {
                    *selected = selected.saturating_sub(1);
                }
                KeyCode::Down if count > 0 => {
                    *selected = (*selected + 1).min(count - 1);
                }
                KeyCode::Enter => {
                    let mut draft = std::mem::take(draft);
                    // Detected steps survive when the highlighted profile is
                    // the detected one; picking another profile resets
                    // everything below to that profile's defaults (said so on
                    // screen). apply_profile_defaults also clears the flag.
                    if !(draft.detected && wizard::PROFILES[*selected].0 == draft.profile) {
                        let profile = wizard::PROFILES[*selected].0;
                        wizard::apply_profile_defaults(&mut draft, profile);
                    }
                    let editor = wizard::StepEditor::new(draft.prefetch.clone());
                    app.screen = Screen::WzPrefetch { editor, draft };
                }
                _ => match cmd {
                    Some('q') => {
                        let draft = std::mem::take(draft);
                        app.screen = Screen::WzCommit {
                            buffer: draft.commit.clone(),
                            error: None,
                            draft,
                        };
                    }
                    Some('k') if count > 0 => {
                        *selected = selected.saturating_sub(1);
                    }
                    Some('j') if count > 0 => {
                        *selected = (*selected + 1).min(count - 1);
                    }
                    _ => {}
                },
            }
        }
        Screen::WzPrefetch { editor, draft } => match wz_steps_key(editor, key, cmd) {
            WzStepsFlow::Next => {
                let mut draft = std::mem::take(draft);
                let editor = std::mem::take(editor);
                draft.prefetch = editor.take_lines();
                let next = wizard::StepEditor::new(draft.build_steps.clone());
                app.screen = Screen::WzBuild {
                    editor: next,
                    draft,
                };
            }
            WzStepsFlow::Back => {
                let mut draft = std::mem::take(draft);
                let editor = std::mem::take(editor);
                draft.prefetch = editor.take_lines();
                let idx = wizard::PROFILES
                    .iter()
                    .position(|(id, _)| *id == draft.profile)
                    .unwrap_or(0);
                app.screen = Screen::WzProfile {
                    selected: idx,
                    draft,
                };
            }
            WzStepsFlow::Stay => {}
        },
        Screen::WzBuild { editor, draft } => match wz_steps_key(editor, key, cmd) {
            WzStepsFlow::Next => {
                let mut draft = std::mem::take(draft);
                let editor = std::mem::take(editor);
                draft.build_steps = editor.take_lines();
                let run_cmd = draft.run_cmd.clone();
                let port = draft.port.clone();
                app.screen = Screen::WzRun {
                    cmd: run_cmd,
                    port,
                    focus_port: false,
                    error: None,
                    draft,
                };
            }
            WzStepsFlow::Back => {
                let mut draft = std::mem::take(draft);
                let editor = std::mem::take(editor);
                draft.build_steps = editor.take_lines();
                let back = wizard::StepEditor::new(draft.prefetch.clone());
                app.screen = Screen::WzPrefetch {
                    editor: back,
                    draft,
                };
            }
            WzStepsFlow::Stay => {}
        },
        Screen::WzRun {
            cmd: run_cmd,
            port,
            focus_port,
            error,
            draft,
        } => match key {
            KeyCode::Esc => {
                let mut draft = std::mem::take(draft);
                draft.run_cmd = std::mem::take(run_cmd);
                draft.port = std::mem::take(port);
                let back = wizard::StepEditor::new(draft.build_steps.clone());
                app.screen = Screen::WzBuild {
                    editor: back,
                    draft,
                };
            }
            KeyCode::Tab => {
                *focus_port = !*focus_port;
            }
            KeyCode::Backspace => {
                if *focus_port {
                    port.pop();
                } else {
                    run_cmd.pop();
                }
            }
            KeyCode::Enter => {
                if run_cmd.trim().is_empty() {
                    *error = Some(
                        "run command must not be empty (use {bin}/{venv}/{self}/{project}/{port})"
                            .into(),
                    );
                } else {
                    let mut d = std::mem::take(draft);
                    d.run_cmd = run_cmd.trim().to_string();
                    match wizard::check_port(port) {
                        Ok(_) => {
                            d.port = port.trim().to_string();
                            app.screen = Screen::WzRes {
                                memory: d.memory_max.clone(),
                                tasks: d.tasks_max.clone(),
                                focus_tasks: false,
                                error: None,
                                draft: d,
                            };
                        }
                        Err(e) => {
                            *draft = d;
                            *error = Some(e);
                        }
                    }
                }
            }
            // Raw char: commands must be typed verbatim on any layout.
            KeyCode::Char(c) => {
                if *focus_port {
                    port.push(c);
                } else {
                    run_cmd.push(c);
                }
            }
            _ => {}
        },
        Screen::WzRes {
            memory,
            tasks,
            focus_tasks,
            error,
            draft,
        } => match key {
            KeyCode::Esc => {
                let mut draft = std::mem::take(draft);
                draft.memory_max = std::mem::take(memory);
                draft.tasks_max = std::mem::take(tasks);
                app.screen = Screen::WzRun {
                    cmd: draft.run_cmd.clone(),
                    port: draft.port.clone(),
                    focus_port: false,
                    error: None,
                    draft,
                };
            }
            KeyCode::Tab => {
                *focus_tasks = !*focus_tasks;
            }
            KeyCode::Backspace => {
                if *focus_tasks {
                    tasks.pop();
                } else {
                    memory.pop();
                }
            }
            KeyCode::Enter => {
                let mut d = std::mem::take(draft);
                let mem_ok = wizard::check_memory(memory);
                let tasks_ok = wizard::check_tasks(tasks);
                match (mem_ok, tasks_ok) {
                    (Ok(()), Ok(())) => {
                        d.memory_max = memory.trim().to_string();
                        d.tasks_max = tasks.trim().to_string();
                        match wizard::preview_yaml(&d) {
                            Ok(yaml) => {
                                app.screen = Screen::WzReview {
                                    draft: d,
                                    yaml: Some(yaml),
                                    error: None,
                                };
                            }
                            Err(e) => {
                                *draft = d;
                                *error = Some(e);
                            }
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        *draft = d;
                        *error = Some(e);
                    }
                }
            }
            KeyCode::Char(c) => {
                if *focus_tasks {
                    tasks.push(c);
                } else {
                    memory.push(c);
                }
            }
            _ => {}
        },
        Screen::WzReview { draft, yaml, error } => match key {
            KeyCode::Esc => {
                let draft = std::mem::take(draft);
                app.screen = Screen::WzRes {
                    memory: draft.memory_max.clone(),
                    tasks: draft.tasks_max.clone(),
                    focus_tasks: false,
                    error: None,
                    draft,
                };
            }
            // Save only: park the manifest in the library (deploy later
            // from Add Service).
            KeyCode::Char('s') => {
                if yaml.is_none() {
                    *error = Some("fix the errors above first (Esc goes back)".into());
                } else {
                    let text = yaml.clone().unwrap_or_default();
                    match wizard_save(draft, &text) {
                        Ok((_, id)) => {
                            let files = crate::hoster::library::list();
                            // Selection space has 3 action rows on top.
                            let selected = files
                                .iter()
                                .position(|f| f.id == id)
                                .map(|i| i + 3)
                                .unwrap_or(3);
                            app.screen = Screen::AddService {
                                files,
                                selected,
                                message: Some(format!("created {id} — Enter deploys it")),
                                armed_delete: None,
                            };
                        }
                        Err(e) => *error = Some(e),
                    }
                }
            }
            // Save and go: the manifest lands in the library and the deploy
            // starts immediately — one key instead of save → pick → confirm.
            KeyCode::Enter => {
                if yaml.is_none() {
                    *error = Some("fix the errors above first (Esc goes back)".into());
                } else {
                    let text = yaml.clone().unwrap_or_default();
                    match wizard_save(draft, &text) {
                        Ok((manifest, id)) => match crate::hoster::library::file_path(&id) {
                            Ok(path) => {
                                let target = workers::DeployTarget::Manifest {
                                    path,
                                    service_id: id,
                                    plan: manifest
                                        .plan_text()
                                        .lines()
                                        .map(str::to_string)
                                        .collect(),
                                };
                                start_deploy_screen(app, target);
                            }
                            Err(e) => *error = Some(format!("{e:#}")),
                        },
                        Err(e) => *error = Some(e),
                    }
                }
            }
            _ => {}
        },
    }
    Flow::Continue
}

fn move_main_selection(selected: &mut usize, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Left => *selected = selected.saturating_sub(1),
        _ => *selected = (*selected + 1).min(MAIN_MENU.len() - 1),
    }
}

/// Switch to the streaming Deploy screen for an already-classified target
/// (and kick the worker off first, so the first lines never get dropped).
/// An outdated build hands the exact target over to the fresh binary first:
/// starting the pipeline on a stale image is what forced manual relaunches
/// mid-deploy, and a relaunch while a worker runs races the recovery pass
/// (the new process sweeps the live tree → clone dies with ENOENT). Only
/// returns when the takeover could not happen (no disk copy, exec refused,
/// or a deploy is already winding down); the pipeline then starts on the
/// running build as before.
fn start_deploy_screen(app: &mut App, target: workers::DeployTarget) {
    if crate::paths::binary_is_stale() {
        restart_with_pending(&crate::paths::PendingAction {
            payload: target.back_to_input(),
            route: crate::paths::PendingRoute::PathDeploy,
        });
    }
    let label = target.describe();
    workers::start_target_deployment(app.tx.clone(), target);
    app.screen = Screen::Deploy {
        lines: vec![format!("deploying {label}...")],
        done: None,
    };
}

/// Autopilot storage: build the manifest from a detected draft, render its
/// YAML and put it in the library under its own id — replacing an earlier
/// run of the same service, so re-entering the same URL just redeploys.
/// Returns the deploy target of the stored file.
fn auto_store(
    draft: &mut wizard::Draft,
    suggested_id: &str,
) -> Result<workers::DeployTarget, String> {
    // Detection leaves draft.id blank — the wizard's step 1 would accept the
    // suggestion there; the autopilot accepts it right here.
    if draft.id.trim().is_empty() {
        draft.id = suggested_id.to_string();
    }
    let manifest = wizard::build_manifest(draft)?;
    let yaml = serde_yaml::to_string(&manifest).map_err(|e| format!("cannot render YAML: {e}"))?;
    let id = manifest.service.id.clone();
    let exists = crate::hoster::library::list().iter().any(|e| e.id == id);
    if exists {
        crate::hoster::library::replace(&id, yaml.as_bytes()).map_err(|e| format!("{e:#}"))?;
    } else {
        crate::hoster::library::save(&manifest, &yaml).map_err(|e| format!("{e:#}"))?;
    }
    let path = crate::hoster::library::file_path(&id).map_err(|e| format!("{e:#}"))?;
    Ok(workers::DeployTarget::Manifest {
        path,
        service_id: id,
        plan: manifest.plan_text().lines().map(str::to_string).collect(),
    })
}

/// Build, validate and store a wizard draft's manifest with the library's
/// duplicate guard (an id already on the shelf must be deleted first — the
/// autopilot path replaces on purpose, the wizard keeps its explicit rule).
/// Returns the manifest and its id so the caller can chain a deploy.
fn wizard_save(
    draft: &wizard::Draft,
    yaml: &str,
) -> Result<(crate::hoster::manifest::ServiceManifest, String), String> {
    let manifest = wizard::build_manifest(draft)?;
    let id =
        crate::hoster::library::save(&manifest, yaml).map_err(|e| workers::short_error_for(&e))?;
    Ok((manifest, id))
}

/// Re-exec the panel onto the fresh build on disk, handing `action` over so
/// the new process resumes it at startup — the user's keystroke survives the
/// restart even though the running image was outdated. Only returns when the
/// takeover could not happen (no disk copy, exec refused); the caller then
/// proceeds with the running build, which still shows the outdated warnings.
/// Never fires mid-deploy or during shutdown: the journal and the terminal
/// must outlive this process untouched.
fn restart_with_pending(action: &crate::paths::PendingAction) {
    if crate::hoster::deploy::deploy_in_flight() || crate::hoster::cancel::is_exiting() {
        return;
    }
    if crate::paths::write_pending_action(action).is_err() {
        return;
    }
    let Some(bin) = crate::paths::disk_binary_path() else {
        let _ = std::fs::remove_file(crate::paths::pending_action_file());
        return;
    };
    // Raw mode and the alternate screen are tty state, not process state:
    // they survive exec, and run() re-initializes them anyway.
    use std::os::unix::process::CommandExt;
    let _err = std::process::Command::new(&bin).exec();
    // Exec refused: this build continues the action itself, so drop the
    // handover — replaying it from a later launch would fire the user's
    // Enter long after they pressed it.
    let _ = std::fs::remove_file(crate::paths::pending_action_file());
}

/// Startup: finish a deploy the previous (outdated) build handed over before
/// re-execing. The original Enter already gave consent — replay it without
/// asking again.
fn resume_pending_action(app: &mut App) {
    let Some(pending) = crate::paths::take_pending_action() else {
        return;
    };
    match pending.route {
        crate::paths::PendingRoute::Auto | crate::paths::PendingRoute::Wizard => {
            let route = match pending.route {
                crate::paths::PendingRoute::Wizard => workers::DetectRoute::Wizard,
                _ => workers::DetectRoute::Auto,
            };
            app.screen = Screen::DetectInput {
                buffer: pending.payload.clone(),
                error: None,
                busy: true,
            };
            workers::spawn_detect(app.tx.clone(), pending.payload, route);
        }
        crate::paths::PendingRoute::PathDeploy => {
            match workers::classify_deploy_input(&pending.payload) {
                Ok(target @ workers::DeployTarget::Manifest { .. }) => {
                    start_deploy_screen(app, target)
                }
                // The payload turned into a URL somehow (or the file is
                // gone): hand the input back instead of failing blind.
                Ok(other) => {
                    app.screen = Screen::UrlInput {
                        buffer: other.back_to_input(),
                        error: None,
                        busy: false,
                    }
                }
                Err(e) => {
                    app.screen = Screen::UrlInput {
                        buffer: pending.payload,
                        error: Some(e),
                        busy: false,
                    }
                }
            }
        }
    }
}

/// Rows for the Edit Service menu: every deployed id (state.json) paired
/// with its library manifest. `state.json` is a BTreeMap, so rows are id-ordered.
fn edit_service_rows() -> Vec<EditRow> {
    crate::state::list()
        .into_iter()
        .map(|(id, entry)| {
            let path = crate::hoster::library::file_path(&id)
                .ok()
                .filter(|p| p.exists());
            let loaded = path
                .as_ref()
                .and_then(|_| crate::hoster::library::load(&id).ok());
            let name = loaded
                .as_ref()
                .map(|m| m.service.name.trim())
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| id.clone());
            // `entry.url` is the source repo; the live endpoint lives in
            // `urls` — show what the service actually answers on.
            let live = entry
                .urls
                .first()
                .cloned()
                .unwrap_or_else(|| entry.url.clone());
            EditRow {
                id,
                name,
                url: live,
                valid: loaded.is_some(),
                path,
            }
        })
        .collect()
}

/// The six row buffers of [`Screen::EditServiceForm`] from a loaded
/// manifest. Missing optional values render empty (the schema still
/// requires memory and tasks, so an empty row only survives until save).
fn edit_fields_of(m: &crate::hoster::manifest::ServiceManifest) -> Vec<String> {
    vec![
        m.service.name.clone(),
        m.service.description.clone(),
        m.source.commit.clone(),
        m.run.port.to_string(),
        m.resources.memory_max.clone().unwrap_or_default(),
        m.resources.tasks_max.clone().unwrap_or_default(),
    ]
}

/// Field-level check when a row leaves edit mode: the value must parse on
/// its own — the full schema revalidation waits for save.
fn commit_edit_field(sel: usize, value: &str) -> Result<String, String> {
    let v = value.trim().to_string();
    match sel {
        EDIT_COMMIT => {
            wizard::check_commit(&v)?;
            Ok(v)
        }
        EDIT_PORT => {
            wizard::check_port(&v)?;
            Ok(v)
        }
        EDIT_MEMORY => {
            wizard::check_memory(&v)?;
            Ok(v)
        }
        EDIT_TASKS => {
            wizard::check_tasks(&v)?;
            Ok(v)
        }
        _ => Ok(v),
    }
}

/// Patch a manifest with the six [`EDIT_FIELDS`] values and revalidate the
/// whole schema — build steps, env, egress and plugins pass through untouched.
fn apply_edit(
    manifest: &mut crate::hoster::manifest::ServiceManifest,
    fields: &[String],
) -> Result<(), String> {
    if fields.len() != EDIT_FIELDS.len() {
        return Err(format!(
            "internal: expected {} fields, got {}",
            EDIT_FIELDS.len(),
            fields.len()
        ));
    }
    manifest.service.name = fields[EDIT_NAME].trim().to_string();
    manifest.service.description = fields[EDIT_DESC].trim().to_string();
    let commit = fields[EDIT_COMMIT].trim().to_string();
    wizard::check_commit(&commit)?;
    manifest.source.commit = commit;
    manifest.run.port = wizard::check_port(&fields[EDIT_PORT])?;
    wizard::check_memory(&fields[EDIT_MEMORY])?;
    manifest.resources.memory_max = Some(fields[EDIT_MEMORY].trim().to_string());
    wizard::check_tasks(&fields[EDIT_TASKS])?;
    manifest.resources.tasks_max = Some(fields[EDIT_TASKS].trim().to_string());
    manifest
        .validate("edit")
        .map_err(|e| workers::short_error_for(&e))
}

/// Load, patch, validate and replace the manifest in place; returns the
/// library path (for the caller's redeploy) or the error for the form.
fn save_edit(id: &str, fields: &[String]) -> Result<std::path::PathBuf, String> {
    let mut manifest =
        crate::hoster::library::load(id).map_err(|e| workers::short_error_for(&e))?;
    apply_edit(&mut manifest, fields)?;
    let yaml = serde_yaml::to_string(&manifest).map_err(|e| format!("cannot render YAML: {e}"))?;
    crate::hoster::library::replace(id, yaml.as_bytes())
        .map_err(|e| workers::short_error_for(&e))?;
    crate::hoster::library::file_path(id).map_err(|e| workers::short_error_for(&e))
}

fn main_menu_activate(app: &mut App, selected: usize) -> Flow {
    match selected {
        0 => {
            workers::spawn_scan(app.tx.clone(), app.scan_seq + 1);
            app.scan_seq += 1;
            app.screen = Screen::Scan {
                report: None,
                running: true,
                seq: app.scan_seq,
            };
        }
        1 => {
            app.screen = Screen::Networks {
                rows: crate::networks::supervisor::rows(),
                selected: 0,
                message: None,
            };
        }
        2 => {
            let rows = workers::service_rows();
            app.screen = Screen::Services {
                rows,
                selected: 0,
                message: None,
            };
        }
        3 => {
            app.screen = Screen::UrlInput {
                buffer: String::new(),
                error: None,
                busy: false,
            }
        }
        4 => {
            app.screen = Screen::AddService {
                files: crate::hoster::library::list(),
                selected: 0,
                message: None,
                armed_delete: None,
            };
        }
        5 => {
            let files = crate::hoster::library::list();
            let deployed: Vec<String> = crate::state::list()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            app.screen = Screen::UserServices {
                files,
                deployed,
                selected: 0,
                message: None,
            };
        }
        6 => {
            app.screen = Screen::EditService {
                rows: edit_service_rows(),
                selected: 0,
                message: None,
            };
        }
        7 => {
            let snap = workers::egress_snapshot();
            app.screen = Screen::Egress {
                files: snap.files,
                deployed: snap.deployed,
                counters: snap.counters,
                verdicts: HashMap::new(),
                checking: None,
                selected: 0,
                message: None,
            };
        }
        8 => {
            // Deploy logs: single shared file is the source of truth so every
            // window streams the same live deploy. File survives across processes.
            let mut deploy_lines = workers::read_deploy_log();
            if deploy_lines.is_empty() {
                if !app.deploy_history.is_empty() {
                    deploy_lines.clone_from(&app.deploy_history);
                } else {
                    deploy_lines
                        .push("No deploy logs yet. Start a deployment to see output here.".into());
                }
            }
            // Keep the persistent history in sync with the file so switching
            // away and back preserves cross-window tail lines.
            app.deploy_history.clone_from(&deploy_lines);

            let mut software_lines = if app.software_history.is_empty() {
                let fetched = workers::fetch_software_logs();
                app.software_history.clone_from(&fetched);
                fetched
            } else {
                app.software_history.clone()
            };
            if software_lines.is_empty() {
                software_lines.push(
                    "No software logs yet. Deploy a service to see journal output here.".into(),
                );
            }
            // Crash screen: persistent history of interrupted deploys and full
            // removals, seeded from the same file the tailer appends to.
            let mut crash_lines = crate::crashlog::read();
            app.crash_history.clone_from(&crash_lines);
            if crash_lines.is_empty() {
                crash_lines.push(
                    "No crash events yet. Interrupt a deploy (or remove a service) to see history here."
                        .into(),
                );
            }
            app.screen = Screen::Logs {
                view: LogView::Deploy,
                deploy_lines,
                software_lines,
                crash_lines,
                scroll: 0,
            };
            start_log_tailers(app);
        }
        _ => {}
    }
    Flow::Continue
}

fn stop_log_tailers(app: &mut App) {
    for keep in [
        app.deploy_tail_keep.take(),
        app.software_tail_keep.take(),
        app.crash_tail_keep.take(),
    ]
    .into_iter()
    .flatten()
    {
        keep.store(false, Ordering::Relaxed);
    }
}

/// Tail `path` in a background thread, forwarding appended lines to the event
/// loop and detecting truncation/removal (a cleared file). Shared by the deploy
/// log and the crash-history file tailers.
fn spawn_file_tailer(
    path: std::path::PathBuf,
    keep: std::sync::Arc<AtomicBool>,
    tx: Sender<Msg>,
    on_line: impl Fn(String) -> Msg + Send + 'static,
    on_cleared: impl Fn() -> Msg + Send + 'static,
) {
    std::thread::spawn(move || {
        let mut pos = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if !keep.load(Ordering::Relaxed) {
                break;
            }
            let content = match std::fs::read(&path) {
                Ok(c) => c,
                Err(_) => {
                    if pos != 0 {
                        let _ = tx.send(on_cleared());
                        pos = 0;
                    }
                    continue;
                }
            };
            let len = content.len() as u64;
            if len < pos {
                let _ = tx.send(on_cleared());
                pos = len;
                continue;
            }
            if len > pos {
                let text = String::from_utf8_lossy(&content[pos as usize..]);
                for line in text.lines() {
                    if !keep.load(Ordering::Relaxed) {
                        break;
                    }
                    if !line.is_empty() || text.contains("\n\n") {
                        let _ = tx.send(on_line(line.to_string()));
                    }
                }
                pos = len;
            }
        }
    });
}

fn start_log_tailers(app: &mut App) {
    if app.deploy_tail_keep.is_some()
        && app.software_tail_keep.is_some()
        && app.crash_tail_keep.is_some()
    {
        return;
    }
    // Deploy: tail the shared deploy.log so every window streams the same live deploy.
    if app.deploy_tail_keep.is_none() {
        let keep = Arc::new(AtomicBool::new(true));
        app.deploy_tail_keep = Some(keep.clone());
        spawn_file_tailer(
            crate::paths::deploy_log_file(),
            keep,
            app.tx.clone(),
            Msg::TailLog,
            || Msg::DeployLogsCleared,
        );
    }
    // Crash history: tail crash.log the same way, so an interruption/removal
    // recorded in-process (or by a sweep) shows up live on the screen.
    if app.crash_tail_keep.is_none() {
        let keep = Arc::new(AtomicBool::new(true));
        app.crash_tail_keep = Some(keep.clone());
        spawn_file_tailer(
            crate::paths::crash_log_file(),
            keep,
            app.tx.clone(),
            Msg::CrashLog,
            || Msg::CrashLogsCleared,
        );
    }
    // Software: poll journalctl per unit; incremental per-unit diff.
    if app.software_tail_keep.is_none() {
        let keep = Arc::new(AtomicBool::new(true));
        app.software_tail_keep = Some(keep.clone());
        let tx = app.tx.clone();
        std::thread::spawn(move || {
            let mut last: HashMap<String, Vec<String>> = HashMap::new();
            // seed — don't re-send lines already in the snapshot
            for (name, entry) in crate::state::list() {
                last.insert(name, workers::journal_raw_for(&entry.unit_name));
            }
            loop {
                std::thread::sleep(Duration::from_secs(2));
                if !keep.load(Ordering::Relaxed) {
                    break;
                }
                let entries = crate::state::list();
                let names: HashSet<String> = entries.iter().map(|(n, _)| n.clone()).collect();
                last.retain(|k, _| names.contains(k));
                for (name, entry) in entries {
                    if !keep.load(Ordering::Relaxed) {
                        break;
                    }
                    let cur = workers::journal_raw_for(&entry.unit_name);
                    match last.get(&name) {
                        None => {
                            let _ = tx.send(Msg::SoftwareLog(format!(
                                "== {} ({}) ==",
                                name, entry.unit_name
                            )));
                            for l in &cur {
                                let _ = tx.send(Msg::SoftwareLog(l.clone()));
                            }
                            last.insert(name, cur);
                        }
                        Some(prev) => {
                            if cur == *prev {
                                continue;
                            }
                            if cur.len() > prev.len() && cur[..prev.len()] == prev[..] {
                                for l in &cur[prev.len()..] {
                                    let _ = tx.send(Msg::SoftwareLog(l.clone()));
                                }
                                last.insert(name, cur);
                            } else {
                                let _ =
                                    tx.send(Msg::SoftwareLog(format!("-- {name} log rotated --")));
                                for l in &cur {
                                    let _ = tx.send(Msg::SoftwareLog(l.clone()));
                                }
                                last.insert(name, cur);
                            }
                        }
                    }
                }
            }
        });
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    // Adaptive floor: below this the 3-pane layout cannot breathe — say so
    // instead of squeezing header/body/hint into nothing.
    if area.width < MIN_TERM_WIDTH || area.height < MIN_TERM_HEIGHT {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "GHOSTPROVIDER",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "window too small — enlarge to continue",
                    Style::default().fg(DIM),
                )),
            ]),
            area,
        );
        return;
    }
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);

    // Force-clean the body area in THIS frame's buffer so the diff engine
    // emits overwrites for stale glyphs left by longer previous frames
    // (ratatui only rewrites cells it believes changed).
    {
        let buf = f.buffer_mut();
        for y in chunks[0].top()..chunks[0].bottom() {
            for x in chunks[0].left()..chunks[0].right() {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.reset();
                }
            }
        }
    }

    // Wizard screens open with the step chain, so the next screen — and
    // therefore what Enter will do — is visible before the key is pressed.
    let mut body = chunks[0];
    if let Some(step) = wizard_step(&app.screen) {
        let parts = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(chunks[0]);
        f.render_widget(Paragraph::new(wizard_progress(step)), parts[0]);
        body = parts[1];
    }

    match &app.screen {
        Screen::Main { selected } => {
            draw_main_menu(f, chunks[0], *selected);
        }
        Screen::Scan {
            report, running, ..
        } => {
            draw_scan(f, chunks[0], report.as_deref(), *running, app.tick);
        }
        Screen::UrlInput {
            buffer,
            error,
            busy,
        } => {
            draw_url_input(f, chunks[0], buffer, error.as_deref(), *busy, app.tick);
        }
        Screen::Confirm {
            target,
            yes_selected,
        } => {
            draw_confirm(f, chunks[0], target, *yes_selected);
        }
        Screen::Deploy { lines, done } => {
            draw_deploy(f, chunks[0], lines, *done, crate::netstatus::summary());
        }
        Screen::Services {
            rows,
            selected,
            message,
        } => {
            draw_services(f, chunks[0], rows, *selected, message.as_deref());
        }
        Screen::ConfirmDelete { name, yes_selected } => {
            draw_confirm_delete(f, chunks[0], name, *yes_selected);
        }
        Screen::Logs {
            view,
            deploy_lines,
            software_lines,
            crash_lines,
            scroll,
        } => {
            draw_logs(
                f,
                chunks[0],
                *view,
                deploy_lines,
                software_lines,
                crash_lines,
                *scroll,
            );
        }
        Screen::ConfirmClear {
            target,
            yes_selected,
        } => {
            draw_confirm_clear(f, chunks[0], *target, *yes_selected);
        }
        Screen::AddService {
            files,
            selected,
            message,
            armed_delete,
        } => {
            draw_add_service(
                f,
                chunks[0],
                files,
                *selected,
                message.as_deref(),
                armed_delete.as_deref(),
            );
        }
        Screen::Import { buffer, error } => {
            draw_import(f, chunks[0], buffer, error.as_deref(), app.tick);
        }
        Screen::DetectInput {
            buffer,
            error,
            busy,
        } => {
            draw_detect_input(f, chunks[0], buffer, error.as_deref(), *busy, app.tick);
        }
        Screen::UserServices {
            files,
            deployed,
            selected,
            message,
        } => {
            draw_user_services(f, chunks[0], files, deployed, *selected, message.as_deref());
        }
        Screen::EditService {
            rows,
            selected,
            message,
        } => {
            draw_edit_service(f, chunks[0], rows, *selected, message.as_deref());
        }
        Screen::EditServiceForm {
            id,
            fields,
            sel,
            buffer,
            editing,
            error,
            message,
        } => {
            draw_edit_service_form(
                f,
                chunks[0],
                id,
                fields,
                *sel,
                buffer,
                *editing,
                error.as_deref(),
                message.as_deref(),
                app.tick,
            );
        }
        Screen::Egress {
            files,
            deployed,
            counters,
            verdicts,
            checking,
            selected,
            message,
        } => {
            draw_egress(
                f,
                chunks[0],
                files,
                deployed,
                counters,
                verdicts,
                checking.as_deref(),
                *selected,
                message.as_deref(),
            );
        }
        Screen::EgressHosts {
            id,
            hosts,
            selected,
            buffer,
            editing,
            armed,
            error,
            message,
        } => {
            draw_egress_hosts(
                f,
                chunks[0],
                id,
                hosts,
                *selected,
                buffer,
                *editing,
                *armed,
                error.as_deref(),
                message.as_deref(),
                app.tick,
            );
        }
        Screen::Networks {
            rows,
            selected,
            message,
        } => {
            draw_networks(f, chunks[0], rows, *selected, message.as_deref());
        }
        Screen::WzId { buffer, error, .. } => {
            draw_wz_input(
                f,
                body,
                "New Service 1/9 · name",
                &[
                    "Give the service a short id: lowercase letters, digits, dashes.",
                    "Example: my-blog, paperless, uptime-kuma.",
                ],
                " Service id: ",
                buffer,
                error.as_deref(),
                app.tick,
            );
        }
        Screen::WzGit { buffer, error, .. } => {
            draw_wz_input(
                f,
                body,
                "New Service 2/9 · source",
                &["Where does the code live? Paste the GitHub repository URL."],
                " Git URL: ",
                buffer,
                error.as_deref(),
                app.tick,
            );
        }
        Screen::WzCommit { buffer, error, .. } => {
            draw_wz_input(
                f,
                body,
                "New Service 3/9 · version pin",
                &[
                    "Which version to deploy? A full 40-character commit SHA (exact pin),",
                    "or a branch name (e.g. main) — its tip is resolved at each deploy.",
                    "Get a SHA with: git ls-remote <url> HEAD",
                ],
                " Version: ",
                buffer,
                error.as_deref(),
                app.tick,
            );
        }
        Screen::WzProfile { selected, draft } => {
            draw_wz_profile(f, body, *selected, draft);
        }
        Screen::WzPrefetch { editor, .. } => {
            draw_wz_steps(
                f,
                body,
                "New Service 5/9 · download dependencies",
                &[
                    "These run ONCE on your machine with network (before the offline build).",
                    "Only downloaders here — they must never run project code.",
                ],
                editor,
                app.tick,
            );
        }
        Screen::WzBuild { editor, .. } => {
            draw_wz_steps(
                f,
                body,
                "New Service 6/9 · build offline",
                &[
                    "These run inside the sandbox with NO network.",
                    "Everything they need must be downloaded on the previous step.",
                ],
                editor,
                app.tick,
            );
        }
        Screen::WzRun {
            cmd: run_cmd,
            port,
            focus_port,
            error,
            ..
        } => {
            draw_wz_run(
                f,
                body,
                run_cmd,
                port,
                *focus_port,
                error.as_deref(),
                app.tick,
            );
        }
        Screen::WzRes {
            memory,
            tasks,
            focus_tasks,
            error,
            ..
        } => {
            draw_wz_res(
                f,
                body,
                memory,
                tasks,
                *focus_tasks,
                error.as_deref(),
                app.tick,
            );
        }
        Screen::WzReview { yaml, error, .. } => {
            draw_wz_review(f, body, yaml.as_deref(), error.as_deref());
        }
    }

    f.render_widget(
        Paragraph::new(hint_line(&app.screen)).alignment(Alignment::Center),
        chunks[1],
    );
}

// --- main menu --------------------------------------------------------------

fn draw_main_menu(f: &mut ratatui::Frame, area: ratatui::prelude::Rect, selected: usize) {
    if area.width < 12 || area.height < 4 {
        return;
    }
    let selected = selected.min(MAIN_MENU.len() - 1);

    // The banner scales WITH the window while keeping the exact style
    // glyphs: wide enough — a nearest-neighbour zoom (each glyph cell
    // repeats n×n, 1×–4×, height-capped); narrower — a width-only
    // nearest-neighbour condense that copies the same glyph cells and
    // keeps all six rows. Same font at every size; the layout below
    // never changes.
    let art = if area.width >= MAIN_ART[0].chars().count() as u16 {
        expand_art(MAIN_ART, art_scale(area))
    } else {
        shrink_art(MAIN_ART, area.width)
    };

    // The whole composition — art, subtitle, mark, menu — is one block,
    // centered in the body both ways; the selected description anchors the
    // bottom line above the hint bar.
    // Vertical rhythm: free rows split into thirds — above the brand block,
    // between brand and menu (which pushes the menu down), and below the
    // menu before the bottom description.
    let brand_h = art.len() as u16 + 3; // art + subtitle + mark + version
    let content_h = brand_h + 2 + MAIN_MENU.len() as u16; // gap + menu
    let slack = area.height.saturating_sub(content_h + 2); // + gap/desc rows
    let mut y = area.y + slack / 3;

    let centered = |f: &mut ratatui::Frame, y: u16, line: Line| {
        f.render_widget(
            Paragraph::new(line).alignment(Alignment::Center),
            ratatui::prelude::Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            },
        );
    };
    for line in &art {
        if y >= area.bottom() {
            return;
        }
        centered(
            f,
            y,
            Line::from(Span::styled(
                line.as_str(),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
        );
        y += 1;
    }
    let version_line = format!("v{}", env!("CARGO_PKG_VERSION"));
    for (text, style) in [
        (
            "SYSTEM FOR AUTOMATED SELF-HOSTING",
            Style::default().fg(BODY).add_modifier(Modifier::BOLD),
        ),
        ("demo panel", Style::default().fg(DIM)),
        (version_line.as_str(), Style::default().fg(BLUE)),
    ] {
        centered(f, y, Line::from(Span::styled(text, style)));
        y += 1;
    }
    y += 1 + slack / 3; // one blank row + a third of the slack before the menu

    // Menu items share one left edge — the block gets centered, not each
    // line — so the list never straggles. Descriptions moved to the bottom.
    let block_w = menu_block_width();
    let bx = area.x + area.width.saturating_sub(block_w) / 2;
    for (i, (icon, title, _, hue)) in MAIN_MENU.iter().enumerate() {
        if y >= area.bottom() {
            break;
        }
        let sel = i == selected;
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    // ASCII marker: U+00BB is East-Asian-ambiguous and
                    // renders double-width in some backends, shifting the
                    // whole block by one column.
                    if sel { "> " } else { "  " },
                    Style::default().fg(*hue).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{icon} "), Style::default().fg(*hue)),
                Span::styled(
                    *title,
                    Style::default()
                        .fg(if sel { Color::White } else { BODY })
                        .add_modifier(if sel {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
            ])),
            ratatui::prelude::Rect {
                x: bx,
                y,
                width: block_w,
                height: 1,
            },
        );
        y += 1;
    }

    // The selected item's description: bottom-anchored, centered.
    let (_, _, desc, hue) = MAIN_MENU[selected];
    centered(
        f,
        area.bottom() - 1,
        Line::from(Span::styled(
            desc,
            Style::default().fg(hue).add_modifier(Modifier::BOLD),
        )),
    );
}

/// Width of the menu block: marker column + icon + widest title.
fn menu_block_width() -> u16 {
    MAIN_MENU
        .iter()
        .map(|(_, title, _, _)| 4 + title.chars().count() as u16)
        .max()
        .unwrap_or(10)
}

// --- system scan ------------------------------------------------------------

/// Two columns when the terminal is wide enough: facts + interfaces on the
/// left, the listening-ports list on the right — a long port list would
/// otherwise push the screen past the bottom of the window. Narrow
/// terminals keep the old stacked layout.
const SCAN_SIDEBYSIDE_MIN_WIDTH: u16 = 70;

fn draw_scan(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    report: Option<&str>,
    running: bool,
    tick: u64,
) {
    let blk = block("System Scan", VIOLET);
    let inner = blk.inner(area);
    f.render_widget(blk, area);
    match (report, running) {
        (Some(r), _) => {
            // The ports section always starts on its own line; everything
            // before it (freshness stamp, tools, interfaces) stays left.
            let split = r
                .find("Listening ports:")
                .map(|i| r[..i].rfind('\n').map(|n| n + 1).unwrap_or(0));
            match split {
                Some(i) if inner.width >= SCAN_SIDEBYSIDE_MIN_WIDTH => {
                    // Columns hug the content: the ports list starts a few
                    // cells after the widest left line, not at some far-away
                    // percentage of the terminal.
                    let left = colorize_scan(&r[..i]);
                    let right = colorize_scan(&r[i..]);
                    let left_w = left.iter().map(|l| l.width() as u16).max().unwrap_or(0);
                    let gap = 3u16;
                    if left_w + gap + 12 <= inner.width {
                        let right_x = inner.x + left_w + gap;
                        let right_w = inner.width.saturating_sub(left_w + gap);
                        f.render_widget(
                            Paragraph::new(left).wrap(Wrap { trim: false }),
                            ratatui::prelude::Rect {
                                x: inner.x,
                                y: inner.y,
                                width: left_w,
                                height: inner.height,
                            },
                        );
                        f.render_widget(
                            Paragraph::new(right).wrap(Wrap { trim: false }),
                            ratatui::prelude::Rect {
                                x: right_x,
                                y: inner.y,
                                width: right_w,
                                height: inner.height,
                            },
                        );
                    } else {
                        f.render_widget(
                            Paragraph::new(left.into_iter().chain(right).collect::<Vec<_>>())
                                .wrap(Wrap { trim: false }),
                            inner,
                        );
                    }
                }
                _ => {
                    f.render_widget(
                        Paragraph::new(colorize_scan(r)).wrap(Wrap { trim: false }),
                        inner,
                    );
                }
            }
        }
        (None, true) => {
            let lines = vec![
                Line::from(vec![
                    Span::styled(spinner_char(tick), spinner_style(tick)),
                    Span::styled(" scanning local system...", Style::default().fg(DIM)),
                ]),
                Line::from(Span::styled(
                    "  (this lists interfaces and occupied ports)",
                    Style::default().fg(DIM),
                )),
            ];
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
        (None, false) => {}
    }
}

fn spinner_char(tick: u64) -> &'static str {
    SPINNER_FRAMES[(tick / 2) as usize % SPINNER_FRAMES.len()]
}

fn spinner_style(tick: u64) -> Style {
    Style::default()
        .fg(RAMP[(tick / 6) as usize % RAMP.len()])
        .add_modifier(Modifier::BOLD)
}

/// Heuristic colorizer for the analyzer report (see workers::spawn_scan).
fn colorize_scan(report: &str) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut in_ports = false;
    let mut in_ifaces = false;
    for raw in report.lines() {
        let line = raw.strip_prefix('\n').unwrap_or(raw);
        let trimmed = line.trim_start();

        if trimmed == "Interfaces:" || trimmed == "Listening ports:" {
            in_ports = trimmed == "Listening ports:";
            in_ifaces = trimmed == "Interfaces:";
            out.push(Line::from(Span::styled(
                format!(" {line}"),
                Style::default().fg(VIOLET).add_modifier(Modifier::BOLD),
            )));
        } else if trimmed.starts_with("PORT ") {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(DIM),
            )));
        } else if in_ports && !trimmed.is_empty() {
            // Empty-section placeholder: dim, never styled like a port row.
            if trimmed == "(none)" {
                out.push(Line::from(Span::styled(
                    format!(" {line}"),
                    Style::default().fg(DIM),
                )));
                continue;
            }
            // Ports of our own deployments carry the "(deployed)" tag —
            // yellow bold. Every other row is an anonymous occupied port:
            // violet bold, with no owner attribution ever.
            let deployed = trimmed.contains("(deployed)");
            let hue = if deployed { WARN_YELLOW } else { VIOLET };
            let mut spans = vec![Span::raw(" ")];
            let (port, rest) = trimmed
                .split_once(char::is_whitespace)
                .unwrap_or((trimmed, ""));
            spans.push(Span::styled(
                port.to_string(),
                Style::default().fg(hue).add_modifier(Modifier::BOLD),
            ));
            if !rest.is_empty() {
                spans.push(Span::styled(
                    format!(" {rest}"),
                    Style::default().fg(hue).add_modifier(Modifier::BOLD),
                ));
            }
            out.push(Line::from(spans));
        } else if in_ifaces && !trimmed.is_empty() && !trimmed.contains(':') {
            // "name [ip] status" — split by exact whitespace boundaries and
            // colorize the trailing state token; keep original column gaps.
            let (head, status) = match trimmed.rfind(char::is_whitespace) {
                Some(i) => (trimmed[..i].to_string(), trimmed[i + 1..].to_string()),
                None => (trimmed.to_string(), String::new()),
            };
            let (name, rest) = match head.find(char::is_whitespace) {
                Some(i) => (head[..i].to_string(), head[i..].to_string()),
                None => (head.clone(), String::new()),
            };
            let status_color = match status.as_str() {
                "up" => OK_GREEN,
                "down" => ERR_RED,
                _ => WARN_YELLOW,
            };
            let mut spans = vec![
                Span::raw("   "),
                Span::styled(name, Style::default().fg(BODY).add_modifier(Modifier::BOLD)),
            ];
            if !rest.is_empty() {
                spans.push(Span::styled(rest, Style::default().fg(DIM)));
            }
            if !status.is_empty() {
                spans.push(Span::styled(
                    format!(" {status}"),
                    Style::default().fg(status_color),
                ));
            }
            out.push(Line::from(spans));
        } else if trimmed.starts_with("[x]") || trimmed.starts_with("[ ]") {
            let ok = trimmed.starts_with("[x]");
            let (mark, mark_color, rest_color) = if ok {
                ("+", OK_GREEN, BODY)
            } else {
                ("x", ERR_RED, DIM)
            };
            out.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(
                    mark.to_string(),
                    Style::default().fg(mark_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {}", &trimmed[3..]),
                    Style::default().fg(rest_color),
                ),
            ]));
        } else if trimmed.starts_with("!") {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
            )));
        } else if trimmed.contains("MISSING")
            || trimmed.contains("not installed")
            || trimmed.contains("offline")
            || trimmed.contains("missing")
        {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(ERR_RED),
            )));
        } else {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(BODY),
            )));
        }
    }
    out
}

// --- url input --------------------------------------------------------------

fn draw_url_input(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    buffer: &str,
    error: Option<&str>,
    busy: bool,
    tick: u64,
) {
    let mut text = vec![
        Line::from(Span::styled(
            " Paste a GitHub URL (detects the stack, nothing deployed yet) or a path to service.yaml:",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " GitHub URL or manifest path: ",
                Style::default().fg(WARN_YELLOW),
            ),
            Span::styled(buffer.to_string(), Style::default().fg(Color::White)),
            cursor_span(tick),
        ]),
    ];

    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    } else if !buffer.trim().is_empty() {
        let trimmed = buffer.trim();
        let (mark, msg, color) = if trimmed.starts_with("https://") {
            ("+", " looks like a GitHub URL", OK_GREEN)
        } else if crate::hoster::manifest::looks_like_manifest_path(trimmed) {
            ("+", " looks like a service.yaml path", OK_GREEN)
        } else {
            (
                "△",
                " expected https://github.com/<owner>/<repo> or a path to service.yaml",
                WARN_YELLOW,
            )
        };
        text.push(Line::from(Span::styled(
            format!(" {mark}{msg}"),
            Style::default().fg(color),
        )));
    }
    if busy {
        text.push(Line::from(vec![
            Span::styled(spinner_char(tick), spinner_style(tick)),
            Span::styled(" resolving...", Style::default().fg(WARN_YELLOW)),
        ]));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Deploy Service", WARN_YELLOW)),
        area,
    );
}

// --- confirmation gates ------------------------------------------------------

/// One selectable YES/NO button; the arrow keys move the highlight.
fn choice_spans(marker: &str, label: &str, hue: Color, selected: bool) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw("   ")];
    if selected {
        spans.push(Span::styled(
            "» ".to_string(),
            Style::default().fg(hue).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            marker.to_string(),
            Style::default()
                .fg(hue)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ));
        spans.push(Span::styled(
            label.to_string(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(marker.to_string(), Style::default().fg(DIM)));
        spans.push(Span::styled(
            label.to_string(),
            Style::default().fg(BODY_ALT),
        ));
    }
    spans
}

fn draw_confirm(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    target: &workers::DeployTarget,
    yes_selected: bool,
) {
    use workers::DeployTarget as Target;
    // Header rows differ by source; the YES/NO gate below is identical.
    let mut text = vec![Line::from("")];
    let (title, yes_label) = match target {
        Target::Detect { url, service_label } => {
            text.push(Line::from(vec![
                Span::styled(
                    " Detect ",
                    Style::default()
                        .fg(WARN_YELLOW)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(service_label.to_string(), Style::default().fg(Color::White)),
                Span::styled(" from GitHub?", Style::default().fg(BODY)),
            ]));
            text.push(Line::from(vec![
                Span::styled(" URL: ", Style::default().fg(DIM)),
                Span::styled(url.to_string(), Style::default().fg(ACCENT)),
            ]));
            text.push(Line::from(Span::styled(
                " Nothing is deployed yet: shallow clone → detect the stack → \
                 review the prefilled wizard.",
                Style::default().fg(DIM),
            )));
            ("Confirm Detect", " — detect stack")
        }
        Target::Manifest {
            path,
            service_id,
            plan,
        } => {
            text.push(Line::from(vec![
                Span::styled(
                    " Host ",
                    Style::default()
                        .fg(WARN_YELLOW)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(service_id.to_string(), Style::default().fg(Color::White)),
                Span::styled(
                    " (service.yaml) on this machine?",
                    Style::default().fg(BODY),
                ),
            ]));
            text.push(Line::from(vec![
                Span::styled(" File: ", Style::default().fg(DIM)),
                Span::styled(path.display().to_string(), Style::default().fg(ACCENT)),
            ]));
            // Validated plan excerpt: source, commit, profile, run, port.
            for line in plan.iter().take(6) {
                text.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().fg(DIM),
                )));
            }
            ("Confirm Deployment", " — deploy")
        }
    };
    // Outdated running build: the gate says so before [Y]es can be pressed —
    // the most likely moment the user would otherwise repeat a failed deploy.
    if crate::paths::binary_is_stale() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            " ⚠ this panel runs an OUTDATED build — the fixed binary is on disk.",
            Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
        )));
        text.push(Line::from(Span::styled(
            " Deploying now runs the old code (known deploy failures stay).",
            Style::default().fg(WARN_YELLOW),
        )));
        text.push(Line::from(Span::styled(
            " Quit (q) and relaunch the panel, then deploy again.",
            Style::default().fg(DIM),
        )));
    }
    text.extend([
        Line::from(""),
        Line::from(choice_spans("[Y]es", yes_label, OK_GREEN, yes_selected)),
        Line::from(choice_spans(
            "[N]o",
            " — cancel",
            WARN_YELLOW,
            !yes_selected,
        )),
        Line::from(""),
        Line::from(Span::styled(
            " ←→ select · Enter confirm",
            Style::default().fg(DIM),
        )),
    ]);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(title, WARN_YELLOW)),
        area,
    );
}

fn draw_confirm_delete(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    name: &str,
    yes_selected: bool,
) {
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " Remove ",
                Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(name.to_string(), Style::default().fg(Color::White)),
            Span::styled("?", Style::default().fg(ERR_RED)),
        ]),
        Line::from(Span::styled(
            " This deletes the unit, the cloned repository and its caches.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(choice_spans("[Y]es", " — remove", ERR_RED, yes_selected)),
        Line::from(choice_spans("[N]o", " — keep", OK_GREEN, !yes_selected)),
        Line::from(""),
        Line::from(Span::styled(
            " ←→ select · Enter confirm",
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Confirm Removal", ERR_RED)),
        area,
    );
}

fn draw_confirm_clear(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    target: LogView,
    yes_selected: bool,
) {
    let label = match target {
        LogView::Deploy => "deploy logs",
        LogView::Software => "software logs",
        LogView::Crash => "crash history",
    };
    let note = match target {
        LogView::Deploy => {
            "This truncates ~/.local/state/demo-ghostprovider/deploy.log and clears the view."
        }
        LogView::Software => {
            "This clears the displayed journal view (systemd journal itself is kept)."
        }
        LogView::Crash => {
            "This clears ~/.local/state/demo-ghostprovider/crash.log (interruption & removal history)."
        }
    };
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " Clear ",
                Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(label.to_string(), Style::default().fg(Color::White)),
            Span::styled("?", Style::default().fg(ERR_RED)),
        ]),
        Line::from(Span::styled(note, Style::default().fg(DIM))),
        Line::from(""),
        Line::from(choice_spans("[Y]es", " — clear", ERR_RED, yes_selected)),
        Line::from(choice_spans("[N]o", " — keep", OK_GREEN, !yes_selected)),
        Line::from(""),
        Line::from(Span::styled(
            " ←→ select · Enter confirm",
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Confirm Clear", ERR_RED)),
        area,
    );
}

/// Rows of the Add Service screen: two clickable actions on top, then the
/// stored manifests. Everything is reachable with ↑↓ + Enter — no hidden
/// hotkeys required (n/a/d/r still work as shortcuts).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LibRow {
    CreateNew,
    ImportFile,
    DetectUrl,
    Entry(usize),
}

/// Map a selection index to a row: 0 = create, 1 = import, 2 = detect,
/// 3.. = files.
fn lib_row(file_count: usize, selected: usize) -> Option<LibRow> {
    match selected {
        0 => Some(LibRow::CreateNew),
        1 => Some(LibRow::ImportFile),
        2 => Some(LibRow::DetectUrl),
        n => {
            let i = n - 3;
            if i < file_count {
                Some(LibRow::Entry(i))
            } else {
                None
            }
        }
    }
}

/// Total selectable rows for a given library size.
fn lib_row_count(file_count: usize) -> usize {
    file_count + 3
}

// --- add service (manifest library) -----------------------------------------

fn draw_add_service(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    files: &[crate::hoster::library::LibraryEntry],
    selected: usize,
    message: Option<&str>,
    armed_delete: Option<&str>,
) {
    let action_row = |label: &str, about: &str, row: LibRow| {
        let sel = lib_row(files.len(), selected) == Some(row);
        ListItem::new(Line::from(vec![
            Span::styled(if sel { " » " } else { "   " }, Style::default().fg(VIOLET)),
            Span::styled(
                label.to_string(),
                Style::default()
                    .fg(if sel { Color::White } else { BODY })
                    .add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(format!("  {about}"), Style::default().fg(DIM)),
        ]))
    };
    let mut items = vec![
        action_row(
            "+ Create new service.yaml",
            "step-by-step wizard (9 steps)",
            LibRow::CreateNew,
        ),
        action_row(
            "⇪ Import existing file",
            "copy from disk into the library",
            LibRow::ImportFile,
        ),
        action_row(
            "⇄ Detect from GitHub URL",
            "clone, detect stack, prefill wizard",
            LibRow::DetectUrl,
        ),
    ];
    if !files.is_empty() {
        items.push(ListItem::new(Line::from("")));
    }
    items.extend(files.iter().enumerate().map(|(i, e)| {
        let sel = lib_row(files.len(), selected) == Some(LibRow::Entry(i));
        let marker = if sel { " » " } else { "   " };
        let (status, hue) = if e.valid {
            ("ready", OK_GREEN)
        } else {
            ("invalid", ERR_RED)
        };
        let mut spans = vec![
            Span::styled(marker, Style::default().fg(if sel { VIOLET } else { DIM })),
            Span::styled(
                e.id.clone(),
                Style::default()
                    .fg(if sel { Color::White } else { BODY })
                    .add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(format!("  [{status}]"), Style::default().fg(hue)),
        ];
        if let Some(src) = e.source_git.as_deref() {
            spans.push(Span::styled(format!("  {src}"), Style::default().fg(DIM)));
        } else if let Some(err) = e.error.as_deref() {
            spans.push(Span::styled(
                format!("  {err}"),
                Style::default().fg(ERR_RED),
            ));
        }
        if armed_delete == Some(e.id.as_str()) {
            spans.push(Span::styled(
                "  ← press d again to delete",
                Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
            ));
        }
        ListItem::new(Line::from(spans))
    }));
    let mut block_widget = block("Add Service", VIOLET);
    if let Some(m) = message {
        block_widget = block_widget.title_bottom(Span::styled(
            format!(" {m} "),
            Style::default().fg(WARN_YELLOW),
        ));
    }
    f.render_widget(List::new(items).block(block_widget), area);
}

/// Deploy mark for one library row: ● when its id is deployed, ○ otherwise.
fn deployed_mark(deployed: &[String], id: &str) -> (&'static str, Color) {
    if deployed.iter().any(|d| d == id) {
        ("●", OK_GREEN)
    } else {
        ("○", DIM)
    }
}

fn draw_user_services(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    files: &[crate::hoster::library::LibraryEntry],
    deployed: &[String],
    selected: usize,
    message: Option<&str>,
) {
    if files.is_empty() {
        let mut text = vec![
            Line::from(""),
            Line::from(Span::styled(
                " No services added yet.",
                Style::default().fg(BODY),
            )),
            Line::from(Span::styled(
                " Use “Add Service” from the menu to import or create one.",
                Style::default().fg(DIM),
            )),
        ];
        if let Some(m) = message {
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                format!(" {m}"),
                Style::default().fg(WARN_YELLOW),
            )));
        }
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(block("My Services", BLUE)),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = files
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let sel = i == selected;
            let (mark, mark_hue) = deployed_mark(deployed, &e.id);
            let (status, hue) = if e.valid {
                ("ready", OK_GREEN)
            } else {
                ("invalid", ERR_RED)
            };
            let mut spans = vec![
                Span::styled(if sel { " » " } else { "   " }, Style::default().fg(BLUE)),
                Span::styled(
                    e.id.clone(),
                    Style::default()
                        .fg(if sel { Color::White } else { BODY })
                        .add_modifier(if sel {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(format!("  [{status}]"), Style::default().fg(hue)),
                Span::styled(format!("  {mark} "), Style::default().fg(mark_hue)),
                Span::styled(
                    if deployed.iter().any(|d| d == &e.id) {
                        "deployed"
                    } else {
                        "not deployed"
                    },
                    Style::default().fg(DIM),
                ),
            ];
            if let Some(src) = e.source_git.as_deref() {
                spans.push(Span::styled(format!("  {src}"), Style::default().fg(DIM)));
            } else if let Some(err) = e.error.as_deref() {
                spans.push(Span::styled(
                    format!("  {err}"),
                    Style::default().fg(ERR_RED),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut block_widget = block("My Services", BLUE);
    if let Some(m) = message {
        block_widget = block_widget.title_bottom(Span::styled(
            format!(" {m} "),
            Style::default().fg(WARN_YELLOW),
        ));
    }
    f.render_widget(List::new(items).block(block_widget), area);
}

/// Deployed services with their manifest status: id, [ready/invalid/no
/// manifest], display name and live URL. All rows are deployed by
/// construction, so the mark carries the manifest health instead.
fn draw_edit_service(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    rows: &[EditRow],
    selected: usize,
    message: Option<&str>,
) {
    if rows.is_empty() {
        let mut text = vec![
            Line::from(""),
            Line::from(Span::styled(
                " No deployed services yet.",
                Style::default().fg(BODY),
            )),
            Line::from(Span::styled(
                " Deploy one from “Deploy Service” — this menu edits units you already run.",
                Style::default().fg(DIM),
            )),
        ];
        if let Some(m) = message {
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                format!(" {m}"),
                Style::default().fg(WARN_YELLOW),
            )));
        }
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(block("Edit Service", ORANGE)),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let sel = i == selected;
            let (status, hue) = if row.path.is_none() {
                ("no manifest", ERR_RED)
            } else if row.valid {
                ("ready", OK_GREEN)
            } else {
                ("invalid", ERR_RED)
            };
            let mut spans = vec![
                Span::styled(if sel { " » " } else { "   " }, Style::default().fg(ORANGE)),
                Span::styled(
                    row.id.clone(),
                    Style::default()
                        .fg(if sel { Color::White } else { BODY })
                        .add_modifier(if sel {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(format!("  [{status}]"), Style::default().fg(hue)),
            ];
            if row.name != row.id {
                spans.push(Span::styled(
                    format!("  {}", row.name),
                    Style::default().fg(BODY_ALT),
                ));
            }
            if !row.url.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", row.url),
                    Style::default().fg(DIM),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut block_widget = block("Edit Service", ORANGE);
    if let Some(m) = message {
        block_widget = block_widget.title_bottom(Span::styled(
            format!(" {m} "),
            Style::default().fg(WARN_YELLOW),
        ));
    }
    f.render_widget(List::new(items).block(block_widget), area);
}

/// The six [`EDIT_FIELDS`] rows of one manifest: the selected row shows the
/// inline buffer with a blinking cursor while editing; errors (red) and the
/// last save result (yellow) hang under the list.
#[allow(clippy::too_many_arguments)]
fn draw_edit_service_form(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    id: &str,
    fields: &[String],
    sel: usize,
    buffer: &str,
    editing: bool,
    error: Option<&str>,
    message: Option<&str>,
    tick: u64,
) {
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Edit the manifest fields below — build steps, env, egress and",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " plugins stay untouched. Saving applies on the next deploy.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    for (i, label) in EDIT_FIELDS.iter().enumerate() {
        let row_sel = i == sel;
        let mut spans = vec![
            Span::styled(
                if row_sel { " » " } else { "   " },
                Style::default().fg(ORANGE),
            ),
            Span::styled(format!("{label}: "), Style::default().fg(DIM)),
        ];
        if row_sel && editing {
            spans.push(Span::styled(
                buffer.to_string(),
                Style::default().fg(Color::White),
            ));
            spans.push(cursor_span(tick));
        } else {
            let value = &fields[i];
            if value.is_empty() {
                spans.push(Span::styled("—", Style::default().fg(DIM)));
            } else {
                spans.push(Span::styled(
                    value.clone(),
                    Style::default().fg(if row_sel { Color::White } else { BODY }),
                ));
            }
        }
        text.push(Line::from(spans));
    }
    if let Some(e) = error {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    }
    if let Some(m) = message {
        text.push(Line::from(Span::styled(
            format!(" {m}"),
            Style::default().fg(WARN_YELLOW),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(&format!("Edit · {id}"), ORANGE)),
        area,
    );
}

/// Human byte counter for the Egress matrix (unit IP accounting).
fn human_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_egress(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    files: &[crate::hoster::library::LibraryEntry],
    deployed: &[String],
    counters: &HashMap<String, (u64, u64)>,
    verdicts: &HashMap<String, String>,
    checking: Option<&str>,
    selected: usize,
    message: Option<&str>,
) {
    if files.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    " No services added yet.",
                    Style::default().fg(BODY),
                )),
                Line::from(Span::styled(
                    " Use “Add Service” from the menu to import or create one.",
                    Style::default().fg(DIM),
                )),
            ])
            .wrap(Wrap { trim: false })
            .block(block("Egress", ERR_RED)),
            area,
        );
        return;
    }
    let mut items: Vec<ListItem> = Vec::new();
    for (i, e) in files.iter().enumerate() {
        let sel = i == selected;
        let marker = Span::styled(
            if sel { " » " } else { "   " },
            Style::default().fg(ERR_RED),
        );
        // Allow list, re-read from the validated file (cheap, always fresh).
        let (allow, auto): (Vec<String>, Option<bool>) = crate::hoster::library::load(&e.id)
            .map(|m| (m.egress.allow, m.egress.auto))
            .unwrap_or_default();
        let policy = if allow.is_empty() {
            "deny-all: REAL (private netns)".to_string()
        } else {
            let auto_marker = if auto == Some(true) { " (auto)" } else { "" };
            let best = if crate::hoster::egress::kernel_enforces_ip_filter() {
                ""
            } else {
                " · best-effort"
            };
            format!("allow: {}{auto_marker}{best}", allow.join(", "))
        };
        let traffic = match counters.get(&e.id) {
            Some((out, inn)) => {
                format!(" · ↑ {} ↓ {}", human_bytes(*out), human_bytes(*inn))
            }
            None if deployed.iter().any(|d| d == &e.id) => " · counters n/a".to_string(),
            None => String::new(),
        };
        items.push(ListItem::new(Line::from(vec![
            marker,
            Span::styled(
                e.id.clone(),
                Style::default()
                    .fg(if sel { Color::White } else { BODY })
                    .add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(format!("  {policy}{traffic}"), Style::default().fg(DIM)),
        ])));
        // Latest verification verdict under the row (first line: the
        // verdict itself; details re-appear on the next check).
        if checking == Some(e.id.as_str()) {
            items.push(ListItem::new(Line::from(Span::styled(
                "     checking…",
                Style::default().fg(WARN_YELLOW),
            ))));
        } else if let Some(v) = verdicts.get(&e.id)
            && let Some(first) = v.lines().next()
        {
            let hue = if first.contains("BLOCKED") {
                OK_GREEN
            } else if first.contains("OPEN") {
                ERR_RED
            } else {
                WARN_YELLOW
            };
            items.push(ListItem::new(Line::from(Span::styled(
                format!("     {first}"),
                Style::default().fg(hue),
            ))));
        }
    }
    let mut block_widget = block("Egress", ERR_RED);
    if let Some(m) = message {
        block_widget = block_widget.title_bottom(Span::styled(
            format!(" {m} "),
            Style::default().fg(WARN_YELLOW),
        ));
    }
    f.render_widget(List::new(items).block(block_widget), area);
}

#[allow(clippy::too_many_arguments)]
fn draw_egress_hosts(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    id: &str,
    hosts: &[String],
    selected: usize,
    buffer: &str,
    editing: bool,
    armed: bool,
    error: Option<&str>,
    message: Option<&str>,
    tick: u64,
) {
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Hostnames this service may reach (besides loopback). Saved on",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " every change — a redeploy renders the new unit filter.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    if hosts.is_empty() {
        text.push(Line::from(Span::styled(
            " (none — deny-all, loopback only)",
            Style::default().fg(DIM),
        )));
    }
    for (i, h) in hosts.iter().enumerate() {
        let sel = i == selected;
        text.push(Line::from(vec![
            Span::styled(
                if sel { " » " } else { "   " },
                Style::default().fg(ERR_RED),
            ),
            Span::styled(
                h.clone(),
                Style::default().fg(if sel { Color::White } else { BODY }),
            ),
        ]));
    }
    if armed {
        text.push(Line::from(Span::styled(
            " ← press d again to delete the highlighted host",
            Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
        )));
    }
    text.push(Line::from(""));
    if editing {
        text.push(Line::from(vec![
            Span::styled(" Add host: ", Style::default().fg(ERR_RED)),
            Span::styled(buffer.to_string(), Style::default().fg(Color::White)),
            cursor_span(tick),
        ]));
    }
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    }
    if let Some(m) = message {
        text.push(Line::from(Span::styled(
            format!(" {m}"),
            Style::default().fg(WARN_YELLOW),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(&format!("Egress · {id}"), ERR_RED)),
        area,
    );
}

fn draw_networks(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    rows: &[crate::networks::supervisor::NetworkRow],
    selected: usize,
    message: Option<&str>,
) {
    let mut title = Line::from(vec![
        Span::styled(" Networks ", Style::default().fg(MAGENTA)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("Enter", Style::default().fg(OK_GREEN)),
        Span::styled("]configure ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("s", Style::default().fg(OK_GREEN)),
        Span::styled("]hare ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("m", Style::default().fg(OK_GREEN)),
        Span::styled("]ail ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("x", Style::default().fg(ERR_RED)),
        Span::styled("]stop ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("r", Style::default().fg(ACCENT)),
        Span::styled("]efresh", Style::default().fg(DIM)),
    ]);
    if let Some(m) = message {
        title.push_span(Span::styled(
            format!("  — {m}"),
            Style::default().fg(WARN_YELLOW),
        ));
    }

    if rows.is_empty() {
        f.render_widget(
            Paragraph::new(vec![Line::from(Span::styled(
                " No deployed services to share.",
                Style::default().fg(DIM),
            ))])
            .block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
        return;
    }

    let footer: Vec<Line> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, row)| {
            if i != selected {
                return None;
            }
            let mut out = Vec::new();
            out.push(Line::from(vec![
                Span::styled(" local: ", Style::default().fg(DIM)),
                Span::styled(row.local_url.clone(), Style::default().fg(BODY)),
            ]));
            if let Some(url) = &row.public_url {
                out.push(Line::from(vec![
                    Span::styled(" public: ", Style::default().fg(DIM)),
                    Span::styled(url.clone(), Style::default().fg(OK_GREEN)),
                ]));
            }
            if let Some(msg) = &row.message {
                out.push(Line::from(vec![
                    Span::styled(" status: ", Style::default().fg(DIM)),
                    Span::styled(msg.clone(), Style::default().fg(WARN_YELLOW)),
                ]));
            }
            Some(out)
        })
        .flatten()
        .collect();

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let sel = i == selected;
            let status_color = match row.status {
                crate::networks::registry::ShareStatus::Live => OK_GREEN,
                crate::networks::registry::ShareStatus::Starting => WARN_YELLOW,
                crate::networks::registry::ShareStatus::Error => ERR_RED,
                crate::networks::registry::ShareStatus::Stopped => DIM,
            };
            let url = row
                .public_url
                .clone()
                .unwrap_or_else(|| row.status.label().to_string());
            ListItem::new(Line::from(vec![
                Span::styled(
                    if sel { " » " } else { "   " },
                    Style::default().fg(MAGENTA).add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                Span::styled(
                    format!("{:<16}", row.service),
                    Style::default()
                        .fg(if sel { Color::White } else { BODY })
                        .add_modifier(if sel {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(format!("  ● {url}"), Style::default().fg(status_color)),
                Span::styled(format!("  ({})", row.local_url), Style::default().fg(DIM)),
            ]))
        })
        .collect();

    let layout = Layout::vertical([Constraint::Min(1), Constraint::Length(6)]).split(area);
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        layout[0],
    );
    let bottom = Paragraph::new(footer)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(bottom, layout[1]);
}

fn draw_detect_input(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    buffer: &str,
    error: Option<&str>,
    busy: bool,
    tick: u64,
) {
    let mut text = vec![
        Line::from(Span::styled(
            " Paste a GitHub URL: it is cloned shallowly into a temp dir,",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " the stack is detected — autopilot deploys, the wizard reviews;",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " detection itself stores nothing.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" GitHub URL: ", Style::default().fg(VIOLET)),
            Span::styled(buffer.to_string(), Style::default().fg(Color::White)),
            cursor_span(tick),
        ]),
    ];
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    }
    if busy {
        text.push(Line::from(vec![
            Span::styled(spinner_char(tick), spinner_style(tick)),
            Span::styled(
                " fetching source and detecting stack...",
                Style::default().fg(WARN_YELLOW),
            ),
        ]));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Detect from GitHub URL", VIOLET)),
        area,
    );
}

fn draw_import(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    buffer: &str,
    error: Option<&str>,
    tick: u64,
) {
    let mut text = vec![
        Line::from(Span::styled(
            " Copy a service.yaml file into your library (~/.local/share/demo-ghostprovider/manifests).",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Manifest file path: ", Style::default().fg(VIOLET)),
            Span::styled(buffer.to_string(), Style::default().fg(Color::White)),
            cursor_span(tick),
        ]),
    ];
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    } else if !buffer.trim().is_empty() {
        let (mark, msg, color) = if crate::hoster::manifest::looks_like_manifest_path(buffer.trim())
        {
            ("+", " looks like a service.yaml path", OK_GREEN)
        } else {
            ("△", " expected /path/to/service.yaml", WARN_YELLOW)
        };
        text.push(Line::from(Span::styled(
            format!(" {mark}{msg}"),
            Style::default().fg(color),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Import service.yaml", VIOLET)),
        area,
    );
}

// --- new-service wizard -------------------------------------------------------

/// Generic one-field wizard screen: explanation lines + prompt + buffer.
#[allow(clippy::too_many_arguments)]
fn draw_wz_input(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    title: &str,
    explain: &[&str],
    prompt: &str,
    buffer: &str,
    error: Option<&str>,
    tick: u64,
) {
    let mut text = vec![Line::from("")];
    for line in explain {
        text.push(Line::from(Span::styled(
            format!(" {line}"),
            Style::default().fg(DIM),
        )));
    }
    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::styled(prompt.to_string(), Style::default().fg(VIOLET)),
        Span::styled(buffer.to_string(), Style::default().fg(Color::White)),
        cursor_span(tick),
    ]));
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(title, VIOLET)),
        area,
    );
}

fn draw_wz_profile(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    selected: usize,
    draft: &wizard::Draft,
) {
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " What is the project built with? The next steps are prefilled for it.",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " (changing the profile later resets those steps)",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    for (i, (id, about)) in wizard::PROFILES.iter().enumerate() {
        let sel = i == selected;
        text.push(Line::from(vec![
            Span::styled(if sel { " » " } else { "   " }, Style::default().fg(VIOLET)),
            Span::styled(
                format!("{id} "),
                Style::default()
                    .fg(if sel { Color::White } else { BODY })
                    .add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(format!("— {about}"), Style::default().fg(DIM)),
        ]));
    }
    // Detection notes: what was guessed and what must be verified. They
    // travel with the draft until a profile switch replaces them.
    if draft.detected && !draft.notes.is_empty() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            " Detected — verify on the next steps:",
            Style::default().fg(WARN_YELLOW),
        )));
        for note in &draft.notes {
            text.push(Line::from(Span::styled(
                format!("  ⚠ {note}"),
                Style::default().fg(WARN_YELLOW),
            )));
        }
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("New Service 4/9 · build profile", VIOLET)),
        area,
    );
}

fn draw_wz_steps(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    title: &str,
    explain: &[&str],
    editor: &wizard::StepEditor,
    tick: u64,
) {
    let mut text = vec![Line::from("")];
    for line in explain {
        text.push(Line::from(Span::styled(
            format!(" {line}"),
            Style::default().fg(DIM),
        )));
    }
    text.push(Line::from(""));
    if editor.lines.is_empty() {
        text.push(Line::from(Span::styled(
            " (no steps — press a to add one, Enter when done)",
            Style::default().fg(DIM),
        )));
    }
    for (i, line) in editor.lines.iter().enumerate() {
        let sel = i == editor.selected;
        if editor.editing.is_some() && sel {
            let buf = editor.editing.as_deref().unwrap_or("");
            text.push(Line::from(vec![
                Span::styled(" » ", Style::default().fg(VIOLET)),
                Span::styled(buf.to_string(), Style::default().fg(Color::White)),
                cursor_span(tick),
            ]));
        } else {
            text.push(Line::from(vec![
                Span::styled(if sel { " » " } else { "   " }, Style::default().fg(VIOLET)),
                Span::styled(
                    line.clone(),
                    Style::default().fg(if sel { Color::White } else { BODY }),
                ),
            ]));
        }
    }
    if let Some(m) = editor.message.as_deref() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            format!(" {m}"),
            Style::default().fg(WARN_YELLOW),
        )));
    }
    // Inline-edit mode is entered with `e`, not Enter — say so while it is
    // on, otherwise the cursor looks like a dead keypress.
    if editor.editing.is_some() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            " editing — Enter confirms the line, Esc cancels",
            Style::default().fg(WARN_YELLOW),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(title, VIOLET)),
        area,
    );
}

fn draw_wz_run(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    cmd: &str,
    port: &str,
    focus_port: bool,
    error: Option<&str>,
    tick: u64,
) {
    let cursor_here = |focused: bool| {
        if focused {
            cursor_span(tick)
        } else {
            Span::raw("")
        }
    };
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " How is the built service started? One command, words split on spaces.",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            " Placeholders: {bin} {venv} {self} {project} {port}. Must bind 127.0.0.1.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Run: ", Style::default().fg(VIOLET)),
            Span::styled(cmd.to_string(), Style::default().fg(Color::White)),
            cursor_here(!focus_port),
        ]),
        Line::from(vec![
            Span::styled(" Port (0 = random): ", Style::default().fg(VIOLET)),
            Span::styled(port.to_string(), Style::default().fg(Color::White)),
            cursor_here(focus_port),
        ]),
    ];
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    } else {
        text.push(Line::from(Span::styled(
            " Tab switches fields",
            Style::default().fg(DIM),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("New Service 7/9 · run", VIOLET)),
        area,
    );
}

fn draw_wz_res(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    memory: &str,
    tasks: &str,
    focus_tasks: bool,
    error: Option<&str>,
    tick: u64,
) {
    let cursor_here = |focused: bool| {
        if focused {
            cursor_span(tick)
        } else {
            Span::raw("")
        }
    };
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Safety budgets: a runaway service must never grind your session.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Memory max (e.g. 384M, 1G): ", Style::default().fg(VIOLET)),
            Span::styled(memory.to_string(), Style::default().fg(Color::White)),
            cursor_here(!focus_tasks),
        ]),
        Line::from(vec![
            Span::styled(" Tasks max (e.g. 300): ", Style::default().fg(VIOLET)),
            Span::styled(tasks.to_string(), Style::default().fg(Color::White)),
            cursor_here(focus_tasks),
        ]),
    ];
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    } else {
        text.push(Line::from(Span::styled(
            " Tab switches fields",
            Style::default().fg(DIM),
        )));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("New Service 8/9 · limits", VIOLET)),
        area,
    );
}

fn draw_wz_review(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    yaml: Option<&str>,
    error: Option<&str>,
) {
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            " This exact file will be saved into your library. Read it once more.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    match yaml {
        Some(y) => {
            // Fit the preview into the visible area; the file itself is whole.
            let budget = area.height.saturating_sub(10) as usize;
            let shown: Vec<&str> = y.lines().take(budget.max(4)).collect();
            for line in shown {
                text.push(Line::from(Span::styled(
                    line.to_string(),
                    Style::default().fg(BODY),
                )));
            }
            if y.lines().count() > budget.max(4) {
                text.push(Line::from(Span::styled(
                    " …(truncated on screen — saved whole)",
                    Style::default().fg(DIM),
                )));
            }
        }
        None => {
            text.push(Line::from(Span::styled(
                " The draft does not validate yet:",
                Style::default().fg(ERR_RED),
            )));
        }
    }
    if let Some(e) = error {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(ERR_RED),
        )));
    }
    f.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block(
            "New Service 9/9 · review (Enter saves + deploys)",
            VIOLET,
        )),
        area,
    );
}

/// Blinking terminal-style cursor block.
fn cursor_span(tick: u64) -> Span<'static> {
    if (tick / 4).is_multiple_of(2) {
        Span::styled("█", Style::default().fg(WARN_YELLOW))
    } else {
        Span::raw(" ")
    }
}

// --- deploy -----------------------------------------------------------------

fn draw_deploy(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    lines: &[String],
    done: Option<bool>,
    net: Option<crate::netstatus::NetSummary>,
) {
    let inner = Layout::vertical([
        Constraint::Length(net.map_or(0, |_| 1)),
        Constraint::Min(1),
        Constraint::Length(done.map_or(0, |_| 1)),
    ])
    .split(area);
    if let Some(n) = net {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " ⚠ NET ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(WARN_YELLOW)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " {} host(s) unreachable — permanent retry, next probe is automatic (since {})",
                        n.down_hosts,
                        fmt_time(n.since)
                    ),
                    Style::default().fg(WARN_YELLOW),
                ),
            ])),
            inner[0],
        );
    }
    let mut spans: Vec<Line> = Vec::new();
    let mut prev_doctor = false;
    for l in lines {
        let t = l.trim_start();
        let is_doctor = t.starts_with("! ") && doctor_body_markers(t);
        if is_doctor && !prev_doctor {
            if !spans.is_empty() {
                spans.push(Line::from(""));
            }
            spans.push(Line::from(vec![
                Span::styled(" ──", Style::default().fg(DIM)),
                Span::styled(
                    " TOOL DOCTOR ",
                    Style::default()
                        .fg(WARN_YELLOW)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("────────────────", Style::default().fg(DIM)),
            ]));
        }
        spans.extend(log_lines(l));
        prev_doctor = is_doctor;
    }
    f.render_widget(
        Paragraph::new(spans)
            .wrap(Wrap { trim: false })
            .block(block("Deployment", MAGENTA)),
        inner[1],
    );
    if let Some(ok) = done {
        let (label, fg) = if ok {
            (" ✔ DEPLOYED ✔ ", OK_GREEN)
        } else {
            (" ✖ FAILED ✖ ", ERR_RED)
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                label,
                Style::default()
                    .fg(Color::Black)
                    .bg(fg)
                    .add_modifier(Modifier::BOLD),
            )))
            .alignment(ratatui::layout::Alignment::Center),
            inner[2],
        );
    }
}

fn fmt_time(d: std::time::Duration) -> String {
    let total = d.as_secs();
    if total >= 3600 {
        format!("{}h{}m", total / 3600, (total % 3600) / 60)
    } else if total >= 60 {
        format!("{}m{}s", total / 60, total % 60)
    } else {
        format!("{total}s")
    }
}

/// Colorize one deployment log line; tool-doctor issues get structured
/// multi-line treatment (problem / fix command / note).
fn log_lines(line: &str) -> Vec<Line<'static>> {
    let s = line.trim_start();
    if let Some(body) = s.strip_prefix("! ") {
        if doctor_body_markers(s) {
            return doctor_lines(body).expect("doctor marker verified above");
        }
        return vec![Line::from(vec![
            Span::styled(
                " ✖ ".to_string(),
                Style::default().fg(ERR_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(body.to_string(), Style::default().fg(ERR_RED)),
        ])];
    }
    if let Some(body) = s.strip_prefix("warn: ") {
        return vec![Line::from(vec![
            Span::styled(
                " ! ".to_string(),
                Style::default()
                    .fg(WARN_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(body.to_string(), Style::default().fg(WARN_YELLOW)),
        ])];
    }
    if let Some(url) = s.strip_prefix("listening on ") {
        return vec![Line::from(vec![
            Span::styled(" ✔ listening on ", Style::default().fg(OK_GREEN)),
            Span::styled(
                url.to_string(),
                Style::default().fg(OK_GREEN).add_modifier(Modifier::BOLD),
            ),
        ])];
    }
    let style = if s.contains("failed") || s.contains("ERROR") {
        Style::default().fg(ERR_RED)
    } else if s.ends_with("...") {
        Style::default().fg(WARN_YELLOW)
    } else if s.starts_with("=>") {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(BODY)
    };
    vec![Line::from(Span::styled(format!(" {line}"), style))]
}

/// A doctor issue carries a problem statement plus an explicit fix command.
fn doctor_body_markers(s: &str) -> bool {
    crate::hoster::toolcheck::is_issue_line(s)
}

fn doctor_lines(body: &str) -> Option<Vec<Line<'static>>> {
    let (problem, cmd, note) = crate::hoster::toolcheck::split_issue(body)?;
    let mut out = vec![
        Line::from(vec![
            Span::styled(
                " ! ".to_string(),
                Style::default()
                    .fg(WARN_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(problem.to_string(), Style::default().fg(ERR_RED)),
        ]),
        Line::from(vec![
            Span::styled("   fix » ".to_string(), Style::default().fg(DIM)),
            Span::styled(
                cmd.to_string(),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    if let Some(n) = note {
        out.push(Line::from(vec![
            Span::styled("      ".to_string(), Style::default().fg(DIM)),
            Span::styled(n.to_string(), Style::default().fg(DIM)),
        ]));
    }
    Some(out)
}

// --- my services ------------------------------------------------------------

fn draw_services(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    rows: &[workers::ServiceRow],
    selected: usize,
    message: Option<&str>,
) {
    let mut title = Line::from(vec![
        Span::styled(" Self-Hosting ", Style::default().fg(BLUE)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("s", Style::default().fg(WARN_YELLOW)),
        Span::styled("]top ", Style::default().fg(DIM)),
        Span::styled("star", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("t", Style::default().fg(OK_GREEN)),
        Span::styled("] ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("d", Style::default().fg(ERR_RED)),
        Span::styled("]elete ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("r", Style::default().fg(ACCENT)),
        Span::styled("]efresh", Style::default().fg(DIM)),
    ]);
    if let Some(m) = message {
        title.push_span(Span::styled(
            format!("  — {m}"),
            Style::default().fg(WARN_YELLOW),
        ));
    }

    if rows.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    " No services deployed yet.",
                    Style::default().fg(DIM),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    " Use “Deploy Service” from the menu.",
                    Style::default().fg(MAGENTA),
                )),
            ])
            .block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let sel = i == selected;
            // No background fills — selection is arrow + bold + white,
            // zebra alternates text shades only.
            let name_fg = if sel {
                Color::White
            } else if !row.managed {
                DIM
            } else if i % 2 == 1 {
                BODY_ALT
            } else {
                BODY
            };
            let url_fg = DIM;
            let status_color = match row.status.as_str() {
                "active" | "running" => OK_GREEN,
                "activating" | "reloading" | "stopped" | "needs login" => WARN_YELLOW,
                _ => ERR_RED,
            };
            // Read-only status rows (tailscale) carry a [vpn] tag instead of
            // the plain managed-unit name column. The left column is the
            // human name; the unit id always trails the URL in parens.
            let name_col = if row.managed {
                format!("{:<16}", row.display)
            } else {
                format!("[vpn] {:<10}", row.display)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    if sel { " » " } else { "   " },
                    Style::default().fg(ACCENT).add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                Span::styled(
                    name_col,
                    Style::default().fg(name_fg).add_modifier(if sel {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                format!("{:<12}", "").into(),
                Span::styled("● ", Style::default().fg(status_color)),
                Span::styled(row.status.clone(), Style::default().fg(status_color)),
                Span::styled(format!("  {}", row.url), Style::default().fg(url_fg)),
                Span::styled(format!("  ({})", row.name), Style::default().fg(DIM)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

// --- logs -------------------------------------------------------------------

/// Style for one log line. Deploy/software lines use the usual verdict
/// colours; crash-history lines are coloured by their `[kind]` tag
/// (`interrupted` red, `recovered` yellow, `removed` green, `ghost` dim).
fn log_line_style(l: &str) -> Style {
    let s = l.trim_start();
    if s.contains("[interrupted]") {
        Style::default().fg(ERR_RED)
    } else if s.contains("[recovered]") {
        Style::default().fg(WARN_YELLOW)
    } else if s.contains("[removed]") {
        Style::default().fg(OK_GREEN)
    } else if s.contains("[ghost]") {
        Style::default().fg(DIM)
    } else if s.contains("failed") || s.contains("ERROR") || s.starts_with('!') {
        Style::default().fg(ERR_RED)
    } else if s.starts_with('✔') {
        Style::default().fg(OK_GREEN).add_modifier(Modifier::BOLD)
    } else if s.starts_with("provision:") || s.starts_with("warn:") {
        Style::default().fg(WARN_YELLOW)
    } else {
        Style::default().fg(BODY)
    }
}

fn draw_logs(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    view: LogView,
    deploy_lines: &[String],
    software_lines: &[String],
    crash_lines: &[String],
    scroll: usize,
) {
    let (title, lines, active_color) = match view {
        LogView::Deploy => (" Deploy Logs ", deploy_lines, WARN_YELLOW),
        LogView::Software => (" Software Logs ", software_lines, OK_GREEN),
        LogView::Crash => (" Crash Logs ", crash_lines, VIOLET),
    };
    let tab_span = |label: &str, active: bool, color: Color| {
        Span::styled(
            if active {
                format!(" [{label}] ")
            } else {
                format!("  {label}  ")
            },
            ratatui::style::Style::default()
                .fg(if active { color } else { DIM })
                .add_modifier(if active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )
    };
    let tab_bar = Line::from(vec![
        tab_span("DEPLOY", view == LogView::Deploy, WARN_YELLOW),
        Span::styled(" · ", Style::default().fg(DIM)),
        tab_span("SOFTWARE", view == LogView::Software, OK_GREEN),
        Span::styled(" · ", Style::default().fg(DIM)),
        tab_span("CRASH", view == LogView::Crash, VIOLET),
        Span::styled("  (Tab to switch)", Style::default().fg(DIM)),
    ]);
    let inner = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(1),
        ratatui::layout::Constraint::Min(1),
    ])
    .split(area);
    f.render_widget(Paragraph::new(tab_bar), inner[0]);
    if lines.is_empty() {
        let empty_msg = match view {
            LogView::Deploy => "No deploy logs yet. Start a deployment to see output here.",
            LogView::Software => "No software logs yet. Journal output will appear here.",
            LogView::Crash => {
                "No crash events yet. Interrupt a deploy or remove a service to see history here."
            }
        };
        f.render_widget(
            Paragraph::new(Span::styled(empty_msg, Style::default().fg(DIM)))
                .block(block(title.trim(), active_color)),
            inner[1],
        );
        return;
    }
    let visible: Vec<Line> = lines[scroll.min(lines.len())..]
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), log_line_style(l))))
        .collect();
    f.render_widget(
        Paragraph::new(visible)
            .wrap(Wrap { trim: false })
            .block(block(title.trim(), active_color)),
        inner[1],
    );
}

// --- wizard progress chain --------------------------------------------------

/// The nine New Service wizard screens in order — one short label each,
/// rendered at the top of every wizard body as `✓ done · » current · next`.
const WIZARD_STEPS: &[&str] = &[
    "name", "src", "pin", "profile", "deps", "build", "run", "limits", "review",
];

/// Position of `screen` in [`WIZARD_STEPS`]; None outside the wizard.
fn wizard_step(screen: &Screen) -> Option<usize> {
    Some(match screen {
        Screen::WzId { .. } => 0,
        Screen::WzGit { .. } => 1,
        Screen::WzCommit { .. } => 2,
        Screen::WzProfile { .. } => 3,
        Screen::WzPrefetch { .. } => 4,
        Screen::WzBuild { .. } => 5,
        Screen::WzRun { .. } => 6,
        Screen::WzRes { .. } => 7,
        Screen::WzReview { .. } => 8,
        _ => return None,
    })
}

fn wizard_progress(current: usize) -> Line<'static> {
    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    for (i, label) in WIZARD_STEPS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(DIM)));
        }
        if i == current {
            spans.push(Span::styled(
                format!("» {label}"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if i < current {
            spans.push(Span::styled(
                format!("✓ {label}"),
                Style::default().fg(OK_GREEN),
            ));
        } else {
            spans.push(Span::styled((*label).to_string(), Style::default().fg(DIM)));
        }
    }
    Line::from(spans)
}

// --- hint bar ---------------------------------------------------------------

fn hint_line(screen: &Screen) -> Line<'static> {
    let pairs: Vec<(&'static str, Color)> = match screen {
        Screen::Main { .. } => vec![
            ("↑↓ select", ACCENT),
            ("Enter choose", OK_GREEN),
            ("q quit", MAGENTA),
        ],
        Screen::Scan { .. } => vec![("Esc back", VIOLET)],
        Screen::UrlInput { busy, .. } => {
            if *busy {
                vec![("working…", WARN_YELLOW)]
            } else {
                vec![
                    ("Enter deploy", OK_GREEN),
                    ("Tab wizard", VIOLET),
                    ("Esc back", WARN_YELLOW),
                ]
            }
        }
        Screen::Confirm { .. } => vec![
            ("←→ select", ACCENT),
            ("Y/N", OK_GREEN),
            ("Enter confirm", OK_GREEN),
            ("Esc cancel", WARN_YELLOW),
        ],
        Screen::ConfirmDelete { .. } => vec![
            ("←→ select", ACCENT),
            ("Y/N", ERR_RED),
            ("Enter confirm", OK_GREEN),
            ("Esc keep", OK_GREEN),
        ],
        Screen::Deploy { done, .. } => {
            if done.is_some() {
                vec![("Enter back", MAGENTA)]
            } else {
                vec![("working…", WARN_YELLOW)]
            }
        }
        Screen::Services { .. } => vec![
            ("↑↓ select", BLUE),
            ("[s]top star[t] [d]elete [r]estart", BLUE),
            ("Esc back", BLUE),
        ],
        Screen::Logs { .. } => vec![
            ("Tab switch", WARN_YELLOW),
            ("↑↓ scroll", BLUE),
            ("[d]elete", ERR_RED),
            ("Esc back", VIOLET),
        ],
        Screen::ConfirmClear { .. } => vec![
            ("←→ select", ACCENT),
            ("Y/N", ERR_RED),
            ("Enter confirm", OK_GREEN),
            ("Esc cancel", WARN_YELLOW),
        ],
        Screen::AddService { .. } => vec![
            ("Enter choose", OK_GREEN),
            ("e edit", VIOLET),
            ("d delete", ERR_RED),
            ("r refresh", BLUE),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::Import { .. } => vec![("Enter import", OK_GREEN), ("Esc back", WARN_YELLOW)],
        Screen::DetectInput { busy, .. } => {
            if *busy {
                vec![("working…", WARN_YELLOW)]
            } else {
                vec![("Enter detect", OK_GREEN), ("Esc back", WARN_YELLOW)]
            }
        }
        Screen::UserServices { .. } => vec![
            ("Enter open", OK_GREEN),
            ("e edit", VIOLET),
            ("r refresh", BLUE),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::Egress { .. } => vec![
            ("Enter edit", OK_GREEN),
            ("v verify", VIOLET),
            ("r refresh", BLUE),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::EgressHosts { .. } => vec![
            ("Enter add", OK_GREEN),
            ("d delete", ERR_RED),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::EditService { .. } => vec![
            ("↑↓ select", ORANGE),
            ("Enter edit", OK_GREEN),
            ("r refresh", BLUE),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::EditServiceForm { editing, .. } => {
            if *editing {
                vec![("Enter confirm", OK_GREEN), ("Esc cancel", WARN_YELLOW)]
            } else {
                vec![
                    ("Enter edit row", OK_GREEN),
                    ("s save", VIOLET),
                    ("r redeploy", MAGENTA),
                    ("e editor", VIOLET),
                    ("Esc back", WARN_YELLOW),
                ]
            }
        }
        Screen::Networks { .. } => vec![
            ("↑↓ select", MAGENTA),
            ("s share", OK_GREEN),
            ("x stop", ERR_RED),
            ("r refresh", ACCENT),
            ("Esc back", WARN_YELLOW),
        ],
        // Wizard hints name their destination: after Enter the next screen
        // must be predictable, not a surprise.
        Screen::WzId { .. } => vec![("Enter → source", OK_GREEN), ("Esc back", WARN_YELLOW)],
        Screen::WzGit { .. } => vec![("Enter → version pin", OK_GREEN), ("Esc back", WARN_YELLOW)],
        Screen::WzCommit { .. } => vec![("Enter → profile", OK_GREEN), ("Esc back", WARN_YELLOW)],
        Screen::WzProfile { .. } => vec![
            ("↑↓ select", VIOLET),
            ("Enter → download steps", OK_GREEN),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::WzPrefetch { editor, .. } => {
            if editor.editing.is_some() {
                vec![("Enter confirm", OK_GREEN), ("Esc cancel", WARN_YELLOW)]
            } else {
                vec![
                    ("Enter → build offline", OK_GREEN),
                    ("e edit", VIOLET),
                    ("a add", VIOLET),
                    ("d del", VIOLET),
                    ("Esc back", WARN_YELLOW),
                ]
            }
        }
        Screen::WzBuild { editor, .. } => {
            if editor.editing.is_some() {
                vec![("Enter confirm", OK_GREEN), ("Esc cancel", WARN_YELLOW)]
            } else {
                vec![
                    ("Enter → run", OK_GREEN),
                    ("e edit", VIOLET),
                    ("a add", VIOLET),
                    ("d del", VIOLET),
                    ("Esc back", WARN_YELLOW),
                ]
            }
        }
        Screen::WzRun { .. } => vec![
            ("Tab field", ACCENT),
            ("Enter → limits", OK_GREEN),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::WzRes { .. } => vec![
            ("Tab field", ACCENT),
            ("Enter → review", OK_GREEN),
            ("Esc back", WARN_YELLOW),
        ],
        Screen::WzReview { .. } => vec![
            ("Enter save + deploy", OK_GREEN),
            ("s save only", VIOLET),
            ("Esc back", WARN_YELLOW),
        ],
    };
    // Mid-deploy and the confirm dialog keep their own hints: the dialog
    // already carries the full outdated-build warning (plus the nav keys),
    // and relaunching mid-deploy would kill the running pipeline.
    let stale = crate::paths::binary_is_stale()
        && !matches!(
            screen,
            Screen::Deploy { done: None, .. } | Screen::Confirm { .. }
        );
    let pairs = stale_hint_pairs(pairs, stale);
    let mut spans: Vec<Span> = Vec::new();
    for (i, (text, color)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(DIM)));
        }
        spans.push(Span::styled(
            format!(" {text}"),
            Style::default().fg(*color),
        ));
    }
    Line::from(spans)
}

/// A stale running build replaces the whole hint bar: while the panel is
/// running old code, "relaunch" beats every navigation hint. Fresh builds
/// pass the per-screen hints through untouched.
fn stale_hint_pairs(pairs: Vec<(&'static str, Color)>, stale: bool) -> Vec<(&'static str, Color)> {
    if stale {
        vec![("⟳ newer build on disk — relaunch panel", ERR_RED)]
    } else {
        pairs
    }
}

fn block(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hint bar collapses to the relaunch notice only on a stale build;
    /// a fresh build must keep the per-screen navigation hints.
    #[test]
    fn stale_hint_replaces_the_bar_but_fresh_keeps_it() {
        let base = vec![("Enter choose", OK_GREEN), ("q quit", MAGENTA)];
        let fresh = stale_hint_pairs(base.clone(), false);
        assert_eq!(fresh.len(), 2);
        assert_eq!(fresh[0].0, "Enter choose");

        let stale = stale_hint_pairs(base, true);
        assert_eq!(stale.len(), 1);
        assert!(stale[0].0.contains("relaunch"));
        assert_eq!(stale[0].1, ERR_RED);
    }

    /// The menu is the single source of truth: five items, Add Service last.
    /// Navigation caps derive from MAIN_MENU so this guards desync.
    #[test]
    fn lib_rows_map_selection_to_actions_and_files() {
        assert_eq!(lib_row(0, 0), Some(LibRow::CreateNew));
        assert_eq!(lib_row(0, 1), Some(LibRow::ImportFile));
        assert_eq!(lib_row(0, 2), Some(LibRow::DetectUrl));
        assert_eq!(lib_row(0, 3), None);
        assert_eq!(lib_row(2, 0), Some(LibRow::CreateNew));
        assert_eq!(lib_row(2, 1), Some(LibRow::ImportFile));
        assert_eq!(lib_row(2, 2), Some(LibRow::DetectUrl));
        assert_eq!(lib_row(2, 3), Some(LibRow::Entry(0)));
        assert_eq!(lib_row(2, 4), Some(LibRow::Entry(1)));
        assert_eq!(lib_row(2, 5), None);
        assert_eq!(lib_row_count(0), 3);
        assert_eq!(lib_row_count(3), 6);
    }

    /// The menu is the single source of truth: Self-Hosting manages units,
    /// My Services lists the user's own added services, Edit Service edits
    /// the deployed ones. Navigation caps derive from MAIN_MENU so this
    /// guards desync.
    #[test]
    fn main_menu_lists_networks_under_system_scan() {
        let titles: Vec<&str> = MAIN_MENU.iter().map(|(_, t, _, _)| *t).collect();
        assert_eq!(
            titles,
            vec![
                "System Scan",
                "Networks",
                "Self-Hosting",
                "Deploy Service",
                "Add Service",
                "My Services",
                "Edit Service",
                "Egress",
                "Logs"
            ]
        );
    }

    /// The brand art is the exact ANSI Shadow rendering picked in
    /// ~/Documents/style: six equal-width lines, verbatim (the outline
    /// frame ═║╔╗╚╝ is part of the glyphs).
    #[test]
    fn main_art_is_six_equal_ansi_shadow_lines() {
        assert_eq!(MAIN_ART.len(), 6);
        let w = MAIN_ART[0].chars().count();
        assert!(w >= 100, "art should span a full headline, got {w} cols");
        for line in MAIN_ART {
            assert_eq!(line.chars().count(), w, "all art lines share one width");
        }
        assert!(
            MAIN_ART[0].trim_start().starts_with("██████╗"),
            "starts with G"
        );
        assert!(MAIN_ART[5].trim_end().ends_with("╚═╝"), "ends with R");
    }

    /// Arrows step through the centered list one item at a time.
    #[test]
    fn main_menu_arrows_move_linearly() {
        let mut s = 0usize;
        move_main_selection(&mut s, KeyCode::Down);
        assert_eq!(s, 1);
        move_main_selection(&mut s, KeyCode::Right);
        assert_eq!(s, 2);
        move_main_selection(&mut s, KeyCode::Up);
        assert_eq!(s, 1);
        move_main_selection(&mut s, KeyCode::Left);
        assert_eq!(s, 0);
        move_main_selection(&mut s, KeyCode::Left);
        assert_eq!(s, 0, "left saturates at the first item");
        let mut last = MAIN_MENU.len() - 1;
        move_main_selection(&mut last, KeyCode::Down);
        assert_eq!(last, MAIN_MENU.len() - 1, "down clamps at the last item");
    }

    /// The scaled art is a nearest-neighbour zoom of the exact same
    /// bitmap: each glyph cell (outline frame included) repeats n×n —
    /// bigger, never re-drawn. Sampling every n-th cell of every n-th
    /// row must give the original style-file art back exactly.
    #[test]
    fn ansi_shadow_art_scales_to_n_times_the_size() {
        for n in 1..=4u16 {
            let big = expand_art(MAIN_ART, n);
            assert_eq!(big.len(), MAIN_ART.len() * n as usize);
            let w = MAIN_ART[0].chars().count() * n as usize;
            assert_eq!(big[0].chars().count(), w);
            if n == 1 {
                assert_eq!(big[0], MAIN_ART[0], "1x is verbatim");
                continue;
            }
            for (j, line) in MAIN_ART.iter().enumerate() {
                let sampled: String = big[j * n as usize].chars().step_by(n as usize).collect();
                assert_eq!(sampled.as_str(), *line, "row {j} at {n}x samples to 1x");
            }
        }
    }

    /// The scale follows the terminal: wider gets bigger (up to 4×), but a
    /// short terminal caps the art so the (always packed) menu still fits.
    /// Base width is 108 cells: 2× needs 216+, 3× 324+, 4× 432+ columns.
    #[test]
    fn art_scale_grows_with_width_and_shrinks_with_height() {
        let s = |w, h| art_scale(ratatui::prelude::Rect::new(0, 0, w, h));
        assert_eq!(s(120, 40), 1, "narrow: 1x");
        assert_eq!(s(220, 50), 2, "2x width fits at 216+");
        assert_eq!(s(330, 60), 3, "3x width fits at 324+");
        assert_eq!(s(440, 80), 4, "wide: 4x");
        assert_eq!(s(440, 30), 2, "short: capped so the menu fits");
        assert_eq!(s(50, 10), 1, "tiny: never below 1x");
    }

    /// The main screen renders the ANSI Shadow art and subtitle as one block
    /// with the free space split into thirds (above brand / between brand
    /// and menu / below menu); menu items share a common left edge (the
    /// block is centered, not each line); the selected description sits on
    /// the very bottom row.
    #[test]
    fn main_menu_screen_renders_art_subtitles_and_list() {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| draw_main_menu(f, f.area(), 3)).unwrap();
        let buf = term.backend().buffer();
        let mut text = String::new();
        let mut art_row = None;
        let mut demo_row = None;
        let mut scan_col = None;
        let mut scan_row = None;
        let mut deploy_col = None;
        let mut desc_row = None;
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            if art_row.is_none() && row.contains(MAIN_ART[0]) {
                art_row = Some(y);
            }
            if row.contains("demo panel") {
                demo_row = Some(y);
            }
            if let Some(col) = row.find("@ System Scan") {
                scan_col = Some(col);
                scan_row = Some(y);
            }
            if let Some(col) = row.find("^ Deploy Service") {
                deploy_col = Some(col);
            }
            if row.contains("deploy via GitHub URL or service.yaml") {
                desc_row = Some(y);
            }
            text.push_str(&row);
            text.push('\n');
        }
        let version_line = format!("v{}", env!("CARGO_PKG_VERSION"));
        for expected in [
            MAIN_ART[0],
            "SYSTEM FOR AUTOMATED SELF-HOSTING",
            "demo panel",
            version_line.as_str(),
            "System Scan",
            "Deploy Service",
            "Logs",
        ] {
            assert!(
                text.contains(expected),
                "screen should contain {expected:?}"
            );
        }
        // No inline descriptions next to the titles any more.
        assert!(
            !text.contains("System Scan —"),
            "descriptions left the rows"
        );
        // The composition hangs below the top edge, not glued to it.
        assert!(art_row.unwrap_or(0) > 0, "art is vertically centered");
        // A third of the free space lands between brand and menu: the list
        // sits noticeably below the demo-panel mark, not glued to it.
        let brand_menu_gap = scan_row.unwrap() - demo_row.unwrap();
        assert!(
            brand_menu_gap >= 3,
            "menu hangs below the brand: {brand_menu_gap}"
        );
        // The menu block shares one left edge: icons align across rows.
        assert_eq!(scan_col, deploy_col, "menu items align as a block");
        // The selected description is anchored to the bottom row.
        assert_eq!(desc_row, Some(buf.area.height - 1));
    }

    /// Condense-fidelity test: shrinking is width-only nearest
    /// neighbour — all glyph rows survive, the output is drawn from the
    /// source font's own characters, and shrinking to the native width
    /// is the identity.
    #[test]
    fn shrink_art_keeps_every_glyph_row() {
        let native: Vec<String> = MAIN_ART.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            shrink_art(MAIN_ART, 108),
            native,
            "native width is identity"
        );
        let source: std::collections::HashSet<char> =
            MAIN_ART.iter().flat_map(|l| l.chars()).collect();
        for w in [107u16, 98, 83, 50, 30] {
            let small = shrink_art(MAIN_ART, w);
            assert_eq!(small.len(), MAIN_ART.len(), "all glyph rows at {w}");
            let charset: std::collections::HashSet<char> =
                small.iter().flat_map(|r| r.chars()).collect();
            assert!(charset.is_subset(&source), "only source glyphs at {w}");
            assert!(
                small.iter().any(|r| r
                    .chars()
                    .any(|c| matches!(c, '═' | '║' | '╔' | '╗' | '╚' | '╝'))),
                "the outline frame survives at {w}"
            );
        }
    }

    /// A window narrower than the 108-cell art condenses the SAME glyph
    /// cells to its width (nearest-neighbour, all six rows kept) —
    /// never a plain-text substitute, never a different font.
    #[test]
    fn narrow_main_menu_keeps_the_ascii_art() {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(90, 30)).unwrap();
        term.draw(|f| draw_main_menu(f, f.area(), 0)).unwrap();
        let buf = term.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        let small = shrink_art(MAIN_ART, 90);
        assert!(
            text.contains(&small[0]),
            "the condensed banner renders whole at 90 cols"
        );
        assert!(
            !text.contains("GHOST PROVIDER"),
            "no plain-text substitute for the art"
        );
        assert!(text.contains("System Scan"), "menu stays");
    }

    /// A wide terminal zooms the same glyph cells up (2× tile).
    #[test]
    fn wide_main_menu_scales_the_art_up() {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(220, 50)).unwrap();
        term.draw(|f| draw_main_menu(f, f.area(), 0)).unwrap();
        let buf = term.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains(&expand_art(MAIN_ART, 2)[0]),
            "2x tiled art on 220 cols"
        );
        assert!(!text.contains(MAIN_ART[0]), "1x art replaced");
    }

    /// An ultrawide terminal uses the largest tile the height allows.
    #[test]
    fn ultrawide_main_menu_scales_art_to_the_max() {
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(440, 80)).unwrap();
        term.draw(|f| draw_main_menu(f, f.area(), 0)).unwrap();
        let buf = term.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains(&expand_art(MAIN_ART, 4)[0]),
            "4x tiled art on 440x80"
        );
    }

    /// Style is constant across window sizes: menu items stay packed
    /// back-to-back everywhere — resizing never re-spaces the list.
    #[test]
    fn menu_stays_packed_at_every_window_size() {
        use ratatui::backend::TestBackend;
        for (w, h) in [(100u16, 30u16), (120, 36), (200, 50), (250, 50)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw_main_menu(f, f.area(), 0)).unwrap();
            let buf = term.backend().buffer();
            let mut scan: Option<(u16, usize)> = None;
            let mut next: Option<(u16, usize)> = None;
            for y in 0..buf.area.height {
                let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
                if let Some(col) = row.find("@ System Scan") {
                    scan = Some((y, col));
                } else if let Some(col) = row.find("⊗ Networks") {
                    next = Some((y, col));
                }
            }
            let (sy, sx) = scan.unwrap_or_else(|| panic!("{w}x{h}: System Scan missing"));
            let (ny, nx) = next.unwrap_or_else(|| panic!("{w}x{h}: Self-Hosting missing"));
            assert_eq!(ny, sy + 1, "{w}x{h}: menu items must be packed");
            assert_eq!(nx, sx, "{w}x{h}: icons stay on one left edge");
        }
    }

    /// Two consecutive frozen heartbeat windows fire the stall exit;
    /// progress, pause windows and pre-first-tick boot samples re-baseline.
    #[test]
    fn stall_watchdog_fires_only_on_repeated_freeze() {
        let mut wd = StallWatchdog::new();
        assert!(!wd.watch(0, false), "boot (no ticks yet) never fires");
        assert!(!wd.watch(0, false), "…even across windows");
        assert!(!wd.watch(10, false), "first real sample only baselines");
        assert!(wd.watch(10, false), "frozen second window fires");
        assert!(!wd.watch(11, false), "progress resets the baseline");
        assert!(!wd.watch(11, true), "paused windows never fire");
        assert!(!wd.watch(11, true), "…even when frozen while paused");
        assert!(!wd.watch(12, false), "resume re-baselines");
        assert!(wd.watch(12, false), "a fresh freeze still fires");
    }

    /// Enter on the step-list screens advances (it used to open the inline
    /// editor, which read as a dead key); `e` opens the editor instead.
    #[test]
    fn step_lists_advance_on_enter_and_edit_on_e() {
        let mut ed = wizard::StepEditor::new(vec!["bun install --frozen-lockfile".into()]);
        assert_eq!(
            wz_steps_key(&mut ed, KeyCode::Enter, None),
            WzStepsFlow::Next
        );
        assert_eq!(wz_steps_key(&mut ed, KeyCode::Tab, None), WzStepsFlow::Next);

        // `e` opens the line, typing goes into it, Enter commits and stays.
        assert_eq!(
            wz_steps_key(&mut ed, KeyCode::Char('e'), Some('e')),
            WzStepsFlow::Stay
        );
        assert!(ed.editing.is_some());
        assert_eq!(
            wz_steps_key(&mut ed, KeyCode::Char('x'), Some('x')),
            WzStepsFlow::Stay
        );
        assert_eq!(
            wz_steps_key(&mut ed, KeyCode::Enter, None),
            WzStepsFlow::Stay
        );
        assert!(ed.editing.is_none());
        assert!(ed.lines[0].ends_with('x'));

        // Esc still walks back out of the screen.
        assert_eq!(wz_steps_key(&mut ed, KeyCode::Esc, None), WzStepsFlow::Back);
    }

    /// Every wizard screen maps to its place in the progress chain; screens
    /// outside the wizard render no chain at all.
    #[test]
    fn wizard_step_positions_and_non_wizard_screens() {
        let d = wizard::Draft::default();
        let screens = [
            (
                Screen::WzId {
                    buffer: String::new(),
                    error: None,
                    draft: d.clone(),
                },
                0,
            ),
            (
                Screen::WzGit {
                    buffer: String::new(),
                    error: None,
                    draft: d.clone(),
                },
                1,
            ),
            (
                Screen::WzCommit {
                    buffer: String::new(),
                    error: None,
                    draft: d.clone(),
                },
                2,
            ),
            (
                Screen::WzProfile {
                    selected: 0,
                    draft: d.clone(),
                },
                3,
            ),
            (
                Screen::WzPrefetch {
                    editor: wizard::StepEditor::new(vec![]),
                    draft: d.clone(),
                },
                4,
            ),
            (
                Screen::WzBuild {
                    editor: wizard::StepEditor::new(vec![]),
                    draft: d.clone(),
                },
                5,
            ),
            (
                Screen::WzRun {
                    cmd: String::new(),
                    port: "0".into(),
                    focus_port: false,
                    error: None,
                    draft: d.clone(),
                },
                6,
            ),
            (
                Screen::WzRes {
                    memory: "384M".into(),
                    tasks: "300".into(),
                    focus_tasks: false,
                    error: None,
                    draft: d.clone(),
                },
                7,
            ),
            (
                Screen::WzReview {
                    draft: d,
                    yaml: None,
                    error: None,
                },
                8,
            ),
        ];
        for (screen, want) in screens {
            assert_eq!(wizard_step(&screen), Some(want));
        }
        assert_eq!(wizard_step(&Screen::Main { selected: 0 }), None);
        assert_eq!(
            wizard_step(&Screen::AddService {
                files: vec![],
                selected: 0,
                message: None,
                armed_delete: None,
            }),
            None
        );
        assert_eq!(
            wizard_step(&Screen::EditService {
                rows: vec![],
                selected: 0,
                message: None,
            }),
            None
        );
        assert_eq!(
            wizard_step(&Screen::EditServiceForm {
                id: "x".into(),
                fields: vec![String::new(); EDIT_FIELDS.len()],
                sel: 0,
                buffer: String::new(),
                editing: false,
                error: None,
                message: None,
            }),
            None
        );
    }

    /// The chain marks past steps ✓, the current one »bold, the rest dim —
    /// so where Enter leads is visible before the key is pressed.
    #[test]
    fn wizard_progress_shows_done_current_and_upcoming() {
        let line = wizard_progress(4); // deps = step 5/9
        let texts: Vec<String> = line.spans.iter().map(|s| s.content.to_string()).collect();
        let joined = texts.concat();
        assert!(joined.contains("✓ name"), "done steps marked: {joined}");
        assert!(joined.contains("» deps"), "current step marked: {joined}");
        assert!(joined.contains("review"), "chain lists the end: {joined}");

        let cur = texts.iter().position(|t| t.starts_with('»')).unwrap();
        assert_eq!(line.spans[cur].style.fg, Some(Color::White));
        assert!(line.spans[cur].style.add_modifier.contains(Modifier::BOLD));

        let done = texts.iter().position(|t| t.starts_with('✓')).unwrap();
        assert_eq!(line.spans[done].style.fg, Some(OK_GREEN));

        let todo = texts.iter().position(|t| t == "build").unwrap();
        assert_eq!(line.spans[todo].style.fg, Some(DIM));
    }

    /// The hint bar must name where Enter goes — the whole point of the
    /// "Enter looked dead" complaint — and switch to edit keys while a
    /// step-list line is being edited.
    #[test]
    fn wizard_hints_name_their_destination() {
        let text = |s: &Screen| -> String {
            hint_line(s)
                .spans
                .iter()
                .map(|sp| sp.content.to_string())
                .collect()
        };
        let d = wizard::Draft::default();

        let prefetch = Screen::WzPrefetch {
            editor: wizard::StepEditor::new(vec!["bun install".into()]),
            draft: d.clone(),
        };
        assert!(text(&prefetch).contains("Enter → build offline"));

        let build = Screen::WzBuild {
            editor: wizard::StepEditor::new(vec!["bun run build".into()]),
            draft: d.clone(),
        };
        assert!(text(&build).contains("Enter → run"));

        let mut editor = wizard::StepEditor::new(vec!["bun install".into()]);
        editor.start_edit();
        let editing = Screen::WzPrefetch {
            editor,
            draft: d.clone(),
        };
        assert!(text(&editing).contains("Enter confirm"));

        let review = Screen::WzReview {
            draft: d,
            yaml: None,
            error: None,
        };
        assert!(text(&review).contains("Enter save + deploy"));
    }

    /// The autopilot path stores the detected manifest on the first run and
    /// REPLACES it on a redeploy of the same service — re-entering the same
    /// URL must just work (the wizard's duplicate guard does not apply here),
    /// and detected build.env vars must survive into the stored file.
    #[test]
    fn autopilot_stores_then_replaces_on_redeploy() {
        let _guard = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-auto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }

        let mut draft = wizard::Draft {
            // Detection hands the id over as a SUGGESTION, not in the draft —
            // the autopilot must seed it, exactly like wizard step 1 would.
            id: String::new(),
            git: "https://github.com/example/auto-demo.git".into(),
            commit: "c".repeat(40),
            ..Default::default()
        };
        assert!(wizard::apply_profile_defaults(&mut draft, "bun"));

        draft.build_env = vec![("PUB_VERTD_URL".into(), "https://vert.local".into())];
        let target = auto_store(&mut draft, "auto-demo").expect("first store");
        assert_eq!(target.short_name(), "auto-demo");
        let path = crate::hoster::library::file_path("auto-demo").unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("PUB_VERTD_URL"), "{first}");

        // Redeploy with changed detection: replaces the stored file.
        draft.build_env = vec![("PUB_NEW".into(), "1".into())];
        let again = auto_store(&mut draft, "auto-demo").expect("redeploy replaces");
        assert_eq!(again.short_name(), "auto-demo");
        let second = std::fs::read_to_string(&path).unwrap();
        assert!(second.contains("PUB_NEW"), "{second}");
        assert!(!second.contains("PUB_VERTD_URL"), "{second}");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The Edit Service list is state.json ∩ reality: every deployed id
    /// shows up; rows with a library manifest are editable, rows deployed
    /// some other way are marked so Enter can explain instead of failing.
    #[test]
    fn edit_service_rows_list_deployed_ids_with_and_without_manifest() {
        let _guard = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-editrows-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME + XDG_STATE_HOME)
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
            std::env::set_var("XDG_STATE_HOME", &tmp);
        }

        // A deployed service whose manifest lives in the library…
        let mut draft = wizard::Draft {
            id: "svc-demo".into(),
            git: "https://github.com/example/svc-demo.git".into(),
            commit: "c".repeat(40),
            ..Default::default()
        };
        assert!(wizard::apply_profile_defaults(&mut draft, "bun"));
        draft.port = "4173".into();
        let mut m = wizard::build_manifest(&draft).expect("manifest builds");
        m.service.name = "VERT demo".into();
        let yaml = serde_yaml::to_string(&m).unwrap();
        crate::hoster::library::save(&m, &yaml).expect("store manifest");

        // …and a deployed one without any library file (external path).
        let state_path = crate::paths::state_file();
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        std::fs::write(
            &state_path,
            r#"{
              "svc-demo": {
                "unit_name": "svc-demo.service",
                "project_dir": "/tmp/svc-demo",
                "url": "https://github.com/example/svc-demo.git",
                "urls": ["http://localhost:4173"]
              },
              "svc-raw": {
                "unit_name": "svc-raw.service",
                "project_dir": "/tmp/svc-raw",
                "url": "http://localhost:9999",
                "urls": []
              }
            }"#,
        )
        .unwrap();

        let rows = edit_service_rows();
        assert_eq!(rows.len(), 2, "every deployed id is listed");
        assert_eq!(rows[0].id, "svc-demo", "BTreeMap id order");
        assert!(rows[0].path.is_some());
        assert!(rows[0].valid);
        assert_eq!(rows[0].name, "VERT demo", "row shows service.name");
        assert_eq!(rows[0].url, "http://localhost:4173");
        assert_eq!(rows[1].id, "svc-raw");
        assert!(rows[1].path.is_none(), "no manifest → not editable");
        assert!(!rows[1].valid);
        assert_eq!(rows[1].name, "svc-raw", "falls back to the id");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The six edited rows patch exactly six manifest fields; build steps,
    /// env, profile and prefetch survive untouched (lossless edit), and a
    /// bad value fails the field's own check before any save happens.
    #[test]
    fn apply_edit_patches_the_six_rows_and_keeps_the_rest() {
        let mut draft = wizard::Draft {
            id: "edit-demo".into(),
            git: "https://github.com/example/edit-demo.git".into(),
            commit: "c".repeat(40),
            ..Default::default()
        };
        assert!(wizard::apply_profile_defaults(&mut draft, "bun"));
        draft.build_env = vec![("PUB_KEEP_ME".into(), "1".into())];
        let mut m = wizard::build_manifest(&draft).expect("manifest builds");
        let prefetch_before = m.prefetch.clone();

        let mut fields = edit_fields_of(&m);
        assert_eq!(fields.len(), EDIT_FIELDS.len());
        fields[EDIT_NAME] = "Renamed".into();
        fields[EDIT_DESC] = "panel demo".into();
        fields[EDIT_COMMIT] = "main".into();
        fields[EDIT_PORT] = "8080".into();
        fields[EDIT_MEMORY] = "512M".into();
        fields[EDIT_TASKS] = "64".into();
        apply_edit(&mut m, &fields).expect("valid patch");

        assert_eq!(m.service.name, "Renamed");
        assert_eq!(m.service.description, "panel demo");
        assert_eq!(m.source.commit, "main");
        assert_eq!(m.run.port, 8080);
        assert_eq!(m.resources.memory_max.as_deref(), Some("512M"));
        assert_eq!(m.resources.tasks_max.as_deref(), Some("64"));
        // Everything outside the six rows stays exactly as it was.
        assert_eq!(m.prefetch, prefetch_before, "prefetch untouched");
        assert_eq!(m.build.profile, "bun", "profile untouched");
        assert!(m.build.env.contains_key("PUB_KEEP_ME"), "env untouched");

        let mut reject = |value: &str, row: usize, hint: &str| {
            let mut f = edit_fields_of(&m);
            f[row] = value.into();
            let err = apply_edit(&mut m, &f).expect_err(hint);
            assert!(err.contains(hint), "{hint} not in: {err}");
        };
        reject("abc", EDIT_PORT, "port");
        reject("lots", EDIT_MEMORY, "memory");
        reject("", EDIT_MEMORY, "memory");
        reject("", EDIT_TASKS, "task");

        let mut f = edit_fields_of(&m);
        f[EDIT_COMMIT] = "bad commit!".into();
        assert!(
            apply_edit(&mut m, &f).is_err(),
            "unparseable commit rejected"
        );
        f[EDIT_COMMIT] = "c".repeat(40);
        assert!(apply_edit(&mut m, &f).is_ok(), "full sha accepted");

        let short = vec!["only-one".to_string()];
        let err = apply_edit(&mut m, &short).expect_err("field count guard");
        assert!(err.contains("internal"), "{err}");
    }

    /// save_edit goes through load → patch → validate → replace: the file
    /// on disk gains the new fields, keeps everything else, and is left
    /// untouched when validation fails.
    #[test]
    fn save_edit_replaces_the_file_and_leaves_it_on_failure() {
        let _guard = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-saveedit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }

        let mut draft = wizard::Draft {
            id: "save-demo".into(),
            git: "https://github.com/example/save-demo.git".into(),
            commit: "c".repeat(40),
            ..Default::default()
        };
        assert!(wizard::apply_profile_defaults(&mut draft, "bun"));
        draft.build_env = vec![("PUB_SAVED".into(), "kept".into())];
        let m = wizard::build_manifest(&draft).expect("manifest builds");
        let yaml = serde_yaml::to_string(&m).unwrap();
        crate::hoster::library::save(&m, &yaml).expect("store manifest");

        let mut fields = edit_fields_of(&m);
        fields[EDIT_NAME] = "Saved name".into();
        fields[EDIT_PORT] = "8080".into();
        let path = save_edit("save-demo", &fields).expect("save succeeds");
        assert!(path.ends_with("save-demo.yaml"), "{}", path.display());

        let reloaded = crate::hoster::library::load("save-demo").expect("reload");
        assert_eq!(reloaded.service.name, "Saved name");
        assert_eq!(reloaded.run.port, 8080);
        assert!(
            reloaded.build.env.contains_key("PUB_SAVED"),
            "lossless round-trip"
        );

        // A bad value fails BEFORE replace: the stored file stays as saved.
        fields[EDIT_PORT] = "nope".into();
        let err = save_edit("save-demo", &fields).expect_err("bad port");
        assert!(err.contains("port"), "{err}");
        let after = crate::hoster::library::load("save-demo").expect("reload");
        assert_eq!(after.run.port, 8080, "file untouched on failure");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The Edit form hints switch with the editing toggle: navigation keys
    /// while browsing, confirm/cancel while typing.
    #[test]
    fn edit_form_hints_switch_with_the_editing_toggle() {
        let text = |s: &Screen| -> String {
            hint_line(s)
                .spans
                .iter()
                .map(|sp| sp.content.to_string())
                .collect()
        };
        let form = |editing: bool| Screen::EditServiceForm {
            id: "svc".into(),
            fields: vec![String::new(); EDIT_FIELDS.len()],
            sel: 0,
            buffer: String::new(),
            editing,
            error: None,
            message: None,
        };
        let browsing = text(&form(false));
        assert!(browsing.contains("Enter edit row"), "{browsing}");
        assert!(browsing.contains("s save"), "{browsing}");
        assert!(browsing.contains("r redeploy"), "{browsing}");
        assert!(browsing.contains("e editor"), "{browsing}");
        let typing = text(&form(true));
        assert!(typing.contains("Enter confirm"), "{typing}");
        assert!(!typing.contains("r redeploy"), "{typing}");

        let list = Screen::EditService {
            rows: vec![],
            selected: 0,
            message: None,
        };
        let list_text = text(&list);
        assert!(list_text.contains("Enter edit"), "{list_text}");
    }

    #[test]
    fn human_bytes_uses_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    /// ←/→ walk the Logs tabs in opposite directions (left must not act as
    /// right — that was the reported bug).
    #[test]
    fn logs_tabs_cycle_forward_and_backward() {
        use LogView as V;
        assert_eq!(logs_tab_next(V::Deploy), V::Software);
        assert_eq!(logs_tab_next(V::Software), V::Crash);
        assert_eq!(logs_tab_next(V::Crash), V::Deploy);
        assert_eq!(logs_tab_prev(V::Deploy), V::Crash);
        assert_eq!(logs_tab_prev(V::Crash), V::Software);
        assert_eq!(logs_tab_prev(V::Software), V::Deploy);
        for v in [V::Deploy, V::Software, V::Crash] {
            assert_eq!(logs_tab_prev(logs_tab_next(v)), v);
            assert_eq!(logs_tab_next(logs_tab_prev(v)), v);
        }
    }

    #[test]
    fn deployed_mark_distinguishes_deployed_ids() {
        let deployed = vec!["my-blog".to_string()];
        assert_eq!(deployed_mark(&deployed, "my-blog").0, "●");
        assert_eq!(deployed_mark(&deployed, "other").0, "○");
        assert_eq!(deployed_mark(&[], "my-blog").0, "○");
    }
    /// Port rows: our deployments render yellow bold; anonymous occupied
    /// ports render violet bold — both without any owner data.
    #[test]
    fn scan_report_colors_deployed_yellow_and_foreign_violet() {
        let report = "Listening ports:\n  5432   \n  23920  demo-memos (deployed)\n";
        let lines = colorize_scan(report);

        // Line layout: header, then one line per port row.
        let foreign = &lines[1];
        let deployed = &lines[2];

        assert!(
            foreign
                .spans
                .iter()
                .skip(1) // leading indent span carries no color
                .all(
                    |s| s.style.fg == Some(VIOLET) && s.style.add_modifier.contains(Modifier::BOLD)
                ),
            "foreign occupied ports must be violet bold, got {:?}",
            foreign.spans.iter().map(|s| s.style.fg).collect::<Vec<_>>()
        );
        assert!(
            deployed
                .spans
                .iter()
                .skip(1)
                .all(|s| s.style.fg == Some(WARN_YELLOW)
                    && s.style.add_modifier.contains(Modifier::BOLD)),
            "deployed rows must be yellow bold, got {:?}",
            deployed
                .spans
                .iter()
                .map(|s| s.style.fg)
                .collect::<Vec<_>>()
        );
    }

    fn scan_report_fixture(ports: usize) -> String {
        let mut r = String::from(
            "  scanned at 2026-10-18T11:22:37.706Z\n\
             [x] systemd          found\n\
             [x] network          online\n\
             \nInterfaces:\n  lo              127.0.0.1           up\n",
        );
        r.push_str("\nListening ports:\n  PORT   SERVICE\n");
        for p in 0..ports {
            r.push_str(&format!("  {:<6}\n", 8000 + p));
        }
        r
    }

    /// A wide terminal puts the port list in a right-hand column beside the
    /// facts and interfaces, so a long list no longer runs past the bottom.
    #[test]
    fn scan_screen_splits_ports_into_a_right_column_when_wide() {
        use ratatui::backend::TestBackend;
        let report = scan_report_fixture(15);
        // 24 rows: stacked, the 15 ports plus the header block would need
        // ~23 rows of content and get clipped; side-by-side must not clip.
        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| draw_scan(f, f.area(), Some(&report), false, 0))
            .unwrap();
        let buf = term.backend().buffer();
        let mut ports_col = None;
        let mut ifaces_col = None;
        let mut last_port_row = 0;
        let mut port_row_col = None;
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            if let Some(col) = row.find("Listening ports:") {
                ports_col = Some(col);
            }
            if let Some(col) = row.find("Interfaces:") {
                ifaces_col = Some(col);
            }
            if let Some(col) = row.find("8014") {
                last_port_row = y;
                port_row_col = Some(col);
            }
        }
        let ports_col = ports_col.expect("ports header rendered");
        // The column hugs the left content: a few cells after the widest
        // fact line, never pinned to the far side of a wide terminal.
        assert!(
            (30..=50).contains(&ports_col),
            "ports column right next to the facts, col={ports_col}"
        );
        // Port rows align under their header (one cell of indent).
        if let Some(c) = port_row_col {
            assert!(
                c.abs_diff(ports_col) <= 2,
                "port rows under the header: {c} vs {ports_col}"
            );
        }
        // The header rows share the top of the screen: the ports column sits
        // beside the facts, not below them.
        if let Some(ifaces_col) = ifaces_col {
            assert!(ports_col > ifaces_col, "ports right of interfaces");
        }
        // Every port row fits: the deepest one is inside the block.
        assert!(
            last_port_row < buf.area.height.saturating_sub(2),
            "last port row {last_port_row} must fit in {} rows",
            buf.area.height
        );
    }

    /// A narrow terminal keeps the old stacked layout (ports below).
    #[test]
    fn scan_screen_stacks_ports_below_on_a_narrow_terminal() {
        use ratatui::backend::TestBackend;
        let report = scan_report_fixture(2);
        let mut term = Terminal::new(TestBackend::new(50, 30)).unwrap();
        term.draw(|f| draw_scan(f, f.area(), Some(&report), false, 0))
            .unwrap();
        let buf = term.backend().buffer();
        let mut ports_row = None;
        let mut ifaces_row = None;
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            if row.contains("Listening ports:") {
                ports_row = Some(y);
            }
            if row.contains("Interfaces:") {
                ifaces_row = Some(y);
            }
        }
        let ports_row = ports_row.expect("ports header rendered");
        let ifaces_row = ifaces_row.expect("interfaces header rendered");
        assert!(ports_row > ifaces_row, "stacked: ports below interfaces");
    }

    #[test]
    fn command_char_passes_latin_through_case_insensitive() {
        assert_eq!(command_char(KeyCode::Char('q')), Some('q'));
        assert_eq!(command_char(KeyCode::Char('Q')), Some('q'));
        assert_eq!(command_char(KeyCode::Char('Y')), Some('y'));
        assert_eq!(command_char(KeyCode::Char('D')), Some('d'));
        assert_eq!(command_char(KeyCode::Char(' ')), Some(' '));
        assert_eq!(command_char(KeyCode::Char('1')), Some('1'));
        // Non-char keys never map to a command letter.
        assert_eq!(command_char(KeyCode::Enter), None);
        assert_eq!(command_char(KeyCode::Esc), None);
    }

    /// Russian ЙЦУКЕН: the same physical keys must trigger the same
    /// commands as their QWERTY counterparts, upper or lower case.
    #[test]
    fn command_char_maps_cyrillic_positionally() {
        let cases = [
            ('й', "q"),
            ('Й', "q"), // quit
            ('л', "k"),
            ('Л', "k"), // up (vim-style)
            ('о', "j"),
            ('О', "j"), // down (vim-style)
            ('к', "r"), // restart
            ('ы', "s"), // stop
            ('е', "t"), // start
            ('в', "d"), // delete
            ('н', "y"),
            ('Н', "y"), // yes
            ('т', "n"),
            ('Т', "n"), // no
        ];
        for (cyr, lat) in cases {
            assert_eq!(
                command_char(KeyCode::Char(cyr)),
                Some(lat.chars().next().unwrap()),
                "{cyr} must act as {lat}"
            );
        }
    }

    /// Letters without a positional counterpart never fire commands.
    #[test]
    fn command_char_leaves_unmapped_chars_alone() {
        assert_eq!(command_char(KeyCode::Char('б')), None);
        assert_eq!(command_char(KeyCode::Char('ю')), None);
        assert_eq!(command_char(KeyCode::Char('ж')), None);
        assert_eq!(command_char(KeyCode::Char('ё')), None);
    }

    #[test]
    fn doctor_line_is_split_into_problem_fix_note() {
        let src = "! Memos needs Go >= 1.27.0, found 1.26.6 — update first: sudo pacman -S --needed go  (this software never runs sudo commands by itself)";
        let body = src.trim_start().strip_prefix("! ").unwrap();
        let lines = doctor_lines(body).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].spans.iter().any(|s| s.content.contains("fix » ")));
        assert!(
            lines[1]
                .spans
                .iter()
                .any(|s| s.content == "sudo pacman -S --needed go")
        );
        assert!(lines[2].spans.iter().any(|s| s.content.starts_with('(')));
    }

    #[test]
    fn doctor_line_without_note_has_two_rows() {
        let lines = doctor_lines("VERT needs Bun >= 1.2.0 but 'bun' is not installed — install: curl -fsSL https://bun.sh/install | bash").unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn marker_detection_matches_only_doctor_issues() {
        assert!(doctor_body_markers(
            "! X needs Go >= 1.27.0 — update first: cmd"
        ));
        assert!(!doctor_body_markers("! invalid GitHub URL format"));
    }

    /// The deploy log is bounded: pushing far beyond the cap never lets the
    /// in-memory buffer (and thus per-frame re-render cost) grow without limit,
    /// and the newest tail is preserved so users still see the live build.
    #[test]
    fn deploy_log_is_bounded_and_keeps_the_tail() {
        let mut lines: Vec<String> = Vec::new();
        for i in 0..(MAX_DEPLOY_LINES * 2) {
            push_deploy_line(&mut lines, format!("line {i}"));
        }
        assert_eq!(lines.len(), MAX_DEPLOY_LINES);
        // Oldest lines are dropped; the newest remain visible.
        assert!(!lines.iter().any(|l| l == "line 0"));
        let expected_last = format!("line {}", MAX_DEPLOY_LINES * 2 - 1);
        assert_eq!(
            lines.last().map(String::as_str),
            Some(expected_last.as_str())
        );
    }

    /// A finished deploy keeps only verdict lines — except when it failed:
    /// then the whole tail from the last `! …` report survives, because that
    /// block is the reason. (The old filter dropped `[warn]`/`[error]` detail
    /// lines, leaving the screen reason-less on a build failure.)
    #[test]
    fn compress_done_on_failure_keeps_the_report_block() {
        let mut lines: Vec<String> = [
            "cloning repository…",
            "! Build step failed (bun run build):",
            "status: exit 1",
            "--- stderr (tail) ---",
            "[warn] https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format",
            "[error] The command \"vite build\" exited with code: 1",
            "deployment failed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        compress_done(&mut lines, false);
        let text = lines.join("\n");
        assert!(
            text.contains("[error] The command \"vite build\""),
            "{text}"
        );
        assert!(text.contains("status: exit 1"), "{text}");
        assert!(text.contains("deployment failed"), "{text}");
        assert!(!text.contains("cloning repository"), "{text}");
    }

    #[test]
    fn compress_done_on_success_keeps_only_verdicts() {
        let mut lines: Vec<String> = [
            "cloning repository…",
            "sandbox: PrivateTmp=true",
            "✔ listening on http://127.0.0.1:4173",
            "chatty progress line",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        compress_done(&mut lines, true);
        let kept: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert_eq!(
            kept,
            vec![
                "sandbox: PrivateTmp=true",
                "✔ listening on http://127.0.0.1:4173"
            ]
        );
    }

    /// A deploy that failed without any `! …` report still falls back to the
    /// verdict filter rather than keeping the full log.
    #[test]
    fn compress_done_on_failure_without_report_falls_back_to_verdicts() {
        let mut lines: Vec<String> = [
            "cloning repository…",
            "warn: host prefetch missed, continuing offline",
            "deployment failed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        compress_done(&mut lines, false);
        let kept: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert_eq!(
            kept,
            vec![
                "warn: host prefetch missed, continuing offline",
                "deployment failed"
            ]
        );
    }

    /// Resize-storm debounce: first resize repaints, then repaints are
    /// rate-limited so an edge-drag doesn't spam cursor-position round-trips.
    #[test]
    fn resize_repaint_debounce_windows_repaints() {
        let now = Instant::now();
        assert!(resize_repaint_due(None, now));
        assert!(!resize_repaint_due(Some(now), now));
        assert!(resize_repaint_due(Some(now - Duration::from_secs(1)), now));
        assert!(!resize_repaint_due(
            Some(now - Duration::from_millis(10)),
            now
        ));
    }

    /// The bottom hint bar centers horizontally on every screen.
    #[test]
    fn hint_bar_is_centered_at_the_bottom() {
        use ratatui::backend::TestBackend;
        let (tx, rx) = std::sync::mpsc::channel();
        let app = App {
            screen: Screen::Main { selected: 0 },
            rx,
            tx,
            tick: 0,
            scan_seq: 0,
            deploy_history: Vec::new(),
            software_history: Vec::new(),
            crash_history: Vec::new(),
            deploy_tail_keep: None,
            software_tail_keep: None,
            crash_tail_keep: None,
            exit_notices: Vec::new(),
        };
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let buf = term.backend().buffer();
        let last = buf.area.height - 1;
        let row: String = (0..buf.area.width)
            .map(|x| buf[(x, last)].symbol())
            .collect();
        assert!(
            row.contains("Enter choose"),
            "hint on the last row: {row:?}"
        );
        let left = row.len() - row.trim_start().len();
        let right = row.len() - row.trim_end().len();
        assert!(left > 0 && right > 0, "padding both sides: {left}/{right}");
        assert!(
            (left as i64 - right as i64).abs() <= 2,
            "roughly centered: left={left} right={right}"
        );
    }
}
