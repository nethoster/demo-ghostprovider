//! Redesigned TUI — monochrome red-on-black theme with ASCII header,
//! 4-panel grid main menu, dashed Unicode borders, and a Logs screen.

use std::io::{self, Stdout};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

// ── palette ──────────────────────────────────────────────────────────────────
// Pure monochrome red-on-black exactly like the concept — sampled #FF0018.
const RED: Color = Color::Rgb(255, 0, 18);
const DIM_RED: Color = Color::Rgb(170, 0, 12);
const BRIGHT_RED: Color = Color::Rgb(255, 48, 48);
const BG: Color = Color::Rgb(0, 0, 0);
const _FG: Color = Color::Rgb(255, 0, 18);
const DIM: Color = Color::Rgb(90, 0, 9);
const BODY: Color = Color::Rgb(255, 0, 18);
const GLOBE_RED: Color = Color::Rgb(255, 0, 18);

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const MAX_DEPLOY_LINES: usize = 2000;

fn push_deploy_line(lines: &mut Vec<String>, line: String) {
    lines.push(line);
    if lines.len() > MAX_DEPLOY_LINES {
        let overflow = lines.len() - MAX_DEPLOY_LINES;
        lines.drain(0..overflow);
    }
}

/// Same contract as the main panel's `compress_done`: on failure keep the
/// whole tail from the last `! …` report — that block is the reason.
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

// ── screens ──────────────────────────────────────────────────────────────────

pub(crate) enum Screen {
    Main {
        selected: usize,
    },
    Scan {
        report: Option<String>,
        running: bool,
        seq: u64,
    },
    UrlInput {
        buffer: String,
        error: Option<String>,
        busy: bool,
    },
    Confirm {
        target: crate::tui::workers::DeployTarget,
        yes_selected: bool,
    },
    Deploy {
        lines: Vec<String>,
        done: Option<bool>,
    },
    Services {
        rows: Vec<crate::tui::workers::ServiceRow>,
        selected: usize,
        message: Option<String>,
    },
    ConfirmDelete {
        name: String,
        yes_selected: bool,
    },
    Logs {
        /// Which log view is active.
        view: LogView,
        /// Deploy log lines (replayed from the latest deploy).
        deploy_lines: Vec<String>,
        /// Software log lines (journalctl output, appended over time).
        software_lines: Vec<String>,
        /// Vertical scroll offset within the active view.
        scroll: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogView {
    Deploy,
    Software,
}

use crate::tui::Msg;

pub(crate) struct App {
    pub screen: Screen,
    pub rx: Receiver<Msg>,
    pub tx: Sender<Msg>,
    pub tick: u64,
    pub scan_seq: u64,
    /// Persistent deploy log history — survives screen switches.
    pub deploy_history: Vec<String>,
    /// Persistent software log history (journal).
    pub software_history: Vec<String>,
}

// ── entry point ──────────────────────────────────────────────────────────────

/// Minimum gap between expensive full repaints while the window is being
/// resized (same rationale as the primary TUI: the 80ms draw loop already
/// picks up the new size via autoresize).
const RESIZE_REPAINT_DEBOUNCE: Duration = Duration::from_millis(150);

/// Window below which the layout cannot breathe: render a short notice.
const MIN_TERM_WIDTH: u16 = 30;
const MIN_TERM_HEIGHT: u16 = 8;

/// Full 26-row globe header needs room for content below it; below this
/// window height fall back to the compact 3-row title.
const TALL_HEADER_MIN_HEIGHT: u16 = 38;
const TALL_HEADER_HEIGHT: u16 = 26;
const COMPACT_HEADER_HEIGHT: u16 = 3;

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

pub fn run() -> anyhow::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // Best-effort: the first draw repaints everything anyway.
    clear_screen(&mut terminal);

    let (tx, rx) = mpsc::channel();
    let mut app = App {
        screen: Screen::Main { selected: 0 },
        rx,
        tx,
        tick: 0,
        scan_seq: 0,
        deploy_history: Vec::new(),
        software_history: Vec::new(),
    };
    let res = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    res
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    // Last full repaint time (None = none yet this run).
    let mut last_repaint: Option<Instant> = None;
    loop {
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
                    for l in line.split('\n') {
                        push_deploy_line(&mut app.deploy_history, l.to_string());
                    }
                    if let Screen::Deploy { lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(lines, l.to_string());
                        }
                    }
                    if let Screen::Logs { deploy_lines, .. } = &mut app.screen {
                        for l in line.split('\n') {
                            push_deploy_line(deploy_lines, l.to_string());
                        }
                    }
                }
                Msg::DeployDone(ok) => {
                    {
                        let l = format!("deploy done: {}", if ok { "ok" } else { "failed" });
                        push_deploy_line(&mut app.deploy_history, l);
                    }
                    if let Screen::Deploy { lines, done } = &mut app.screen {
                        if !ok {
                            push_deploy_line(lines, "deployment failed".into());
                        }
                        compress_done(lines, ok);
                        *done = Some(ok);
                    }
                    if let Screen::Logs { deploy_lines, .. } = &mut app.screen
                        && !ok
                    {
                        push_deploy_line(deploy_lines, "deployment failed".into());
                    }
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
                Msg::DeployLogsCleared => {
                    app.deploy_history.clear();
                    if let Screen::Logs { deploy_lines, .. } = &mut app.screen {
                        deploy_lines.clear();
                        deploy_lines.push("Logs cleared.".into());
                    }
                }
                Msg::SoftwareLogsCleared => {
                    app.software_history.clear();
                    if let Screen::Logs { software_lines, .. } = &mut app.screen {
                        software_lines.clear();
                        software_lines.push("Logs cleared.".into());
                    }
                }
                // The primary TUI owns the Crash log; the v1 companion UI keeps
                // this screen out of its selector, so the reload/clear requests
                // it may still receive are no-ops here.
                Msg::CrashLog(_) | Msg::CrashLogsCleared => {}
                // Stack detection lives in the primary TUI only; drop it here.
                Msg::DetectDone { .. } => {}
                // Same for egress live-checks.
                Msg::EgressChecked { .. } => {}
                Msg::Terminate => {
                    // Termination signal: clean up any in-flight deploy, then
                    // leave (mirrors the primary TUI's early-exit behaviour).
                    let _ = crate::hoster::deploy::reconcile_stale(true);
                    return Ok(());
                }
            }
        }

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
                            Flow::Exit => {
                                let _ = crate::hoster::deploy::reconcile_stale(true);
                                return Ok(());
                            }
                        }
                        if std::mem::discriminant(&app.screen) != before {
                            clear_screen(terminal);
                            last_repaint = Some(Instant::now());
                        }
                    }
                }
                Event::Resize(_, _) if resize_repaint_due(last_repaint, Instant::now()) => {
                    // Debounced: the draw loop already picks up the new size.
                    clear_screen(terminal);
                    last_repaint = Some(Instant::now());
                }
                _ => {}
            }
        }
    }
}

enum Flow {
    Continue,
    Exit,
}

// ── keyboard ─────────────────────────────────────────────────────────────────

const LAYOUT_MAP: &[(char, char)] = &[
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

fn on_key(app: &mut App, key: KeyCode, mods: KeyModifiers) -> Flow {
    if matches!(key, KeyCode::Char('c')) && mods.contains(KeyModifiers::CONTROL) {
        return Flow::Exit;
    }
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
            KeyCode::Esc => return Flow::Exit,
            _ => match cmd {
                Some('q') => return Flow::Exit,
                Some('j') | Some('l') => *selected = (*selected + 1).min(3),
                Some('k') | Some('h') => *selected = selected.saturating_sub(1),
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
                KeyCode::Esc => app.screen = Screen::Main { selected: 1 },
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter => {
                    if buffer.trim().is_empty() {
                        *error = Some("enter a GitHub URL or a path to service.yaml".into());
                    } else {
                        match crate::tui::workers::classify_deploy_input(buffer.trim()) {
                            // This stripped panel has no detect/wizard flow:
                            // URL detection lives in the main panel.
                            Ok(crate::tui::workers::DeployTarget::Detect { .. }) => {
                                *error = Some(
                                    "URL detection runs in the main panel \
                                     (Add Service → Detect)"
                                        .into(),
                                );
                            }
                            Ok(target) => {
                                app.screen = Screen::Confirm {
                                    target,
                                    // Outdated running build: open on [N]o —
                                    // deploying now runs old code.
                                    yes_selected: !crate::paths::binary_is_stale(),
                                };
                            }
                            Err(e) => *error = Some(e),
                        }
                    }
                }
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
                KeyCode::Enter => decision = Some(*yes_selected),
                _ => match cmd {
                    Some('y') => *yes_selected = true,
                    Some('n') => *yes_selected = false,
                    _ => {}
                },
            }
            match decision {
                Some(true) => match target {
                    // Defensive: URLs are rejected at the input in this
                    // panel (no wizard here); detection is main-panel only.
                    crate::tui::workers::DeployTarget::Detect { .. } => {
                        app.screen = Screen::UrlInput {
                            buffer: target.back_to_input(),
                            error: Some(
                                "URL detection runs in the main panel \
                                 (Add Service → Detect)"
                                    .into(),
                            ),
                            busy: false,
                        };
                    }
                    manifest @ crate::tui::workers::DeployTarget::Manifest { .. } => {
                        let label = manifest.describe();
                        crate::tui::workers::start_target_deployment(
                            app.tx.clone(),
                            manifest.clone(),
                        );
                        app.screen = Screen::Deploy {
                            lines: vec![format!("deploying {label}...")],
                            done: None,
                        };
                    }
                },
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
                app.screen = Screen::Main { selected: 1 };
            }
        }
        Screen::Services {
            rows,
            selected,
            message,
        } => {
            let _ = message;
            let count = rows.len();
            match key {
                KeyCode::Esc => app.screen = Screen::Main { selected: 2 },
                KeyCode::Up if count > 0 => *selected = selected.saturating_sub(1),
                KeyCode::Down if count > 0 => *selected = (*selected + 1).min(count - 1),
                _ => match cmd {
                    Some('q') => app.screen = Screen::Main { selected: 2 },
                    Some('k') if count > 0 => *selected = selected.saturating_sub(1),
                    Some('j') if count > 0 => *selected = (*selected + 1).min(count - 1),
                    Some('r') => {
                        *rows = crate::tui::workers::service_rows();
                        *message = Some("refreshed".into());
                    }
                    Some(action @ ('s' | 't' | 'd')) if count > 0 => {
                        let selected_row = rows.get(*selected).map(|r| (r.managed, r.name.clone()));
                        if let Some((managed, name)) = selected_row {
                            if !managed {
                                // Read-only status row (tailscale): no
                                // systemctl actions on it, ever.
                                *rows = crate::tui::workers::service_rows();
                                *message = Some("tailscale is not managed by the panel".into());
                            } else {
                                match action {
                                    's' => {
                                        let msg =
                                            crate::tui::workers::service_action(&name, "stop");
                                        *rows = crate::tui::workers::service_rows();
                                        *message = Some(msg);
                                    }
                                    't' => {
                                        let msg =
                                            crate::tui::workers::service_action(&name, "start");
                                        *rows = crate::tui::workers::service_rows();
                                        *message = Some(msg);
                                    }
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
                KeyCode::Enter => decision = Some(*yes_selected),
                _ => match cmd {
                    Some('y') => *yes_selected = true,
                    Some('n') => *yes_selected = false,
                    _ => {}
                },
            }
            match decision {
                Some(true) => {
                    let msg = crate::tui::workers::service_action(name, "delete");
                    let rows = crate::tui::workers::service_rows();
                    app.screen = Screen::Services {
                        rows,
                        selected: 0,
                        message: Some(msg),
                    };
                }
                Some(false) => {
                    let rows = crate::tui::workers::service_rows();
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
            scroll,
        } => {
            let active_lines = match view {
                LogView::Deploy => deploy_lines.len(),
                LogView::Software => software_lines.len(),
            };
            match key {
                KeyCode::Esc | KeyCode::Enter => {
                    app.screen = Screen::Main { selected: 3 };
                }
                KeyCode::Tab | KeyCode::Right => {
                    *view = match view {
                        LogView::Deploy => LogView::Software,
                        LogView::Software => LogView::Deploy,
                    };
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
                _ => {}
            }
        }
    }
    Flow::Continue
}

fn move_main_selection(selected: &mut usize, key: KeyCode) {
    match key {
        KeyCode::Left | KeyCode::Up => *selected = selected.saturating_sub(1),
        KeyCode::Right | KeyCode::Down => *selected = (*selected + 1).min(3),
        _ => {}
    }
}

fn main_menu_activate(app: &mut App, selected: usize) -> Flow {
    match selected {
        0 => {
            crate::tui::workers::spawn_scan(app.tx.clone(), app.scan_seq + 1);
            app.scan_seq += 1;
            app.screen = Screen::Scan {
                report: None,
                running: true,
                seq: app.scan_seq,
            };
        }
        1 => {
            app.screen = Screen::UrlInput {
                buffer: String::new(),
                error: None,
                busy: false,
            };
        }
        2 => {
            let rows = crate::tui::workers::service_rows();
            app.screen = Screen::Services {
                rows,
                selected: 0,
                message: None,
            };
        }
        3 => {
            let deploy_lines = app.deploy_history.clone();
            let mut software_lines = app.software_history.clone();
            // On first open, seed software logs from journalctl if empty.
            if software_lines.is_empty() {
                let fetched = crate::tui::workers::fetch_software_logs();
                if !fetched.is_empty() {
                    software_lines.clone_from(&fetched);
                    app.software_history = fetched;
                } else {
                    software_lines.push(
                        "No software logs yet. Deploy a service to see journal output here.".into(),
                    );
                }
            }
            app.screen = Screen::Logs {
                view: LogView::Deploy,
                deploy_lines,
                software_lines,
                scroll: 0,
            };
            // Also spawn a background refresh for software logs.
            let tx = app.tx.clone();
            std::thread::spawn(move || {
                let logs = crate::tui::workers::fetch_software_logs();
                for l in logs {
                    let _ = tx.send(Msg::SoftwareLog(l));
                }
            });
        }
        _ => {}
    }
    Flow::Continue
}

// ── drawing ──────────────────────────────────────────────────────────────────

fn draw(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    // Adaptive floor: below this the layout cannot breathe — say so
    // instead of squeezing header/body/hint into nothing.
    if area.width < MIN_TERM_WIDTH || area.height < MIN_TERM_HEIGHT {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "GHOST PROVIDER",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
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
    // Pure black background for whole screen — exact screenshot
    {
        let buf = f.buffer_mut();
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                if let Some(c) = buf.cell_mut((x, y)) {
                    c.set_style(Style::default().bg(BG).fg(RED));
                }
            }
        }
    }
    // Adaptive header: the full 26-row globe only fits tall windows; short
    // ones get a compact 3-row title so the body keeps usable space.
    let tall = area.height >= TALL_HEADER_MIN_HEIGHT;
    let header_h: u16 = if tall {
        TALL_HEADER_HEIGHT
    } else {
        COMPACT_HEADER_HEIGHT
    };
    let chunks = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);

    if tall {
        draw_header(f, chunks[0]);
    } else {
        draw_compact_header(f, chunks[0]);
    }

    {
        let buf = f.buffer_mut();
        for y in chunks[1].top()..chunks[1].bottom() {
            for x in chunks[1].left()..chunks[1].right() {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.reset();
                }
            }
        }
    }

    match &app.screen {
        Screen::Main { selected } => draw_main_menu(f, chunks[1], *selected),
        Screen::Scan {
            report, running, ..
        } => {
            draw_scan(f, chunks[1], report.as_deref(), *running, app.tick);
        }
        Screen::UrlInput {
            buffer,
            error,
            busy,
        } => {
            draw_url_input(f, chunks[1], buffer, error.as_deref(), *busy, app.tick);
        }
        Screen::Confirm {
            target,
            yes_selected,
        } => {
            draw_confirm(f, chunks[1], target, *yes_selected);
        }
        Screen::Deploy { lines, done } => {
            draw_deploy(f, chunks[1], lines, *done);
        }
        Screen::Services {
            rows,
            selected,
            message,
        } => {
            draw_services(f, chunks[1], rows, *selected, message.as_deref());
        }
        Screen::ConfirmDelete { name, yes_selected } => {
            draw_confirm_delete(f, chunks[1], name, *yes_selected);
        }
        Screen::Logs {
            view,
            deploy_lines,
            software_lines,
            scroll,
        } => {
            draw_logs(f, chunks[1], *view, deploy_lines, software_lines, *scroll);
        }
    }

    f.render_widget(Paragraph::new(hint_line(&app.screen)), chunks[2]);
}

// ── header (wireframe globe + eye, pixel-matched to concept) ───────────────

pub const GLOBE: &[&str] = &[
    r#"                       ███████████                       "#,
    r#"                   ████           ████                   "#,
    r#"                ███                   ███                "#,
    r#"              ██                         ██              "#,
    r#"            ██                             ██            "#,
    r#"           █               ───┬───               █           "#,
    r#"          █           ──────┼──────              █          "#,
    r#"        █           ──  │   │   │  ──           █        "#,
    r#"       █           │ ╲  │  ╱│╲  │ ╱  │           █       "#,
    r#"       █           │  ╲ │ ╱ │ ╲ │╱   │           █       "#,
    r#"      █            │   ╲│╱  │  ╲│   │            █      "#,
    r#"      █      ──────┼────╳───┼───╳────┼──────      █      "#,
    r#"      █            │   ╱│╲  │  ╱│   │            █      "#,
    r#"       █           │  ╱ │ ╲ │ ╱ │╲  │           █       "#,
    r#"       █           │ ╱  │  ╲│╱  │ ╲ │           █       "#,
    r#"        █           ──  │   │   │  ──           █        "#,
    r#"          █           ──────┼──────              █          "#,
    r#"           █               ───┴───               █           "#,
    r#"            ██                             ██            "#,
    r#"              ██                         ██              "#,
    r#"                ███                   ███                "#,
    r#"                   ████           ████                   "#,
    r#"                       ███████████                       "#,
];

pub const EYE_LINES: &[&str] = &[
    r#"      ─      ──────┼───╱▓▓▓▓▓▓▓▓▓▓▓▓▓▓╲───┼──────      ─      "#,
    r#"      ─            │  ╱▓▓▓▓▓▓▓▓●▓▓▓▓▓▓╲ │            ─      "#,
    r#"      ─      ──────┼───╲▓▓▓▓▓▓▓▓▓▓▓▓▓▓╱───┼──────      ─      "#,
];

fn draw_header(f: &mut ratatui::Frame, area: Rect) {
    // Fill background pure black
    let buf = f.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_style(Style::default().bg(BG).fg(RED));
            }
        }
    }
    let mut lines: Vec<Line> = Vec::new();
    for (idx, row) in GLOBE.iter().enumerate() {
        if (11..=13).contains(&idx) {
            let eye = EYE_LINES[idx - 11];
            lines.push(Line::from(Span::styled(
                eye.to_string(),
                Style::default().fg(GLOBE_RED).add_modifier(Modifier::BOLD),
            )));
            continue;
        }
        lines.push(Line::from(Span::styled(
            row.to_string(),
            Style::default().fg(GLOBE_RED),
        )));
    }
    // Exact spacing like screenshot: 1 empty line, then big title, then 1 line subtitle
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "GHOST PROVIDER".to_string(),
        Style::default().fg(RED).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "Программное обеспечение для самохостинга".to_string(),
        Style::default().fg(RED),
    )));
    let para = Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center);
    f.render_widget(para, area);
}

/// Compact 3-row title for short windows: same identity as the globe
/// header, but leaves the body usable instead of eating 26 rows.
fn draw_compact_header(f: &mut ratatui::Frame, area: Rect) {
    let buf = f.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_style(Style::default().bg(BG).fg(RED));
            }
        }
    }
    let lines = vec![
        Line::from(Span::styled(
            "GHOST PROVIDER".to_string(),
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "self-hosting · local-only".to_string(),
            Style::default().fg(DIM),
        )),
    ];
    let para = Paragraph::new(lines)
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(DIM_RED)),
        );
    f.render_widget(para, area);
}

// ── main menu (1×4 horizontal, dashed boxes + arrow — exact concept) ───────

fn draw_main_menu(f: &mut ratatui::Frame, area: Rect, selected: usize) {
    // Screenshot: labels exactly "СИСТЕМА" "РАЗВЁРТЫВАНИЕ" "СЕРВИСЫ" "ЛОГИ"
    // (replacing "СЕТЬ" → "ЛОГИ" as requested) — all uppercase, red, centered.
    let labels = ["СИСТЕМА", "РАЗВЁРТЫВАНИЕ", "СЕРВИСЫ", "ЛОГИ"];

    // Vertically center the 4-box row inside the body area to mimic screenshot's
    // large black gap between subtitle and menu.
    let v_center = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(8),
        Constraint::Min(2),
    ])
    .split(area);
    let row_area = v_center[1];

    let cols = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ])
    .split(row_area);

    for (i, &label) in labels.iter().enumerate() {
        let sel = i == selected;
        let cell = cols[i];

        // Fill cell bg black
        {
            let buf = f.buffer_mut();
            for y in cell.top()..cell.bottom() {
                for x in cell.left()..cell.right() {
                    if let Some(c) = buf.cell_mut((x, y)) {
                        c.set_style(Style::default().bg(BG));
                    }
                }
            }
        }

        let inner = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(7),
            Constraint::Min(0),
        ])
        .split(cell);

        // Label — exactly as screenshot: small caps red, selected = BOLD
        #[allow(clippy::if_same_then_else)]
        let label_fg = if sel { RED } else { RED };
        let label_line = Paragraph::new(Line::from(Span::styled(
            label.to_string(),
            Style::default().fg(label_fg).add_modifier(if sel {
                Modifier::BOLD
            } else {
                Modifier::empty()
            }),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(label_line, inner[0]);

        // Dashed box — screenshot exact: ┌┄┄┄┐ with gap, red, arrow filled
        // Box 9×5, arrow "⬇" solid block (screenshot's thick arrow), centered
        let box_w: u16 = 9;
        let box_h: u16 = 5;
        let bx = inner[1].x + inner[1].width.saturating_sub(box_w) / 2;
        let by = inner[1].y;
        let box_area = Rect {
            x: bx,
            y: by,
            width: box_w,
            height: box_h,
        };

        // Screenshot boxes are all identical red dashed — selected gets brighter + bold border
        let bcol = if sel { RED } else { DIM_RED };
        // Use thick solid arrow like screenshot: "⬇" (U+2B07) — fallback "↓" if unavailable
        let arrow = "⬇";

        let box_lines = vec![
            Line::from(Span::styled("┌┄┄┄┄┄┄┐", Style::default().fg(bcol))),
            Line::from(Span::styled("┆       ┆", Style::default().fg(bcol))),
            Line::from(vec![
                Span::styled("┆   ", Style::default().fg(bcol)),
                Span::styled(arrow, Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                Span::styled("   ┆", Style::default().fg(bcol)),
            ]),
            Line::from(Span::styled("┆       ┆", Style::default().fg(bcol))),
            Line::from(Span::styled("└┄┄┄┄┄┄┘", Style::default().fg(bcol))),
        ];
        let box_para = Paragraph::new(box_lines).alignment(ratatui::layout::Alignment::Center);
        f.render_widget(box_para, box_area);
    }
}

// ── system scan ──────────────────────────────────────────────────────────────

/// Two columns when the terminal is wide enough: facts + interfaces on the
/// left, the listening-ports list on the right — a long port list would
/// otherwise push the screen past the bottom of the window. Narrow
/// terminals keep the old stacked layout.
const SCAN_SIDEBYSIDE_MIN_WIDTH: u16 = 70;

fn draw_scan(f: &mut ratatui::Frame, area: Rect, report: Option<&str>, running: bool, tick: u64) {
    let blk = block("System Scan", RED);
    let inner = blk.inner(area);
    f.render_widget(blk, area);
    match (report, running) {
        (Some(r), _) => {
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
                            Rect {
                                x: inner.x,
                                y: inner.y,
                                width: left_w,
                                height: inner.height,
                            },
                        );
                        f.render_widget(
                            Paragraph::new(right).wrap(Wrap { trim: false }),
                            Rect {
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

// ── url input ────────────────────────────────────────────────────────────────

fn draw_url_input(
    f: &mut ratatui::Frame,
    area: Rect,
    buffer: &str,
    error: Option<&str>,
    busy: bool,
    tick: u64,
) {
    let mut text = vec![
        Line::from(Span::styled(
            " Paste a path to service.yaml (this panel deploys manifests only):",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" GitHub URL or manifest path: ", Style::default().fg(DIM)),
            Span::styled(buffer.to_string(), Style::default().fg(RED)),
            cursor_span(tick),
        ]),
    ];
    if let Some(e) = error {
        text.push(Line::from(Span::styled(
            format!(" x {e}"),
            Style::default().fg(BRIGHT_RED),
        )));
    } else if !buffer.trim().is_empty() {
        let trimmed = buffer.trim();
        let (mark, msg, color) = if trimmed.starts_with("https://") {
            ("+", " looks like a GitHub URL", RED)
        } else if crate::hoster::manifest::looks_like_manifest_path(trimmed) {
            ("+", " looks like a service.yaml path", RED)
        } else {
            (
                "△",
                " expected https://github.com/<owner>/<repo> or a path to service.yaml",
                DIM_RED,
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
            Span::styled(" resolving...", Style::default().fg(DIM)),
        ]));
    }
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Deploy Service", RED)),
        area,
    );
}

// ── confirm ──────────────────────────────────────────────────────────────────

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
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(marker.to_string(), Style::default().fg(DIM)));
        spans.push(Span::styled(label.to_string(), Style::default().fg(DIM)));
    }
    spans
}

fn draw_confirm(
    f: &mut ratatui::Frame,
    area: Rect,
    target: &crate::tui::workers::DeployTarget,
    yes_selected: bool,
) {
    use crate::tui::workers::DeployTarget as Target;
    let mut text = vec![Line::from("")];
    let (title, yes_label) = match target {
        Target::Detect { url, service_label } => {
            text.push(Line::from(vec![
                Span::styled(
                    " Detect ",
                    Style::default().fg(DIM).add_modifier(Modifier::BOLD),
                ),
                Span::styled(service_label.to_string(), Style::default().fg(RED)),
                Span::styled(" from GitHub?", Style::default().fg(BODY)),
            ]));
            text.push(Line::from(vec![
                Span::styled(" URL: ", Style::default().fg(DIM)),
                Span::styled(url.to_string(), Style::default().fg(RED)),
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
                    Style::default().fg(DIM).add_modifier(Modifier::BOLD),
                ),
                Span::styled(service_id.to_string(), Style::default().fg(RED)),
                Span::styled(
                    " (service.yaml) on this machine?",
                    Style::default().fg(BODY),
                ),
            ]));
            text.push(Line::from(vec![
                Span::styled(" File: ", Style::default().fg(DIM)),
                Span::styled(path.display().to_string(), Style::default().fg(RED)),
            ]));
            for line in plan.iter().take(6) {
                text.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().fg(DIM),
                )));
            }
            ("Confirm Deployment", " — deploy")
        }
    };
    // Outdated running build: say it before [Y]es can be pressed.
    if crate::paths::binary_is_stale() {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            " ⚠ this panel runs an OUTDATED build — the fixed binary is on disk.",
            Style::default().fg(DIM_RED).add_modifier(Modifier::BOLD),
        )));
        text.push(Line::from(Span::styled(
            " Quit (q) and relaunch the panel, then deploy again.",
            Style::default().fg(DIM),
        )));
    }
    text.extend([
        Line::from(""),
        Line::from(choice_spans("[Y]es", yes_label, RED, yes_selected)),
        Line::from(choice_spans("[N]o", " — cancel", DIM_RED, !yes_selected)),
        Line::from(""),
        Line::from(Span::styled(
            " ←→ select · Enter confirm",
            Style::default().fg(DIM),
        )),
    ]);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block(title, RED)),
        area,
    );
}

fn draw_confirm_delete(f: &mut ratatui::Frame, area: Rect, name: &str, yes_selected: bool) {
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " Remove ",
                Style::default().fg(BRIGHT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(name.to_string(), Style::default().fg(RED)),
            Span::styled("?", Style::default().fg(BRIGHT_RED)),
        ]),
        Line::from(Span::styled(
            " This deletes the unit, the cloned repository and its caches.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(choice_spans("[Y]es", " — remove", BRIGHT_RED, yes_selected)),
        Line::from(choice_spans("[N]o", " — keep", RED, !yes_selected)),
        Line::from(""),
        Line::from(Span::styled(
            " ←→ select · Enter confirm",
            Style::default().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(block("Confirm Removal", RED)),
        area,
    );
}

// ── deploy ───────────────────────────────────────────────────────────────────

fn draw_deploy(f: &mut ratatui::Frame, area: Rect, lines: &[String], done: Option<bool>) {
    let inner = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(done.map_or(0, |_| 1)),
    ])
    .split(area);
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
                    Style::default().fg(DIM_RED).add_modifier(Modifier::BOLD),
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
            .block(block("Deployment", RED)),
        inner[0],
    );
    if let Some(ok) = done {
        let (label, fg) = if ok {
            (" ✔ DEPLOYED ✔ ", RED)
        } else {
            (" ✖ FAILED ✖ ", BRIGHT_RED)
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                label,
                Style::default().fg(BG).bg(fg).add_modifier(Modifier::BOLD),
            )))
            .alignment(ratatui::layout::Alignment::Center),
            inner[1],
        );
    }
}

fn log_lines(line: &str) -> Vec<Line<'static>> {
    let s = line.trim_start();
    if let Some(body) = s.strip_prefix("! ") {
        if doctor_body_markers(s) {
            return doctor_lines(body).unwrap_or_default();
        }
        return vec![Line::from(vec![
            Span::styled(
                " ✖ ".to_string(),
                Style::default().fg(BRIGHT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(body.to_string(), Style::default().fg(BRIGHT_RED)),
        ])];
    }
    if let Some(body) = s.strip_prefix("warn: ") {
        return vec![Line::from(vec![
            Span::styled(
                " ! ".to_string(),
                Style::default().fg(DIM_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(body.to_string(), Style::default().fg(DIM_RED)),
        ])];
    }
    if let Some(body) = s.strip_prefix("provision: ") {
        return vec![Line::from(vec![
            Span::styled(
                " ● ".to_string(),
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(body.to_string(), Style::default().fg(RED)),
        ])];
    }
    if let Some(url) = s.strip_prefix("listening on ") {
        return vec![Line::from(vec![
            Span::styled(" ✔ listening on ", Style::default().fg(RED)),
            Span::styled(
                url.to_string(),
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            ),
        ])];
    }
    let style = if s.contains("failed") || s.contains("ERROR") {
        Style::default().fg(BRIGHT_RED)
    } else if s.ends_with("...") {
        Style::default().fg(DIM_RED)
    } else if s.starts_with("=>") {
        Style::default().fg(RED)
    } else {
        Style::default().fg(BODY)
    };
    vec![Line::from(Span::styled(format!(" {line}"), style))]
}

fn doctor_body_markers(s: &str) -> bool {
    crate::hoster::toolcheck::is_issue_line(s)
}

fn doctor_lines(body: &str) -> Option<Vec<Line<'static>>> {
    let (problem, cmd, note) = crate::hoster::toolcheck::split_issue(body)?;
    let mut out = vec![
        Line::from(vec![
            Span::styled(
                " ! ".to_string(),
                Style::default().fg(DIM_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(problem.to_string(), Style::default().fg(BRIGHT_RED)),
        ]),
        Line::from(vec![
            Span::styled("   fix » ".to_string(), Style::default().fg(DIM)),
            Span::styled(
                cmd.to_string(),
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
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

// ── services ─────────────────────────────────────────────────────────────────

fn draw_services(
    f: &mut ratatui::Frame,
    area: Rect,
    rows: &[crate::tui::workers::ServiceRow],
    selected: usize,
    message: Option<&str>,
) {
    let mut title = Line::from(vec![
        Span::styled(" My Services ", Style::default().fg(RED)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("s", Style::default().fg(DIM_RED)),
        Span::styled("]top ", Style::default().fg(DIM)),
        Span::styled("star", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("t", Style::default().fg(RED)),
        Span::styled("] ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("d", Style::default().fg(BRIGHT_RED)),
        Span::styled("]elete ", Style::default().fg(DIM)),
        Span::styled("[", Style::default().fg(DIM)),
        Span::styled("r", Style::default().fg(RED)),
        Span::styled("]efresh", Style::default().fg(DIM)),
    ]);
    if let Some(m) = message {
        title.push_span(Span::styled(
            format!("  — {m}"),
            Style::default().fg(DIM_RED),
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
                    " Use \"Deploy Service\" from the menu.",
                    Style::default().fg(DIM_RED),
                )),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(RED))
                    .title(title),
            ),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let sel = i == selected;
            let name_fg = if sel {
                RED
            } else if !row.managed {
                DIM
            } else {
                BODY
            };
            let status_color = match row.status.as_str() {
                "active" | "running" => RED,
                "activating" | "reloading" | "stopped" | "needs login" => DIM_RED,
                _ => BRIGHT_RED,
            };
            // Read-only status rows (tailscale) carry a [vpn] tag instead of
            // the plain managed-unit name column.
            let name_col = if row.managed {
                format!("{:<16}", row.name)
            } else {
                format!("[vpn] {:<10}", row.name)
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    if sel { " » " } else { "   " },
                    Style::default().fg(RED).add_modifier(if sel {
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
                Span::styled(format!("  {}", row.url), Style::default().fg(DIM)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .title(title),
        ),
        area,
    );
}

// ── logs ─────────────────────────────────────────────────────────────────────

fn draw_logs(
    f: &mut ratatui::Frame,
    area: Rect,
    view: LogView,
    deploy_lines: &[String],
    software_lines: &[String],
    scroll: usize,
) {
    let (title, lines, tab_deploy_active) = match view {
        LogView::Deploy => (" Deploy Logs ", deploy_lines, true),
        LogView::Software => (" Software Logs ", software_lines, false),
    };

    // Tab bar
    let tab_bar = Line::from(vec![
        Span::styled(
            if tab_deploy_active {
                " [DEPLOY] "
            } else {
                "  DEPLOY  "
            },
            Style::default()
                .fg(if tab_deploy_active { RED } else { DIM })
                .add_modifier(if tab_deploy_active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
        Span::styled(" · ", Style::default().fg(DIM)),
        Span::styled(
            if !tab_deploy_active {
                " [SOFTWARE] "
            } else {
                "  SOFTWARE  "
            },
            Style::default()
                .fg(if !tab_deploy_active { RED } else { DIM })
                .add_modifier(if !tab_deploy_active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
        Span::styled("  (Tab to switch)", Style::default().fg(DIM)),
    ]);

    let inner = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);

    f.render_widget(Paragraph::new(tab_bar), inner[0]);

    if lines.is_empty() {
        let empty_msg = match view {
            LogView::Deploy => "No deploy logs yet. Start a deployment to see output here.",
            LogView::Software => "No software logs yet. Journal output will appear here.",
        };
        f.render_widget(
            Paragraph::new(Span::styled(empty_msg, Style::default().fg(DIM)))
                .block(block(title.trim(), RED)),
            inner[1],
        );
        return;
    }

    let visible_lines: Vec<Line> = lines[scroll.min(lines.len())..]
        .iter()
        .map(|l| {
            let s = l.trim_start();
            let style = if s.contains("failed") || s.contains("ERROR") || s.starts_with("!") {
                Style::default().fg(BRIGHT_RED)
            } else if s.starts_with("✔") {
                Style::default().fg(RED).add_modifier(Modifier::BOLD)
            } else if s.starts_with("provision:") || s.starts_with("warn:") {
                Style::default().fg(DIM_RED)
            } else if s.starts_with("sandbox:") {
                Style::default().fg(DIM)
            } else {
                Style::default().fg(BODY)
            };
            Line::from(Span::styled(l.clone(), style))
        })
        .collect();

    f.render_widget(
        Paragraph::new(visible_lines)
            .wrap(Wrap { trim: false })
            .block(block(title.trim(), RED)),
        inner[1],
    );
}

// ── scan colorizer ───────────────────────────────────────────────────────────

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
                Style::default().fg(RED).add_modifier(Modifier::BOLD),
            )));
        } else if trimmed.starts_with("PORT ") {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(DIM),
            )));
        } else if in_ports && !trimmed.is_empty() {
            if trimmed == "(none)" {
                out.push(Line::from(Span::styled(
                    format!(" {line}"),
                    Style::default().fg(DIM),
                )));
                continue;
            }
            let deployed = trimmed.contains("(deployed)");
            let hue = if deployed { RED } else { DIM_RED };
            let mut spans = vec![Span::raw(" ")];
            let (port, rest) = trimmed
                .split_once(char::is_whitespace)
                .unwrap_or((trimmed, ""));
            spans.push(Span::styled(
                port.to_string(),
                Style::default().fg(hue).add_modifier(Modifier::BOLD),
            ));
            if !rest.is_empty() {
                spans.push(Span::styled(format!(" {rest}"), Style::default().fg(hue)));
            }
            out.push(Line::from(spans));
        } else if in_ifaces && !trimmed.is_empty() && !trimmed.contains(':') {
            let (head, status) = match trimmed.rfind(char::is_whitespace) {
                Some(i) => (trimmed[..i].to_string(), trimmed[i + 1..].to_string()),
                None => (trimmed.to_string(), String::new()),
            };
            let (name, rest) = match head.find(char::is_whitespace) {
                Some(i) => (head[..i].to_string(), head[i..].to_string()),
                None => (head.clone(), String::new()),
            };
            let status_color = match status.as_str() {
                "up" => RED,
                "down" => BRIGHT_RED,
                _ => DIM_RED,
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
                ("+", RED, BODY)
            } else {
                ("x", BRIGHT_RED, DIM)
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
                Style::default().fg(BRIGHT_RED).add_modifier(Modifier::BOLD),
            )));
        } else if trimmed.contains("MISSING")
            || trimmed.contains("not installed")
            || trimmed.contains("offline")
        {
            out.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(BRIGHT_RED),
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

// ── hint bar ─────────────────────────────────────────────────────────────────

fn hint_line(screen: &Screen) -> Line<'static> {
    // Main screen: exact screenshot — no hint bar, pure black
    let pairs: Vec<(&str, Color)> = match screen {
        Screen::Main { .. } => vec![],
        Screen::Scan { .. } => vec![("Esc back", RED)],
        Screen::UrlInput { busy, .. } => {
            if *busy {
                vec![("working…", DIM_RED)]
            } else {
                vec![("Enter continue", RED), ("Esc back", DIM_RED)]
            }
        }
        Screen::Confirm { .. } => vec![
            ("←→ select", RED),
            ("Y/N", RED),
            ("Enter confirm", RED),
            ("Esc cancel", DIM_RED),
        ],
        Screen::ConfirmDelete { .. } => vec![
            ("←→ select", RED),
            ("Y/N", BRIGHT_RED),
            ("Enter confirm", RED),
            ("Esc keep", RED),
        ],
        Screen::Deploy { done, .. } => {
            if done.is_some() {
                vec![("Enter back", RED)]
            } else {
                vec![("working…", DIM_RED)]
            }
        }
        Screen::Services { .. } => vec![
            ("↑↓ select", RED),
            ("[s]top star[t] [d]elete [r]efresh", RED),
            ("Esc back", RED),
        ],
        Screen::Logs { .. } => vec![
            ("Tab switch view", RED),
            ("↑↓ scroll", RED),
            ("Esc back", RED),
        ],
    };
    // Outdated running build: the bar collapses to the relaunch notice
    // (mid-deploy and the confirm dialog keep their own hints).
    let stale = crate::paths::binary_is_stale()
        && !matches!(
            screen,
            Screen::Deploy { done: None, .. } | Screen::Confirm { .. }
        );
    let pairs: Vec<(&'static str, Color)> = if stale {
        vec![("⟳ newer build on disk — relaunch panel", RED)]
    } else {
        pairs
    };
    if pairs.is_empty() {
        return Line::from(vec![Span::styled("", Style::default().bg(BG))]);
    }
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

// ── helpers ──────────────────────────────────────────────────────────────────

fn spinner_char(tick: u64) -> &'static str {
    SPINNER_FRAMES[(tick / 2) as usize % SPINNER_FRAMES.len()]
}

fn spinner_style(_tick: u64) -> Style {
    Style::default().fg(RED).add_modifier(Modifier::BOLD)
}

fn cursor_span(tick: u64) -> Span<'static> {
    if (tick / 4).is_multiple_of(2) {
        Span::styled("█", Style::default().fg(RED))
    } else {
        Span::raw(" ")
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
}
