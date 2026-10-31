//! `__cloudflared-supervisor`: the small process that owns one `cloudflared`
//! child. It is deliberately a separate process so a wedged panel, a closed
//! TUI or a hard kill cannot orphan a public tunnel.

#![allow(unsafe_code)] // process groups + PDEATHSIG; see pre_exec below.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::networks::cloudflare::{self, CloudflaredInfo};
use crate::networks::registry::{self, ShareRecord, ShareStatus};

const STOP_GRACE: Duration = Duration::from_secs(8);
const REAP_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct NetworkRow {
    pub service: String,
    pub unit_name: String,
    pub local_url: String,
    pub port: Option<u16>,
    pub status: ShareStatus,
    pub public_url: Option<String>,
    pub message: Option<String>,
}

impl NetworkRow {
    pub fn can_start(&self) -> bool {
        self.port.is_some() && !matches!(self.status, ShareStatus::Live | ShareStatus::Starting)
    }
}

/// Start a share for one deployed service. Returns immediately: the TUI polls
/// the event file and flips the row to live when the public URL appears.
pub fn start(service: &str, unit_name: &str, local_url: &str) -> Result<ShareRecord, String> {
    let port = cloudflare::parse_local_url(local_url)?;
    let info = CloudflaredInfo::discover()?;
    stop(service);

    let dir = crate::paths::network_dir(service);
    create_private_dir(&dir).map_err(|e| format!("cannot create share dir: {e}"))?;
    let home = dir.join("home");
    let tmp = dir.join("tmp");
    create_private_dir(&home).map_err(|e| format!("cannot create HOME dir: {e}"))?;
    create_private_dir(&tmp).map_err(|e| format!("cannot create TMPDIR: {e}"))?;

    let events = dir.join("events.log");
    let log = dir.join("cloudflared.log");
    let supervisor_pid = dir.join("supervisor.pid");
    let child_pid = dir.join("cloudflared.pid");
    let _ = std::fs::remove_file(&supervisor_pid);
    let _ = std::fs::remove_file(&child_pid);
    let _ = std::fs::write(&events, b"");
    let _ = std::fs::write(
        &log,
        format!("== share {service} -> http://127.0.0.1:{port} starting ==\n"),
    );

    let label = format!(
        "demo-ghostprovider-{}-{}",
        crate::paths::safe_component(service),
        crate::atomic::random_hex(4).unwrap_or_else(|_| "connector".into())
    );
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.arg("__cloudflared-supervisor")
        .arg("--service")
        .arg(service)
        .arg("--port")
        .arg(port.to_string())
        .arg("--cloudflared")
        .arg(&info.path)
        .arg("--events")
        .arg(&events)
        .arg("--log")
        .arg(&log)
        .arg("--home")
        .arg(&home)
        .arg("--tmp")
        .arg(&tmp)
        .arg("--supervisor-pid")
        .arg(&supervisor_pid)
        .arg("--child-pid")
        .arg(&child_pid)
        .arg("--label")
        .arg(&label);
    cmd.env_clear();
    for key in [
        "PATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd.env("HOME", &home)
        .env("TMPDIR", &tmp)
        .env(
            "PATH",
            std::env::var("PATH")
                .unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        // If the panel is killed, the kernel sends SIGTERM to the supervisor,
        // which then stops cloudflared with the normal grace period.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
    }

    let child = cmd
        .spawn()
        .map_err(|e| format!("cannot start the Cloudflare supervisor: {e}"))?;
    let record = ShareRecord {
        service: service.into(),
        unit_name: unit_name.into(),
        local_url: format!("http://127.0.0.1:{port}"),
        port,
        public_url: None,
        supervisor_pid: child.id(),
        cloudflared_pid: None,
        status: ShareStatus::Starting,
        message: Some("waiting for cloudflared…".into()),
        started_at: unix_now(),
    };
    registry::put(record.clone());
    let _ = write_pid(&supervisor_pid, child.id());
    Ok(record)
}

/// Stop one share and forget its registry record. Idempotent.
pub fn stop(service: &str) {
    let record = registry::get(service);
    let dir = crate::paths::network_dir(service);
    let sup = record
        .as_ref()
        .map(|r| r.supervisor_pid)
        .filter(|p| *p != 0)
        .or_else(|| read_pid(&dir.join("supervisor.pid")));
    if let Some(pid) = sup {
        terminate_supervisor(pid, service);
    }
    let child = record
        .and_then(|r| r.cloudflared_pid)
        .or_else(|| read_pid(&dir.join("cloudflared.pid")));
    if let Some(pid) = child
        && pid_alive(pid)
    {
        signal_group(pid, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(dir.join("supervisor.pid"));
    let _ = std::fs::remove_file(dir.join("cloudflared.pid"));
    registry::remove(service);
}

/// Stop every known or discoverable share. Called at panel exit, on service
/// deletion and from `__cleanup`.
pub fn stop_all() {
    refresh_all();
    for record in registry::list() {
        stop(&record.service);
    }
    sweep_orphans();
}

/// Kill supervisors that outlived a lost registry (crash, manual rm).
pub fn sweep_orphans() {
    let root = crate::paths::networks_dir();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(pid) = read_pid(&dir.join("supervisor.pid")) {
            if is_supervisor(pid, name) {
                terminate_supervisor(pid, name);
            }
            let _ = std::fs::remove_file(dir.join("supervisor.pid"));
        }
        if let Some(pid) = read_pid(&dir.join("cloudflared.pid")) {
            if pid_alive(pid) {
                signal_group(pid, libc::SIGKILL);
            }
            let _ = std::fs::remove_file(dir.join("cloudflared.pid"));
        }
    }
}

/// Fold event files and process liveness into the persisted records.
pub fn refresh_all() {
    let mut shares = registry::load();
    let mut changed = false;
    for record in shares.values_mut() {
        let events = registry::read_events(&record.service);
        let dir = crate::paths::network_dir(&record.service);
        let child = read_pid(&dir.join("cloudflared.pid"));
        if record.cloudflared_pid != child {
            record.cloudflared_pid = child;
            changed = true;
        }
        if let Some(url) = events.public_url
            && (record.public_url.as_deref() != Some(url.as_str())
                || record.status != ShareStatus::Live)
        {
            record.public_url = Some(url);
            record.status = ShareStatus::Live;
            record.message = None;
            changed = true;
        }
        if let Some(error) = events.error
            && (record.status != ShareStatus::Error
                || record.message.as_deref() != Some(error.as_str()))
        {
            record.status = ShareStatus::Error;
            record.message = Some(error);
            changed = true;
        }
        if let Some(code) = events.exit
            && !matches!(record.status, ShareStatus::Error | ShareStatus::Stopped)
        {
            record.status = ShareStatus::Stopped;
            record.message = Some(format!("cloudflared exited ({code})"));
            changed = true;
        }
        let alive = record.supervisor_pid != 0
            && pid_alive(record.supervisor_pid)
            && is_supervisor(record.supervisor_pid, &record.service);
        if !alive && matches!(record.status, ShareStatus::Starting | ShareStatus::Live) {
            record.status = ShareStatus::Stopped;
            record.message = Some("supervisor exited".into());
            changed = true;
        }
    }
    if changed {
        let _ = registry::save(&shares);
    }
}

/// Deployed services annotated with their current share state, sorted by
/// service name. Stale records for units that no longer exist are included so
/// the user can stop them, but they can never be started.
pub fn rows() -> Vec<NetworkRow> {
    refresh_all();
    let shares = registry::load();
    let mut out: Vec<NetworkRow> = crate::state::list()
        .into_iter()
        .map(|(name, entry)| {
            let share = shares.get(&name);
            let local_url = entry
                .urls
                .first()
                .cloned()
                .or_else(|| (!entry.url.is_empty()).then(|| entry.url.clone()))
                .unwrap_or_default();
            let port = cloudflare::parse_local_url(&local_url).ok();
            NetworkRow {
                service: name,
                unit_name: entry.unit_name,
                local_url,
                port,
                status: share.map(|s| s.status).unwrap_or(ShareStatus::Stopped),
                public_url: share.and_then(|s| s.public_url.clone()),
                message: share.and_then(|s| s.message.clone()),
            }
        })
        .collect();
    for (name, record) in shares {
        if out.iter().any(|r| r.service == name) {
            continue;
        }
        out.push(NetworkRow {
            service: name,
            unit_name: record.unit_name,
            local_url: record.local_url,
            port: Some(record.port),
            status: record.status,
            public_url: record.public_url,
            message: Some("service is no longer deployed — stop this share".into()),
        });
    }
    out.sort_by(|a, b| a.service.cmp(&b.service));
    out
}

pub fn public_url(service: &str) -> Option<String> {
    registry::get(service).and_then(|r| r.public_url)
}

pub fn share_log_tail(service: &str, max: usize) -> Vec<String> {
    let path = crate::paths::network_dir(service).join("cloudflared.log");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if lines.len() > max {
        lines.drain(..lines.len() - max);
    }
    lines
}

// ---------------------------------------------------------------------------
// supervisor child
// ---------------------------------------------------------------------------

struct Cli {
    #[allow(dead_code)]
    service: String,
    port: u16,
    cloudflared: PathBuf,
    events: PathBuf,
    log: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
    supervisor_pid: PathBuf,
    child_pid: PathBuf,
    label: String,
}

fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let mut service = None;
    let mut port = None;
    let mut cloudflared = None;
    let mut events = None;
    let mut log = None;
    let mut home = None;
    let mut tmp = None;
    let mut supervisor_pid = None;
    let mut child_pid = None;
    let mut label = None;
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        let value = |i: usize| {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{key} needs a value"))
        };
        match key {
            "--service" => service = Some(value(i)?),
            "--port" => {
                port = Some(
                    value(i)?
                        .parse::<u16>()
                        .map_err(|_| "invalid --port".to_string())?,
                )
            }
            "--cloudflared" => cloudflared = Some(PathBuf::from(value(i)?)),
            "--events" => events = Some(PathBuf::from(value(i)?)),
            "--log" => log = Some(PathBuf::from(value(i)?)),
            "--home" => home = Some(PathBuf::from(value(i)?)),
            "--tmp" => tmp = Some(PathBuf::from(value(i)?)),
            "--supervisor-pid" => supervisor_pid = Some(PathBuf::from(value(i)?)),
            "--child-pid" => child_pid = Some(PathBuf::from(value(i)?)),
            "--label" => label = Some(value(i)?),
            other => return Err(format!("unknown supervisor argument: {other}")),
        }
        i += 2;
    }
    Ok(Cli {
        service: service.ok_or("missing --service")?,
        port: port.ok_or("missing --port")?,
        cloudflared: cloudflared.ok_or("missing --cloudflared")?,
        events: events.ok_or("missing --events")?,
        log: log.ok_or("missing --log")?,
        home: home.ok_or("missing --home")?,
        tmp: tmp.ok_or("missing --tmp")?,
        supervisor_pid: supervisor_pid.ok_or("missing --supervisor-pid")?,
        child_pid: child_pid.ok_or("missing --child-pid")?,
        label: label.ok_or("missing --label")?,
    })
}

/// Internal subcommand entry point. `args` excludes argv[0].
pub fn run_cli(args: &[String]) -> anyhow::Result<()> {
    let cfg = parse_cli(args).map_err(anyhow::Error::msg)?;
    let fail = |msg: String| {
        write_event(&cfg.events, "GP_TUNNEL_ERROR", &msg);
        write_event(&cfg.events, "GP_TUNNEL_EXIT", "1");
        anyhow::anyhow!(msg)
    };
    let info = cloudflare::probe_path(&cfg.cloudflared).map_err(fail)?;
    let argv = cloudflare::build_args(&info, cfg.port, &cfg.label).map_err(fail)?;

    create_private_dir(&cfg.home).map_err(|e| fail(format!("cannot create HOME: {e}")))?;
    create_private_dir(&cfg.tmp).map_err(|e| fail(format!("cannot create TMPDIR: {e}")))?;
    if let Some(dir) = cfg.events.parent() {
        create_private_dir(dir).map_err(|e| fail(format!("cannot create events dir: {e}")))?;
    }
    let _ = write_pid(&cfg.supervisor_pid, std::process::id());
    write_event(
        &cfg.events,
        "GP_TUNNEL_STARTING",
        &format!("supervisor pid {}", std::process::id()),
    );

    let mut cmd = Command::new(&info.path);
    cmd.args(&argv)
        .env_clear()
        .env("HOME", &cfg.home)
        .env("TMPDIR", &cfg.tmp)
        .env(
            "PATH",
            std::env::var("PATH")
                .unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        // If the supervisor is SIGKILLed, cloudflared goes with it immediately
        // rather than lingering as an orphan that still publishes the port.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }

    let result = run_child(
        cmd,
        &cfg.events,
        &cfg.log,
        &cfg.child_pid,
        Arc::clone(&stop),
    );
    let _ = std::fs::remove_file(&cfg.supervisor_pid);
    let _ = std::fs::remove_file(&cfg.child_pid);
    match result {
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            if !status.success() {
                return Err(anyhow::anyhow!("cloudflared exited with status {code}"));
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn run_child(
    mut cmd: Command,
    events: &Path,
    log: &Path,
    child_pid_path: &Path,
    stop: Arc<AtomicBool>,
) -> std::io::Result<ExitStatus> {
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            write_event(
                events,
                "GP_TUNNEL_ERROR",
                &format!("cannot start cloudflared: {e}"),
            );
            write_event(events, "GP_TUNNEL_EXIT", "1");
            return Err(e);
        }
    };
    let pid = child.id();
    let _ = write_pid(child_pid_path, pid);

    let seen_url = Arc::new(Mutex::new(false));
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let mut pumps = Vec::new();
    if let Some(stdout) = stdout {
        pumps.push(std::thread::spawn({
            let events = events.to_path_buf();
            let log = log.to_path_buf();
            let seen_url = Arc::clone(&seen_url);
            move || pump(stdout, &log, &events, &seen_url)
        }));
    }
    if let Some(stderr) = stderr {
        pumps.push(std::thread::spawn({
            let events = events.to_path_buf();
            let log = log.to_path_buf();
            let seen_url = Arc::clone(&seen_url);
            move || pump(stderr, &log, &events, &seen_url)
        }));
    }

    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if stop.load(Ordering::Relaxed) {
            terminate_child(&mut child, pid);
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    for pump in pumps {
        let _ = pump.join();
    }
    let _ = std::fs::remove_file(child_pid_path);

    let code = status.code().unwrap_or(-1);
    write_event(events, "GP_TUNNEL_EXIT", &code.to_string());
    if !status.success() && !*seen_url.lock().unwrap() {
        write_event(
            events,
            "GP_TUNNEL_ERROR",
            &format!("cloudflared exited before publishing a URL (status {code})"),
        );
    }
    Ok(status)
}

fn pump<R: Read>(reader: R, log: &Path, events: &Path, seen_url: &Arc<Mutex<bool>>) {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let raw = String::from_utf8_lossy(&buf);
                let line = raw.trim_end_matches(['\n', '\r']);
                append_log(log, line);
                if let Some(url) = cloudflare::parse_quick_tunnel_url(line) {
                    let mut seen = seen_url.lock().unwrap();
                    if !*seen {
                        *seen = true;
                        write_event(events, "GP_TUNNEL_URL", &url);
                    }
                }
            }
        }
    }
}

fn terminate_child(child: &mut Child, pid: u32) {
    signal_group(pid, libc::SIGTERM);
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    signal_group(pid, libc::SIGKILL);
    let _ = child.kill();
    let deadline = Instant::now() + REAP_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn terminate_supervisor(pid: u32, service: &str) {
    if !pid_alive(pid) || !is_supervisor(pid, service) {
        return;
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + STOP_GRACE + REAP_GRACE;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

fn signal_group(pid: u32, sig: i32) {
    if pid == 0 {
        return;
    }
    unsafe {
        libc::kill(-(pid as i32), sig);
        libc::kill(pid as i32, sig);
    }
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn is_supervisor(pid: u32, service: &str) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    text.contains("__cloudflared-supervisor") && text.contains(service)
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn write_pid(path: &Path, pid: u32) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::atomic::write_atomic(path, pid.to_string().as_bytes())
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn append_log(path: &Path, line: &str) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let capped: String = line.chars().take(4000).collect();
        let _ = writeln!(f, "{capped}");
    }
}

fn write_event(path: &Path, kind: &str, message: &str) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let line = format!("{kind}\t{}\n", message.replace(['\n', '\r'], " "));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gp-net-{tag}-{}-{}",
            std::process::id(),
            crate::atomic::random_hex(4).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fake_cloudflared_url_is_evented_and_emails_are_redacted() {
        let dir = tmp("sup");
        let events = dir.join("events.log");
        let log = dir.join("cloudflared.log");
        let child_pid = dir.join("child.pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "printf 'https://quiet-marble-otter.trycloudflare.com\\n'; \
             printf 'allowed alice@example.com\\n' >&2; sleep 30",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let events_thread = events.clone();
        let log_thread = log.clone();
        let child_thread = child_pid.clone();
        let handle = std::thread::spawn(move || {
            run_child(cmd, &events_thread, &log_thread, &child_thread, stop_thread)
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while registry::read_events_file(&events).public_url.is_none() && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Relaxed);
        let status = handle.join().unwrap().unwrap();
        assert!(!status.success() || status.success()); // reaped without hanging
        let text = std::fs::read_to_string(&events).unwrap();
        assert!(text.contains("GP_TUNNEL_URL\thttps://quiet-marble-otter.trycloudflare.com"));
        assert!(text.contains("GP_TUNNEL_EXIT"));
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("allowed alice@example.com"));
        assert!(!child_pid.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stop_is_idempotent_for_unknown_service() {
        stop("gp-no-such-service");
    }
}
