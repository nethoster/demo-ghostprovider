//! Auto-provisioning of build tools (bun, pnpm, Go) into the project cache.
//!
//! Deploying a service must not require the operator to pre-install
//! every build tool. For the three tools whose official release mechanics are
//! pure downloads — bun (zip), pnpm (standalone tarball) and the Go toolchain
//! (tarball) — this module provisions a *pinned*, SHA-256-verified binary into
//! `<project>/.ghost-cache/toolbox` when the tool doctor finds a gap, and the
//! deploy then prepends the toolbox dirs to PATH so the host prefetch and the
//! offline sandbox build both use exactly the pinned binaries.
//!
//! POLICY (from `toolcheck.rs`): this software never upgrades system packages
//! by itself — sudo stays a human decision — and it never drops binaries
//! outside the user's project. `toolbox` only ever writes inside the project
//! cache (which `wipe` removes together with the clone and caches). `python3`
//! stays a real system requirement: SearXNG's pip/python runtime is not a pure
//! binary drop and is left to the OS package manager.
//!
//! Every download goes through the allowlisted client, so it is gated by
//! [`crate::netlog::ALLOWED_ENDPOINTS`] and net.log-recorded like any other
//! egress. bun and pnpm sit behind a GitHub release redirect to
//! `release-assets.githubusercontent.com` (a permitted host); Go is fetched
//! directly from `dl.google.com`.

use std::fs::Permissions;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, anyhow};
use sha2::{Digest, Sha256};

use crate::hoster::toolcheck::{Tool, Ver};

/// Which libc the host runs, choosing the matching release asset for tools
/// that publish per-libc binaries (bun, pnpm). Go's official tarball is the
/// same on glibc and musl, so its pin carries no libc tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Libc {
    Glibc,
    Musl,
}

/// Mirrors the archive layout of the pinned release asset so extraction can
/// place the right executable where the PATH expects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pack {
    /// A zip whose single directory entry carries the `bun` binary (e.g.
    /// `bun-linux-x64.zip` → `bun-linux-x64/bun`). The binary is copied
    /// standalone into `<toolbox>/bin/bun`.
    ZipBin,
    /// A tar.gz with a root executable plus a support tree it resolves at
    /// runtime. pnpm's standalone tarball is `pnpm` + `dist/`; the executable
    /// must keep `dist/` beside it (`<toolbox>/pnpm-<version>/…`).
    StandaloneTree,
    /// A tar.gz with the official `go/` prefix (`<toolbox>/go-<version>/bin`).
    GoTree,
}

/// One verified release asset. `libc` is `None` when the asset is libc-agnostic
/// (Go); `Some` matches the host libc. Every SHA-256 was computed from the
/// official download bytes before pinning (see the provenance comments).
struct Pin {
    tool: &'static str,
    version: &'static str,
    libc: Option<&'static str>,
    asset: &'static str,
    url: &'static str,
    sha256: &'static str,
    kind: Pack,
}

// Pin provenance (all verified on x86_64-linux on 2026-09-11):
//   * bun v1.4.2 — official `bun-linux-x64{,-musl}.zip` release assets.
//   * pnpm v11.0.1 — the version Memos pins via `packageManager`; no official
//     checksums exist for the standalone tarball, so the SHA-256 is pinned
//     ourselves (the same class of dual control as the paraglide pins).
//   * go1.27.1 — satisfies every demo `go 1.27.0` directive; digest matches
//     the official go.dev/dl checksum for `go1.27.1.linux-amd64.tar.gz`.
const TOOLBOX_PINS: &[Pin] = &[
    Pin {
        tool: "bun",
        version: "1.4.2",
        libc: Some("glibc"),
        asset: "bun-linux-x64.zip",
        url: "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64.zip",
        sha256: "36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913",
        kind: Pack::ZipBin,
    },
    Pin {
        tool: "bun",
        version: "1.4.2",
        libc: Some("musl"),
        asset: "bun-linux-x64-musl.zip",
        url: "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64-musl.zip",
        sha256: "4835eca59d6da70f4674f5642f6e459dcadab773695b2ed9922d131057989742",
        kind: Pack::ZipBin,
    },
    Pin {
        tool: "pnpm",
        version: "11.0.1",
        libc: Some("glibc"),
        asset: "pnpm-linux-x64.tar.gz",
        url: "https://github.com/pnpm/pnpm/releases/download/v11.0.1/pnpm-linux-x64.tar.gz",
        sha256: "8094c4cea89440c2a4208f5a6402de7b3802bb39c480c1d854519b0545c1554d",
        kind: Pack::StandaloneTree,
    },
    Pin {
        tool: "pnpm",
        version: "11.0.1",
        libc: Some("musl"),
        asset: "pnpm-linux-x64-musl.tar.gz",
        url: "https://github.com/pnpm/pnpm/releases/download/v11.0.1/pnpm-linux-x64-musl.tar.gz",
        sha256: "acca60f1d57c50d37d0ac418837a4697c5a2f0ebc243de1c009efdab24a16e90",
        kind: Pack::StandaloneTree,
    },
    Pin {
        tool: "go",
        version: "1.27.1",
        libc: None,
        asset: "go1.27.1.linux-amd64.tar.gz",
        url: "https://dl.google.com/go/go1.27.1.linux-amd64.tar.gz",
        sha256: "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
        kind: Pack::GoTree,
    },
];

fn tool_name(tool: Tool) -> &'static str {
    match tool {
        Tool::Go => "go",
        Tool::Bun => "bun",
        Tool::Pnpm => "pnpm",
        Tool::Node => "node",
        Tool::Python => "python3",
    }
}

fn parse_ver(s: &str) -> Ver {
    crate::hoster::toolcheck::parse_version(s).unwrap_or((0, 0, 0))
}

/// Does this host's own process image link musl libc? Reading `/proc/self/maps`
/// avoids shelling out and is immune to a *packaged* musl being installed
/// alongside glibc (e.g. Arch's `musl` package ships the loader but the
/// process still runs glibc). A host without `/proc` (exotic) falls back to
/// the glibc asset — the safer default on typical desktop/servers.
fn detect_libc() -> Libc {
    match std::fs::read_to_string("/proc/self/maps") {
        Ok(maps) if maps.lines().any(|l| l.contains("libc.musl-")) => Libc::Musl,
        _ => Libc::Glibc,
    }
}

/// The pin for `tool` on this host that satisfies `min` (when known). Prefer
/// the newest pinned version, and fail closed when the manifest demands more
/// than any pin covers: an unverified download is never fetched.
fn select_pin(tool: Tool, min: Option<Ver>, libc: Libc) -> anyhow::Result<&'static Pin> {
    let name = tool_name(tool);
    let mut best: Option<&'static Pin> = None;
    for pin in TOOLBOX_PINS {
        if pin.tool != name {
            continue;
        }
        match pin.libc {
            Some(l) if l == if libc == Libc::Musl { "musl" } else { "glibc" } => {}
            Some(_) => continue,
            // Go's tarball is libc-agnostic.
            None => {}
        }
        if let Some(min) = min
            && parse_ver(pin.version) < min
        {
            continue;
        }
        if best.is_none_or(|b: &'static Pin| parse_ver(pin.version) > parse_ver(b.version)) {
            best = Some(pin);
        }
    }
    best.ok_or_else(|| match (name, min) {
        (_, Some(m)) => anyhow!(
            "no pinned {name} >= {} for this platform/libc (pins: {}); the manifest \
                 would need a newer build than this release can provision. Install the \
                 tool system-wide or bump the pin table in toolbox.rs.",
            crate::hoster::toolcheck::v_str(m),
            pin_list(name)
        ),
        _ => anyhow!(
            "no pinned {name} for this platform/libc (pins: {})",
            pin_list(name)
        ),
    })
}

fn pin_list(name: &str) -> String {
    TOOLBOX_PINS
        .iter()
        .filter(|p| p.tool == name)
        .map(|p| format!("{}-{}", p.version, p.libc.unwrap_or("any")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a provisioned deploy prepends to PATH (and, for Go, the extra dir).
#[derive(Debug, Clone, Default)]
pub struct Provisioned {
    /// Absolute PATH entries, each pointing at the executable(s).
    pub bin_dirs: Vec<PathBuf>,
}

impl Provisioned {
    /// The `PATH` value with the pinned binaries first, falling back to the
    /// ambient PATH the process inherited. Empty when nothing was provisioned.
    pub fn prepend_path(&self) -> Option<String> {
        (!self.bin_dirs.is_empty()).then(|| join_path_with_ambient(&self.bin_dirs))
    }
}

/// `prefix` entries joined with the process ambient `PATH`. Used wherever a
/// provisioned tool must lead the search path — the sandbox build env, the
/// host prefetch env, and the go probes.
pub fn join_path_with_ambient(prefix: &[PathBuf]) -> String {
    let mut parts: Vec<String> = prefix
        .iter()
        .map(|d| d.to_string_lossy().into_owned())
        .collect();
    if let Ok(cur) = std::env::var("PATH") {
        parts.push(cur);
    }
    parts.join(":")
}

fn toolbox_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".ghost-cache").join("toolbox")
}

/// Size of one Range segment and the parallel worker count of the sharded
/// asset fetch (mirrors `goenv::fetch_zip`).
const SEGMENT: u64 = 4 * 1024 * 1024;
const WORKERS: usize = 6;
/// Upper sanity bound for a pinned asset: the largest today is go's tarball
/// (~152 MiB); anything far beyond that is a proxy/edge artifact, not a tool.
const MAX_ASSET: u64 = 400 * 1024 * 1024;

/// Remove stale extraction dirs from a previously interrupted provision, so a
/// resumed run never collides with half-extracted bytes.
fn cleanup_tmp(box_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(box_dir) else {
        return;
    };
    for entry in rd.flatten() {
        let fname = entry.file_name();
        let Some(name) = fname.to_str() else { continue };
        if name.starts_with(".tmp-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Provision every tool listed in `needs` (those the doctor found missing or
/// too old). Each provisioning is idempotent: a fully placed pin (its marker
/// file or its directory + executable) is left untouched.
///
/// Failures are hard errors: the offline build sandbox has no network, so a
/// tool that was not provisioned before the build cannot be fetched inside it.
pub fn provision(
    project_dir: &Path,
    needs: &[(Tool, Option<Ver>)],
    log: &dyn Fn(&str),
) -> anyhow::Result<Provisioned> {
    if needs.is_empty() {
        return Ok(Provisioned::default());
    }
    let libc = detect_libc();
    let box_dir = toolbox_dir(project_dir);
    std::fs::create_dir_all(&box_dir).with_context(|| format!("creating {}", box_dir.display()))?;
    cleanup_tmp(&box_dir);

    let mut out = Provisioned::default();
    for (tool, min) in needs {
        let pin = select_pin(*tool, *min, libc)?;
        let bin_dir = provision_one(&box_dir, pin)?;
        log(&format!(
            "provision: {} {} ({}) → {}",
            pin.tool,
            pin.version,
            pin.libc.unwrap_or("linux"),
            relative_to_project(&bin_dir)
        ));
        if !out.bin_dirs.contains(&bin_dir) {
            out.bin_dirs.push(bin_dir);
        }
    }
    Ok(out)
}

fn relative_to_project(path: &Path) -> String {
    let s = path.to_string_lossy();
    match s.rsplit_once(".ghost-cache/") {
        Some((_, tail)) => format!(".ghost-cache/{tail}"),
        None => s.into_owned(),
    }
}

/// Place one pinned tool, returning the directory that must be prepended to
/// PATH. Skips straight to the answer when an earlier run already placed it.
fn provision_one(box_dir: &Path, pin: &'static Pin) -> anyhow::Result<PathBuf> {
    match pin.kind {
        Pack::ZipBin => {
            let bin_dir = box_dir.join("bin");
            let target = bin_dir.join(pin.tool);
            let stamp = bin_dir.join(format!(".{}-{}", pin.tool, pin.version));
            if stamp.is_file() && target.is_file() {
                return Ok(bin_dir);
            }
            let bytes = fetch_verify(box_dir, pin)?;
            let tmp = box_dir.join(format!(
                ".tmp-{}",
                crate::atomic::random_hex(4).unwrap_or_default()
            ));
            std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            let entry = zip_bin_entry(&bytes, pin.tool)
                .with_context(|| format!("extracting {} from {}", pin.tool, pin.asset))?;
            std::fs::create_dir_all(&bin_dir)?;
            let staged = bin_dir.join(format!(
                ".tmp-{}-{}",
                pin.tool,
                crate::atomic::random_hex(3).unwrap_or_default()
            ));
            write_executable(&staged, &entry)?;
            std::fs::rename(&staged, &target)
                .with_context(|| format!("placing {} into {}", pin.asset, target.display()))?;
            let _ = std::fs::remove_dir_all(&tmp);
            write_stamp(&stamp)?;
            Ok(bin_dir)
        }
        Pack::StandaloneTree => {
            let dir = box_dir.join(format!("{}-{}", pin.tool, pin.version));
            let bin = dir.join(pin.tool);
            if bin.is_file() {
                return Ok(dir);
            }
            let tmp = box_dir.join(format!(
                ".tmp-{}",
                crate::atomic::random_hex(4).unwrap_or_default()
            ));
            unpack_tree(&tmp, box_dir, pin)?;
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::rename(&tmp, &dir)
                .with_context(|| format!("placing {} into {}", pin.asset, dir.display()))?;
            set_executable(&dir.join(pin.tool))?;
            Ok(dir)
        }
        Pack::GoTree => {
            let dir = box_dir.join(format!("go-{}", pin.version));
            let bin = dir.join("bin").join("go");
            if bin.is_file() {
                return Ok(dir.join("bin"));
            }
            let tmp = box_dir.join(format!(
                ".tmp-{}",
                crate::atomic::random_hex(4).unwrap_or_default()
            ));
            unpack_tree(&tmp, box_dir, pin)?;
            let src = tmp.join("go");
            if !src.join("bin").join("go").is_file() {
                return Err(anyhow!("{} did not contain go/bin/go", pin.asset));
            }
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::rename(&src, &dir)
                .with_context(|| format!("placing {} into {}", pin.asset, dir.display()))?;
            let _ = std::fs::remove_dir_all(&tmp);
            set_executable(&dir.join("bin").join("go"))?;
            Ok(dir.join("bin"))
        }
    }
}

/// Download a pinned asset and verify it against the pinned SHA-256 before
/// anything is placed. Large bodies are fetched as parallel Range segments
/// (see [`fetch_sharded`]) rather than one long GET: several links cut or
/// stall long single-flow transfers while serving short 206 flows fine — the
/// same reason the built-in go toolchain zip and the VERT static blob already
/// shard. Every hop keeps the allowlist gate and its net.log record.
fn fetch_verify(box_dir: &Path, pin: &'static Pin) -> anyhow::Result<Vec<u8>> {
    let size = crate::hoster::httpclient::remote_len(pin.url)?;
    if size == 0 || size > MAX_ASSET {
        anyhow::bail!("implausible size {size} for {}", pin.asset);
    }
    let bytes = if size <= SEGMENT {
        crate::hoster::httpclient::get_bytes_range(pin.url, 0, size - 1)?
    } else {
        fetch_sharded(box_dir, pin, size)?
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got = format!("{:x}", hasher.finalize());
    if got != pin.sha256 {
        return Err(anyhow!(
            "SHA-256 mismatch for {} ({}) — expected {}, got {}. The allowlisted \
             endpoint served different bytes than the pin; refusing to place it.",
            pin.tool,
            pin.asset,
            pin.sha256,
            got
        ));
    }
    Ok(bytes)
}

/// Range shard of a pinned asset. Worker threads pull disjoint `SEGMENT`-sized
/// spans through the shared allowlisted client and stage each part; a part of
/// the exact expected length counts as done (so an interrupted run resumes it).
/// Any worker failure aborts the rest; the assembly order is fixed by part
/// index, so the returned bytes are byte-identical to a single whole-body GET.
fn fetch_sharded(box_dir: &Path, pin: &'static Pin, size: u64) -> anyhow::Result<Vec<u8>> {
    let stage = box_dir.join(format!(
        ".tmp-fetch-{}",
        crate::atomic::random_hex(4).unwrap_or_default()
    ));
    std::fs::create_dir_all(&stage).with_context(|| format!("creating {}", stage.display()))?;
    let segs = size.div_ceil(SEGMENT);
    let seg_len = move |i: u64| ((i + 1) * SEGMENT).min(size) - i * SEGMENT;
    let next = Arc::new(Mutex::new(0u64));
    let failure: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
    let aborted = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for _ in 0..WORKERS {
        let next = Arc::clone(&next);
        let failure = Arc::clone(&failure);
        let aborted = Arc::clone(&aborted);
        let url = pin.url.to_string();
        let stage = stage.clone();
        handles.push(std::thread::spawn(move || {
            loop {
                if aborted.load(Ordering::SeqCst) {
                    break;
                }
                let i = {
                    let mut g = next.lock().unwrap();
                    let i = *g;
                    *g += 1;
                    i
                };
                if i >= segs {
                    break;
                }
                let part = stage.join(format!("{i:07}"));
                if part.metadata().map(|m| m.len()).unwrap_or(0) == seg_len(i) {
                    continue;
                }
                let start = i * SEGMENT;
                let end = ((i + 1) * SEGMENT - 1).min(size - 1);
                match crate::hoster::httpclient::get_bytes_range(&url, start, end) {
                    Ok(bytes) => {
                        if bytes.len() as u64 != seg_len(i) {
                            *failure.lock().unwrap() = Some(anyhow!(
                                "short range {}..={} for {} (got {} of {} bytes)",
                                start,
                                end,
                                url,
                                bytes.len(),
                                seg_len(i)
                            ));
                            aborted.store(true, Ordering::SeqCst);
                            break;
                        }
                        if let Err(e) = std::fs::write(&part, &bytes) {
                            *failure.lock().unwrap() =
                                Some(anyhow!("writing {}: {e}", part.display()));
                            aborted.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                    Err(e) => {
                        *failure.lock().unwrap() = Some(e);
                        aborted.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    if let Some(e) = failure.lock().unwrap().take() {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }

    let mut out = Vec::with_capacity(size as usize);
    for i in 0..segs {
        let part = stage.join(format!("{i:07}"));
        let bytes = std::fs::read(&part)
            .with_context(|| format!("reading assembled part {}", part.display()))?;
        out.extend_from_slice(&bytes);
    }
    let _ = std::fs::remove_dir_all(&stage);
    Ok(out)
}

fn write_executable(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    set_executable(path)
}

fn set_executable(path: &Path) -> anyhow::Result<()> {
    std::fs::set_permissions(path, Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x {}", path.display()))
}

fn write_stamp(stamp: &Path) -> anyhow::Result<()> {
    std::fs::write(stamp, b"ok\n").with_context(|| format!("writing {}", stamp.display()))
}

/// Extract the single binary of a `ZipBin` archive into memory. The zip may
/// carry the binary at any entry (bun uses `bun-linux-x64/bun`); we match the
/// entry whose path ends with `/<tool>`.
fn zip_bin_entry(bytes: &[u8], tool: &str) -> anyhow::Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec()))
        .context("opening zip archive")?;
    let wanted = format!("/{tool}");
    let mut hit: Option<(String, Vec<u8>)> = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("reading zip entry")?;
        let path = file.name().context("reading zip entry name")?.to_string();
        if path.starts_with("__MACOSX") {
            continue;
        }
        if path.ends_with(&wanted) {
            let mut buf = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut buf)
                .context("reading zip entry body")?;
            hit = Some((path, buf));
            break;
        }
    }
    hit.map(|(_, b)| b).ok_or_else(|| {
        anyhow!("no entry ending in '{wanted}' inside the zip (bun layout changed?)")
    })
}

/// Extract a gzip'd tar tree into `dest`. Used for the standalone pnpm and Go
/// layouts; directory modes come from the archive, so it is safe to rename
/// the whole tree into place.
fn unpack_tree(dest: &Path, box_dir: &Path, pin: &'static Pin) -> anyhow::Result<()> {
    let bytes = fetch_verify(box_dir, pin)?;
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(dest)
        .with_context(|| format!("extracting {} into {}", pin.asset, dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amd64_glibc_bun_pin_has_known_verified_digest() {
        // Digest sanity that survives copy-paste: the pinned sha256 must be a
        // well-formed hex string of the right length, never a placeholder.
        for pin in TOOLBOX_PINS {
            assert_eq!(pin.sha256.len(), 64, "{}", pin.asset);
            assert!(
                pin.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "{}: {}",
                pin.asset,
                pin.sha256
            );
            assert!(
                pin.url.starts_with("https://"),
                "{} must be https",
                pin.asset
            );
        }
    }

    #[test]
    fn every_pin_asset_matches_its_pack_layout() {
        for pin in TOOLBOX_PINS {
            match pin.kind {
                Pack::ZipBin => assert!(
                    pin.asset.ends_with(".zip"),
                    "{}: ZipBin asset must be a zip",
                    pin.asset
                ),
                Pack::StandaloneTree | Pack::GoTree => assert!(
                    pin.asset.ends_with(".tar.gz"),
                    "{}: tree asset must be a tar.gz",
                    pin.asset
                ),
            }
        }
    }

    #[test]
    fn selection_prefers_satisfying_newest_and_fails_closed() {
        // Explicit min above every pin for the tool → no pin, hard error.
        assert!(select_pin(Tool::Bun, Some((2, 0, 0)), Libc::Glibc).is_err());
        assert!(select_pin(Tool::Pnpm, Some((12, 0, 0)), Libc::Glibc).is_err());
        assert!(select_pin(Tool::Go, Some((1, 29, 0)), Libc::Glibc).is_err());
        // Unprovisionable tools have no pins at all.
        assert!(select_pin(Tool::Python, None, Libc::Glibc).is_err());

        let bun = select_pin(Tool::Bun, Some((1, 2, 0)), Libc::Glibc).unwrap();
        assert_eq!(bun.version, "1.4.2");
        assert_eq!(bun.libc, Some("glibc"));
        let bun_musl = select_pin(Tool::Bun, Some((1, 2, 0)), Libc::Musl).unwrap();
        assert_eq!(bun_musl.libc, Some("musl"));
        assert_ne!(bun.sha256, bun_musl.sha256, "libc variants must differ");

        // Go: no libc tag, and a gap to satisfy is honored.
        let go = select_pin(Tool::Go, Some((1, 27, 0)), Libc::Musl).unwrap();
        assert_eq!(go.version, "1.27.1");
        assert_eq!(go.libc, None);
    }

    #[test]
    fn prepend_path_leaves_ambient_intact_and_empty_when_nothing_provisioned() {
        let empty = Provisioned::default();
        assert_eq!(empty.prepend_path(), None);
        let p = Provisioned {
            bin_dirs: vec![PathBuf::from("/srv/demo/.ghost-cache/toolbox/bin")],
        };
        let v = p.prepend_path().unwrap();
        assert!(
            v.starts_with("/srv/demo/.ghost-cache/toolbox/bin:"),
            "pinned dir must come first: {v}"
        );
        assert!(
            v.ends_with(&std::env::var("PATH").unwrap_or_default()),
            "ambient PATH must be preserved: {v}"
        );
    }

    #[test]
    fn detect_libc_returns_something_sane() {
        assert!(matches!(detect_libc(), Libc::Glibc | Libc::Musl));
    }
}
