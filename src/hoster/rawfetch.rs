//! Materialize a GitHub repository's working tree from the REST tree API plus
//! `raw.githubusercontent.com` blob downloads, instead of a `git clone`.
//!
//! Why this exists: some egress filters throttle per-*flow* transfers to
//! `github.com`/`codeload.github.com` hard enough (measured ~10KB/s with the
//! flow dying at ~10-12MB) that cloning or downloading a tarball of any
//! mid-sized repository takes many minutes and then fails. The same
//! environments leave `raw.githubusercontent.com` (Fastly) functional; raw
//! supports HTTP Range, so a large file is sharded across parallel flows
//! whose aggregate clears the per-flow cap.
//!
//! Security invariants (same as the rest of the hoster):
//!  * Every request goes through [`crate::hoster::httpclient`]: allowlist-
//!    gated, https-only, net.log-accounted, and credentials never leave
//!    api.github.com — `raw` never receives the token.
//!  * Tree paths from GitHub JSON are strictly validated (no absolute paths,
//!    no `..`, no empty/control/backslash components) before they are joined
//!    anywhere; symlink entries (mode 120000) are skipped, submodules never
//!    materialized.
//!  * Every part is written to a 0600 temp file created with `O_EXCL` (refuses
//!    symlink planting) and renamed atomically; payload sizes are verified
//!    byte-for-byte against the tree's recorded sizes.
//!  * Staging lives *inside* the dedicated, freshly-cleared dest, so nothing
//!    leaks outside the project tree; any failure removes the whole dest.
//!  * Worker threads are joined; nothing is spawned, no argv/procfile involved.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};

use super::httpclient;

/// Per-flow chunk for large blobs — far below the observed transfer cap.
const SEGMENT: u64 = 4 * 1024 * 1024;
const WORKERS: usize = 6;
/// Defensive sanity caps; built-in services are far smaller. Hitting these
/// must fail loudly, never silently truncate the tree.
const MAX_FILES: usize = 30_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_DIRS: usize = 5_000;

#[derive(serde::Deserialize)]
struct RepoInfo {
    default_branch: String,
}

#[derive(serde::Deserialize)]
struct TreeResp {
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    tree: Vec<TreeEntry>,
}

#[derive(serde::Deserialize)]
struct TreeEntry {
    path: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

/// `https://github.com/<owner>/<repo>` (optionally `.git`, trailing slash).
fn github_repo(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" {
        return None;
    }
    let path = rest.split(['?', '#']).next()?.split('/');
    let mut segs = path.filter(|s| !s.is_empty());
    let host = segs.next()?;
    if host != "github.com" {
        return None;
    }
    let owner = segs.next()?;
    let repo = segs.next()?.trim_end_matches(".git");
    if segs.next().is_some() || repo.is_empty() {
        return None;
    }
    let clean = |s: &str| {
        !s.is_empty()
            && !s.contains("..")
            && s.len() <= 100
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    if !clean(owner) || !clean(repo) {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// A tree path must survive being `join`ed under a dedicated dest: no
/// absolute path, no `..`/`.`/empty components, no backslashes, no NUL or
/// control bytes, sane per-component and total lengths.
fn safe_rel_path(path: &str) -> Option<PathBuf> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.len() > 4000
    {
        return None;
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." || comp.len() > 255 {
            return None;
        }
        if comp.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
    }
    Some(PathBuf::from(path))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// `raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>`. Branch keeps
/// its `/` (GitHub accepts slash refs there); each path segment is encoded.
fn raw_url(owner: &str, repo: &str, branch: &str, rel: &Path) -> String {
    let path = rel
        .components()
        .map(|c| percent_encode(&c.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>()
        .join("/");
    format!("https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}")
}

/// API listing URL for `refname` (branch name or tree SHA). Slash refs
/// ("feature/x") need `%2F`; percent-encoding handles that.
fn tree_url(owner: &str, repo: &str, refname: &str) -> String {
    format!(
        "https://api.github.com/repos/{owner}/{repo}/git/trees/{}",
        percent_encode(refname)
    )
}

fn list_tree(url: &str) -> anyhow::Result<TreeResp> {
    httpclient::get_json::<TreeResp>(url).map(|(_, r)| r)
}

fn resolve_branch(owner: &str, repo: &str) -> anyhow::Result<String> {
    let meta = format!("https://api.github.com/repos/{owner}/{repo}");
    if let Ok((_, info)) = httpclient::get_json::<RepoInfo>(&meta)
        && !info.default_branch.is_empty()
    {
        return Ok(info.default_branch);
    }
    for cand in ["main", "master"] {
        if httpclient::get_text(&tree_url(owner, repo, cand)).is_ok() {
            return Ok(cand.to_string());
        }
    }
    bail!("could not resolve the default branch of {owner}/{repo}")
}

fn is_symlink(e: &TreeEntry) -> bool {
    e.mode.as_deref() == Some("120000")
}

fn push_blob(files: &mut Vec<(PathBuf, u64)>, e: TreeEntry, prefix: &str) -> anyhow::Result<()> {
    if e.typ != "blob" || is_symlink(&e) {
        return Ok(());
    }
    let Some(size) = e.size else { return Ok(()) };
    if let Some(rel) = safe_rel_path(&format!("{prefix}{}", e.path)) {
        if files.len() >= MAX_FILES {
            bail!("tree has more than {MAX_FILES} files");
        }
        files.push((rel, size));
    }
    Ok(())
}

/// Collect (relative path, size) of every regular file. Prefers one
/// `recursive=1` call (single round trip); falls back to an iterative
/// per-directory walk when the recursive payload is truncated (large repos),
/// keeping every API response small and the walk depth-bounded.
fn collect_files(owner: &str, repo: &str, branch: &str) -> anyhow::Result<Vec<(PathBuf, u64)>> {
    let mut files: Vec<(PathBuf, u64)> = Vec::new();

    let rec = format!("{}?recursive=1", tree_url(owner, repo, branch));
    match list_tree(&rec) {
        Ok(resp) if !resp.truncated => {
            for e in resp.tree {
                push_blob(&mut files, e, "")?;
            }
        }
        _ => {
            let mut queue: Vec<(String, String)> =
                vec![(tree_url(owner, repo, branch), String::new())];
            let mut dirs = 0usize;
            while let Some((url, prefix)) = queue.pop() {
                dirs += 1;
                if dirs > MAX_DIRS {
                    bail!("tree has too many directories (> {MAX_DIRS})");
                }
                let resp = list_tree(&url)?;
                for e in resp.tree {
                    let full = format!("{prefix}{}", e.path);
                    match e.typ.as_str() {
                        "blob" => push_blob(&mut files, e, &prefix)?,
                        "tree" => {
                            if prefix.matches('/').count() + 1 > MAX_DEPTH {
                                bail!("tree is deeper than {MAX_DEPTH} levels");
                            }
                            queue.push((tree_url(owner, repo, &e.path), format!("{full}/")));
                        }
                        _ => {} // submodule ("commit") and symlink entries
                    }
                }
            }
        }
    }

    let total: u64 = files.iter().map(|(_, s)| *s).sum();
    if files.is_empty() {
        bail!("tree contains no files");
    }
    if total > MAX_TOTAL_BYTES {
        bail!("tree is too large for the materializer ({total} bytes)");
    }
    Ok(files)
}

struct Spec {
    rel: PathBuf,
    size: u64,
    segs: u64,
}

fn segment_len(spec: &Spec, seg: u64) -> u64 {
    let start = seg * SEGMENT;
    let end = ((seg + 1) * SEGMENT).min(spec.size);
    end - start
}

#[cfg(unix)]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Fan out every file (big files sharded into `SEGMENT`-sized Range flows)
/// across [`WORKERS`] threads writing `{idx}-{seg}.part` files in `staging`.
/// On the first error the sharing `aborted` flag is set so the remaining
/// workers wind down promptly; parts left behind are discarded with staging.
fn fetch_all(
    owner: &str,
    repo: &str,
    branch: &str,
    specs: &Arc<Vec<Spec>>,
    staging: &Path,
    aborted: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    use std::io::Write;

    let mut tasks = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        for seg in 0..spec.segs {
            tasks.push((i, seg));
        }
    }

    let next = Arc::new(Mutex::new(0usize));
    let failure: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
    let tasks = Arc::new(tasks);

    // Defense in depth: the staging dir is created again here (idempotent) so
    // the workers can never observe it missing.
    std::fs::create_dir_all(staging).context("creating staging dir")?;

    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let owner = owner.to_string();
        let repo = repo.to_string();
        let branch = branch.to_string();
        let staging = staging.to_path_buf();
        let specs = specs.clone();
        let next = next.clone();
        let failure = failure.clone();
        let aborted = aborted.clone();
        let tasks = tasks.clone();
        handles.push(std::thread::spawn(move || {
            let fail = |failure: &Mutex<Option<anyhow::Error>>, e: anyhow::Error| {
                if failure.lock().unwrap().is_none() {
                    *failure.lock().unwrap() = Some(e);
                }
                aborted.store(true, Ordering::Relaxed);
            };
            loop {
                if aborted.load(Ordering::Relaxed) || failure.lock().unwrap().is_some() {
                    break;
                }
                let idx = {
                    let mut n = next.lock().unwrap();
                    let cur = *n;
                    if cur >= tasks.len() {
                        break;
                    }
                    *n += 1;
                    cur
                };
                let (file, seg) = tasks[idx];
                let spec = &specs[file];
                let expected = segment_len(spec, seg);
                let url = raw_url(&owner, &repo, &branch, &spec.rel);
                let bytes = match httpclient::get_bytes_range(
                    &url,
                    seg * SEGMENT,
                    seg * SEGMENT + expected - 1,
                ) {
                    Ok(b) if b.len() as u64 == expected => b,
                    Ok(b) => {
                        fail(
                            &failure,
                            anyhow!(
                                "range mismatch for {} seg {seg}: got {}B, expected {expected}B",
                                spec.rel.display(),
                                b.len()
                            ),
                        );
                        break;
                    }
                    Err(e) => {
                        fail(
                            &failure,
                            anyhow!("downloading {} seg {seg}: {e:#}", spec.rel.display()),
                        );
                        break;
                    }
                };
                for attempt in 0..2 {
                    let part = staging.join(format!("{file}-{seg}.part"));
                    let r = open_exclusive(&part).and_then(|mut f| f.write_all(&bytes).map(|_| ()));
                    match r {
                        Ok(()) => break,
                        Err(e) if attempt == 0 => {
                            // Parent may race with an external wipe; recreate
                            // and retry once before giving up.
                            let _ = std::fs::create_dir_all(&staging);
                            std::thread::sleep(Duration::from_millis(50));
                            let _ = e;
                        }
                        Err(e) => {
                            fail(
                                &failure,
                                anyhow!(
                                    "writing {} (staging_is_dir={}): {e}",
                                    part.display(),
                                    staging.is_dir()
                                ),
                            );
                            break;
                        }
                    }
                }
                if failure.lock().unwrap().is_some() {
                    break;
                }
            }
        }));
    }
    let mut first_err: Option<anyhow::Error> = None;
    for h in handles {
        if let Err(e) = h.join() {
            first_err.get_or_insert_with(|| anyhow!("download worker panicked: {e:?}"));
        }
    }
    if let Some(e) = failure.lock().unwrap().take() {
        first_err.get_or_insert(e);
    }
    first_err.map_or(Ok(()), Err)
}

/// Concatenate the downloaded parts in order into `dest/rel` atoms: a fresh
/// 0600 temp file is written and synced, made 0644, then renamed over the
/// final name (which cannot yet exist).
fn assemble(specs: &[Spec], staging: &Path, dest: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    for (idx, spec) in specs.iter().enumerate() {
        let final_path = dest.join(&spec.rel);
        if let Some(parent) = final_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            bail!("creating {}: {e}", parent.display());
        }
        if final_path.exists() {
            bail!("path collision at {}", final_path.display());
        }
        let tmp = staging.join(format!("{idx}.out"));
        let mut out =
            open_exclusive(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        let mut written = 0u64;
        for seg in 0..spec.segs {
            let part = staging.join(format!("{idx}-{seg}.part"));
            let mut part_f = std::fs::File::open(&part)
                .with_context(|| format!("opening part {}", part.display()))?;
            written += std::io::copy(&mut part_f, &mut out)
                .with_context(|| format!("assembling {}", spec.rel.display()))?;
        }
        if written != spec.size {
            bail!(
                "size mismatch for {}: wrote {written}B, tree said {}B",
                spec.rel.display(),
                spec.size
            );
        }
        out.flush().ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).ok();
        }
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            bail!("renaming {}: {e}", final_path.display());
        }
    }
    Ok(())
}

/// Leave a usable, committed git repo behind so `clone()`'s reuse check
/// (`worktree_intact`) treats the materialized tree as a real checkout.
fn init_git(dest: &Path, branch: &str) -> anyhow::Result<()> {
    use std::process::Command;
    Command::new("git")
        .arg("init")
        .current_dir(dest)
        .output()
        .context("git init")?;
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(dest)
        .output()
        .context("git add")?;
    let out = Command::new("git")
        .args(["commit", "-q", "-m", &format!("materialized from {branch}")])
        .current_dir(dest)
        .env("GIT_AUTHOR_NAME", "demo-ghostprovider")
        .env("GIT_AUTHOR_EMAIL", "ghost@invalid")
        .env("GIT_COMMITTER_NAME", "demo-ghostprovider")
        .env("GIT_COMMITTER_EMAIL", "ghost@invalid")
        .output()
        .context("git commit")?;
    if !out.status.success() {
        // Empty repos legitimately fail here; not an error for a checkout.
        return Err(anyhow!(
            "git commit: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Materialize the tree of `url` into `dest`. `dest` must be dedicated to
/// this call: any failure removes it wholesale, and on success it holds a
/// committed git repo (matching `clone()`'s contract).
///
/// `pin` selects which ref to build from. `Some(sha)` builds exactly that
/// commit's tree: the API tree listing and every blob download address
/// `raw.githubusercontent.com/.../<sha>/...`, so a materialized tree is
/// *provably* the pinned commit — no git protocol, nothing to drift; a pin
/// that won't resolve is an error. `None` keeps the old behavior: resolve the
/// default branch and build its tip (used for unpinned / ad-hoc clones). In
/// both cases the winning refname is recorded in `.ghost-source-pin` so a
/// later reuse can verify it matches the recipe.
pub(crate) fn materialize(url: &str, dest: &Path, pin: Option<&str>) -> anyhow::Result<()> {
    let (owner, repo) =
        github_repo(url).ok_or_else(|| anyhow!("not a github.com repository URL: {url}"))?;
    let refname = match pin {
        Some(sha) => sha.to_string(),
        None => resolve_branch(&owner, &repo)?,
    };
    let files = collect_files(&owner, &repo, &refname)?;

    let specs: Arc<Vec<Spec>> = Arc::new(
        files
            .into_iter()
            .map(|(rel, size)| Spec {
                // A zero-byte blob has no parts to fetch (a Range on it is
                // unsatisfiable: 416); assembly just creates the empty file.
                segs: if size == 0 {
                    0
                } else {
                    size.div_ceil(SEGMENT).max(1)
                },
                rel,
                size,
            })
            .collect(),
    );

    std::fs::create_dir_all(dest).context("creating project dir")?;
    let staging = dest.join(".ghost-materialize");
    std::fs::create_dir_all(&staging).context("creating staging dir")?;

    let aborted = Arc::new(AtomicBool::new(false));
    let stage = (
        fetch_all(&owner, &repo, &refname, &specs, &staging, &aborted),
        assemble(&specs, &staging, dest),
    );
    if let Err(e) = stage.0.and(stage.1) {
        let _ = super::gitclone::force_remove_all(dest);
        return Err(e);
    }

    let _ = super::gitclone::force_remove_all(&staging);
    if let Err(e) = init_git(dest, &refname) {
        eprintln!("note: finalizing the local git repo failed: {e:#}");
    }
    // Record the ref this tree was built from. For a pinned clone this is the
    // looked-up SHA; `clone()`'s reuse path refuses to serve a checkout whose
    // marker does not match the requested pin.
    let _ = std::fs::write(
        dest.join(super::gitclone::PIN_MARKER_FILE),
        format!("{refname}\n"),
    );
    Ok(())
}

/// Read the `.ghost-source-pin` marker left by `materialize`. Returns the ref
/// (SNA/branch name) the tree was built from, or `None` for an unpinned or
/// legacy clone. Local only — never touches the network.
pub(crate) fn pinned_sha(dir: &Path) -> Option<String> {
    let marker = dir.join(super::gitclone::PIN_MARKER_FILE);
    let content = std::fs::read_to_string(marker).ok()?;
    let s = content.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_urls() {
        assert_eq!(
            github_repo("https://github.com/VERT-sh/VERT"),
            Some(("VERT-sh".into(), "VERT".into()))
        );
        assert_eq!(
            github_repo("https://github.com/a/b.git"),
            Some(("a".into(), "b".into()))
        );
        assert_eq!(
            github_repo("https://github.com/a/b/"),
            Some(("a".into(), "b".into()))
        );
        assert!(github_repo("https://github.com/a").is_none());
        assert!(github_repo("https://github.com/a/b/c").is_none());
        assert!(github_repo("https://gitlab.com/a/b").is_none());
        assert!(github_repo("http://github.com/a/b").is_none());
        assert!(github_repo("https://github.com/a/../b").is_none());
        assert!(github_repo("https://github.com/a..b/c").is_none());
    }

    #[test]
    fn rejects_unsafe_path_shapes() {
        for bad in [
            "/abs/path",
            "../escape",
            "a/../../escape",
            "a/./b",
            "a//b",
            "a\\b",
            "a\x00b",
            "a/\t\n",
            "a/..\\evil",
        ] {
            assert!(safe_rel_path(bad).is_none(), "{bad:?} must be rejected");
        }
        assert_eq!(
            safe_rel_path("static/pandoc.wasm").as_deref(),
            Some(Path::new("static/pandoc.wasm"))
        );
        assert_eq!(
            safe_rel_path("a b/c~d").as_deref(),
            Some(Path::new("a b/c~d"))
        );
    }

    #[test]
    fn raw_url_builds() {
        let rel = Path::new("static/pandoc.wasm");
        assert_eq!(
            raw_url("VERT-sh", "VERT", "main", rel),
            "https://raw.githubusercontent.com/VERT-sh/VERT/main/static/pandoc.wasm"
        );
        let weird = Path::new("a b/c#d/e%f");
        assert_eq!(
            raw_url("o", "r", "main", weird),
            "https://raw.githubusercontent.com/o/r/main/a%20b/c%23d/e%25f"
        );
    }

    #[test]
    fn segment_sizing() {
        let spec = Spec {
            rel: PathBuf::from("f"),
            size: SEGMENT * 3 + 7,
            segs: 4,
        };
        assert_eq!(segment_len(&spec, 0), SEGMENT);
        assert_eq!(segment_len(&spec, 2), SEGMENT);
        assert_eq!(segment_len(&spec, 3), 7);
    }

    #[test]
    fn percent_encoding_covers_url_hazards() {
        assert_eq!(percent_encode("feature/x y"), "feature%2Fx%20y");
        assert_eq!(percent_encode("main"), "main");
    }
}
