//! User manifest library: imported `service.yaml` files.
//!
//! The Add Service screen lists these, redeploys them and deletes them.
//! Files live as `<service-id>.yaml` under [`crate::paths::manifests_dir`].
//! Import validates before copying, so the library only ever holds manifests
//! the engine would accept; entries are re-validated on listing because the
//! files can change on disk between runs.

use std::path::{Path, PathBuf};

use super::manifest::ServiceManifest;

/// Cap on stored manifests: the library is a hand-curated shelf, not a dump.
pub const MAX_LIBRARY_FILES: usize = 64;

#[derive(Debug, Clone)]
pub struct LibraryEntry {
    pub id: String,
    pub path: PathBuf,
    pub source_git: Option<String>,
    /// Re-validation result for the file as it is on disk right now.
    pub valid: bool,
    pub error: Option<String>,
}

pub fn dir() -> PathBuf {
    crate::paths::manifests_dir()
}

fn valid_id(id: &str) -> bool {
    id.len() >= 3
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// All stored manifests, sorted by id. Unreadable/invalid files are listed
/// too (marked), never silently skipped — the screen shows why they fail.
pub fn list() -> Vec<LibraryEntry> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir()) else {
        return out;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        let is_yaml = path.extension().is_some_and(|e| e == "yaml" || e == "yml");
        if !is_yaml || !path.is_file() {
            continue;
        }
        let id = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !valid_id(&id) {
            continue;
        }
        match ServiceManifest::load_from_file(&path) {
            Ok(m) => out.push(LibraryEntry {
                id,
                path,
                source_git: Some(m.source.git),
                valid: true,
                error: None,
            }),
            Err(e) => out.push(LibraryEntry {
                id,
                path,
                source_git: None,
                valid: false,
                error: Some(short_error(&e)),
            }),
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Validate `src` and copy it into the library as `<service-id>.yaml.
/// Refuses when that id is already stored (delete it first to replace) and
/// when the shelf is full. Returns the service id.
pub fn import(src: &Path) -> anyhow::Result<String> {
    let m = ServiceManifest::load_from_file(src)?;
    let items = list();
    if items.len() >= MAX_LIBRARY_FILES {
        anyhow::bail!("manifest library is full ({MAX_LIBRARY_FILES} files)");
    }
    if items.iter().any(|e| e.id == m.service.id) {
        anyhow::bail!(
            "“{}” is already in the library — delete it first to replace",
            m.service.id
        );
    }
    let dest = dir().join(format!("{}.yaml", m.service.id));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = std::fs::read(src)?;
    // Atomic + 0600, symlink-proof (see atomic.rs): readers never see a
    // half-written file and a pre-planted symlink is replaced, not followed.
    // The duplicate-id check above is what prevents silent replacement.
    crate::atomic::write_atomic(&dest, &bytes)?;
    Ok(m.service.id)
}

/// Delete a stored manifest. Returns true when a file was actually removed.
pub fn remove(id: &str) -> anyhow::Result<bool> {
    if !valid_id(id) {
        anyhow::bail!("invalid service id “{id}”");
    }
    let path = dir().join(format!("{id}.yaml"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Load a stored manifest by id (re-validated on the spot).
pub fn load(id: &str) -> anyhow::Result<ServiceManifest> {
    if !valid_id(id) {
        anyhow::bail!("invalid service id “{id}”");
    }
    ServiceManifest::load_from_file(&dir().join(format!("{id}.yaml")))
}

fn short_error(e: &anyhow::Error) -> String {
    let first = format!("{e:#}")
        .lines()
        .next()
        .unwrap_or("invalid manifest")
        .to_string();
    let short: String = first.chars().take(120).collect();
    if short.len() < first.len() {
        format!("{short}…")
    } else {
        short
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Isolated XDG_DATA_HOME for this test (serializes via the shared lock).
    fn isolated_data_home(tag: &str) -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::paths::ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dgp-lib-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        #[allow(unsafe_code)] // test-only env mutation (XDG_DATA_HOME)
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
        }
        guard
    }

    const GOOD: &str = r#"
manifest_version: 1
service:
  id: lib-demo
  name: Lib Demo
source:
  git: https://github.com/example/lib-demo.git
  commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
prefetch: []
build:
  profile: bun
  steps:
    - ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
run:
  command: ["{self}", "__serve-static", "{project}/build", "{port}"]
  port: 0
resources:
  memory_max: "384M"
  tasks_max: "300"
tools: ["bun"]
"#;

    fn write_src(tag: &str, body: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("dgp-lib-src-{tag}-{}.yaml", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn import_list_load_remove_roundtrip() {
        let _env = isolated_data_home("roundtrip");
        assert!(list().is_empty());
        let src = write_src("roundtrip", GOOD);
        let id = import(&src).unwrap();
        assert_eq!(id, "lib-demo");
        let items = list();
        assert_eq!(items.len(), 1);
        assert!(items[0].valid);
        assert_eq!(
            items[0].source_git.as_deref(),
            Some("https://github.com/example/lib-demo.git")
        );
        assert_eq!(load("lib-demo").unwrap().service.id, "lib-demo");
        assert!(remove("lib-demo").unwrap());
        assert!(!remove("lib-demo").unwrap());
        assert!(list().is_empty());
    }

    #[test]
    fn import_rejects_invalid_and_duplicates() {
        let _env = isolated_data_home("reject");
        let bad = write_src("reject", "manifest_version: 99\n");
        assert!(import(&bad).is_err());
        assert!(list().is_empty());
        let src = write_src("reject2", GOOD);
        import(&src).unwrap();
        let err = format!("{:#}", import(&src).unwrap_err());
        assert!(err.contains("already in the library"), "{err}");
    }

    #[test]
    fn remove_rejects_path_traversal() {
        let _env = isolated_data_home("traversal");
        for evil in ["../x", "a/b", ".", "", "AB", "x"] {
            assert!(remove(evil).is_err(), "{evil}");
            assert!(load(evil).is_err(), "{evil}");
        }
    }
}
