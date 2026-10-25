//! Declared outbound needs: which hosts a service's own configuration says
//! it must reach at runtime.
//!
//! The fingerprint is a searx-style `settings.yml` with an `engines:` list
//! — the repository itself declares which search engines it queries, so the
//! egress plan is derived from that declaration instead of guessed. Two
//! sources feed the plan:
//!
//! 1. A curated module→hosts table for built-in engines whose request URLs
//!    live in the engine's Python code, not in the settings file. Ranks put
//!    general web search first: the plan caps at [`MAX_EGRESS_HOSTS`] and a
//!    truncated tail must lose the niche engines, never the core search.
//! 2. Literal URLs the settings file itself carries (`search_url`,
//!    `base_url`, `url` on xpath/json engines) — hosts parsed straight out
//!    of the declaration, rank after the table.
//!
//! Everything here is pure file parsing: no DNS, no network. Resolution and
//! the fail-open drop of unreachable hosts live in the deploy pipeline
//! (`deploy_service`), because an auto-suggestion must never fail a deploy.
//!
//! Returns `None` when no fingerprint matches — an unknown app keeps the
//! historic deny-all and the user opts in by hand via the Egress menu.

use std::path::Path;

use crate::hoster::manifest::MAX_EGRESS_HOSTS;

/// What the tree declares the service talks to. `hosts` is priority-ordered
/// and already capped at [`MAX_EGRESS_HOSTS`]; `note` explains a truncation
/// so the deploy log stays honest about what was left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPlan {
    pub hosts: Vec<String>,
    pub note: Option<String>,
}

/// Curated engine module → hosts contacted at search time.
/// Rank order: 0 = general web (must survive truncation), 1 = reference/
/// media, 2 = dev/science staples. Dedup keeps the first (best-ranked) home.
const ENGINE_HOSTS: &[(&str, u8, &[&str])] = &[
    // ── rank 0: general web search — the reason a search engine exists ──
    ("duckduckgo", 0, &["duckduckgo.com", "html.duckduckgo.com"]),
    ("duckduckgo_extra", 0, &["duckduckgo.com"]),
    ("brave", 0, &["search.brave.com"]),
    ("google", 0, &["www.google.com"]),
    ("google_news", 0, &["www.google.com"]),
    ("google_videos", 0, &["www.google.com"]),
    ("bing", 0, &["www.bing.com"]),
    ("bing_images", 0, &["www.bing.com"]),
    ("bing_news", 0, &["www.bing.com"]),
    ("bing_videos", 0, &["www.bing.com"]),
    ("startpage", 0, &["www.startpage.com"]),
    ("mojeek", 0, &["www.mojeek.com"]),
    // ── rank 1: reference / media ──
    ("wikipedia", 1, &["en.wikipedia.org"]),
    ("youtube_noapi", 1, &["www.youtube.com"]),
    ("youtube_api", 1, &["www.youtube.com"]),
    ("wikidata", 1, &["www.wikidata.org"]),
    ("google_scholar", 1, &["scholar.google.com"]),
    ("google_cse", 1, &["cse.google.com"]),
    // ── rank 2: dev / science staples ──
    ("stackexchange", 2, &["api.stackexchange.com"]),
    ("github", 2, &["api.github.com"]),
    ("arxiv", 2, &["arxiv.org"]),
    ("pypi", 2, &["pypi.org"]),
    (
        "openstreetmap",
        2,
        &["openstreetmap.org", "nominatim.openstreetmap.org"],
    ),
    (
        "soundcloud",
        2,
        &["soundcloud.com", "api-v2.soundcloud.com"],
    ),
    ("docker_hub", 2, &["hub.docker.com"]),
    ("mdn", 2, &["developer.mozilla.org"]),
];

/// Rank for hosts parsed out of settings URLs (engine not in the table).
const RANK_DECLARED_URL: u8 = 50;

/// Settings files that may carry the fingerprint, in probe order.
const SETTINGS_CANDIDATES: &[&str] = &[
    "searx/settings.yml",
    "searx/settings.yaml",
    "settings.yml",
    "settings.yaml",
];

/// Ask the tree who it talks to, or `None` when it says nothing usable.
pub fn detect_egress(dir: &Path) -> Option<EgressPlan> {
    let text = SETTINGS_CANDIDATES
        .iter()
        .find_map(|rel| std::fs::read_to_string(dir.join(rel)).ok())?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let engines = doc.get("engines")?.as_sequence()?;
    if engines.is_empty() {
        return None;
    }

    // (rank, host) in declaration order; the stable sort keeps rank ties in
    // the order the settings list the engines (general ones early alphabet).
    let mut ranked: Vec<(u8, String)> = Vec::new();
    for entry in engines {
        let Some(map) = entry.as_mapping() else {
            continue;
        };
        // Only mapping entries with a declaration key count — this keeps a
        // stray YAML doc with an unrelated `engines:` list from matching.
        let name_of = |k: &str| {
            map.get(serde_yaml::Value::String(k.to_string()))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let engine = name_of("engine");
        let label = name_of("name");
        if engine.is_none()
            && label.is_none()
            && map
                .get(serde_yaml::Value::String("search_url".into()))
                .is_none()
        {
            return None;
        }
        // The repo's own opt-outs win: disabled/inactive engines are not
        // queried, so they must not open holes in the firewall.
        if map
            .get(serde_yaml::Value::String("disabled".into()))
            .and_then(|v| v.as_bool())
            == Some(true)
            || map
                .get(serde_yaml::Value::String("inactive".into()))
                .and_then(|v| v.as_bool())
                == Some(true)
        {
            continue;
        }
        if let Some(e) = engine.as_deref()
            && let Some((rank, hosts)) = table_hosts(e)
        {
            for h in hosts {
                ranked.push((rank, (*h).to_string()));
            }
        }
        // Declaration URLs (`search_url` / `base_url` / `url`, string or
        // list) — hosts parsed from what the file literally says.
        for key in ["search_url", "base_url", "url"] {
            for url in url_values(map, key) {
                if let Some(host) = host_from_url(&url)
                    && let Ok(norm) = crate::hoster::manifest::validate_egress_host(&host)
                {
                    ranked.push((RANK_DECLARED_URL, norm));
                }
            }
        }
    }

    // Stable sort by rank: general web (rank 0) first, ties keep the
    // declaration order (settings list the important engines early).
    ranked.sort_by_key(|(rank, _)| *rank);
    let mut hosts: Vec<String> = Vec::new();
    for (_, h) in ranked {
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    if hosts.is_empty() {
        return None;
    }
    let total = hosts.len();
    hosts.truncate(MAX_EGRESS_HOSTS);
    let note = (total > hosts.len()).then(|| {
        format!(
            "truncated to {MAX_EGRESS_HOSTS} of {total} detected host(s) — extend the list in the Egress menu"
        )
    });
    Some(EgressPlan { hosts, note })
}

/// Table lookup for one engine module id.
fn table_hosts(engine: &str) -> Option<(u8, &'static [&'static str])> {
    ENGINE_HOSTS
        .iter()
        .find(|(id, _, _)| *id == engine)
        .map(|(_, rank, hosts)| (*rank, *hosts))
}

/// All string values of `key` in an engine mapping (scalar or sequence).
fn url_values(map: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    let Some(v) = map.get(serde_yaml::Value::String(key.to_string())) else {
        return Vec::new();
    };
    match v {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Host out of a literal URL: `scheme://host/...` only; templates
/// (`{subdomain}.x.org`) fail downstream validation and drop out.
fn host_from_url(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.is_empty() || host.starts_with('[') {
        return None;
    }
    Some(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dgp-egress-{tag}-{}", std::process::id()));
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
    fn no_settings_is_none() {
        let dir = tree("none", &[("go.mod", "module x")]);
        assert_eq!(detect_egress(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_without_engines_is_none() {
        let dir = tree("noeng", &[("settings.yml", "server:\n  port: 8888\n")]);
        assert_eq!(detect_egress(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_list_prefilled_with_unrelated_shape_is_none() {
        // `engines:` exists but no entry declares anything we understand —
        // an unrelated YAML must not be mistaken for a search config.
        let dir = tree(
            "shape",
            &[("settings.yml", "engines:\n  - v8\n  - diesel\n")],
        );
        assert_eq!(detect_egress(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn general_engines_win_the_cap() {
        // The searx default picture: lots of enabled engines. General web
        // (rank 0) + reference (rank 1) must fill the cap; sci/dev (rank 2)
        // and declared URLs fall off the end.
        let settings = r#"
engines:
  - name: arxiv
    engine: arxiv
  - name: google scholar
    engine: google_scholar
  - name: duckduckgo
    engine: duckduckgo
  - name: pypi
    engine: pypi
  - name: bing images
    engine: bing_images
  - name: wikipedia
    engine: wikipedia
  - name: youtube
    engine: youtube_noapi
  - name: wikidata
    engine: wikidata
  - name: brave
    engine: brave
  - name: stackoverflow
    engine: stackexchange
  - name: custom blog
    engine: xpath
    search_url: "https://blog.example.org/search?q={query}"
"#;
        let dir = tree("cap", &[("searx/settings.yml", settings)]);
        let plan = detect_egress(&dir).unwrap();
        assert_eq!(plan.hosts.len(), MAX_EGRESS_HOSTS);
        // rank 0 first, stable within the rank: duckduckgo (both hosts),
        // then bing (declared before brave), then brave.
        assert_eq!(plan.hosts[0], "duckduckgo.com");
        assert_eq!(plan.hosts[1], "html.duckduckgo.com");
        assert_eq!(plan.hosts[2], "www.bing.com");
        assert_eq!(plan.hosts[3], "search.brave.com");
        assert!(plan.hosts.contains(&"en.wikipedia.org".to_string()));
        // rank 2 (arxiv/pypi/stackexchange) and the declared URL lost.
        assert!(!plan.hosts.iter().any(|h| h.contains("arxiv")));
        assert!(!plan.hosts.iter().any(|h| h.contains("blog.example.org")));
        let note = plan.note.expect("truncation must be reported");
        assert!(note.contains("detected host(s)"), "{note}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_and_inactive_engines_open_nothing() {
        let settings = r#"
engines:
  - name: duckduckgo
    engine: duckduckgo
    disabled: true
  - name: arxiv
    engine: arxiv
    inactive: true
  - name: brave
    engine: brave
"#;
        let dir = tree("optout", &[("searx/settings.yml", settings)]);
        let plan = detect_egress(&dir).unwrap();
        assert_eq!(plan.hosts, vec!["search.brave.com".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn declared_urls_are_parsed_and_validated() {
        let settings = r#"
engines:
  - name: custom blog
    engine: xpath
    search_url: "https://blog.example.org/search?q={query}"
  - name: other
    engine: json_engine
    base_url:
      - "https://api.example.net/v1"
      - "https://{host}.template.io/x"
"#;
        let dir = tree("urls", &[("settings.yml", settings)]);
        let plan = detect_egress(&dir).unwrap();
        assert_eq!(
            plan.hosts,
            vec![
                "blog.example.org".to_string(),
                "api.example.net".to_string()
            ],
            "template hosts fail validation and must drop out"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn table_dedup_keeps_the_better_rank() {
        // google_news and google_videos both map to www.google.com — one
        // hole, not two, and no duplicate entry in the plan.
        let settings = r#"
engines:
  - name: google news
    engine: google_news
  - name: google videos
    engine: google_videos
"#;
        let dir = tree("dedup", &[("settings.yml", settings)]);
        let plan = detect_egress(&dir).unwrap();
        assert_eq!(plan.hosts, vec!["www.google.com".to_string()]);
        assert_eq!(plan.note, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_from_url_shapes() {
        assert_eq!(
            host_from_url("https://a.example.org/path?q=1"),
            Some("a.example.org".into())
        );
        assert_eq!(
            host_from_url("http://user:pw@b.example.io:8080/x"),
            Some("b.example.io:8080".into())
        );
        assert_eq!(host_from_url("not a url"), None);
        assert_eq!(host_from_url("file:///etc/passwd"), None);
    }
}
