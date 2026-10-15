//! Built-in static file server (`__serve-static` internal subcommand).
//!
//! Replaces the Python version's `{python} -m http.server {port}` so the
//! deployed unit needs nothing but this binary. Single-threaded accept loop,
//! loopback-only bind, path traversal rejected.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};

pub fn serve_static(root: &Path, port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    // Canonicalize once so every request is contained against a resolved root
    // (a served path may otherwise escape through symlinks planted in the
    // build output by a compromised upstream).
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    eprintln!("serving {} on http://127.0.0.1:{port}", root.display());
    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle(s, &root),
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, root: &Path) {
    // A stalled client must not pin the single-threaded accept loop forever.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next();
    // Static server: GET/HEAD only. A POST/Trace/...  must not be silently
    // downgraded to GET; respond 405 so callers cannot tunnel odd methods
    // through the panel's own listener. HEAD returns the headers (same
    // Content-Length) with no body.
    let head_only = method.eq_ignore_ascii_case("HEAD");
    if !method.eq_ignore_ascii_case("GET") && !head_only {
        return respond(&mut stream, 405, "text/plain", b"method not allowed", false);
    }
    let Some(path) = path else {
        return respond(&mut stream, 400, "text/plain", b"bad request", false);
    };
    // Strip query/fragment.
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let decoded = percent_decode(path);
    let with_body = !head_only;

    if !decoded.starts_with('/') {
        return respond(&mut stream, 400, "text/plain", b"bad request", with_body);
    }
    let rel: PathBuf = decoded.trim_start_matches('/').into();
    if rel.components().any(|c| matches!(c, Component::ParentDir)) {
        return respond(&mut stream, 403, "text/plain", b"forbidden", with_body);
    }
    // Hidden entries (.env, .git, ...) are secrets in enough build outputs
    // that direct reads are refused too, not just hidden from the listing.
    if is_hidden(&rel) {
        return respond(&mut stream, 403, "text/plain", b"forbidden", with_body);
    }

    let full = root.join(rel);
    // Resolve symlinks and enforce containment before touching the filesystem.
    let Some(target) = resolve_inside(root, &full) else {
        // 404 when nothing exists; 403 when it exists but resolves outside root.
        let (status, body) = match full.symlink_metadata() {
            Ok(_) => (403, b"forbidden".as_slice()),
            Err(_) => (404, b"not found".as_slice()),
        };
        return respond(&mut stream, status, "text/plain", body, with_body);
    };

    if target.is_dir() {
        // index.html/index.htm are only honored when they stay inside root too.
        match find_index(&target).and_then(|i| resolve_inside(root, &i)) {
            Some(index) => read_and_respond(&mut stream, &index, with_body),
            None => {
                let listing = dir_listing(root, &target);
                respond(&mut stream, 200, "text/html", listing.as_bytes(), with_body);
            }
        }
    } else {
        read_and_respond(&mut stream, &target, with_body);
    }
}

/// True when any path element is hidden (leading dot). `.`/`..` never reach
/// here (ParentDir is rejected separately) and are excluded defensively.
fn is_hidden(rel: &Path) -> bool {
    use std::ffi::OsStr;
    rel.iter().any(|c| {
        c != OsStr::new(".") && c != OsStr::new("..") && c.to_string_lossy().starts_with('.')
    })
}

/// Resolve `candidate` (symlinks included) and return it only while it stays
/// inside `root`. A non-existent path yields `None` (caller maps to 404).
fn resolve_inside(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let canonical = candidate.canonicalize().ok()?;
    if canonical.starts_with(root) {
        Some(canonical)
    } else {
        None
    }
}

fn read_and_respond(stream: &mut TcpStream, target: &Path, with_body: bool) {
    match std::fs::read(target) {
        Ok(bytes) => {
            let mime = mime_of(target);
            respond(stream, 200, mime, &bytes, with_body)
        }
        Err(_) => respond(stream, 404, "text/plain", b"not found", with_body),
    }
}

fn find_index(dir: &Path) -> Option<PathBuf> {
    ["index.html", "index.htm"]
        .iter()
        .map(|i| dir.join(i))
        .find(|p| p.is_file())
}

/// Escape text for safe embedding in HTML attribute and text positions.
/// Directory listings render file names that may come from untrusted build
/// output, so both the href and the visible text must be escaped.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn dir_listing(root: &Path, dir: &Path) -> String {
    let entries = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    // Hidden files (.env, .git, .htaccess, ...) are secrets in
                    // enough build outputs that they are neither listed nor
                    // linked from this page.
                    if name.starts_with('.') {
                        return None;
                    }
                    let suffix = if e.path().is_dir() { "/" } else { "" };
                    let shown = format!("{name}{suffix}");
                    Some(format!(
                        "<li><a href=\"{0}\">{0}</a></li>",
                        html_escape(&shown)
                    ))
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let rel = dir
        .strip_prefix(root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{}</title>\
         <h1>Directory listing for /{rel}</h1><hr><ul>\n{entries}\n</ul>",
        html_escape(&rel)
    )
}

fn respond(stream: &mut TcpStream, code: u16, mime: &str, body: &[u8], with_body: bool) {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.0 {code} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    // HEAD still reports the real Content-Length above, but carries no body.
    if with_body {
        let _ = stream.write_all(body);
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mime_of(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dgp-serve-{tag}-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ))
    }

    #[test]
    fn html_escape_covers_active_and_attr_chars() {
        let evil = r#"><script>alert("x&'")</script>"#;
        let escaped = html_escape(evil);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&quot;"));
        assert!(escaped.contains("&amp;"));
        assert!(escaped.contains("&#39;"));
        // Every `<`, `>`, `"`, `'`, `&` from input is replaced by an entity,
        // never left raw.
        assert_eq!(escaped.matches("&lt;").count(), 2);
        assert_eq!(escaped.matches("&gt;").count(), 3);
        assert_eq!(escaped.matches("&amp;").count(), 1);
        assert_eq!(html_escape("plain.txt"), "plain.txt");
    }

    #[test]
    fn symlink_escaping_root_is_blocked() {
        let root = tmpdir("link");
        std::fs::create_dir_all(&root).unwrap();
        let outside = tmpdir("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("leak")).unwrap();

        let canon_root = root.canonicalize().unwrap();
        // In-root file resolves fine.
        std::fs::write(root.join("ok.txt"), "ok").unwrap();
        assert!(resolve_inside(&canon_root, &root.join("ok.txt")).is_some());
        // Symlink pointing outside root must be rejected.
        assert!(resolve_inside(&canon_root, &root.join("leak")).is_none());
        // Missing path yields None (404), not a claim of containment.
        assert!(resolve_inside(&canon_root, &root.join("nope")).is_none());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn dir_listing_escapes_names_and_hides_dotfiles() {
        let root = tmpdir("listing");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("report.txt"), "x").unwrap();
        std::fs::write(root.join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();

        let html = dir_listing(&root, &root);
        assert!(html.contains("report.txt"));
        assert!(html.contains("sub/"));
        // Dotfiles are neither listed nor leaked.
        assert!(!html.contains(".env"));
        assert!(!html.contains("SECRET"));

        // A hostile filename (no '<', no embeddable tag; the escaping must
        // neutralise both the attribute and text context).
        let evil = "report<.svg\" onload=alert(1)>.html";
        std::fs::write(root.join(evil), "x").unwrap();
        let html = dir_listing(&root, &root);
        assert!(!html.contains("<.svg"));
        assert!(html.contains("report&lt;.svg&quot; onload=alert(1)&gt;.html"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Hidden entries are refused by the request gate, not just the listing.
    #[test]
    fn hidden_paths_are_forbidden() {
        assert!(is_hidden(std::path::Path::new(".env")));
        assert!(is_hidden(std::path::Path::new("public/.git/config")));
        assert!(is_hidden(std::path::Path::new("sub/.well-known/x")));
        assert!(!is_hidden(std::path::Path::new("index.html")));
        assert!(!is_hidden(std::path::Path::new("assets/app.js")));
    }

    /// Raw low-level request handling: GET serves the body with a nosniff
    /// header, HEAD carries the same Content-Length with an empty body, and
    /// POST/PUT/TRACE are answered 405 (never downgraded to GET). Each
    /// request is a fresh connection — `handle` serves exactly one request
    /// per accepted socket, like the real accept loop.
    #[test]
    fn raw_method_parsing_get_head_and_405() {
        let root = tmpdir("method");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "hello").unwrap();
        let canon = root.canonicalize().unwrap();

        fn roundtrip(canon: &std::path::Path, raw: &[u8]) -> String {
            use std::io::{Read as _, Write as _};
            let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _peer) = listener.accept().unwrap();
            let canon = canon.to_path_buf();
            std::thread::spawn(move || handle(server, &canon));
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            sock.write_all(raw).unwrap();
            let mut resp = String::new();
            let _ = sock.read_to_string(&mut resp);
            resp
        }

        let resp = roundtrip(&canon, b"GET /a.txt HTTP/1.0\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.0 200 OK"), "GET resp: {resp:?}");
        assert!(resp.contains("hello"));
        assert!(resp.contains("nosniff"));

        let resp = roundtrip(&canon, b"HEAD /a.txt HTTP/1.0\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.0 200 OK"), "HEAD resp: {resp:?}");
        assert!(resp.contains("Content-Length: 5"));
        assert!(!resp.contains("hello"), "HEAD must not send a body");

        let resp = roundtrip(
            &canon,
            b"POST /a.txt HTTP/1.0\r\nContent-Length: 4\r\n\r\nx=1",
        );
        assert!(
            resp.starts_with("HTTP/1.0 405 Method Not Allowed"),
            "POST resp: {resp:?}"
        );
        let resp = roundtrip(&canon, b"TRACE / HTTP/1.0\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.0 405"), "TRACE resp: {resp:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
