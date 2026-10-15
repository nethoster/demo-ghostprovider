//! Allowlisted HTTP client.
//!
//! Every request goes through [`get_json`]/[`get_text`], which refuse to open
//! a socket to any host outside [`crate::netlog::ALLOWED_ENDPOINTS`], and
//! refuse plaintext (`http://`) transport outright. Redirects are followed
//! MANUALLY, hop by hop: ureq is configured with `max_redirects(0)` and every
//! hop target is re-checked against `ensure_allowed` *before* a socket opens
//! for it — the Python version (and ureq's built-in redirect chasing) had no
//! such interception point, which is how a tarball fallback could silently
//! jump to `codeload.github.com` while the allowlist only ever saw the
//! initial URL. All attempts, one record per hop, are logged via
//! `netlog::record` regardless of outcome.
//!
//! A `GITHUB_TOKEN`/`GH_TOKEN` from the environment is attached to
//! api.github.com calls only (avoids the 60 req/h anonymous limit). It is
//! reconstructed per hop and never crosses a redirect boundary to another
//! host; it is never logged, never written to disk.

use std::time::Duration;

use anyhow::{Context, anyhow};
use ureq::http::Response;

const TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const RETRIES: u32 = 2;
/// Max pause between retries — DNS/transient blips can last minutes;
/// 120s caps exponential backoff without giving up (retries are permanent).
const MAX_BACKOFF: Duration = Duration::from_secs(120);
/// Hop cap for manual redirect following. GitHub pointers (e.g. the archive
/// 302 to codeload) are a single hop; anything beyond this is hostile.
const MAX_REDIRECTS: u32 = 5;
/// Budget for a whole large body (source tarballs). Slow-but-alive links
/// (e.g. a rate-limited path to codeload at ~8KB/s) legitimately need tens of
/// minutes; this only caps the absolute worst case. Truly-dead transfers are
/// caught much sooner by [`SLOW_BODY_IDLE`] below.
const SLOW_TIMEOUT: Duration = Duration::from_secs(60 * 90);
/// A single body read (or pause between chunks) may block for at most this
/// long on the slow path. A trickling peer keeps individual reads short;
/// a socket that stopped moving data entirely aborts after one idle window
/// instead of hanging for [`SLOW_TIMEOUT`].
const SLOW_BODY_IDLE: Duration = Duration::from_secs(45);
/// [`fetch`]'s transport retries stop the moment response headers arrive; a
/// stall *during* the body read (the [`SLOW_BODY_IDLE`] idle timeout) or an
/// error status beats them with nothing left to retry. Big bodies — toolchains,
/// wasm shards, tarballs — are exactly where such a mid-body stall hurts most,
/// so those fetches re-request the whole body a couple of times over a fresh
/// connection before failing. The backoff base, in ms, doubles per attempt.
const SLOW_BODY_RETRIES: u32 = 2;
const SLOW_BODY_RETRY_BASE_MS: u64 = 1_000;

fn scheme_of(url: &str) -> Option<&str> {
    url.split_once("://").map(|(s, _)| s)
}

fn deny(url: &str) -> anyhow::Error {
    let host = host_of(url).unwrap_or_else(|| "<unparseable>".into());
    crate::netlog::record(
        &host,
        &path_of(url),
        Err("DENY: host not in allowlist".into()),
    );
    anyhow!("host '{host}' is not in the endpoint allowlist")
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next().unwrap_or(host);
    Some(host.to_string())
}

fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    match rest.find('/') {
        Some(i) => {
            let p = &rest[i..];
            p.split(['?', '#']).next().unwrap_or("/").to_string()
        }
        None => "/".to_string(),
    }
}

/// Deny-by-default check used by every public entry point and re-run on every
/// redirect hop. Refuses anything that is not `https` before a socket can
/// open, then refuses hosts outside the allowlist.
pub fn ensure_allowed(url: &str) -> anyhow::Result<()> {
    let host = host_of(url).ok_or_else(|| anyhow!("cannot parse URL: {url}"))?;
    // HTTPS-only: a plaintext URL (user input or a downgrade redirect target)
    // must never reach the wire, even to an otherwise allowlisted host.
    if scheme_of(url) != Some("https") {
        crate::netlog::record(
            &host,
            &path_of(url),
            Err("DENY: non-https scheme (allowlist is https-only)".into()),
        );
        return Err(anyhow!(
            "refused {url}: the endpoint allowlist is https-only"
        ));
    }
    if crate::netlog::is_allowed_host(&host) {
        Ok(())
    } else {
        Err(deny(url))
    }
}

fn github_token_for(url: &str) -> Option<String> {
    if url.contains("api.github.com") {
        std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .ok()
            .filter(|t| !t.is_empty())
    } else {
        None
    }
}

fn build_agent(global: Duration, recv_body: Option<Duration>) -> ureq::Agent {
    build_agent_named_encoding(global, recv_body, None)
}

fn build_agent_named_encoding(
    global: Duration,
    recv_body: Option<Duration>,
    accept_encoding: Option<ureq::config::AutoHeaderValue>,
) -> ureq::Agent {
    agent_with_proxy(global, recv_body, accept_encoding, true)
}

/// Shared agent builder. With `use_ambient_proxy`, honours
/// HTTP(S)_PROXY / ALL_PROXY / NO_PROXY so a user behind a corporate proxy or
/// local TUN/VPN breakout can reach the allowlisted hosts. (ureq already picks
/// these up via [`Config::default`], the explicit `.proxy(...)` merely pinches
/// the intent; without it the choice rides on a ureq default.) The proxy only
/// changes the transport connection; the request still targets the allowlisted
/// host and is re-checked on every hop. The `false` variant is the fallback
/// transport for the case where a configured proxy/VPN goes away mid-deploy:
/// it forces `proxy(None)` because ureq's default would otherwise keep routing
/// through the env proxy that just died.
fn agent_with_proxy(
    global: Duration,
    recv_body: Option<Duration>,
    accept_encoding: Option<ureq::config::AutoHeaderValue>,
    use_ambient_proxy: bool,
) -> ureq::Agent {
    let mut b = ureq::Agent::config_builder()
        // Redirects are followed by hand below so the allowlist can be
        // re-checked on every hop. Turning automatic chasing off is what
        // makes that possible.
        .max_redirects(0)
        .proxy(if use_ambient_proxy {
            ureq::Proxy::try_from_env()
        } else {
            None
        });
    b = b.user_agent(format!("demo-ghostprovider/{}", env!("CARGO_PKG_VERSION")));
    if let Some(t) = recv_body {
        b = b.timeout_recv_body(Some(t));
    }
    if let Some(enc) = accept_encoding {
        b = b.accept_encoding(enc);
    }
    b = b.timeout_global(Some(global));
    let config = b.build();
    ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        super::resolver::SmartResolver::default(),
    )
}

/// The proxy from the environment that would actually be used for `url`, or
/// `None` when nothing is configured or the target is exempted via NO_PROXY.
/// Used to decide whether a direct-connection fallback is worth trying: if a
/// proxy is configured and the proxy/VPN is switched off mid-deploy, the
/// direct route may be the healthy one.
fn ambient_proxy_for(url: &str) -> Option<ureq::Proxy> {
    let proxy = ureq::Proxy::try_from_env()?;
    let uri: ureq::http::Uri = url.parse().ok()?;
    if proxy.is_no_proxy(&uri) {
        None
    } else {
        Some(proxy)
    }
}

/// Resolve a `Location` header against the current hop URL.
///
/// Handles absolute, protocol-relative (`//host/...`), root-relative
/// (`/path`) and path-relative targets. The result is always passed back
/// through [`ensure_allowed`], so a plaintext or off-allowlist target is
/// refused before a socket opens, never followed.
fn resolve_redirect(base: &str, location: &str) -> anyhow::Result<String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("https://{rest}"));
    }
    // `base` is always https (enforced upstream): origin = scheme + authority.
    let origin = base.split('/').take(3).collect::<Vec<_>>().join("/");
    if location.starts_with('/') {
        return Ok(format!("{origin}{location}"));
    }
    // Path-relative (RFC 3986 join): resolve against the base's directory.
    // `dir` is kept with its leading slash, so it is appended raw.
    let base_path = base.trim_start_matches(&origin);
    let dir = match base_path.rsplit_once('/') {
        Some((dir, _)) => dir,
        None => "/",
    };
    Ok(format!("{origin}{dir}/{location}"))
}

/// Execute one full request without automatic redirects. Every hop is gated
/// by [`ensure_allowed`] before a connection can open, and each hop is
/// net.log-recorded individually. Authorization/Accept headers are rebuilt
/// per hop, so the token never follows the redirect to another host.
fn attempt(agent: &ureq::Agent, url: &str) -> Result<Response<ureq::Body>, ureq::Error> {
    attempt_impl(agent, url, None)
}

/// Like [`attempt`] but sends a `Range` header for segment-wise downloads of
/// large blobs through the same allowlist/redirect machinery.
fn attempt_range(
    agent: &ureq::Agent,
    url: &str,
    range: (u64, u64),
) -> Result<Response<ureq::Body>, ureq::Error> {
    attempt_impl(agent, url, Some(range))
}

fn attempt_impl(
    agent: &ureq::Agent,
    url: &str,
    range: Option<(u64, u64)>,
) -> Result<Response<ureq::Body>, ureq::Error> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        ensure_allowed(&current)
            .map_err(|e| ureq::Error::Io(std::io::Error::other(e.to_string())))?;

        let mut req = agent.get(&current);
        if let Some((start, end)) = range {
            req = req.header("Range", &format!("bytes={start}-{end}"));
        }
        if let Some(token) = github_token_for(&current) {
            req = req.header("Authorization", &format!("token {token}"));
        }
        // The GitHub REST media type is only valid on api.github.com; sending
        // it to plain github.com makes the server answer HTTP 406 (found live).
        if host_of(&current).as_deref() == Some("api.github.com") {
            req = req.header("Accept", "application/vnd.github.v3+json");
        }

        let res = match req.call() {
            Ok(r) => r,
            Err(e) => {
                // Failed hop is net.log-recorded at the URL it attempted.
                record_failure(&current, &e);
                return Err(e);
            }
        };
        record_outcome(&current, &res);
        let status = res.status();
        let location = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if status.is_redirection() {
            let Some(location) = location else {
                let _ = res.into_body().read_to_vec();
                return Err(ureq::Error::Io(std::io::Error::other(
                    "redirect response without a Location header",
                )));
            };
            // Consume the (usually tiny) redirect body so the pooled
            // connection is released cleanly.
            let _ = res.into_body().read_to_vec();
            current = resolve_redirect(&current, &location)
                .map_err(|e| ureq::Error::Io(std::io::Error::other(e.to_string())))?;
            continue;
        }
        return Ok(res);
    }
    Err(ureq::Error::Io(std::io::Error::other(format!(
        "too many redirects from {url}"
    ))))
}

fn record_outcome(url: &str, res: &Response<ureq::Body>) {
    let host = host_of(url).unwrap_or_default();
    let path = path_of(url);
    crate::netlog::record(&host, &path, Ok(res.status().as_u16()));
}

fn record_failure(url: &str, err: &ureq::Error) {
    let host = host_of(url).unwrap_or_default();
    let path = path_of(url);
    match err {
        ureq::Error::StatusCode(code) => {
            crate::netlog::record(&host, &path, Err(format!("HTTP {code}")))
        }
        e => crate::netlog::record(&host, &path, Err(e.to_string())),
    }
}

/// Total length of a range-addressable blob without transferring it. Sends a
/// `Range: bytes=0-0` probe under identity encoding (so a gzip decision at
/// the proxy cannot skew the reported size) and reads the size from a
/// standard range-response header. Traverses the same retry core as every
/// other fetch ([`fetch`] with a `(0,0)` range), so a DNS/transient blip is
/// absorbed by the shared permanent-retry loop and net.log-recorded — never
/// the instant-fail path the old per-module `go module retry` loop was born
/// from.
pub fn remote_len(url: &str) -> anyhow::Result<u64> {
    let res = fetch(
        url,
        Duration::from_secs(30),
        Some(Duration::from_secs(60)),
        true,
        Some((0, 0)),
    )?;
    let status = res.status().as_u16();
    if status >= 400 {
        anyhow::bail!("probe failed: HTTP {status} for {url}");
    }
    let hdrs = res.headers();
    // On a 206 the `content-length` equals the *range* length (here: 1), while
    // `content-range` carries the real total — so it must win. storage loops
    // additionally expose the canonical size via x-goog-stored-content-length;
    // a plain 200 (Range ignored) is served with an honest content-length.
    for key in [
        "content-range",
        "x-goog-stored-content-length",
        "content-length",
    ] {
        let Some(v) = hdrs.get(key) else {
            continue;
        };
        let Ok(s) = v.to_str() else {
            continue;
        };
        let parsed = if key == "content-range" {
            // "bytes 0-0/TOTAL"
            s.rsplit_once('/')
                .and_then(|(_, total)| total.trim().parse::<u64>().ok())
        } else {
            s.trim().parse::<u64>().ok()
        };
        if let Some(n) = parsed
            && n > 0
        {
            return Ok(n);
        }
    }
    anyhow::bail!("no usable size header in probe response for {url}")
}

fn is_dns_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("try again")
        || m.contains("temporary failure")
        || m.contains("name or service not known")
        || m.contains("address not available")
        || m.contains("failed to lookup address")
        || m.contains("no address associated")
        || m.contains("name resolution")
}

fn backoff_delay(attempt: u32) -> Duration {
    // 1s, 2s, 4s, 8s, 16s, 32s, 64s, 120s, 120s, ...
    let secs = 1u64
        .checked_shl(attempt)
        .unwrap_or(u64::MAX)
        .min(MAX_BACKOFF.as_secs());
    Duration::from_secs(secs)
}

/// Shared retry core for every GET-family fetch.
///
/// Transports are tried in preference order per attempt: the ambient proxy
/// first (the user's explicit intent), then a direct connection when a proxy
/// applies to this URL. Network/DNS errors are retried **permanently** with
/// exponential backoff capped at 120s — the deploy never fails-closed on a
/// transient blip (e.g. DNS `Try again`). Only non-retryable HTTP 4xx (except
/// 403 rate-limit and 5xx) are terminal. Every retry is net.log-recorded.
fn fetch(
    url: &str,
    global: Duration,
    recv_body: Option<Duration>,
    identity_encoding: bool,
    ranged: Option<(u64, u64)>,
) -> Result<Response<ureq::Body>, anyhow::Error> {
    ensure_allowed(url)?;
    let accept_encoding = identity_encoding.then_some(ureq::config::AutoHeaderValue::None);
    let proxied = agent_with_proxy(global, recv_body, accept_encoding.clone(), true);
    let direct =
        ambient_proxy_for(url).map(|_| agent_with_proxy(global, recv_body, accept_encoding, false));

    let mut attempt_no: u32 = 0;
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        for agent in std::iter::once(&proxied).chain(direct.iter()) {
            let res = match ranged {
                Some((start, end)) => attempt_range(agent, url, (start, end)),
                None => attempt(agent, url),
            };
            match res {
                Ok(r) => {
                    let code = r.status().as_u16();
                    // 403 rate-limit: retry indefinitely with backoff.
                    if code == 403 {
                        let _ = r.into_body().read_to_vec();
                        last_err = Some(anyhow!("HTTP 403 from {url} (rate-limited, retrying)"));
                        break;
                    }
                    // 5xx: server overload — retry permanently.
                    if (500..=599).contains(&code) {
                        let _ = r.into_body().read_to_vec();
                        last_err = Some(anyhow!("HTTP {code} from {url}"));
                        break;
                    }
                    // Other 4xx: terminal (bad request, not found, etc.).
                    if (400..=499).contains(&code) {
                        crate::netstatus::note_up(&host_of(url).unwrap_or_default());
                        return Err(anyhow!("HTTP {code} from {url}"));
                    }
                    crate::netstatus::note_up(&host_of(url).unwrap_or_default());
                    return Ok(r);
                }
                Err(e @ ureq::Error::StatusCode(_)) => {
                    // ureq status wrapper — extract code if possible.
                    let s = e.to_string();
                    let is_5xx = s.contains(" 500")
                        || s.contains(" 502")
                        || s.contains(" 503")
                        || s.contains(" 504");
                    let is_403 = s.contains(" 403");
                    if is_403 || is_5xx {
                        last_err = Some(anyhow!("{e}"));
                        break;
                    }
                    return Err(anyhow!("{e}"));
                }
                Err(e) => {
                    let msg = e.to_string();
                    let dns = is_dns_error(&msg);
                    let host = host_of(url).unwrap_or_default();
                    // Record every transient failure so the user can see
                    // we are waiting, not stuck.
                    crate::netlog::record(
                        &host,
                        &path_of(url),
                        Err(format!("retry #{attempt_no}: {msg}")),
                    );
                    let _ = dns;
                    last_err = Some(anyhow!("{e}"));
                }
            }
        }
        // Permanent retry: exponential backoff capped at MAX_BACKOFF.
        let delay = backoff_delay(attempt_no);
        // Coalesced "network looks down" reporting (the anti-spam half).
        crate::netstatus::note_down(&host_of(url).unwrap_or_default());
        std::thread::sleep(delay);
        // Safety: attempt_no saturates at 30 to keep delay at cap.
        attempt_no = attempt_no.saturating_add(1).min(30);
        // Loop forever — only successful fetch or terminal 4xx returns.
        // The process can be interrupted with Ctrl-C (SIGINT).
        if attempt_no == 0 {
            unreachable!();
        }
        let _ = &last_err;
    }
}

/// GET a URL and return the response body as text with retry/curl-fallback
/// semantics of the Python version reduced to: 1 retry after backoff on
/// connection errors, plus a direct-connection fallback when the ambient proxy
/// has gone away. Status >= 400 is returned as an error carrying the code.
pub fn get_text(url: &str) -> anyhow::Result<String> {
    let res = fetch(url, TIMEOUT, None, false, None)?;
    let status = res.status().as_u16();
    let body = res.into_body().read_to_string().context("reading body")?;
    match status {
        200..=299 => Ok(body),
        code => Err(anyhow!("HTTP {code} from {url}")),
    }
}

/// GET a URL and return the response body as bytes with the same
/// allowlist/net.log/retry semantics as [`get_text`]. Used for binary payloads
/// such as source tarballs.
pub fn get_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let res = fetch(url, TIMEOUT, None, false, None)?;
    let status = res.status().as_u16();
    let body = res.into_body().read_to_vec().context("reading body")?;
    match status {
        200..=299 => Ok(body),
        code => Err(anyhow!("HTTP {code} from {url}")),
    }
}

/// One complete body-fetch attempt: the HTTP status plus the fully-read body.
struct FetchOut {
    status: u16,
    body: Vec<u8>,
}

/// Bounded-retry core shared by the slow body paths. `attempt` yields one
/// whole body fetch (transport *and* body-read phase both count); any error
/// or non-2xx status is retried up to [`SLOW_BODY_RETRIES`] more times with a
/// doubling backoff over a fresh request, then the last error surfaces.
fn fetch_slow_bytes_with(
    mut attempt: impl FnMut(&str, Option<(u64, u64)>) -> anyhow::Result<FetchOut>,
    url: &str,
    ranged: Option<(u64, u64)>,
) -> anyhow::Result<Vec<u8>> {
    let mut delay_ms = SLOW_BODY_RETRY_BASE_MS;
    for attempt_no in 0..=SLOW_BODY_RETRIES {
        let outcome = attempt(url, ranged).and_then(|out| match out.status {
            200..=299 => Ok(out.body),
            code => Err(anyhow!("HTTP {code} from {url}")),
        });
        match outcome {
            Ok(body) => return Ok(body),
            Err(_) if attempt_no < SLOW_BODY_RETRIES => {
                std::thread::sleep(Duration::from_millis(delay_ms));
                delay_ms <<= 1;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("SLOW_BODY_RETRIES bounds the loop")
}

/// Shared slow-path body fetch with bounded retry. The transport half of
/// [`fetch`] retries only until response headers arrive; `body_ctx` names the
/// body-read phase so a stall mid-body (the [`SLOW_BODY_IDLE`] idle timeout)
/// or an error status is retried by [`fetch_slow_bytes_with`] as a whole
/// fresh request.
fn fetch_slow_bytes(
    url: &str,
    ranged: Option<(u64, u64)>,
    body_ctx: &'static str,
) -> anyhow::Result<Vec<u8>> {
    fetch_slow_bytes_with(
        |url, ranged| {
            let res = fetch(
                url,
                SLOW_TIMEOUT,
                Some(SLOW_BODY_IDLE),
                ranged.is_some(),
                ranged,
            )?;
            let status = res.status().as_u16();
            let body = res.into_body().read_to_vec().context(body_ctx)?;
            Ok(FetchOut { status, body })
        },
        url,
        ranged,
    )
}

/// GET a large body (source tarball) over a slow-but-alive link. The global
/// budget is [`SLOW_TIMEOUT`] and a single idle read may take up to
/// [`SLOW_BODY_IDLE`] — so a rate-limited transfer slowly crawling along is
/// allowed to finish, while a socket that truly stopped moving data aborts in
/// one idle window instead of hanging for the whole budget. Mid-body stalls
/// and error statuses are retried via [`fetch_slow_bytes`].
pub fn get_bytes_slow(url: &str) -> anyhow::Result<Vec<u8>> {
    fetch_slow_bytes(url, None, "reading slow body")
}

/// GET a byte range (`start..=end`, inclusive) of a large body over a
/// slow-but-alive link. Used to shard one huge blob (e.g. a 52MB embedded
/// wasm) into parallel flows whose aggregate clears a per-flow transfer cap.
/// The request carries a `Range` header and returns exactly the requested
/// span; if the server ignores Range (HTTP 200 full body), the caller's
/// length check catches it and treats the fetch as failed. Same budgets and
/// hop-by-hop allowlist gating as [`get_bytes_slow`], including the bounded
/// retry of mid-body stalls and error statuses via [`fetch_slow_bytes`].
pub fn get_bytes_range(url: &str, start: u64, end: u64) -> anyhow::Result<Vec<u8>> {
    fetch_slow_bytes(url, Some((start, end)), "reading ranged body")
}

/// Probe an allowlisted host with an almost-bodyless HEAD request. Used by
/// preflight where a full GET (e.g. the github.com homepage) can be tens of
/// kilobytes — legitimately slow on a throttled link — and would falsely
/// report "unreachable". Redirects are followed hop-by-hop through the same
/// allowlist gate as any other request; success means HTTPS + host answered.
/// When an ambient proxy is configured, a transport failure is retried via a
/// direct connection once (proxy/VPN may have been switched off moments ago).
pub fn head_ok(url: &str) -> bool {
    ensure_allowed(url).is_ok_and(|_| {
        let proxied = build_agent(TIMEOUT, None);
        let direct = ambient_proxy_for(url).map(|_| agent_with_proxy(TIMEOUT, None, None, false));
        std::iter::once(&proxied)
            .chain(direct.iter())
            .any(|agent| probe_head(agent, url))
    })
}

/// One HEAD-through-redirects probe against a single transport. Every hop is
/// gated by the allowlist and net.log-recorded; nothing outside
/// [`ALLOWED_ENDPOINTS`] is ever contacted.
fn probe_head(agent: &ureq::Agent, url: &str) -> bool {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let res = match agent.head(&current).call() {
            Ok(r) => r,
            Err(e) => {
                record_failure(&current, &e);
                return false;
            }
        };
        record_outcome(&current, &res);
        if res.status().is_redirection() {
            let Some(location) = res
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
            else {
                let _ = res.into_body().read_to_vec();
                return false;
            };
            let _ = res.into_body().read_to_vec();
            current = match resolve_redirect(&current, &location) {
                Ok(next) => next,
                Err(_) => return false,
            };
            if ensure_allowed(&current).is_err() {
                return false;
            }
            continue;
        }
        return res.status().is_success();
    }
    false
}

/// GET a URL and parse JSON.
pub fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> anyhow::Result<(u16, T)> {
    let text = get_text(url)?;
    let val = serde_json::from_str(&text).with_context(|| format!("parsing JSON from {url}"))?;
    Ok((200, val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_non_allowlisted_hosts_without_socket() {
        let err = get_text("https://evil.example/payload").unwrap_err();
        assert!(err.to_string().contains("allowlist"), "{err}");
    }

    #[test]
    fn denies_lookalike_hosts() {
        for url in [
            "https://github.com.evil.example/x",
            "https://api.github.com.evil.example/x",
            "https://raw.githubusercontent.com@127.0.0.1/x", // userinfo trick
            "notaurl",
        ] {
            assert!(ensure_allowed(url).is_err(), "{url} must be denied");
        }
    }

    #[test]
    fn accepts_allowlisted_hosts() {
        assert!(ensure_allowed("https://api.github.com/repos/a/b").is_ok());
        assert!(ensure_allowed("https://raw.githubusercontent.com/a/b/main/f").is_ok());
        // codeload is the archive-redirect target the tarball fallback needs.
        assert!(ensure_allowed("https://codeload.github.com/a/b/tar.gz/master").is_ok());
    }

    #[test]
    #[ignore = "network — opt-in live probe of the dead-proxy->direct fallback"]
    #[allow(unsafe_code)] // test-only env mutation (HTTPS_PROXY)
    fn direct_fallback_when_proxy_is_dead() {
        // Opt-in live probe (network): with HTTPS_PROXY pointing at a dead
        // socket, the fetch must fall back to a direct connection and succeed
        // against a real allowlisted host. Run manually:
        //   cargo test --lib -- --ignored direct_fallback_when_proxy_is_dead
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
            std::env::set_var("https_proxy", "");
            std::env::set_var("ALL_PROXY", "");
            std::env::set_var("NO_PROXY", "");
        }
        let body = get_bytes(
            "https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/README.md",
        )
        .unwrap();
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("https_proxy");
            std::env::remove_var("ALL_PROXY");
            std::env::remove_var("NO_PROXY");
        }
        assert!(!body.is_empty());
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (HTTPS_PROXY)
    fn ambient_proxy_decision() {
        // No proxy configured -> no fallback transport, no proxy route.
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("https_proxy");
            std::env::remove_var("ALL_PROXY");
        }
        assert!(ambient_proxy_for("https://api.github.com/x").is_none());

        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:9999");
            std::env::set_var("NO_PROXY", "");
        }
        // Proxy applies when the target is not NO_PROXY-exempt.
        assert!(ambient_proxy_for("https://api.github.com/x").is_some());
        // NO_PROXY exemption means the route would be direct after all; the
        // fallback is never armed for a target that already bypasses the proxy.
        unsafe {
            std::env::set_var("NO_PROXY", "api.github.com");
        }
        assert!(ambient_proxy_for("https://api.github.com/x").is_none());

        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("https_proxy");
            std::env::remove_var("ALL_PROXY");
            std::env::remove_var("NO_PROXY");
        }
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (HTTPS_PROXY)
    fn honours_ambient_https_proxy() {
        // Regression guard for VPN/proxy users: `Agent::config_builder()` in
        // ureq does NOT read the environment, but our transport must route
        // through the ambient HTTPS proxy. We point the proxy at a real
        // loopback CONNECT sink and assert the connection actually lands on
        // it (proving the proxy is used) rather than going to the real host.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy_url = format!("http://{addr}");
        // Clone the listener into the sink thread so the original can be
        // dropped deterministically after the request; a clone shares the same
        // socket, and `sock` is bound by the time we drop the clone.
        let sink_listener = listener.try_clone().unwrap();
        let sink = std::thread::spawn(move || {
            use std::io::Read;
            let (mut sock, _) = sink_listener
                .accept()
                .expect("proxy must receive the connect");
            let mut buf = vec![0u8; 512];
            let mut n = 0;
            // ureq sends the whole CONNECT line in a single write; one read
            // is enough to capture it, but loop to be robust to short reads.
            while n < buf.len() {
                match sock.read(&mut buf[n..]) {
                    Ok(0) | Err(_) => break,
                    Ok(m) => n += m,
                }
            }
            buf.truncate(n);
            buf
        });

        // SAFETY: single-threaded test, no other lib test touches these vars.
        unsafe {
            std::env::set_var("HTTPS_PROXY", &proxy_url);
            std::env::set_var("https_proxy", "");
            std::env::set_var("ALL_PROXY", "");
            // Do NOT set NO_PROXY for api.github.com, so the CONNECT is proxied.
            std::env::set_var("NO_PROXY", "");
            std::env::set_var("no_proxy", "");
        }

        let agent = build_agent(Duration::from_secs(5), None);
        // Target an allowlisted https host. With a silent proxy sink no reply
        // arrives, but the connection must reach the sink as a CONNECT tunnel
        // to api.github.com:443 (instead of going straight to the real host).
        let _ = agent.head("https://api.github.com/").call();

        drop(listener);
        let handshake = sink.join().unwrap();
        let text = String::from_utf8_lossy(&handshake);
        assert!(
            text.contains("CONNECT api.github.com:443"),
            "expected CONNECT to api.github.com:443 via proxy, got {text:?}"
        );

        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("https_proxy");
            std::env::remove_var("ALL_PROXY");
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("no_proxy");
        }
    }

    #[test]
    fn refuses_plaintext_even_for_allowlisted_hosts() {
        for url in [
            "http://github.com/x",
            "http://api.github.com/repos/a/b",
            "http://codeload.github.com/a/b",
        ] {
            let err = get_text(url).unwrap_err();
            assert!(err.to_string().contains("allowlist"), "{url}: {err}");
        }
    }

    #[test]
    fn redirect_target_resolution() {
        let base = "https://api.github.com/repos/a/b";
        assert_eq!(
            resolve_redirect(base, "https://codeload.github.com/a/tar.gz/main").unwrap(),
            "https://codeload.github.com/a/tar.gz/main"
        );
        assert_eq!(
            resolve_redirect(base, "//codeload.github.com/a/tar.gz/main").unwrap(),
            "https://codeload.github.com/a/tar.gz/main"
        );
        assert_eq!(
            resolve_redirect(base, "/archive/main.tar.gz").unwrap(),
            "https://api.github.com/archive/main.tar.gz"
        );
        assert_eq!(
            resolve_redirect(base, "tarball/main.tar.gz").unwrap(),
            "https://api.github.com/repos/a/tarball/main.tar.gz"
        );
        // A plaintext absolute Location is returned as-is; the per-hop
        // ensure_allowed inside attempt() then refuses it.
        assert_eq!(
            resolve_redirect(base, "http://evil.example/x").unwrap(),
            "http://evil.example/x"
        );
    }

    #[test]
    fn redirect_hop_cap_bounds_loop() {
        // resolve+continue past MAX_REDIRECTS must fail closed with the
        // allowlist gate intact (no sockets opened by the loop itself).
        let base = "https://github.com/a/b";
        assert!(resolve_redirect(base, "https://github.com/c").is_ok());
    }

    #[test]
    fn host_and_path_parsing() {
        assert_eq!(
            host_of("https://api.github.com/repos/a/b?x=1").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            host_of("https://u:p@api.github.com/x").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            path_of("https://api.github.com/repos/a/b?x=1"),
            "/repos/a/b"
        );
        assert_eq!(path_of("https://api.github.com"), "/");
    }

    #[test]
    #[allow(unsafe_code)] // test-only env mutation (GITHUB_TOKEN)
    fn token_only_for_api_host() {
        unsafe { std::env::set_var("GITHUB_TOKEN", "secret") };
        assert!(github_token_for("https://api.github.com/x").is_some());
        assert!(github_token_for("https://github.com/x").is_none());
        assert!(github_token_for("https://raw.githubusercontent.com/x/y").is_none());
        unsafe { std::env::remove_var("GITHUB_TOKEN") };
    }

    #[test]
    fn slow_body_retries_transient_stall_then_succeeds() {
        let url = "https://raw.githubusercontent.com/x/y/main/f";
        let mut attempts = 0;
        let body = fetch_slow_bytes_with(
            |_url, _ranged| {
                attempts += 1;
                if attempts <= 2 {
                    Err(anyhow!(
                        "downloading f seg 11: reading ranged body: timeout: receive body"
                    ))
                } else {
                    Ok(FetchOut {
                        status: 200,
                        body: b"ok".to_vec(),
                    })
                }
            },
            url,
            None,
        )
        .unwrap();
        assert_eq!(body, b"ok");
        assert_eq!(attempts, 3, "two stalls then a green attempt must win");
    }

    #[test]
    fn slow_body_retry_exhausts_and_reports_last_error() {
        let url = "https://raw.githubusercontent.com/x/y/main/f";
        let mut attempts = 0;
        let err = fetch_slow_bytes_with(
            |_url, _ranged| {
                attempts += 1;
                Err(anyhow!(
                    "downloading f seg 11: reading ranged body: timeout: receive body"
                ))
            },
            url,
            None,
        )
        .unwrap_err();
        assert_eq!(attempts, 3, "SLOW_BODY_RETRIES + first attempt in total");
        assert!(err.to_string().contains("reading ranged body"), "{err}");
    }

    #[test]
    fn slow_body_retries_error_status_then_succeeds() {
        let url = "https://raw.githubusercontent.com/x/y/main/f";
        let mut attempts = 0;
        let body = fetch_slow_bytes_with(
            |_url, _ranged| {
                attempts += 1;
                if attempts == 1 {
                    Ok(FetchOut {
                        status: 502,
                        body: vec![],
                    })
                } else {
                    Ok(FetchOut {
                        status: 200,
                        body: b"ok".to_vec(),
                    })
                }
            },
            url,
            None,
        )
        .unwrap();
        assert_eq!(body, b"ok");
        assert_eq!(attempts, 2, "a 5xx burst is retried on a fresh request");
    }
}
