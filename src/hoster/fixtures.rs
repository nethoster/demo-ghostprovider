//! Test-only manifest fixtures.
//!
//! Formerly `docs/examples/{vert,searxng,memos}.yaml`: reference files that
//! shipped nothing to users (never embedded into the binary) and existed
//! only for the test suite. v0.0.44+ deploys exclusively from a
//! user-provided `service.yaml`, so the shipped examples were dropped and
//! the same three manifests now live here as string fixtures.

/// VERT (SvelteKit/bun) — the `sample()` base of most manifest tests.
pub const VERT_YAML: &str = r##"# Test fixture: VERT (mirrors the former hardcoded recipe 1:1).
manifest_version: 1
service:
  id: demo-vert
  name: VERT
  description: "VERT \u2014 next-generation file converter (Svelte)"
source:
  git: https://github.com/VERT-sh/VERT.git
  commit: "cc7b5a54d5e9c797b377db47b9bdfbb561707783"
prefetch:
  - ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
plugins:
  # Pinned 2026-10-16: upstream released under the @4 tag (npm 4.5.4 —
  # tarball dist/index.js matches these bytes). Bump consciously on drift.
  - url: "https://cdn.jsdelivr.net/npm/@inlang/plugin-message-format@4/dist/index.js"
    sha256: "85a5ce9d714530f6cf2e5491fa6118b5759396e27f2cb673e334fa4adeca7ab3"
  - url: "https://cdn.jsdelivr.net/npm/@inlang/plugin-m-function-matcher@2/dist/index.js"
    sha256: "a7e6c41307afc64b3f34116f220e925f0ad3aca47231e849f080051a2fb459a8"
build:
  profile: bun
  # VERT imports eight PUB_* names from $env/static/public; SvelteKit
  # fails the offline vite build when any of them is unset. Values mirror
  # upstream .env.example with analytics/vertd disabled (loopback-only
  # runtime can never reach them anyway).
  env:
    PUB_ENV: production
    PUB_HOSTNAME: localhost
    PUB_PLAUSIBLE_URL: ''
    PUB_VERTD_URL: https://vertd.vert.sh
    PUB_DISABLE_ALL_EXTERNAL_REQUESTS: 'true'
    PUB_DISABLE_FAILURE_BLOCKS: 'true'
    PUB_DONATION_URL: https://donations.vert.sh
    PUB_STRIPE_KEY: pk_live_51TlrPaFTPjkhEGBSu5Kwy5jJQYxcX5yUUHXiH5g7Xzvb0NKzDqbooc126HjlW35uUkfAgQN2ruEoCuyQynoxpKaA00ojFgQ116
  steps:
    - ["bun", "run", "build"]
run:
  command: ["{self}", "__serve-static", "{project}/build", "{port}"]
  port: 0
resources:
  memory_high: "256M"
  memory_max: "384M"
  tasks_max: "300"
  cpu_quota: "100%"
  limit_nofile: 65536
  oom_score_adjust: 0
healthcheck:
  type: http
  path: /
tools: ["bun"]
"##;

/// SearXNG (Python/granian) — carries the `touch …/.done` prefetch marker
/// and the only `egress.auto` allowlist in the fixtures.
pub const SEARXNG_YAML: &str = r##"manifest_version: 1
service:
  id: demo-searxng
  name: SearXNG
  description: SearXNG — privacy-friendly metasearch engine (Python)
source:
  git: https://github.com/searxng/searxng.git
  commit: 18af21159bd7b84880cd7265b184825493322232
prefetch:
- - python3
  - -m
  - pip
  - download
  - -r
  - requirements.txt
  - -r
  - requirements-server.txt
  - -d
  - .ghost-cache/pip-wheelhouse
  - '--only-binary=:all:'
- touch .ghost-cache/pip-wheelhouse/.done
build:
  profile: python
  steps:
  - python3 -m venv --clear .venv
  - .venv/bin/pip install --no-cache-dir -r requirements.txt -r requirements-server.txt
run:
  command:
  - '{venv}'
  - -m
  - granian
  - searx.webapp:app
  - --host
  - 127.0.0.1
  - --port
  - '{port}'
  port: 8888
  env:
    GRANIAN_INTERFACE: wsgi
    SEARXNG_SECRET: '{secret}'
resources:
  memory_high: 768M
  memory_max: 1536M
  tasks_max: '512'
  cpu_quota: 100%
  limit_nofile: 65536
  oom_score_adjust: -100
healthcheck:
  type: http
  path: /
tools:
- python3
egress:
  allow:
  - www.bing.com
  - duckduckgo.com
  - html.duckduckgo.com
  - www.google.com
  - www.startpage.com
  - search.brave.com
  - en.wikipedia.org
  - www.wikidata.org
  auto: true
"##;

/// Memos (Go/pnpm) — the repair-pipeline and `resolve_start` fixture.
pub const MEMOS_YAML: &str = r##"# Test fixture: Memos (mirrors the former hardcoded recipe 1:1).
manifest_version: 1
service:
  id: demo-memos
  name: Memos
  description: "Memos \u2014 self-hosted, open-source knowledge base (Go)"
source:
  git: https://github.com/usememos/memos.git
  commit: "245e5e3a3e95cd3648fd66a696e0970e5eef1254"
pre_build: []
prefetch:
  - ["pnpm", "--dir", "web", "fetch", "--store-dir", "{project}/.ghost-cache/pnpm"]
build:
  profile: go
  steps:
    - "pnpm --dir web install --offline --store-dir {project}/.ghost-cache/pnpm"
    - "pnpm --dir web release"
    - "go build -o ghost-server ./cmd/memos"
run:
  command: ["{bin}", "--addr", "127.0.0.1", "--port", "{port}"]
  port: 0
resources:
  memory_high: "512M"
  memory_max: "1024M"
  tasks_max: "512"
  cpu_quota: "100%"
  limit_nofile: 65536
  oom_score_adjust: 0
healthcheck:
  type: http
  path: /
tools: ["pnpm", "go"]
"##;
