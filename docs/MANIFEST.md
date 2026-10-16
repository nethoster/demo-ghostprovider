# GhostProvider service manifests (`service.yaml`, v1)

A manifest is the contract between GhostProvider and one deployable
service. The engine validates it, prints a plan, and only then deploys —
sandbox (`PrivateNetwork=yes`), loopback-only units and journaled cleanup
stay mandatory no matter what the manifest says.

## Minimal example

```yaml
manifest_version: 1
service:
  id: my-service            # ^[a-z0-9-]{3,64}$
  name: My Service
  description: My self-hosted app
source:
  git: https://github.com/example/my-service.git
  commit: "0123456789abcdef0123456789abcdef01234567"  # full 40-hex SHA
prefetch:                   # host phase (network allowed): downloaders only
  - ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
build:
  profile: bun              # bun | python | python-searxng | go | node
  steps:
    - ["bun", "run", "build"]
run:
  command: ["{self}", "__serve-static", "{project}/build", "{port}"]
  port: 0                   # 0 = random free port, else 1024..65535
resources:
  memory_max: "384M"        # required
  tasks_max: "300"          # required
  memory_high: "256M"
  cpu_quota: "100%"
tools: ["bun"]
```

## Rules

* `manifest_version` must be `1`. Unknown fields are rejected.
* `source.git` must be `https://github.com/<owner>/<repo>(.git)`.
  `source.commit` must be a full 40-hex SHA (anti-TOFU: never tracks `main`).
* Steps accept shell strings (`"python3 -m venv --clear .venv"`) or argv
  arrays (`["bun", "run", "build"]`). Argv is preferred: items are
  shell-quoted so `sh -c` cannot reinterpret them.
* `prefetch` (host, network on) is allowlisted to downloaders that never run
  fetched code on the host:
  `bun install --frozen-lockfile --ignore-scripts`, `pnpm ... fetch ...`,
  `pip download ... --only-binary=:all:`, `go mod download`,
  `touch .ghost-cache/...`. Anything else fails validation.
* `pre_build`/`build.steps` (sandbox, network off) pass the same heuristic
  screen as before; the sandbox is the real boundary.
* `run.command` is argv with `{bin}/{venv}/{self}/{project}/{port}`
  placeholders. It must reference `{port}` (except `searxng: true`, where the
  port is injected via `settings.yml`) and bind loopback (`__serve-static`
  or `127.0.0.1`).
* `resources.memory_max` + `resources.tasks_max` are required.
* `plugins` (bun only) pin `https://cdn.jsdelivr.net/npm/@inlang/plugin-*`
  modules by SHA-256, like the built-in VERT manifest.
* Secrets never go in the manifest (see `secrets.rs`).

## CLI

```bash
demo-ghostprovider __check-manifest service.yaml
demo-ghostprovider __deploy --manifest service.yaml
```

`__check-manifest` validates and prints the plan without side effects:
source/revision, host-prefetch vs offline-build steps, run command, port
and limits.

## Library (Add Service screen)

The panel's 5th menu item keeps your own manifests in
`~/.local/share/demo-ghostprovider/manifests/<service-id>.yaml`:

* `a` imports a file from disk (validated before copying; duplicates are
  refused — delete the stored one first to replace it),
* `Enter` deploys the selected file through the same Confirm gate and the
  same sandbox + loopback + cleanup pipeline as everything else,
* `d` twice deletes the stored file (the deployed service, if any, is
  untouched — remove it separately from My Services),
* `r` refreshes the list (files are re-validated on every listing).

## Built-ins

`src/hoster/manifests/{vert,searxng,memos}.yaml` are the three former
hardcoded recipes expressed as manifests 1:1. URL deploys resolve through
them, so the old pipeline and its tests exercise the manifest path.
