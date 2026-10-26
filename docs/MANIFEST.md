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
  commit: "0123456789abcdef0123456789abcdef01234567"  # 40-hex SHA (exact pin) or branch name (e.g. main)
prefetch:                   # host phase (network allowed): downloaders only
  - ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
build:
  profile: bun              # bun | python | go | node
  steps:
    - ["bun", "run", "build"]
  # env:                    # optional: build-time env for every sandboxed
  #   PUB_ENV: production   # build step (e.g. SvelteKit's PUB_* public env,
  #   # ...                # without which $env/static/public imports fail).
  #   # Keys: [A-Za-z_][A-Za-z0-9_], ≤64 vars, values ≤4096 chars, no
  #   # NUL/newlines. Runtime units never see these; PATH always wins.
run:
  command: ["{self}", "__serve-static", "{project}/build", "{port}"]
  port: 0                   # 0 = random free port, else 1024..65535
resources:
  memory_max: "384M"        # required
  tasks_max: "300"          # required
  memory_high: "256M"
  cpu_quota: "100%"
tools: ["bun"]
# egress:                   # optional: runtime network exceptions
#   allow: [api.example.com] # ≤8 bare hostnames or IPv4; default = deny-all
```

## Rules

* `manifest_version` must be `1`. Unknown fields are rejected.
* `source.git` must be `https://github.com/<owner>/<repo>(.git)`.
  `source.commit` must be a full 40-hex SHA (exact pin — the deploy builds
  exactly that commit) or a safe branch name such as `main` (branch
  tracking — the tip is resolved to a SHA at the start of each deploy and
  the build proceeds pin-exact against that resolution; for upstreams that
  force-push, where a static pin would go stale). The plan output shows
  which mode is in effect.
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
  placeholders. It must reference `{port}` and bind loopback (`__serve-static`
  or `127.0.0.1`).
* `run.env` (optional) is a map of runtime env vars, written to the unit's
  per-service 0600 EnvironmentFile. Keys are `[A-Za-z_][A-Za-z0-9_]`
  (≤64 vars); values ≤4096 chars, no NUL/newlines, and may hold two
  placeholders: `{port}` (the deploy's chosen port) and `{secret}` (fresh
  16-byte hex per deploy — one value shared by all entries, never stored in
  the manifest). Unknown `{tokens}` fail validation. Typical use: an app
   config that documents an env override for a committed placeholder secret
   (e.g. `SEARXNG_SECRET: "{secret}"` in the app's config file).
* `resources.memory_max` + `resources.tasks_max` are required.
* `egress.allow` (optional, top level) is the per-service runtime egress
  allowlist: at most 8 bare hostnames or IPv4 addresses, normalized
  (trimmed, lowercased), duplicates rejected. `localhost`, ranges, wildcards,
  ports and numeric TLDs are rejected — loopback is always allowed anyway.
  Empty (the default) means deny-all: the rendered unit carries
  `IPAddressDeny=any` + `IPAddressAllow=127.0.0.1 ::1`. Because systemd's
  `IPAddressAllow=` accepts bare addresses only (never hostnames), the deploy
  resolves each listed name to its A/AAAA records just before writing the
  unit and appends the literal addresses; resolution fails closed — one
  unresolvable host aborts the deploy. Redeploying re-resolves, which is how
  DNS drift is corrected. `IPAccounting=yes` records the per-service byte
  counters the Egress screen shows. The list affects the *runtime* unit only:
  the build sandbox stays offline and host prefetch stays on its own
  downloader allowlist.
* `plugins` (bun only) pin `https://cdn.jsdelivr.net/npm/@inlang/plugin-*`
  modules by SHA-256, like the built-in VERT manifest. Stack detection
  fills these automatically from `project.inlang/settings.json` (fetched
  and hashed on the host) — without the pins an offline build compiles
  paraglide projects with an empty messages module and they die at
  prerender.
* Secrets never go in the manifest (see `secrets.rs`).

## CLI

```bash
demo-ghostprovider __check-manifest service.yaml
demo-ghostprovider __deploy --manifest service.yaml
```

`__check-manifest` validates and prints the plan without side effects:
source/revision, host-prefetch vs offline-build steps, run command, port,
limits and the egress allowlist.

```bash
demo-ghostprovider __egress-probe --hosts api.example.com,1.1.1.1
```

`__egress-probe` is the same live check the Egress screen runs: a loopback
beat plus one TCP beat per host, printed as `host <h>: open|blocked|failed(…)`
lines (open = the host was reachable, blocked = filtered, failed = timeout /
no route). It only reads state; nothing is changed.

## Library (Add Service screen, menu item 4)

The panel's 4th menu item keeps your own manifests in
`~/.local/share/demo-ghostprovider/manifests/<service-id>.yaml`. The top of
the list holds three clickable rows (↑↓ + Enter, hotkeys in brackets):

* `+ Create new service.yaml` (`n`) — the built-in wizard: 9 plain questions
  (name → git URL → commit pin → build profile → download steps → build
  steps → run command and port → memory/task limits → YAML review). Every
  screen carries a progress chain (`✓ done · » current · upcoming`) and the
  hint bar names what Enter opens next; on the two step-list screens `e`
  edits the selected line (`a`/`d` add/delete). Enter at 9/9 saves the file
  into the library,
* `⇪ Import existing file` (`a`) — copy a file from disk (validated before
  copying; duplicates are refused — delete the stored one first to replace
  it),
* `⇄ Detect from GitHub URL` (Enter) — clone the repo shallowly into a temp
  dir, detect the stack (bun/pnpm/python/go/npm …), wipe the tree, and open
  the wizard prefilled. Nothing is stored until you save at step 9/9.

Below them, every stored file (re-validated on each listing):

* `Enter` deploys the selected file through the same Confirm gate and the
  same sandbox + loopback + cleanup pipeline as everything else,
* `e` edits the stored YAML in `$VISUAL`/`$EDITOR` (the process suspends the
  TUI around the editor; the file is re-validated on the next listing — same
  mechanism as `__recipe-edit <id>`, which runs the editor without the panel),
* `d` twice deletes the stored file (the deployed service, if any, is
  untouched — remove it separately from My Services),
* `r` refreshes the list.

## My Services (menu item 5)

Menu item 5 is the overview of the services you added: the same library
annotated with deploy status (`● deployed` / `○ not deployed`). Enter on a
ready service deploys it through the usual Confirm gate; Enter on a deployed
one jumps to Self-Hosting with the cursor on its unit. Importing, creating
and deleting stay in Add Service.

## Edit Service (menu item 6)

Menu item 6 lists the deployed services (state.json) with their stored
manifests and edits them in place — six rows: `name`, `description`,
`commit` (full SHA or branch), `port`, `memory` and `tasks`. Everything
else in the manifest (build steps, build env, prefetch, egress, plugins)
passes through untouched.

* Enter opens the form; Enter on a row starts inline editing seeded with
  the current value, Enter again commits the row through its own field
  check (port / memory / tasks / commit must parse before they are
  accepted),
* `s` saves the whole manifest through full schema validation —
  `saved — applies on next deploy`,
* `r` saves and immediately redeploys the service; an outdated build
  re-execs the panel onto the fresh binary first and resumes the deploy
  there,
* `e` opens the raw `service.yaml` in `$EDITOR` for anything beyond the
  six rows (the form reloads from the file when the editor returns),
* `Esc` walks back: cancel a row edit, then return to the list,
* `r` on the list refreshes it from state.json.

A deployed service without a library manifest (deployed from an external
path) is listed as `no manifest` — import it through Add Service first.

## Egress (menu item 7)

Menu item 7 is the runtime egress matrix: one row per library service with
its policy (`deny-all (loopback only)` or `allow: …`), the `IPAccounting`
byte counters of the deployed unit (`↑ … ↓ …`) and, after a check, the last
verdict under the row (`BLOCKED` = the filter held, `OPEN` = the host was
reachable, `checking…` while a probe runs):

* `Enter` opens the host editor for the selected service — `a` (or Enter at
  the prompt) appends the typed hostname through full manifest validation,
  `d` twice deletes the highlighted host. Every change is saved to the
  stored `service.yaml` immediately; the new `IPAddressAllow` line takes
  effect on the next deploy (the unit must be recreated, not just reloaded —
  and the deploy re-resolves the hostnames to literal addresses, so DNS
  drift is corrected on every redeploy),
* `v` runs the live check for the selected service (async; loopback beat +
  one TCP beat per allowed host — the same probe as `__egress-probe`),
* `r` refreshes files, deploy status and counters.

Threat model: this is *egress* control for already-deployed services, not a
substitute for the sandbox. The build phase never sees this list (offline),
host prefetch stays on its own downloader allowlist, and the runtime default
is deny-all — a compromised app starts with zero network until the manifest
explicitly names a host. The check is honest about its limits: TCP beats can
report `open` through any network path the unit actually has, so treat
`OPEN` on a deny-all service as a finding, not a probe error.

## Examples

There are no shipped reference files: every service deploys from a
`service.yaml` you own, and the format is validated by the test suite,
never embedded into the binary. Paste a GitHub URL (panel Deploy input or
`__deploy URL`) and the stack is detected into a `service.yaml` you review
before deploying, or write one by hand with the in-panel 9-step wizard.
