## 📜 License — read this before you fork

GhostProvider is **source-available**, not OSI open-source software. The full text is in [LICENSE](LICENSE). What this means:

- **Allowed**: reading and studying the source, using, modifying, and running the program for **personal non-commercial** purposes.
- **What about forks?**: you can create a fork thanks to GitHub rules, but this rule grants no additional rights.
- **Not allowed without the author's written permission**: redistributing the source or builds, opening a pull request with changes, using it commercially (selling, offering as a service, bundling into a paid product).
- Any permitted modification must retain the copyright notice and the license text.

In short: forking for yourself is fine; opening a pull request or making money with it requires asking first. To request permission, open an issue
([github.com/nethoster/demo-ghostprovider/issues](https://github.com/nethoster/demo-ghostprovider/issues)).

<h1 align="center">Automated self-hosting platform</h1>

> <p align="center">GhostProvider — a source-available platform that makes self-hosting simple</p>

![GHOST PROVIDER Panel](assets/GHOSTPROVIDER%20PANEL.JPEG)

GhostProvider is a terminal panel for Linux. It takes a GitHub URL or a
`service.yaml`, builds the project in a sandbox and runs it as a systemd
**user** service on your machine. No root, no cloud, no third parties.

## One-Click Deploy

Paste a GitHub URL or a path to `service.yaml` — deploy it as a systemd service.
Private, local, no third parties.

![Experience with GhostProvider](assets/user-experience.webp)

[Watch the full experience as video (user-experience.mp4)](assets/user-experience.mp4)

## The panel

Eight screens, one menu:

| # | Screen | What it does |
|---|--------|--------------|
| 1 | **System Scan** | shows interfaces, occupied ports and installed tools |
| 2 | **Self-Hosting** | every deployed unit: start, stop, restart, status |
| 3 | **Deploy Service** | deploy from a GitHub URL or a `service.yaml` |
| 4 | **Add Service** | import a `service.yaml` into your library |
| 5 | **My Services** | your added services with their deploy status |
| 6 | **Edit Service** | change a deployed service — name, port, commit, limits |
| 7 | **Egress** | what each service may reach outside, verified live |
| 8 | **Logs** | three tabs: deploy, software and crash logs |

## Requirements

- SystemD (user-level)
- Git
- Linux

## Tech Stack

- Rust / [ratatui](https://github.com/ratatui/ratatui) (TUI framework)
- ureq + rustls — HTTPS client locked to a compile-time host allowlist
- systemd (user-level service management)

## Why systemd?

GhostProvider runs every service as a systemd **user** unit:

- **No root** — you manage only your own services; nothing is installed system-wide.
- **Starts with login** — services survive reboots without extra setup.
- **Clean removal** — disable the unit and GhostProvider also wipes the clone,
  the secrets file and the port it announced.
- **Sandboxing** — every unit ships with NoNewPrivileges, ProtectHome and
  ProtectSystem enabled.

User units are the standard on Arch, Ubuntu, Fedora, Debian and most modern
Linux distributions.

### When the clean removal happens

GhostProvider removes the unit, the secrets file, the cloned repo (build
caches included) and the announced port whenever a deploy did not finish
cleanly:

- **Explicit delete** — removing a service from *My Services*.
- **Failed deploy** — rolled back and wiped immediately.
- **Panel closed mid-deploy** (Ctrl+C, `q`, SIGTERM/SIGHUP) — cleaned as the
  panel exits.
- **Shutdown or `SIGKILL` mid-deploy** — recorded in an on-disk journal and
  removed on the next panel start.
- **Panel never launched again** — the shipped `demo-ghostprovider-cleanup`
  timer sweeps leftovers in the background.

The sweep is race-free: a deploy holds an exclusive `flock` (`deploy.lock`)
from the moment its journal entry is written until it is cleared. The kernel
releases the lock on any exit — including `SIGKILL` and power loss — so the
timer only removes deploys whose process is provably dead. A deploy that
*finished* is never touched: its service is registered and auto-starts on
login; removing it is always an explicit act.

A scripted deploy (`demo-ghostprovider __deploy --manifest service.yaml`) gets
the same treatment: the first `SIGINT`/`SIGTERM`/`SIGHUP` triggers the removal
path and exits `130`.

## Security Model

- **All data stays local** — every request goes through an HTTPS client locked
  to a compile-time host allowlist, is recorded in net.log, and credentials
  never leave api.github.com. Nothing is sent to third parties.

- **Outbound traffic is controlled per service** — two modes:
  - **Allowlist** — the unit gets `IPAddressDeny=any` plus the hosts you
    approved; the panel verifies the filter live and says honestly when the
    kernel cannot enforce it (best-effort warning, never silent).
  - **Deny-all** — the unit runs with `PrivateNetwork=yes` and a
    socket-activated `__egress-shim`: the service gets a real network
    namespace with **loopback only**, so its entire network is the localhost
    tunnel and nothing else routes.
  Hosts are detected from the manifest (`auto: true`) and you review the list
  before deploying.

- **DNS that survives broken VPN/TUN setups** — system `getaddrinfo` first;
  if that fails, a pinned DNS-over-HTTPS fallback at `cloudflare-dns.com`
  (pinned anycast IPs, Mozilla roots). Retries never fail closed on a
  transient network blip.

- **No root required** — ordinary systemd user units; nothing installed
  system-wide.

- **Explicit confirmation before deploy** — nothing is built or installed
  on its own.

- **Sandbox** — builds run in an isolated environment (sandboxed home,
  locked-down network, resource caps). A deploy proceeds only when the sandbox
  verifies as FULL.

- **Pinned build tools, provisioned into the project cache** — `bun`, `pnpm`,
  `go` and pip wheels are downloaded through the same allowlisted client,
  SHA-256-verified against compiled-in checksums and unpacked into the
  project's `.ghost-cache` (never system-wide). Python installs then run
  offline from that wheelhouse. `python3` itself remains a hard system
  requirement.

## System Scan

Before deploying, GhostProvider checks what is already on your machine:

- **Prerequisites** — python3, cargo, git, systemd.
- **Listening ports** — which ports are taken and by which process.
- **Known services** — is VERT, SearXNG or Memos already running?
- **Tailscale** — the `tailscale` binary is present (presence only; the tunnel
  state is shown in the Self-Hosting panel).

That avoids port conflicts and helps pick the right deploy strategy. The scan
stays useless to anyone but you: no VPN login state, no service fingerprinting;
reachability is measured with the same allowlisted, net.log-recorded HTTPS GET
to github.com — never an ICMP ping.

## Control panel

A full dashboard for everything that runs: start, stop, restart or remove —
one removal cleans the service, unit file, cloned repo, secrets file and
lingering ports. GhostProvider cleans the resources it manages; applications
may still leave their own state (databases, caches, external sockets)
elsewhere.

- **Egress screen** — each service's outbound policy with live verification,
  including an explicit `deny-all: REAL (private netns)` row while the
  loopback-only tunnel is active.
- **Logs screen** — three tabs: **Deploy**, **Software** and **Crash**.
- **Tailscale** — a read-only status row (`running` / `stopped` /
  `needs login`) whenever the daemon is up; the panel never touches the tunnel.

## Service support

This demo ships three reference `service.yaml` manifests in `docs/examples/`
(format: `docs/MANIFEST.md`):

- **VERT** - https://github.com/VERT-sh/VERT
- **SearXNG** - https://github.com/searxng/searxng
- **Memos** - https://github.com/usememos/memos

Nothing deploys from a URL by itself: paste a GitHub URL anywhere (panel
Deploy input, `demo-ghostprovider __deploy URL`) and the stack is detected
into a `service.yaml` you review before deploying — pressing **Enter** on a
detected URL runs the autopilot (detect → store manifest → deploy). Same
format for every service:

```bash
demo-ghostprovider __check-manifest service.yaml    # validate and print the plan
demo-ghostprovider __deploy --manifest service.yaml # deploy it
```

Both go through the identical sandbox + loopback + cleanup pipeline.

In the panel, menu item 4 (Add Service) imports `service.yaml` files into your
library (`~/.local/share/demo-ghostprovider/manifests/`) for one-key redeploys,
or walks you through writing one with the built-in 9-step wizard (first row);
the third row detects the stack of a GitHub URL and prefills the wizard.
Menu item 5 (My Services) lists your added services with deploy status;
item 6 (Edit Service) edits a deployed service's manifest in place — name,
description, commit, port, limits; item 7 (Egress) shows each service's
runtime network allowlist with live verification; item 2 (Self-Hosting)
manages the actually deployed units.

## Install

One command:

```bash
curl -fsSL https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh | sh
```

`install.sh` fails closed by default: it downloads the release and its minisign
signature, verifies the signature (with system `minisign`/`rsign`, or a pinned
static minisign it fetches on demand from jedisct1/minisign) and only then
installs. A missing signature, a missing verifier, or any verification failure
aborts unless you explicitly opt out with `--allow-checksum-only`.

If you want to verify the installer script itself *before* executing it, the
installed script is also signed (`install.sh.minisig`) — see
`docs/DISTRIBUTION.md`.

## Usage

```bash
demo-ghostprovider                                  # launch the interactive panel
demo-ghostprovider --show-endpoints                 # allowlist + session request counters
demo-ghostprovider --selftest                       # E2E check against live systemd (loopback only)
demo-ghostprovider --verify-sandbox                 # audit the build sandbox under strace (needs strace)
demo-ghostprovider __check-manifest PATH            # validate a service.yaml and print the plan
demo-ghostprovider __deploy --manifest PATH         # deploy one service.yaml
demo-ghostprovider __deploy GITHUB_URL              # detect the stack, print service.yaml to stdout
demo-ghostprovider __cleanup                        # manual leftover sweep (runs automatically via a timer)
demo-ghostprovider --version                        # print version
```

## Uninstall

`install.sh` is the single installer and uninstaller — the same signature verifier
from above covers `--uninstall`, which fully removes the binary, the cleanup
timer (`demo-ghostprovider-cleanup.timer`/`.service`), all demo-* systemd user
units, the deploy registry/secrets state and installed service data:

```bash
curl -fsSL https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh | sh -s -- --uninstall
```
