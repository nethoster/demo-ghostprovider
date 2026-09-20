## 📜 License — read this before you fork

GhostProvider is **source-available**, not OSI open-source software. The full
terms are in [LICENSE](LICENSE). What they mean for you:

- **You may** read and study the source code, and use, modify, and run the
  program for **personal, non-commercial** purposes.
- **You may NOT** fork, modify, publish, or redistribute the project, and
  **may NOT** use it commercially (selling it, offering it as a service,
  bundling it into a product) — **without prior written permission** from the
  author.
- Any permitted modification must retain the copyright notice and this license
  as-is.

In short: forking for a personal experiment is fine per the license; publishing
your fork, redistributing it, or using it commercially requires asking first.
To request permission, open an issue
([github.com/nethoster/demo-ghostprovider/issues](https://github.com/nethoster/demo-ghostprovider/issues)).

<h1 align="center">Automated self-hosting platform</h1>

> <p align="center">GhostProvider is an open-source platform that simplifies self-hosting</p>

![GHOST PROVIDER Panel](assets/GHOSTPROVIDER%20PANEL.JPEG)

## One-Click Deploy

Paste a GitHub URL — deploy one of the three supported services as a systemd service.
Private, local, no third parties.

![Experience with GhostProvider](assets/user-experience.webp)

[Watch the full experience as video (user-experience.mp4)](assets/user-experience.mp4)

## Requirements

- SystemD (user-level)
- Git
- Linux

## Tech Stack

- Rust / [ratatui](https://github.com/ratatui/ratatui) (TUI framework)
- ureq + rustls — HTTPS client locked to a compile-time host allowlist
- systemd (user-level service management)

## Why systemd?

GhostProvider uses systemd user-level services because they provide:
- **No root required** — every user can manage their own services
- **Auto-start on login** — services survive reboots without manual config
- **Clean removal** — `systemctl --user disable` + delete unit file; demo-ghostprovider also cleans the cloned repo, secrets file, and lingering ports
- **Sandboxing** — built-in security directives (NoNewPrivileges, ProtectHome, ProtectSystem)

This is the standard on Arch, Ubuntu, Fedora, Debian, and most modern Linux distributions.

### When the clean removal happens

GhostProvider cleans up everything it created for a service — the systemd unit,
the secrets file, the cloned project tree (build caches included) and the
announced port — in every scenario:

- **Explicit delete** — removing a service from *My Services* cleans unit, env
  file, clone and registry entry.
- **Failed deploy** — a deploy that fails in-process is rolled back and wiped
  immediately (`clean removal` applies to the failed attempt, not just to a
  finished service).
- **User leaves while a deploy is running** (Ctrl+C / `q` / closing the
  terminal, `SIGTERM`/`SIGHUP`) — the in-flight deploy is cleaned up as the
  panel exits.
- **The system shut down or rebooted mid-deploy** (or the panel was killed with
  `SIGKILL`) — nothing can run while the machine is off, so the deploy is
  recorded in an on-disk journal and fully removed on the next panel start.

A deploy that *finished* is never touched by this: its service is registered
and survives reboots (auto-start on login), and removing it is always an
explicit act.

## Security Model

Here is the security module that Ghost Provider uses, this is the necessary architecture for the secure operation of the software.

- **All data stays local** — every request goes through an HTTPS client locked to a compile-time host allowlist, is recorded in net.log, and credentials never leave api.github.com. Nothing is sent to third parties.

- **DNS that survives broken VPN/TUN setups** — resolution is system `getaddrinfo` first; if that fails or times out (broken TUN DNS, `EAI_AGAIN` storms), the client transparently falls back to a DNS-over-HTTPS bootstrap at `cloudflare-dns.com` (pinned anycast IPs, Mozilla roots), which is allowlisted and net.log-recorded like any other outbound hop. Retries remain permanent — the deploy never fails closed on a transient network blip, and a network outage is reported as one clear status line instead of a retry storm.

- **No root required** — services run as ordinary systemd user units; no sudo, no elevated privileges, nothing installed system-wide.

- **Explicit confirmation before deploy** — a deploy only starts after you explicitly confirm it; nothing is built or installed on its own.

- **Sandbox** — builds run in a mandatory isolated environment (sandboxed home, locked-down network, resource caps). A deploy proceeds only when the sandbox verifies as FULL.

- **Pinned build tools, provisioned into the project cache** — when a service needs the build tools `bun`/`pnpm`/`go` and none (or an outdated one) is installed, the exact pinned release is downloaded through the same allowlisted, net.log-recorded client, SHA-256-verified against a compiled-in checksum table, and extracted into the project's `.ghost-cache` (never system-wide, no root). `python3` remains a hard system requirement.

## System Scan

Scans your machine for prerequisites and maps occupied ports with their owning processes — nothing more. Deliberately: no VPN detection, no service fingerprinting, so the report stays useless to anyone but you. "Network" is measured with the same allowlisted, net.log-recorded HTTPS GET to github.com the fetches use — never ICMP ping or raw DNS.

### Why System Scan?

Before deploying a new service, demo-ghostprovider checks what's already running on your machine:
- **Prerequisites** — do you have cargo, systemd, git installed?
- **Listening ports** — which ports are already in use?
- **Known services** — is SearXNG, Memos, or VERT already running?

This avoids port conflicts and helps GhostProvider choose the right deployment strategy. All data stays on your machine — nothing is sent anywhere.

## Control panel

Full dashboard for all deployed services. Start, stop, restart, or remove — one click cleans the service, unit file, cloned repo, secrets file, and lingering ports. GhostProvider cleans up the resources it manages; applications may still leave their own state (databases, caches, external sockets) elsewhere.

## Service support

This is a restricted demo version of GhostProvider that only supports deploying the following services:

- **VERT** - https://github.com/VERT-sh/VERT
- **SearXNG** - https://github.com/searxng/searxng
- **Memos** - https://github.com/usememos/memos

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
demo-ghostprovider --version                        # print version
```

## Uninstall

`install.sh` is the single installer and uninstaller — the same signature verifier
from above covers `--uninstall`, which fully removes the binary, all demo-*
systemd user units, the deploy registry/secrets state and installed service data:

```bash
curl -fsSL https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh | sh -s -- --uninstall
```
