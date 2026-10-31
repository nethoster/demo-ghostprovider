# Public sharing (Cloudflare Quick Tunnel)

GhostProvider can publish an already-deployed service at a temporary
public HTTPS URL while the panel is running. The deployed service itself
does not change: it remains bound to `127.0.0.1`, has no new ports and no
changes to `service.yaml`, and the existing outbound allow-list is untouched.

## How it works

1. Pick `Networks` in the panel menu and select a deployed service.
2. Press `s` for an open link, or `m` to require one or more email addresses.
3. Liveness and the public URL are read from the supervised `cloudflared`
   process; the row flips to `live` when the URL appears.
4. Press `x` to stop, or simply exit the panel — every running tunnel is
   stopped on exit.

Network → `__cloudflared-supervisor` → `cloudflared tunnel --url http://127.0.0.1:PORT`.
`cloudflared` is the external agent; GhostProvider never downloads or updates
it and it is not part of `ALLOWED_ENDPOINTS`.

## Supervision

- Each tunnel has its own process group and `PDEATHSIG`.
- Stop is `SIGTERM` + grace period + `SIGKILL`, so no orphan survives a
  panel exit, reboot, or `SIGKILL`.
- `__cleanup`/`__networks-stop-all` sweep pidfiles left by a lost registry.
- `install.sh --uninstall` stops all tunnels before removing anything.

## Consent and scope

- Starting a tunnel requires an explicit confirmation every session.
- A tunnel publishes one existing deployed service only; it does not change
  `service.yaml`, ports or resources.
- `cloudflared.log` stores process output but never service secrets.
- `networks.log` stores operational details only.

## Diagnostics

- Account log: `…/state/demo-ghostprovider/networks/<service>/cloudflared.log`.
- Event stream: `…/networks/<service>/events.log`.
- `Networks` screen shows status, local URL, public URL and recent messages.
- `--show-endpoints` lists the compiled-in allow-list and reports the tunnel
  agent as opt-in.
