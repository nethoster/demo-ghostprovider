#!/bin/sh
# demo-ghostprovider one-shot installer (static binary).
#
# Simplest: one command, no pre-verification ceremony:
#
#   curl -fsSL https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh | sh -s -- --uninstall
#
# The script verifies the DOWNLOADED RELEASE itself (minisign, fail-closed)
# before installing. To also verify the installer script before running it
# (itself signed as `install.sh` + `install.sh.minisig`):
#
#   curl -fsSL -o /tmp/dgp-install.sh https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh
#   curl -fsSL -o /tmp/dgp-install.sh.minisig https://raw.githubusercontent.com/nethoster/demo-ghostprovider/main/install.sh.minisig
#   minisign -Vm /tmp/dgp-install.sh -x /tmp/dgp-install.sh.minisig -P "RWSUAckJJhM011XphIH3LQE0Ebn62qqMMQej4Ong52/rGNw/rxRKniqA" && sh /tmp/dgp-install.sh
#
# The public key/fingerprint are published in docs/DISTRIBUTION.md; cross-check
# the pasted key above against that document rather than trusting this comment.
#
# Downloads the latest tagged musl binary, verifies sha256 always, and the
# minisign signature whenever a verifier is at hand: a system minisign/rsign,
# or a pinned static minisign binary fetched on demand from the independent
# jedisct1/minisign release. If no verifier can be obtained the install ABORTS
# (fail-closed): the signature is the only trust anchor against a compromised
# release, and SHA-256 alone shares its bytes with the attacker. Install
# minisign, or rerun with --allow-checksum-only to accept a checksum-only
# install deliberately. Installs into ~/.local/bin.
#
# This is the project's single installer: `install.sh` installs or upgrades the
# static binary, and `install.sh --uninstall` fully removes it along with the
# demo-* systemd user units, the deploy registry/secrets state directory and
# installed service data.
#
# git is a runtime requirement (cloning services); if missing it is
# auto-installed via the distro package manager under sudo when possible.
#
# Flags: --uninstall | --tag v0.0.14 | --bin-dir DIR | --mirror codeberg
#        | --allow-unsigned    (accept a release with NO signature file)
#        | --allow-checksum-only (accept a signature file that cannot be
#                              verified because no verifier is available)
#          Neither flag is ever the default; both require the explicit user.
set -eu

REPO_GH="nethoster/demo-ghostprovider"
REPO_CB="netuser/demo-ghostprovider"
BIN_NAME="demo-ghostprovider"
DEFAULT_BIN_DIR="${HOME}/.local/bin"
RELEASE_PUB="RWSUAckJJhM011XphIH3LQE0Ebn62qqMMQej4Ong52/rGNw/rxRKniqA"
FINGERPRINT="D734132609C90194"
# Pinned static minisign verifier, from the independent jedisct1/minisign
# release (not from this repo, so a compromised leverage of our releases cannot
# swap the verifier). sha256 locks it against upstream tampering.
MINISIGN_URL="https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz"
MINISIGN_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
MINISIGN_RELPATH="minisign-linux/x86_64/minisign"

TAG=""
BIN_DIR="$DEFAULT_BIN_DIR"
HOST="github"
ACTION="install"
ALLOW_UNSIGNED=0
ALLOW_CHECKSUM_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) ACTION="uninstall" ;;
        --tag) TAG="${2:?}"; shift ;;
        --bin-dir) BIN_DIR="${2:?}"; shift ;;
        --mirror) HOST="codeberg" ;;   # also auto-fallback per file
        --allow-unsigned) ALLOW_UNSIGNED=1 ;;
        --allow-checksum-only) ALLOW_CHECKSUM_ONLY=1 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

log()  { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }

# Version of an already-installed binary, or empty when absent/unparsable.
# Normalized to a `v`-prefixed tag (the binary may print `0.0.19` or `v0.0.19`).
old_version() {
    [ -x "$1" ] || return 0
    version=$("$1" --version 2>/dev/null | sed -n 's/.*\(v\?[0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/p' | head -n1)
    [ -n "$version" ] || return 0
    case "$version" in
        v*) printf '%s' "$version" ;;
        *)  printf 'v%s' "$version" ;;
    esac
}

# Auto-install git via the distro package manager when missing (sudo unless
# running as root); the panel needs git to clone services. Returns 0 when git
# is (now) available, 1 otherwise (the install still proceeds).
ensure_git() {
    command -v git >/dev/null 2>&1 && return 0
    if [ "$(id -u)" = "0" ]; then
        run_rooted() { "$@"; }
    elif command -v sudo >/dev/null 2>&1; then
        run_rooted() { sudo "$@"; }
    else
        warn "git not found and neither root nor sudo available — git is needed to deploy services"
        return 1
    fi
    warn "git not found — installing via your package manager..."
    if command -v pacman >/dev/null 2>&1; then
        run_rooted pacman -S --noconfirm git || return 1
    elif command -v apt-get >/dev/null 2>&1; then
        run_rooted apt-get update || true
        run_rooted apt-get install -y git || return 1
    elif command -v dnf >/dev/null 2>&1; then
        run_rooted dnf install -y git || return 1
    else
        warn "no supported package manager (pacman/apt/dnf) — install git manually"
        return 1
    fi
    command -v git >/dev/null 2>&1
}

# Fetch the pinned static minisign verifier into $TMP. Returns 0 on success;
# non-zero on download/hash/extract failure (caller falls back to checksum-only).
ensure_verifier() {
    warn "minisign/rsign not found — fetching pinned static verifier..."
    if ! curl -fsSL -o "$TMP/minisign.tar.gz" "$MINISIGN_URL" 2>/dev/null; then
        warn "could not download the verifier — signature cannot be verified (only SHA-256 remains; abort unless --allow-checksum-only)"
        return 1
    fi
    if [ "$(sha256sum "$TMP/minisign.tar.gz" | cut -d' ' -f1)" != "$MINISIGN_SHA256" ]; then
        warn "verifier hash mismatch — refusing it (only SHA-256 remains; abort unless --allow-checksum-only)"
        return 1
    fi
    tar -xzf "$TMP/minisign.tar.gz" -C "$TMP" 2>/dev/null
    VERIFIER="$TMP/$MINISIGN_RELPATH"
    if [ ! -x "$VERIFIER" ]; then
        warn "verifier extraction failed (only SHA-256 remains; abort unless --allow-checksum-only)"
        return 1
    fi
    return 0
}

# Verify the release signature with whichever verifier is available:
# system minisign, system rsign, or the pinned fetched static minisign.
# Returns 0 = signature good; 1 = no verifier could be obtained
# (checksum-only); 2 = signature FAILED (fatal).
verify_signature() {
    if command -v minisign >/dev/null 2>&1; then
        ( cd "$TMP" && minisign -Vm SHA256SUMS -P "$RELEASE_PUB" ) >/dev/null 2>&1 \
            && { ok "minisign signature verified (system minisign, key $FINGERPRINT)"; return 0; }
        return 2
    fi
    if command -v rsign >/dev/null 2>&1; then
        ( cd "$TMP" && rsign verify -P "$RELEASE_PUB" -x SHA256SUMS.minisig SHA256SUMS ) >/dev/null 2>&1 \
            && { ok "minisign signature verified (rsign, key $FINGERPRINT)"; return 0; }
        return 2
    fi
    VERIFIER=""
    if ensure_verifier; then
        ( cd "$TMP" && "$VERIFIER" -Vm SHA256SUMS -P "$RELEASE_PUB" ) >/dev/null 2>&1 \
            && { ok "minisign signature verified (fetched verifier, key $FINGERPRINT)"; return 0; }
        return 2
    fi
    return 1
}

if [ "$ACTION" = "uninstall" ]; then
    # Non-interactive (piped/scripted) runs proceed without prompting.
    confirm_uninstall() {
        [ -t 0 ] || return 0
        printf '%s [Y/n] ' "$1" >&2
        a=""
        read -r a </dev/tty || return 0
        case "$a" in [Nn]*) return 1 ;; esac
    }

    state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/demo-ghostprovider"
    install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/demo-ghostprovider"
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

    if command -v systemctl >/dev/null 2>&1; then
        log "stopping and removing demo-* user units..."
        {
            systemctl --user list-units --all --type=service --plain --no-legend 2>/dev/null | awk '{print $1}' || true
            systemctl --user list-unit-files --type=service --plain --no-legend 2>/dev/null | awk '{print $1}' || true
            if [ -f "$state_dir/state.json" ]; then
                grep -o '"unit_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$state_dir/state.json" | cut -d'"' -f4 || true
            fi
        } | sort -u | { grep '^demo-' || true; } | while IFS= read -r unit; do
            systemctl --user stop "$unit" 2>/dev/null || true
            systemctl --user disable "$unit" 2>/dev/null || true
            rm -f "$unit_dir/$unit" 2>/dev/null || true
        done
        # The cleanup TIMER never shows up in the service-only listing above
        # (and the timer starts with `demo-` only once the binary flagged);
        # stop and remove both cleanup units explicitly so an upgrade never
        # leaves a stale timer pointing at a removed binary.
        systemctl --user stop demo-ghostprovider-cleanup.timer 2>/dev/null || true
        systemctl --user disable demo-ghostprovider-cleanup.timer 2>/dev/null || true
        rm -f "$unit_dir/demo-ghostprovider-cleanup.timer" "$unit_dir/demo-ghostprovider-cleanup.service" 2>/dev/null || true
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user reset-failed 2>/dev/null || true
    fi

    for f in "$BIN_DIR/$BIN_NAME"; do
        if [ -e "$f" ]; then rm -f "$f" && ok "removed $f"; fi
    done

    if [ -d "$state_dir" ]; then
        rm -rf "$state_dir" && ok "removed $state_dir (registry, net log, secrets)"
    fi

    if [ -d "$install_dir" ]; then
        if confirm_uninstall "This also removes ALL deployed service data under $install_dir. Remove it?"; then
            rm -rf "$install_dir" && ok "removed $install_dir (installed program + cloned services)"
        else
            warn "kept $install_dir — remove manually later if desired."
        fi
    fi

    log "fully uninstalled."
    exit 0
fi

for dep in curl sha256sum uname tar grep; do need "$dep"; done

[ "$(uname -s)" = "Linux" ] || die "prebuilt binaries are Linux-only; build from source instead"
[ "$(uname -m)" = "x86_64" ] || die "prebuilt binaries are x86_64-only; build from source instead"

ensure_git || warn "continuing without git; you can install it later"

# A release tag is `v<major>.<minor>.<patch>` — anything else (a sed
# extraction mistake, a malicious redirect) must abort, not download.
valid_tag() {
    printf '%s' "$1" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

if [ -z "$TAG" ]; then
    log "resolving latest release tag..."
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO_GH/releases/latest" \
          | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    if [ -z "$TAG" ]; then
        TAG=$(curl -fsSL "https://codeberg.org/api/v1/repos/$REPO_CB/releases?limit=1" \
              | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
        HOST="codeberg"
    fi
    [ -n "$TAG" ] || die "could not resolve latest tag; pass one explicitly: --tag v0.0.14"
fi
valid_tag "$TAG" || die "malformed tag '$TAG' — expected v<major>.<minor>.<patch>; refusing to install"

case "$HOST" in
    github)  BASE="https://github.com/$REPO_GH/releases/download/$TAG" ;;
    codeberg) BASE="https://codeberg.org/$REPO_CB/releases/download/$TAG" ;;
esac

ART="$BIN_NAME-$TAG-x86_64-linux-musl"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# fetch <name> -> 0 when downloaded; quiet: a missing optional
#          file must not spook the user (signature handling is below)
fetch() {
    curl -fsSL -o "$TMP/$1" "$BASE/$1" 2>/dev/null || \
        curl -fsSL -o "$TMP/$1" \
        "https://github.com/$REPO_GH/releases/download/$TAG/$1" 2>/dev/null
}

log "downloading $TAG..."
fetch "$ART"           || die "download failed: $ART"
fetch "SHA256SUMS"     || die "download failed: SHA256SUMS"

( cd "$TMP" && sha256sum -c SHA256SUMS ) || die "checksum mismatch — aborting"

# Signature is verified whenever a verifier is at hand (system minisign/rsign
# or the pinned fetched static minisign). A real signature FAILURE, a missing
# SHA256SUMS.minisig on the release, or a signature that cannot be verified
# because no verifier could be obtained all ABORT by default; the only way
# past is an explicit flag (--allow-unsigned for a missing signature file,
# --allow-checksum-only for an unavailable verifier). Fail-closed: a
# checksum-only install is never chosen silently.
fetch "SHA256SUMS.minisig" || true
if [ -f "$TMP/SHA256SUMS.minisig" ]; then
    rc=0
    verify_signature || rc=$?
    case "$rc" in
        2) die "signature verification FAILED — aborting" ;;
        1) if [ "$ALLOW_CHECKSUM_ONLY" -eq 1 ]; then
               warn "no signature verifier available (minisign/rsign, or the pinned static verifier could not be fetched) — --allow-checksum-only set, checksum-only install." >&2
           else
               die "signature verification UNAVAILABLE — no minisign/rsign and the pinned static verifier could not be obtained. Install minisign, or rerun with --allow-checksum-only to accept a SHA-256-only install."
           fi ;;
    esac
elif [ "$ALLOW_UNSIGNED" -eq 1 ] || [ "$ALLOW_CHECKSUM_ONLY" -eq 1 ]; then
    warn "release has no minisign signature (SHA256SUMS.minisig) — flag set, checksum-only install."
else
    die "release is UNSIGNED (SHA256SUMS.minisig missing) — refusing to install; verify the release is properly signed (docs/DISTRIBUTION.md, key $FINGERPRINT)"
fi

mkdir -p "$BIN_DIR"
BIN_PATH="$BIN_DIR/$BIN_NAME"
OLD_VER="$(old_version "$BIN_PATH")"
if [ -n "$OLD_VER" ]; then
    if [ "$OLD_VER" = "$TAG" ]; then
        ok "already up to date ($OLD_VER)"
    else
        log "upgrading $OLD_VER -> $TAG"
    fi
fi

# Write atomically: build the new binary in place under a temp name, then
# `mv` it over the target so a concurrent read (or an interrupted run) never
# sees a half-written file.
install -m755 "$TMP/$ART" "$BIN_PATH.tmp.$$"
mv -f "$BIN_PATH.tmp.$$" "$BIN_PATH"

# The binary must actually run before we report success; otherwise roll back
# so the user is never left with a silent broken install.
if ! "$BIN_PATH" --show-endpoints >/dev/null 2>&1; then
    rm -f "$BIN_PATH"
    die "installed binary failed its self-report (--show-endpoints) — install rolled back"
fi
if [ -n "$OLD_VER" ]; then
    if [ "$OLD_VER" = "$TAG" ]; then
        ok "already up to date ($OLD_VER); refreshed $BIN_PATH"
    else
        ok "updated: $BIN_PATH ($OLD_VER -> $TAG)"
    fi
else
    ok "installed: $BIN_PATH"
fi

# Install the periodic cleanup timer. It runs `demo-ghostprovider __cleanup`:
# a background sweep that removes leftovers of deploys interrupted out-of-band
# (panel exit/kill, shutdown/reboot) even if the panel is never launched again.
# The sweep is safe by construction — it only proceeds while holding the deploy
# lock, which is only free once no deploy process is running.
CLEANUP_UNITS=0
if command -v systemctl >/dev/null 2>&1; then
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    log "installing periodic cleanup timer..."
    mkdir -p "$unit_dir"
    cat > "$unit_dir/demo-ghostprovider-cleanup.service" <<EOF
[Unit]
Description=Clean up leftover demo-ghostprovider deploy artifacts

[Service]
Type=oneshot
ExecStart=$BIN_PATH __cleanup
# The unit only ever deletes state owned by this user; minimal hardening anyway.
NoNewPrivileges=true
PrivateTmp=true
UMask=0077
EOF
    cat > "$unit_dir/demo-ghostprovider-cleanup.timer" <<EOF
[Unit]
Description=Periodic demo-ghostprovider deploy-artifact cleanup

[Timer]
# Hours after boot, plus every 15min while the machine is up, and a catch-up
# run after resume/reboot via Persistent=true.
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=2min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 644 "$unit_dir/demo-ghostprovider-cleanup.service" "$unit_dir/demo-ghostprovider-cleanup.timer"
    systemctl --user daemon-reload 2>/dev/null
    if systemctl --user enable --now demo-ghostprovider-cleanup.timer 2>/dev/null; then
        CLEANUP_UNITS=1
        ok "cleanup timer enabled: demo-ghostprovider-cleanup.timer"
    else
        warn "could not enable the cleanup timer (is a user systemd manager running?); leftover cleanup will run on next launch instead"
    fi
else
    warn "systemctl not found — no background cleanup timer; leftover cleanup runs on next launch"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not in PATH. Add to your shell profile:"
       warn "  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
log "run it:  $BIN_NAME"
