#!/usr/bin/env bash
# Blind detection audit: dry-run the smart detector over real repositories
# and print what the autopilot would deploy. Nothing is installed or run —
# `__deploy URL` only clones to a temp dir, prints notes + the manifest,
# and wipes the tree.
#
#   scripts/detect-audit.sh                      # default sample (python + go)
#   scripts/detect-audit.sh https://github.com/owner/repo ...
#   BIN=~/.local/bin/demo-ghostprovider scripts/detect-audit.sh ...
set -u

BIN="${BIN:-target/release/demo-ghostprovider}"
if [ ! -x "$BIN" ]; then
    echo "binary not found at $BIN — cargo build --release first" >&2
    exit 1
fi

repos=("$@")
if [ "${#repos[@]}" -eq 0 ]; then
    repos=(
        https://github.com/searxng/searxng
        https://github.com/usememos/memos
    )
fi

fail=0
for url in "${repos[@]}"; do
    echo "=== $url"
    out="$("$BIN" __deploy "$url" 2>&1)"
    if [ -z "$out" ]; then
        echo "  DETECT FAILED (stack not recognized or fetch failed)"
        fail=1
        continue
    fi

    echo "  --- notes:"
    printf '%s\n' "$out" | grep '^note:' | sed 's/^/    /' || true
    echo "  --- what the autopilot would deploy:"
    printf '%s\n' "$out" | sed -n '/^build:/,/^resources:/p' | sed 's/^/    /' || true

    if printf '%s\n' "$out" | grep -q '^note: warn:'; then
        echo "  verdict: OPENS WIZARD (warn notes present)"
        fail=1
    elif printf '%s\n' "$out" | grep -qE '^note:.*(guess|no run/port declaration|fill in how)'; then
        echo "  verdict: OPENS WIZARD (low confidence — honest review)"
    else
        echo "  verdict: AUTOPILOT-READY (confident, no warns)"
    fi
    echo
done

exit "$fail"
