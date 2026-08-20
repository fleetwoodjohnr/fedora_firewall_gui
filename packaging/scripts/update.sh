#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRANCH="main"

# shellcheck disable=SC1091
source "$SRC_DIR/packaging/scripts/lib-git-sync.sh"

log() {
    echo "[$(date -Iseconds)] $*"
}

cd "$SRC_DIR"

if [[ ! -d .git ]]; then
    log "not a git checkout — skipping"
    exit 0
fi

result="$(sync_repo "$SRC_DIR" "$BRANCH")"
case "$result" in
    up-to-date)
        log "already up to date ($(git rev-parse --short HEAD))"
        ;;
    skipped-dirty)
        log "local changes present in $SRC_DIR — skipping auto-update"
        ;;
    skipped-diverged)
        log "local branch has diverged from origin/$BRANCH — skipping auto-update"
        ;;
    fetch-failed)
        log "git fetch failed (offline?) — will retry next run"
        exit 1
        ;;
    updated)
        log "updated to $(git rev-parse --short HEAD), reinstalling"
        if FIREWALL_GUI_NO_TIMER=1 "$SRC_DIR/install.sh"; then
            log "reinstall complete"
        else
            log "reinstall failed"
            exit 1
        fi
        if pgrep -f firewall_gui.main >/dev/null 2>&1; then
            log "note: Firewall app is currently running; the update takes effect next launch"
        fi
        ;;
esac
