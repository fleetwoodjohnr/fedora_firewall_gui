#!/usr/bin/env bash
# sync_repo <dir> <branch>
# Fetches <branch> from origin in the git repo at <dir> and fast-forwards to it.
# Never touches a dirty or diverged working tree. Prints exactly one of:
#   up-to-date | updated | skipped-dirty | skipped-diverged | fetch-failed
sync_repo() {
    local dir="$1" branch="$2" before after

    before="$(git -C "$dir" rev-parse HEAD 2>/dev/null)" || { echo fetch-failed; return; }

    if ! git -C "$dir" fetch --quiet origin "$branch"; then
        echo fetch-failed
        return
    fi

    if [[ -n "$(git -C "$dir" status --porcelain)" ]]; then
        echo skipped-dirty
        return
    fi

    if ! git -C "$dir" merge --ff-only --quiet "origin/$branch"; then
        echo skipped-diverged
        return
    fi

    after="$(git -C "$dir" rev-parse HEAD)"
    if [[ "$before" == "$after" ]]; then
        echo up-to-date
    else
        echo updated
    fi
}
