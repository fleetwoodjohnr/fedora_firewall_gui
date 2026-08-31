#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/fleetwoodjohnr/fedora_firewall_gui.git"
BRANCH="main"
PERSIST_SRC_DIR="$HOME/.local/share/firewall-gui-src"
SHARE_DIR="$HOME/.local/share/firewall-gui"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
HELPER_PATH="/usr/libexec/firewall-gui-helper"
POLKIT_ACTION_PATH="/usr/share/polkit-1/actions/org.jrf.FirewallGui.policy"

require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

check_deps() {
    local missing=()
    require_cmd python3 || missing+=("python3")
    if ! python3 -c "
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw
" >/dev/null 2>&1; then
        missing+=("python3-gobject / gtk4 / libadwaita bindings")
    fi
    require_cmd firewall-cmd || missing+=("firewalld")
    require_cmd nmcli || missing+=("NetworkManager")
    require_cmd git || missing+=("git")

    if ((${#missing[@]})); then
        echo "Missing required dependencies:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        echo >&2
        echo "On Fedora, install everything needed with:" >&2
        echo "  sudo dnf install -y python3-gobject gtk4 libadwaita firewalld NetworkManager git" >&2
        exit 1
    fi

    if require_cmd systemctl && ! systemctl is-active --quiet firewalld; then
        echo "warning: firewalld is installed but not running — enable with:" >&2
        echo "  sudo systemctl enable --now firewalld" >&2
    fi
}

# Resolves to the directory this install is running from (or being bootstrapped into).
#
# When executed as a real script file from inside a checkout (./install.sh, make install),
# BASH_SOURCE[0] points at it directly. Under `curl | bash`, `bash -c "$(curl ...)"`, or
# `bash <(curl ...)`, BASH_SOURCE[0] is either unset or not a regular file — those cases,
# plus a checkout dir that just doesn't look right, fall through to a standalone bootstrap
# that clones (or refreshes an existing clone of) the repo into a fixed, permanent location.
resolve_src_dir() {
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        local candidate
        candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -d "$candidate/firewall_gui" && -f "$candidate/bin/firewall-gui" ]]; then
            echo "$candidate"
            return
        fi
    fi

    require_cmd git || { echo "git is required to install from a standalone script" >&2; exit 1; }

    if [[ -d "$PERSIST_SRC_DIR/.git" ]]; then
        if [[ -f "$PERSIST_SRC_DIR/packaging/scripts/lib-git-sync.sh" ]]; then
            # shellcheck disable=SC1091
            source "$PERSIST_SRC_DIR/packaging/scripts/lib-git-sync.sh"
            sync_repo "$PERSIST_SRC_DIR" "$BRANCH" >/dev/null || true
        fi
    else
        mkdir -p "$(dirname "$PERSIST_SRC_DIR")"
        git clone --branch "$BRANCH" "$REPO_URL" "$PERSIST_SRC_DIR"
    fi
    echo "$PERSIST_SRC_DIR"
}

install_app() {
    local src_dir="$1"

    mkdir -p "$SHARE_DIR" "$BIN_DIR" "$APPS_DIR" "$ICON_DIR"

    if require_cmd rsync; then
        rsync -a --delete "$src_dir/firewall_gui/" "$SHARE_DIR/firewall_gui/"
    else
        rm -rf "$SHARE_DIR/firewall_gui"
        cp -a "$src_dir/firewall_gui" "$SHARE_DIR/firewall_gui"
    fi

    chmod +x "$src_dir/bin/firewall-gui"
    ln -sfn "$src_dir/bin/firewall-gui" "$BIN_DIR/firewall-gui"
    ln -sfn "$src_dir/packaging/org.jrf.FirewallGui.desktop" "$APPS_DIR/org.jrf.FirewallGui.desktop"
    ln -sfn "$src_dir/packaging/icons/org.jrf.FirewallGui.svg" "$ICON_DIR/org.jrf.FirewallGui.svg"

    require_cmd update-desktop-database && update-desktop-database "$APPS_DIR" || true
    require_cmd gtk-update-icon-cache && gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" || true
    require_cmd desktop-file-validate && desktop-file-validate "$APPS_DIR/org.jrf.FirewallGui.desktop" || true
}

install_update_timer() {
    local src_dir="$1"

    if ! require_cmd systemctl; then
        echo "warning: systemctl not found — skipping auto-update timer setup" >&2
        return
    fi

    if ! systemctl --user list-units >/dev/null 2>&1; then
        echo "warning: no systemd user session available — skipping auto-update timer setup" >&2
        echo "  (log into a graphical/user session and re-run install.sh to enable it)" >&2
        return
    fi

    mkdir -p "$SYSTEMD_USER_DIR"
    sed "s#@SRC_DIR@#$src_dir#g" \
        "$src_dir/packaging/systemd/firewall-gui-update.service.in" \
        > "$SYSTEMD_USER_DIR/firewall-gui-update.service"
    cp "$src_dir/packaging/systemd/firewall-gui-update.timer" \
        "$SYSTEMD_USER_DIR/firewall-gui-update.timer"

    if ! systemctl --user daemon-reload || ! systemctl --user enable --now firewall-gui-update.timer; then
        echo "warning: failed to enable the auto-update timer — you can retry later with:" >&2
        echo "  systemctl --user daemon-reload && systemctl --user enable --now firewall-gui-update.timer" >&2
    fi
}

# The Hardening page's DNS and encryption levels need to write to /etc, which
# nothing else in this app does -- firewalld and NetworkManager authorize their
# own changes through PolicyKit and need no privileges from us.
#
# So this is the one part of the install that asks for root, and it stays
# optional: decline it and the app still runs, with the Hardening page saying
# what's missing and how to get it. The helper is installed root-owned into
# /usr/libexec rather than left in ~/.local on purpose -- pkexec runs it as
# root, and root must never execute a file that a compromised user account
# could rewrite first.
install_privileged_helper() {
    local src_dir="$1"

    if [[ -n "${FIREWALL_GUI_NO_HELPER:-}" ]]; then
        return
    fi

    if ! require_cmd pkexec; then
        echo "warning: pkexec not found — skipping the system hardening helper" >&2
        echo "  (install it with: sudo dnf install polkit)" >&2
        return
    fi

    if ! require_cmd sudo; then
        echo "warning: sudo not found — skipping the system hardening helper" >&2
        return
    fi

    # `curl | bash` leaves stdin pointing at the script, so there is nothing to
    # read a y/n from. Skip rather than hang, and say how to opt in.
    if [[ ! -t 0 && -z "${FIREWALL_GUI_HELPER:-}" ]]; then
        echo "note: skipping the optional system hardening helper (not running interactively)" >&2
        echo "  to install it, re-run from a checkout, or set FIREWALL_GUI_HELPER=1" >&2
        return
    fi

    if [[ -z "${FIREWALL_GUI_HELPER:-}" ]]; then
        echo
        echo "The Hardening page can also manage your DNS privacy settings, the system-wide"
        echo "crypto policy, and SSH hardening. Those need a small helper installed as root:"
        echo "  $HELPER_PATH"
        echo "  $POLKIT_ACTION_PATH"
        echo "Everything else in the app works without it."
        local reply=""
        read -r -p "Install it now with sudo? [y/N] " reply
        case "$reply" in
            [Yy]*) ;;
            *)
                echo "Skipped. Re-run this installer later if you change your mind." >&2
                return
                ;;
        esac
    fi

    if ! sudo install -D -o root -g root -m 0755 \
            "$src_dir/packaging/helper/firewall-gui-helper" "$HELPER_PATH" \
        || ! sudo install -D -o root -g root -m 0644 \
            "$src_dir/packaging/polkit/org.jrf.FirewallGui.policy" "$POLKIT_ACTION_PATH"; then
        echo "warning: couldn't install the system hardening helper — you can retry with:" >&2
        echo "  sudo install -D -o root -g root -m 0755 \\" >&2
        echo "    $src_dir/packaging/helper/firewall-gui-helper $HELPER_PATH" >&2
        echo "  sudo install -D -o root -g root -m 0644 \\" >&2
        echo "    $src_dir/packaging/polkit/org.jrf.FirewallGui.policy $POLKIT_ACTION_PATH" >&2
    fi
}

print_summary() {
    local src_dir="$1"
    echo "Installed:"
    echo "  Launcher:      $BIN_DIR/firewall-gui"
    echo "  Desktop entry: $APPS_DIR/org.jrf.FirewallGui.desktop"
    echo "  Icon:          $ICON_DIR/org.jrf.FirewallGui.svg"
    echo "  App source:    $SHARE_DIR/firewall_gui"
    echo "  Checkout:      $src_dir"
    if [[ -x "$HELPER_PATH" && -f "$POLKIT_ACTION_PATH" ]]; then
        echo "  Hardening:     system helper installed ($HELPER_PATH)"
    else
        echo "  Hardening:     system helper not installed — DNS/encryption levels will be unavailable"
    fi
    if require_cmd systemctl && systemctl --user is-enabled --quiet firewall-gui-update.timer 2>/dev/null; then
        echo "  Auto-update:   checks for updates every 30 minutes (systemctl --user status firewall-gui-update.timer)"
    fi
    echo
    echo "Run 'firewall-gui' (make sure ~/.local/bin is on your PATH), or launch 'Firewall' from the app grid."
}

main() {
    check_deps
    local src_dir
    src_dir="$(resolve_src_dir)"
    install_app "$src_dir"
    install_privileged_helper "$src_dir"
    if [[ -z "${FIREWALL_GUI_NO_TIMER:-}" ]]; then
        install_update_timer "$src_dir"
    fi
    print_summary "$src_dir"
}

main "$@"
