# Firewall

A small GTK4/libadwaita app for viewing and editing your firewalld setup: what's
open right now, what each option actually means, and which firewall zone gets
applied automatically depending on which network you're connected to.

Talks to `firewalld` over the system D-Bus (each privileged change is
authorized by PolicyKit, same as `firewall-cmd`) and to `NetworkManager` via
`nmcli` for per-network zone assignment. No root, no venv — it runs on the
system Python/GTK stack already installed on Fedora Workstation.

## Install

**Quick install** (fresh machine, nothing cloned yet):

```
curl -fsSL https://raw.githubusercontent.com/fleetwoodjohnr/fedora_firewall_gui/main/install.sh | bash
```

This clones the repo to `~/.local/share/firewall-gui-src`, installs the app,
and sets up the auto-update timer below. Set `FIREWALL_GUI_NO_TIMER=1` before
running it to skip the auto-update timer.

**From a checkout** (development):

```
git clone https://github.com/fleetwoodjohnr/fedora_firewall_gui.git
cd fedora_firewall_gui
make install
```

Either way installs to `~/.local` (no sudo): the app itself under
`~/.local/share/firewall-gui`, a launcher at `~/.local/bin/firewall-gui`, and
a `Firewall` entry in the GNOME app grid. Requires `python3-gobject`, `gtk4`,
`libadwaita`, `firewalld`, `NetworkManager`, and `git` — on a minimal/Server
install missing any of these, `install.sh` will say which and print the
`dnf install` command to fix it.

## Run

```
firewall-gui
```

or launch **Firewall** from the app grid.

## Auto-update

A `systemd --user` timer checks the repo for new commits on `main` every 30
minutes (plus once ~5 minutes after login) and, if found, pulls and
reinstalls automatically. It never touches a checkout with uncommitted or
diverged local changes.

```
systemctl --user status firewall-gui-update.timer     # timer status
systemctl --user list-timers firewall-gui-update.timer # next scheduled run
journalctl --user -u firewall-gui-update.service       # update logs
make update                                            # check for updates now
systemctl --user disable --now firewall-gui-update.timer  # turn it off
```

## Uninstall

```
make uninstall
```

Removes the installed app, launcher, desktop entry, icon, and the
auto-update timer. It leaves a curl-bootstrapped checkout at
`~/.local/share/firewall-gui-src` in place (it may be a dev checkout you
want to keep); use `make purge` instead to also remove that.

## Pages

- **Dashboard** — what's connected right now and its firewall zone, a
  temporary per-session zone override, a Panic Mode switch (blocks all
  traffic), and editable hardening suggestions for your default zone.
- **Zone Editor** — pick any firewalld zone and toggle its services/ports,
  each with a plain-English explanation and risk note.
- **Network Profiles** — assign a firewall zone to each saved WiFi/wired/VPN
  connection, applied automatically whenever that network connects.
