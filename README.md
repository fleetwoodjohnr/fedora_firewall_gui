# Firewall

A small GTK4/libadwaita app for viewing and editing your firewalld setup: what's
open right now, what each option actually means, and which firewall zone gets
applied automatically depending on which network you're connected to.

Talks to `firewalld` over the system D-Bus (each privileged change is
authorized by PolicyKit, same as `firewall-cmd`) and to `NetworkManager` via
`nmcli` for per-network zone assignment. No venv — it runs on the system
Python/GTK stack already installed on Fedora Workstation.

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

Either way installs the app to `~/.local` (no sudo): the app itself under
`~/.local/share/firewall-gui`, a launcher at `~/.local/bin/firewall-gui`, and
a `Firewall` entry in the GNOME app grid. Requires `python3-gobject`, `gtk4`,
`libadwaita`, `firewalld`, `NetworkManager`, and `git` — on a minimal/Server
install missing any of these, `install.sh` will say which and print the
`dnf install` command to fix it.

The installer also offers one **optional** `sudo` step, for the system
hardening helper described below. Decline it and everything else still works.
Set `FIREWALL_GUI_NO_HELPER=1` to skip the question, or `FIREWALL_GUI_HELPER=1`
to answer yes without being asked.

## System hardening helper

Most of this app needs no privileges of its own: firewalld and NetworkManager
each authorize their own changes through PolicyKit. But three things on the
Hardening page have no unprivileged API at all — systemd-resolved's global
settings, the system-wide crypto policy, and `sshd` (whose config directory is
mode `0700`). Those go through a small helper:

```
/usr/libexec/firewall-gui-helper                        # root-owned, 0755
/usr/share/polkit-1/actions/org.jrf.FirewallGui.policy  # one polkit action
```

It's installed root-owned in `/usr/libexec` rather than left in `~/.local`
deliberately. `pkexec` runs it as root, and root must never execute a file that
a compromised user account could rewrite first — which is exactly what a helper
living in your home directory would be.

The helper accepts a verb and a level id matched against four fixed strings,
and nothing else: no paths, no addresses, no free text. It only ever creates or
deletes files it owns, so every change undoes by deleting a file and it can't
damage config you wrote yourself. Reading current state needs no privileges, so
opening the Hardening page never prompts for a password.

Install it later, or after an update that changes it:

```
cd ~/.local/share/firewall-gui-src && ./install.sh
```

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
- **Hardening** — two four-position switches, each explaining in plain English
  what a level turns on and what it might break.
  **DNS Hardening** goes from Fedora's plaintext default up to mandatory
  DNS-over-TLS with strict DNSSEC, and can pin a resolver (Quad9, Cloudflare,
  Mullvad, AdGuard) on whichever saved networks you choose — per connection, so
  a VPN can keep resolving inside its own tunnel.
  **Encryption Hardening** moves the system-wide crypto policy, SSH, and your
  plaintext service ports together, from tidying up obsolete protocols at Basic
  through to `FUTURE` at Strict. Password logins are only disabled when a usable
  SSH key is already installed, so it can't lock you out. Alongside it, a switch
  turns the SSH server itself on and off (`systemctl enable --now` /
  `disable --now`, authorized by systemd's own PolicyKit action, so it works
  with or without the helper) — on a laptop that never accepts remote logins,
  switching the server off beats any amount of hardening applied to it.
