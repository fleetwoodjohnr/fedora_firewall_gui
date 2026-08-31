import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk

from ..data.dns_levels import (
    DNS_LEVELS,
    DNS_PROVIDERS,
    get_dns_provider,
    provider_dns_values,
)
from ..data.encryption_levels import (
    ENCRYPTION_LEVELS,
    FIPS_NOTE,
    INBOUND_ONLY_NOTE,
    REBOOT_NOTE,
    get_encryption_level,
)
from ..widgets.confirm import escape_markup, show_error_toast, show_toast
from ..widgets.level_selector import LevelSelector

# How each DNS level wants NetworkManager's per-connection dns-over-tls set on a
# connection with a pinned resolver. "" means "leave it at the default", which
# lets the global systemd-resolved setting decide.
DOT_FOR_LEVEL = {"off": "", "basic": "opportunistic", "balanced": "opportunistic", "strict": "yes"}


def _card(child):
    """Wrap a plain widget so it sits inside a PreferencesGroup's boxed list
    like any other row."""
    row = Adw.PreferencesRow(activatable=False, selectable=False)
    child.set_margin_top(14)
    child.set_margin_bottom(14)
    child.set_margin_start(14)
    child.set_margin_end(14)
    row.set_child(child)
    return row


class HardeningPage(Adw.PreferencesPage):
    """Two system-level hardening controls that reach past the firewall itself.

    Both are deliberately shaped as one switch with four notches rather than a
    screen of checkboxes: the hard part of hardening a laptop isn't flipping the
    settings, it's knowing which ones are safe to flip and what breaks when you
    go too far. So each notch carries the full consequence text, and the app
    keeps the definition of a level in one place rather than scattering it.

    The two halves reach the system by different routes, for reasons that are
    not arbitrary:

      * Resolver pinning and closing plaintext services go through
        NetworkManager and firewalld, which authorize each change through
        PolicyKit themselves. No root, and this is how the rest of the app works.
      * The global systemd-resolved settings, the crypto policy and sshd have no
        unprivileged API at all, so those go through a small helper run under
        pkexec. If it isn't installed the page still works -- it just says so and
        limits itself to the half that doesn't need it.
    """

    def __init__(self, window, firewalld, netmgr, settings, hardening):
        super().__init__(title="Hardening", icon_name="channel-secure-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._hardening = hardening

        self._status = None
        self._default_zone = None
        self._zone_services = set()
        self._connection_rows = {}
        self._provider_syncing = False
        self._connection_syncing = False

        self._build_helper_group()
        self._build_dns_group()
        self._build_encryption_group()

        # Someone can close the same services by hand in the Zone Editor, so the
        # encryption level's firewall half has to re-read rather than assume.
        for signal in ("zone-updated", "service-added", "service-removed"):
            self._fw.connect(signal, lambda *_a: self._refresh_zone_services())

    def refresh(self):
        self._refresh_status()
        self._refresh_zone_services()
        self._refresh_connections()

    # -- Helper availability -------------------------------------------------------

    def _build_helper_group(self):
        self._helper_group = Adw.PreferencesGroup()
        self._helper_row = Adw.ActionRow(title="System hardening helper not installed")
        self._helper_row.set_subtitle_lines(0)
        self._helper_row.add_css_class("warning")

        copy_button = Gtk.Button(label="Copy Command", valign=Gtk.Align.CENTER)
        copy_button.connect("clicked", self._on_copy_install_command)
        self._helper_row.add_suffix(copy_button)

        self._helper_group.add(self._helper_row)
        self.add(self._helper_group)
        self._helper_group.set_visible(False)

    def _on_copy_install_command(self, _button):
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(self._hardening.install_command())
        show_toast(self._window.toast_overlay, "Install command copied to the clipboard.")

    def _show_helper_problem(self, title, detail):
        self._helper_row.set_title(title)
        self._helper_row.set_subtitle(escape_markup(detail))
        self._helper_group.set_visible(True)
        self._dns_selector.set_sensitive(False)
        self._encryption_selector.set_sensitive(False)
        # Without the helper these can't be read at all, so say that rather than
        # leaving "Checking…" on screen forever.
        unavailable = "Needs the system hardening helper — see above."
        self._crypto_row.set_subtitle(unavailable)
        self._ssh_row.set_subtitle(unavailable)

    def _hide_helper_problem(self):
        self._helper_group.set_visible(False)
        self._dns_selector.set_sensitive(True)
        self._encryption_selector.set_sensitive(True)

    # -- DNS Hardening ---------------------------------------------------------------

    def _build_dns_group(self):
        group = Adw.PreferencesGroup(
            title="DNS Hardening",
            description="Every website you visit starts with a DNS lookup. By default those go out in "
            "plain text, so anyone on the same network — and your internet provider — can read the list "
            "of everywhere you go, and can forge answers to send you somewhere else.",
        )
        self.add(group)

        self._dns_selector = LevelSelector(
            DNS_LEVELS, self._apply_dns_level, self._window, "Set DNS hardening to"
        )
        group.add(_card(self._dns_selector))

        self._provider_expander = Adw.ExpanderRow(
            title="Choose who answers your lookups",
            subtitle="Optional. Independent of the level above — that setting protects your lookups, "
            "this one decides which company sees them.",
        )
        self._provider_expander.set_subtitle_lines(0)
        group.add(self._provider_expander)

        self._provider_combo = Adw.ComboRow(
            title="Resolver",
            model=Gtk.StringList.new([p.label for p in DNS_PROVIDERS]),
        )
        self._provider_combo.connect("notify::selected", self._on_provider_selected)
        self._provider_expander.add_row(self._provider_combo)

        self._provider_detail = Adw.ActionRow()
        self._provider_detail.set_subtitle_lines(0)
        self._provider_expander.add_row(self._provider_detail)

        self._connections_header = Adw.ActionRow(
            title="Apply to these saved networks",
            subtitle="Pick the networks that should use the resolver above. Leave a VPN switched off "
            "unless you specifically want its lookups leaving the tunnel.",
        )
        self._connections_header.set_subtitle_lines(0)
        self._provider_expander.add_row(self._connections_header)

        self._sync_provider_combo()

    def _sync_provider_combo(self):
        provider = get_dns_provider(self._settings.dns_provider)
        index = next((i for i, p in enumerate(DNS_PROVIDERS) if p.id == provider.id), 0)
        self._provider_syncing = True
        self._provider_combo.set_selected(index)
        self._provider_syncing = False
        self._show_provider_detail(provider)

    def _show_provider_detail(self, provider):
        self._provider_detail.set_title(provider.label)
        self._provider_detail.set_subtitle(escape_markup(provider.detail))
        pinnable = provider.id != "automatic"
        self._connections_header.set_sensitive(pinnable)
        if not pinnable:
            self._connections_header.set_subtitle(
                "Nothing to apply — “Automatic” leaves each network's own resolver in place."
            )
        else:
            self._connections_header.set_subtitle(
                "Pick the networks that should use the resolver above. Leave a VPN switched off "
                "unless you specifically want its lookups leaving the tunnel."
            )
        for entry in self._connection_rows.values():
            entry["row"].set_sensitive(pinnable)

    def _on_provider_selected(self, combo, _pspec):
        if self._provider_syncing:
            return
        provider = DNS_PROVIDERS[combo.get_selected()]
        self._settings.dns_provider = provider.id
        self._show_provider_detail(provider)

        # Re-point every already-pinned network at the new resolver, so the
        # picker never leaves connections quietly pinned to the previous one.
        pinned = self._settings.get_pinned_uuids()
        if not pinned:
            return
        self._pin_connections(pinned, provider, unpin=provider.id == "automatic")

    def _refresh_connections(self):
        def on_connections(connections, error):
            for entry in self._connection_rows.values():
                self._provider_expander.remove(entry["row"])
            self._connection_rows.clear()
            if error is not None:
                show_error_toast(self._window.toast_overlay, error, "Couldn't list saved networks")
                return

            pinned = set(self._settings.get_pinned_uuids())
            provider = get_dns_provider(self._settings.dns_provider)
            for conn in connections or []:
                if conn["type"] == "loopback":
                    continue
                self._add_connection_row(conn, conn["uuid"] in pinned, provider)

        self._nm.list_connections(on_connections)

    def _add_connection_row(self, conn, pinned, provider):
        is_vpn = self._nm.is_vpn_like(conn["type"])
        subtitle = escape_markup(f"{conn['type']} • {conn['device'] or 'not connected'}")
        if is_vpn:
            subtitle += " • tunnel — leave off to keep resolving inside the VPN"

        row = Adw.SwitchRow(title=escape_markup(conn["name"]), subtitle=subtitle)
        row.set_subtitle_lines(0)
        row.set_sensitive(provider.id != "automatic")
        self._connection_syncing = True
        row.set_active(pinned)
        self._connection_syncing = False
        row.connect("notify::active", self._on_connection_toggled, conn["uuid"])
        self._provider_expander.add_row(row)
        self._connection_rows[conn["uuid"]] = {"row": row, "conn": conn}

    def _on_connection_toggled(self, row, _pspec, uuid):
        if self._connection_syncing:
            return
        provider = get_dns_provider(self._settings.dns_provider)
        wanted = row.get_active()

        # Same non-optimistic rule as everywhere else: put it back, then let the
        # result move it.
        self._connection_syncing = True
        row.set_active(not wanted)
        self._connection_syncing = False
        row.set_sensitive(False)

        def done(ok, error):
            row.set_sensitive(provider.id != "automatic")
            if not ok:
                show_error_toast(self._window.toast_overlay, error, "Couldn't change this network's DNS")
                return
            self._connection_syncing = True
            row.set_active(wanted)
            self._connection_syncing = False
            pinned = set(self._settings.get_pinned_uuids())
            pinned.add(uuid) if wanted else pinned.discard(uuid)
            self._settings.set_pinned_uuids(pinned)

        self._pin_one(uuid, provider, unpin=not wanted, callback=done)

    def _pin_one(self, uuid, provider, unpin, callback):
        if unpin:
            self._nm.set_connection_dns(uuid, "", "", "", callback)
            return
        ipv4, ipv6 = provider_dns_values(provider)
        level_id = self._dns_selector.get_active_level().id
        self._nm.set_connection_dns(uuid, ipv4, ipv6, DOT_FOR_LEVEL.get(level_id, ""), callback)

    def _pin_connections(self, uuids, provider, unpin=False):
        """Fan out across several connections and report once, using the same
        countdown accumulator as the Dashboard's hardening rules."""
        uuids = list(uuids)
        if not uuids:
            return
        state = {"pending": len(uuids), "errors": []}

        def on_one(ok, error):
            state["pending"] -= 1
            if not ok and error is not None:
                state["errors"].append(str(error))
            if state["pending"] == 0:
                if state["errors"]:
                    show_error_toast(
                        self._window.toast_overlay, "; ".join(state["errors"]), "Some networks failed"
                    )
                else:
                    what = "Resolver unpinned." if unpin else f"Now using {provider.label.split(' — ')[0]}."
                    show_toast(self._window.toast_overlay, what)
                if unpin:
                    self._settings.set_pinned_uuids([])
                self._refresh_connections()

        for uuid in uuids:
            self._pin_one(uuid, provider, unpin, on_one)

    def _apply_dns_level(self, level, done):
        """Called by the LevelSelector once the user has confirmed."""

        def on_helper(ok, error):
            if not ok:
                show_error_toast(self._window.toast_overlay, error, "Couldn't change DNS hardening")
                done(False, error)
                return
            show_toast(self._window.toast_overlay, f"DNS hardening set to {level.label}.")
            done(True, None)
            self._refresh_status()
            # The per-connection DNS-over-TLS setting follows the level, so any
            # pinned network needs rewriting to match.
            pinned = self._settings.get_pinned_uuids()
            provider = get_dns_provider(self._settings.dns_provider)
            if pinned and provider.id != "automatic":
                for uuid in pinned:
                    self._pin_one(uuid, provider, unpin=False, callback=lambda *_a: None)

        self._hardening.apply_dns(level.id, on_helper)

    # -- Encryption Hardening -----------------------------------------------------------

    def _build_encryption_group(self):
        group = Adw.PreferencesGroup(
            title="Encryption Hardening",
            description="One setting for three layers: the system-wide crypto policy that every program "
            "on this laptop inherits, the SSH server's configuration, and which plaintext services your "
            "firewall will accept connections on.",
        )
        self.add(group)

        self._encryption_selector = LevelSelector(
            ENCRYPTION_LEVELS, self._apply_encryption_level, self._window, "Set encryption hardening to"
        )
        group.add(_card(self._encryption_selector))

        self._crypto_row = Adw.ActionRow(title="System crypto policy", subtitle="Checking…")
        self._crypto_row.set_subtitle_lines(0)
        group.add(self._crypto_row)

        self._ssh_row = Adw.ActionRow(title="SSH server", subtitle="Checking…")
        self._ssh_row.set_subtitle_lines(0)
        group.add(self._ssh_row)

        self._services_row = Adw.ActionRow(title="Plaintext services", subtitle="Checking…")
        self._services_row.set_subtitle_lines(0)
        group.add(self._services_row)

        notes = Adw.PreferencesGroup()
        for text in (INBOUND_ONLY_NOTE, REBOOT_NOTE, FIPS_NOTE):
            row = Adw.ActionRow(subtitle=escape_markup(text))
            row.set_subtitle_lines(0)
            notes.add(row)
        self.add(notes)

    def _refresh_zone_services(self):
        def on_default_zone(zone, error):
            if error is not None or zone is None:
                self._services_row.set_subtitle("Couldn't read your firewall's default zone.")
                return
            self._default_zone = zone

            def on_settings(zone_settings, error2):
                if error2 is not None or zone_settings is None:
                    self._services_row.set_subtitle("Couldn't read the default zone's services.")
                    return
                self._zone_services = set(zone_settings.get("services", []))
                self._update_services_row()

            self._fw.get_zone_settings(zone, on_settings)

        self._fw.get_default_zone(on_default_zone)

    def _update_services_row(self):
        level = self._encryption_selector.get_active_level()
        still_open = [s for s in level.firewalld_services if s in self._zone_services]
        removed = self._settings.get_removed_services()
        if not level.firewalld_services:
            self._services_row.set_subtitle(
                f"Nothing closed by this page. Default zone: {self._default_zone or 'unknown'}."
            )
        elif still_open:
            self._services_row.set_subtitle(
                f"Still open in “{self._default_zone}”: {', '.join(still_open)}. Re-apply this level to "
                "close them."
            )
        else:
            closed = ", ".join(removed) if removed else "none were open to begin with"
            self._services_row.set_subtitle(f"Closed in “{self._default_zone}”: {closed}.")

    def _apply_encryption_level(self, level, done):
        zone = self._default_zone
        if zone is None:
            # Status can be applied before the first zone read has come back;
            # fetch it and come round again rather than guessing at "public".
            def on_zone(fetched, error):
                if error is not None or not fetched:
                    done(False, error or "couldn't read your firewall's default zone")
                    return
                self._default_zone = fetched
                self._apply_encryption_level(level, done)

            self._fw.get_default_zone(on_zone)
            return

        target = set(level.firewalld_services)
        already_removed = set(self._settings.get_removed_services())
        # Only close what is actually open, and only reopen what this page closed.
        to_remove = [s for s in target if s in self._zone_services]
        to_restore = [s for s in already_removed if s not in target]

        state = {"pending": 1 + len(to_remove) + len(to_restore), "errors": []}

        def finish():
            if state["errors"]:
                show_error_toast(self._window.toast_overlay, "; ".join(state["errors"]), "Some steps failed")
                done(False, "; ".join(state["errors"]))
            else:
                self._settings.set_removed_services((already_removed | set(to_remove)) - set(to_restore))
                show_toast(
                    self._window.toast_overlay,
                    f"Encryption hardening set to {level.label}."
                    + (" Reboot when convenient." if level.crypto_policy else ""),
                )
                done(True, None)
            self._refresh_status()
            self._refresh_zone_services()

        def on_step(ok, error, _partial=False):
            state["pending"] -= 1
            if not ok and error is not None:
                state["errors"].append(str(error))
            if state["pending"] == 0:
                finish()

        self._hardening.apply_crypto(level.id, on_step)
        for service in to_remove:
            self._fw.remove_service(zone, service, on_step)
        for service in to_restore:
            self._fw.add_service(zone, service, on_step)

    # -- Status ---------------------------------------------------------------------------

    def _refresh_status(self):
        if not self._hardening.is_installed():
            self._show_helper_problem(
                "System hardening helper not installed",
                "The DNS and encryption levels below need a small helper installed with root "
                "privileges, which the normal install deliberately doesn't do without asking. "
                "Everything else on this page — picking a resolver for your saved networks — works "
                "without it.\n\nInstall it by re-running:\n  "
                + self._hardening.install_command(),
            )
            return

        def on_status(status, error):
            if error is not None:
                self._show_helper_problem("Couldn't read the current hardening state", str(error))
                return
            self._hide_helper_problem()
            self._status = status
            recorded = status.get("state", {})
            self._dns_selector.set_active_level(recorded.get("dns", {}).get("level", "off"))
            self._encryption_selector.set_active_level(recorded.get("crypto", {}).get("level", "off"))
            self._update_crypto_row(status, recorded)
            self._update_ssh_row(status, recorded)
            self._update_services_row()

        self._hardening.get_status(on_status)

    def _update_crypto_row(self, status, recorded):
        observed = status.get("crypto_policy") or "unknown"
        level = get_encryption_level(recorded.get("crypto", {}).get("level", "off"))
        expected = level.crypto_policy or recorded.get("crypto", {}).get("previous_policy") or "DEFAULT"
        if observed == expected:
            self._crypto_row.set_subtitle(f"Currently {observed}. {REBOOT_NOTE}")
        else:
            # Report what's actually there rather than what we meant to set.
            self._crypto_row.set_subtitle(
                f"Currently {observed}, but this page last set {expected}. Something changed it outside "
                "this app — re-apply a level to take control of it again."
            )

    def _update_ssh_row(self, status, recorded):
        crypto = recorded.get("crypto", {})
        if not status.get("sshd_available"):
            self._ssh_row.set_subtitle("OpenSSH server isn't installed, so there's nothing to harden here.")
            return
        running = "running" if status.get("sshd_active") else "installed but not running"
        if not crypto.get("ssh_applied"):
            self._ssh_row.set_subtitle(f"SSH server is {running}. No hardening applied by this page yet.")
            return
        reason = crypto.get("ssh_skipped_reason")
        if reason:
            self._ssh_row.set_subtitle(f"SSH server is {running}. {reason}")
            self._ssh_row.add_css_class("warning")
        else:
            self._ssh_row.remove_css_class("warning")
            self._ssh_row.set_subtitle(
                f"SSH server is {running}. Hardened, and password logins are disabled — you need your key."
            )
