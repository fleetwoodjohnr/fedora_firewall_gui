import json
import os

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
from ..widgets.debounce import Debouncer
from ..widgets.confirm import confirm, escape_markup, show_error_toast, show_toast
from ..widgets.level_selector import LevelSelector
from ..widgets.pending import ApplyControls, PendingValue
from ..widgets.page_intro import page_intro

# How each DNS level wants NetworkManager's per-connection dns-over-tls set on a
# connection with a pinned resolver. "" means "leave it at the default", which
# lets the global systemd-resolved setting decide.
DOT_FOR_LEVEL = {"off": "", "basic": "opportunistic", "balanced": "opportunistic", "strict": "yes"}
DOT_READBACK = {"": {"-1", "default", ""}, "opportunistic": {"1", "opportunistic"}, "yes": {"2", "yes"}}


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

    def __init__(self, window, firewalld, netmgr, settings, hardening, systemd):
        super().__init__(title="Hardening", icon_name="channel-secure-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._hardening = hardening
        self._systemd = systemd

        self._status = None
        self._default_zone = None
        self._zone_services = set()
        self._connection_rows = {}
        self._pin_models = {}
        self._provider_syncing = False
        self._sshd_state = None

        self.add(page_intro("Hardening", "Tune DNS, encryption, and remote access with the effect of each choice visible before Apply.", "channel-secure-symbolic"))

        self._build_helper_group()
        self._build_dns_group()
        self._build_resolver_group()
        self._build_encryption_group()

        # Someone can close the same services by hand in the Zone Editor, so the
        # encryption level's firewall half has to re-read rather than assume.
        self._refresh_zone_services_debounced = Debouncer(self._refresh_zone_services)
        for signal in ("zone-updated", "service-added", "service-removed"):
            self._fw.connect(signal, self._refresh_zone_services_debounced)

    def refresh(self):
        self._refresh_status()
        self._refresh_zone_services()
        self._refresh_connections()
        self._refresh_sshd()

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

    def _build_resolver_group(self):
        # Its own visible group rather than tucked inside an expander: which
        # company answers your lookups is a decision in its own right, not a
        # detail of the level above, and it can't be made without reading what
        # each provider actually does.
        self._resolver_group = Adw.PreferencesGroup(
            title="DNS Resolver",
            description="Independent of the level above. That setting protects your lookups in transit; "
            "this one decides which company gets to see them in the first place.",
        )
        self.add(self._resolver_group)

        self._provider_combo = Adw.ComboRow(
            title="Answer my lookups with",
            model=Gtk.StringList.new([p.label for p in DNS_PROVIDERS]),
        )
        self._provider_model = PendingValue(self._settings.dns_provider)
        self._provider_combo.add_suffix(
            ApplyControls(self._provider_model, self._apply_provider)
        )
        self._provider_combo.connect("notify::selected", self._on_provider_selected)
        self._resolver_group.add(self._provider_combo)

        self._provider_detail = Adw.ActionRow()
        self._provider_detail.set_subtitle_lines(0)
        self._resolver_group.add(self._provider_detail)

        self._connections_header = Adw.ActionRow(
            title="Apply to these saved networks",
            subtitle="Pick the networks that should use the resolver above. Leave a VPN switched off "
            "unless you specifically want its lookups leaving the tunnel.",
        )
        self._connections_header.set_subtitle_lines(0)
        self._resolver_group.add(self._connections_header)

        self._provider_model.connect(self._sync_provider_model)
        self._sync_provider_combo()

    def _sync_provider_combo(self):
        self._provider_model.observe(self._settings.dns_provider)

    def _sync_provider_model(self, model):
        provider = get_dns_provider(model.draft)
        index = next((i for i, p in enumerate(DNS_PROVIDERS) if p.id == provider.id), 0)
        self._provider_syncing = True
        self._provider_combo.set_selected(index)
        self._provider_syncing = False
        self._show_provider_detail(provider)

    def _show_provider_detail(self, provider):
        self._provider_detail.set_title(provider.label)
        self._provider_detail.set_subtitle(escape_markup(provider.detail))
        pinnable = provider.id != "automatic" and not self._provider_model.dirty
        self._connections_header.set_sensitive(pinnable)
        for entry in self._connection_rows.values():
            entry["row"].set_sensitive(pinnable)
        self._update_pin_summary()

    def _update_pin_summary(self):
        """Say whether the chosen resolver is actually in use.

        Picking a provider on its own changes nothing -- it has to be switched
        on per connection. Without this the page would let someone select Quad9,
        see it sitting there in the dropdown, and reasonably believe their
        lookups had moved when they hadn't. Saying "selected but not in use" out
        loud is the same rule the rest of this page follows: report what the
        system is doing, not what was asked for.
        """
        if self._provider_model.dirty:
            self._connections_header.set_subtitle(
                "Resolver change pending. Apply it before editing network assignments."
            )
            return
        provider = get_dns_provider(self._settings.dns_provider)
        if provider.id == "automatic":
            self._connections_header.remove_css_class("warning")
            self._connections_header.set_subtitle(
                "Nothing to apply — “Automatic” leaves each network's own resolver in place."
            )
            return

        short = provider.label.split(" — ")[0]
        pinned = [
            entry["conn"]["name"]
            for uuid, entry in self._connection_rows.items()
            if uuid in set(self._settings.get_pinned_uuids())
        ]
        if pinned:
            self._connections_header.remove_css_class("warning")
            self._connections_header.set_subtitle(
                f"{short} is in use on: {', '.join(sorted(pinned))}. Every other network keeps its own "
                "resolver."
            )
        else:
            self._connections_header.add_css_class("warning")
            self._connections_header.set_subtitle(
                f"{short} is selected but not in use anywhere yet — switch on the networks below that "
                "should use it. Until you do, your lookups still go to whichever resolver each network "
                "or VPN hands you."
            )

    def _on_provider_selected(self, combo, _pspec):
        if self._provider_syncing:
            return
        index = combo.get_selected()
        if not 0 <= index < len(DNS_PROVIDERS):
            return
        self._provider_model.stage(DNS_PROVIDERS[index].id)

    def _apply_provider(self, provider_id, done):
        provider = get_dns_provider(provider_id)
        pinned = self._settings.get_pinned_uuids()

        def persist():
            ok, error = self._settings.apply("dns_provider", provider_id)
            if not ok:
                done(False, error)
                return
            if provider_id == "automatic":
                ok, error = self._settings.apply("dns_pinned_uuids", "[]")
                if not ok:
                    done(False, error)
                    return
            done(True)
            self._refresh_connections()
            show_toast(self._window.toast_overlay, f"Resolver {provider.label} applied.")

        if not pinned:
            persist()
            return
        state = {"remaining": len(pinned), "errors": []}

        def one(ok, error):
            if not ok:
                state["errors"].append(str(error or "network update failed"))
            state["remaining"] -= 1
            if not state["remaining"]:
                if state["errors"]:
                    done(False, "; ".join(state["errors"]))
                else:
                    persist()

        for uuid in pinned:
            self._pin_one(uuid, provider, unpin=provider_id == "automatic", callback=one)

    def _refresh_connections(self):
        def on_connections(connections, error):
            for entry in self._connection_rows.values():
                entry["model"].disconnect(entry["listener"])
                entry["controls"].detach()
                self._resolver_group.remove(entry["row"])
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
            self._update_pin_summary()

        self._nm.list_connections(on_connections)

    def _add_connection_row(self, conn, pinned, provider):
        is_vpn = self._nm.is_vpn_like(conn["type"])
        subtitle = escape_markup(f"{conn['type']} • {conn['device'] or 'not connected'}")
        if is_vpn:
            subtitle += " • tunnel — leave off to keep resolving inside the VPN"

        row = Adw.SwitchRow(title=escape_markup(conn["name"]), subtitle=subtitle)
        row.set_subtitle_lines(0)
        row.set_sensitive(provider.id != "automatic" and not self._provider_model.dirty)
        uuid = conn["uuid"]
        model = self._pin_models.setdefault(uuid, PendingValue(pinned))
        model.observe(pinned)
        state = {"syncing": False}

        def sync(value):
            state["syncing"] = True
            row.set_active(bool(value.draft))
            state["syncing"] = False

        def changed(widget, _pspec):
            if not state["syncing"]:
                model.stage(widget.get_active())

        listener = model.connect(sync)
        row.connect("notify::active", changed)
        controls = ApplyControls(model, lambda wanted, done, u=uuid: self._request_pin(u, wanted, done))
        row.add_suffix(controls)
        self._resolver_group.add(row)
        self._connection_rows[uuid] = {"row": row, "conn": conn, "model": model,
                                       "listener": listener, "controls": controls}

    def _request_pin(self, uuid, wanted, done):
        """Apply a staged resolver assignment to one saved network."""
        entry = self._connection_rows.get(uuid)
        if entry is None:
            done(False, "Network profile is no longer available")
            return
        row = entry["row"]
        provider = get_dns_provider(self._settings.dns_provider)
        row.set_sensitive(False)

        def finished(ok, error):
            if not ok:
                row.set_sensitive(provider.id != "automatic" and not self._provider_model.dirty)
                show_error_toast(self._window.toast_overlay, error, "Couldn't change this network's DNS")
                done(False, error)
                return
            def verified(values, read_error):
                row.set_sensitive(provider.id != "automatic" and not self._provider_model.dirty)
                if read_error or values is None:
                    done(False, read_error or "could not verify DNS settings")
                    return
                ipv4, ipv6 = provider_dns_values(provider) if wanted else ("", "")
                def addresses(raw):
                    return {part.strip() for part in raw.split(",") if part.strip()}

                if addresses(values["ipv4"]) != addresses(ipv4) or addresses(values["ipv6"]) != addresses(ipv6):
                    done(False, "saved DNS servers did not match")
                    return
                pinned = set(self._settings.get_pinned_uuids())
                pinned.add(uuid) if wanted else pinned.discard(uuid)
                saved, save_error = self._settings.apply("dns_pinned_uuids", json.dumps(sorted(pinned)))
                done(saved, save_error)
                self._update_pin_summary()

            self._nm.get_connection_dns(uuid, verified)

        self._pin_one(uuid, provider, unpin=not wanted, callback=finished)

    def _pin_one(self, uuid, provider, unpin, callback, level_id=None):
        ipv4, ipv6 = ("", "") if unpin else provider_dns_values(provider)
        level_id = level_id or self._dns_selector.get_active_level().id
        dot = "" if unpin else DOT_FOR_LEVEL.get(level_id, "")

        def written(ok, error):
            if not ok:
                callback(False, error)
                return

            def read(values, read_error):
                if read_error or values is None:
                    callback(False, read_error or "DNS readback unavailable")
                    return
                def addresses(raw):
                    return {part.strip() for part in raw.split(",") if part.strip()}

                if addresses(values["ipv4"]) != addresses(ipv4) or addresses(values["ipv6"]) != addresses(ipv6):
                    callback(False, "saved DNS servers did not match")
                elif values["ignore_auto"] != (not unpin):
                    callback(False, "saved automatic-DNS setting did not match")
                elif str(values["dns_over_tls"]).strip().lower() not in DOT_READBACK[dot]:
                    callback(False, "saved DNS-over-TLS setting did not match")
                else:
                    callback(True, None)

            self._nm.get_connection_dns(uuid, read)

        self._nm.set_connection_dns(uuid, ipv4, ipv6, dot, written)

    def _apply_dns_level(self, level, done):
        """Called by the LevelSelector once the user has confirmed."""

        def on_helper(ok, error):
            if not ok:
                show_error_toast(self._window.toast_overlay, error, "Couldn't change DNS hardening")
                done(False, error)
                return

            def verified(status, read_error):
                actual = (status or {}).get("state", {}).get("dns", {}).get("level", "off")
                if read_error or actual != level.id:
                    done(False, read_error or f"helper still reports {actual}")
                    return
                pinned = self._settings.get_pinned_uuids()
                provider = get_dns_provider(self._settings.dns_provider)
                if not pinned or provider.id == "automatic":
                    finish(True, None)
                    return
                state = {"remaining": len(pinned), "errors": []}

                def one(pin_ok, pin_error):
                    if not pin_ok:
                        state["errors"].append(str(pin_error or "DNS update failed"))
                    state["remaining"] -= 1
                    if not state["remaining"]:
                        finish(not state["errors"], "; ".join(state["errors"]) or None)

                for uuid in pinned:
                    self._pin_one(uuid, provider, unpin=False, callback=one, level_id=level.id)

            self._hardening.get_status(verified)

        def finish(ok, error):
            if ok:
                show_toast(self._window.toast_overlay, f"DNS hardening set to {level.label}.")
            else:
                show_error_toast(self._window.toast_overlay, error, "DNS level only partly applied")
            done(ok, error)
            self._refresh_status()

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

        self._sshd_row = Adw.SwitchRow(
            title="Allow remote login to this laptop over SSH",
            subtitle="Checking…",
        )
        self._sshd_row.set_subtitle_lines(0)
        self._sshd_model = PendingValue()
        self._sshd_syncing = False
        self._sshd_model.connect(self._sync_sshd_row)
        self._sshd_row.connect("notify::active", self._on_sshd_selected)
        self._sshd_row.add_suffix(ApplyControls(self._sshd_model, self._request_sshd))
        group.add(self._sshd_row)

        self._ssh_row = Adw.ActionRow(title="SSH hardening", subtitle="Checking…")
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

    def _sync_sshd_row(self, model):
        self._sshd_syncing = True
        self._sshd_row.set_active(bool(model.draft))
        self._sshd_syncing = False

    def _on_sshd_selected(self, row, _pspec):
        if not self._sshd_syncing:
            self._sshd_model.stage(row.get_active())

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
                self._update_sshd_row()

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
                self._refresh_status()
                self._refresh_zone_services()
                return

            checks = {"remaining": 3, "errors": []}

            def check_done():
                checks["remaining"] -= 1
                if checks["remaining"]:
                    return
                if checks["errors"]:
                    reason = "; ".join(checks["errors"])
                    show_error_toast(self._window.toast_overlay, reason, "Could not verify hardening")
                    done(False, reason)
                else:
                    remembered = sorted((already_removed | set(to_remove)) - set(to_restore))
                    saved, save_error = self._settings.apply("encryption_removed_services", json.dumps(remembered))
                    if not saved:
                        done(False, save_error)
                    else:
                        show_toast(
                            self._window.toast_overlay,
                            f"Encryption hardening set to {level.label}."
                            + (" Reboot when convenient." if level.crypto_policy else ""),
                        )
                        done(True, None)
                self._refresh_status()
                self._refresh_zone_services()

            def check_helper(status, error):
                actual = (status or {}).get("state", {}).get("crypto", {}).get("level", "off")
                if error or actual != level.id:
                    checks["errors"].append(str(error or f"helper still reports {actual}"))
                check_done()

            def check_zone(settings, error):
                services = set((settings or {}).get("services", []))
                if error or settings is None:
                    checks["errors"].append(str(error or "zone settings unavailable"))
                elif any(s in services for s in to_remove) or any(s not in services for s in to_restore):
                    checks["errors"].append("zone services did not match the requested level")
                check_done()

            self._hardening.get_status(check_helper)
            self._fw.get_zone_settings(zone, check_zone)
            self._fw.get_permanent_zone_settings(zone, check_zone)

        def on_step(ok, error, _partial=False):
            state["pending"] -= 1
            if not ok or _partial:
                state["errors"].append(str(error or "runtime and saved rules differ"))
            if state["pending"] == 0:
                finish()

        self._hardening.apply_crypto(level.id, on_step)
        for service in to_remove:
            self._fw.remove_service(zone, service, on_step)
        for service in to_restore:
            self._fw.add_service(zone, service, on_step)

    # -- SSH server on/off ------------------------------------------------------------
    #
    # Separate from the encryption levels on purpose. The levels harden a server
    # you intend to run; this switches off one you don't. On a laptop that has
    # never accepted an SSH login, turning the server off is worth more than any
    # amount of hardening applied to it -- there is nothing left to attack.

    SSHD_UNIT = "sshd.service"
    SSHD_ALSO = ("sshd.socket",)

    @staticmethod
    def _user_has_ssh_key():
        path = os.path.expanduser("~/.ssh/authorized_keys")
        try:
            return os.path.getsize(path) > 0
        except OSError:
            return False

    def _refresh_sshd(self):
        def on_connected(error):
            if error is not None:
                self._sshd_row.set_sensitive(False)
                self._sshd_row.set_subtitle(f"Couldn't reach systemd to check: {error}")
                return

            def on_state(state, state_error):
                if state_error is not None or state is None:
                    self._sshd_row.set_sensitive(False)
                    self._sshd_row.set_subtitle(f"Couldn't read the SSH server's state: {state_error}")
                    return
                self._sshd_state = state
                self._sshd_model.observe(state["enabled"] or state["active"])
                self._update_sshd_row()

            self._systemd.get_service_state(self.SSHD_UNIT, on_state)

        self._systemd.ensure_connected(on_connected)

    def _update_sshd_row(self):
        state = self._sshd_state
        if state is None:
            return
        if not state["exists"]:
            self._sshd_row.set_sensitive(False)
            self._sshd_row.set_subtitle(
                "OpenSSH server isn't installed, so nothing is listening for remote logins."
            )
            return

        self._sshd_row.set_sensitive(True)
        if not (state["enabled"] or state["active"]):
            self._sshd_row.set_subtitle(
                "Off. Nothing can log in to this laptop over SSH. Connecting out to other machines "
                "with ssh, scp or git is unaffected — that's a separate program."
            )
            self._sshd_row.remove_css_class("warning")
            return

        # Reachability is the part people get wrong, so spell it out rather than
        # leaving them to cross-reference the Zone Editor.
        reachable = "ssh" in self._zone_services
        where = (
            f"reachable from the network — your default zone “{self._default_zone}” allows it"
            if reachable
            else f"but your firewall's default zone “{self._default_zone}” is blocking incoming "
                 "connections, so it isn't reachable from the network right now"
        )
        running = "Running" if state["active"] else "Enabled at boot but not running"
        password_note = (
            " No SSH key is installed for you, so logins would use a password."
            if not self._user_has_ssh_key()
            else ""
        )
        self._sshd_row.set_subtitle(f"{running}, {where}.{password_note}")
        if reachable and not self._user_has_ssh_key():
            self._sshd_row.add_css_class("warning")
        else:
            self._sshd_row.remove_css_class("warning")

    def _request_sshd(self, wanted, done):
        """Apply a staged SSH server setting and verify systemd state."""
        row = self._sshd_row

        def apply():
            row.set_sensitive(False)

            def finished(ok, error):
                row.set_sensitive(True)
                if not ok:
                    show_error_toast(self._window.toast_overlay, error, "Couldn't change the SSH server")
                    done(False, error)
                    self._refresh_sshd()
                    return

                def verified(state, read_error):
                    correct = state and (state["enabled"] and state["active"] if wanted else
                                         not state["enabled"] and not state["active"])
                    if read_error or not correct:
                        done(False, read_error or "systemd state did not match")
                    elif wanted:
                        done(True)
                        show_toast(self._window.toast_overlay, "SSH server setting applied.")
                    else:
                        def socket_checked(socket_state, socket_error):
                            if socket_error or socket_state is None or socket_state["enabled"] or socket_state["active"]:
                                done(False, socket_error or "SSH socket is still enabled or active")
                            else:
                                done(True)
                                show_toast(self._window.toast_overlay, "SSH server setting applied.")
                            self._refresh_sshd()

                        self._systemd.get_service_state(self.SSHD_ALSO[0], socket_checked)
                        return
                    self._refresh_sshd()

                self._systemd.get_service_state(self.SSHD_UNIT, verified)

            self._systemd.set_service_enabled(
                self.SSHD_UNIT, wanted, also_disable=() if wanted else self.SSHD_ALSO, callback=finished
            )

        if wanted:
            body = (
                "This starts the OpenSSH server and sets it to start at every boot, so other machines "
                "can log in to this laptop.\n\n"
                "Your firewall still decides who can actually reach it — add the “ssh” service to a zone "
                "in the Zone Editor if you want it reachable from the network."
            )
            if not self._user_has_ssh_key():
                body += (
                    "\n\nWorth knowing: you have no SSH key installed, so logins would fall back to your "
                    "account password. Add a key first (ssh-copy-id from the machine you'll connect from) "
                    "and the encryption levels above can then switch password logins off entirely."
                )
            confirm(
                self._window, "Turn on the SSH server?", body, "Turn It On", apply,
                destructive=True, on_cancel=lambda: done(False, "Still pending"),
            )
        else:
            confirm(
                self._window,
                "Turn off the SSH server?",
                "This stops the OpenSSH server and prevents it starting at boot, so nothing will be able "
                "to log in to this laptop over SSH.\n\n"
                "It does not affect connecting out — ssh, scp, sftp and git carry on working normally, "
                "because those are the client, a separate program. Nothing is uninstalled, and you can "
                "switch it back on here whenever you want.",
                "Turn It Off",
                apply,
                destructive=False,
                on_cancel=lambda: done(False, "Still pending"),
            )

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
