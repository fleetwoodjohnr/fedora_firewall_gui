import datetime as dt
import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, GLib

from ..backend.activity import ActivityClient
from ..backend.hardening import HELPER_PATH
from ..data.hardening_rules import get_applicable_rules
from ..data.zones_catalog import filter_zones, get_zone_info
from ..widgets.debounce import Debouncer
from ..widgets.pending import ApplyControls, PendingValue
from ..widgets.page_intro import page_intro
from ..widgets.confirm import confirm, escape_markup, show_error_toast, show_toast


class DashboardPage(Adw.PreferencesPage):
    def __init__(self, window, firewalld, netmgr, settings, zone_assignments):
        super().__init__(title="Dashboard", icon_name="security-high-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._assignments = zone_assignments
        self._connection_rows = {}
        self._rows_by_iface = {}
        self._hardening_zone = None
        self._hardening_rules = []
        self._nm_poll_in_flight = False
        self._activity_reader = ActivityClient()
        self._activity_in_flight = False
        self._activity_requires_helper = False
        self._log_mode = None

        self.add(page_intro("Your protection at a glance", "Live firewall coverage, logged denials, and the networks using each zone.", "security-high-symbolic"))
        self._build_overview_group()
        self._build_activity_group()
        self._build_active_connections_group()
        self._build_layers_group()
        self._build_panic_group()
        self._build_hardening_group()

        self._fw.connect("interface-zone-changed", self._on_interface_zone_changed)
        self._refresh_hardening_debounced = Debouncer(self._refresh_hardening)
        for _signal in ("zone-updated", "service-added", "service-removed", "port-added", "port-removed"):
            self._fw.connect(_signal, self._refresh_hardening_debounced)
        self._fw.connect("panic-mode-changed", self._on_panic_mode_changed)
        self._settings.connect("notify::show-all-zones", self._on_show_all_zones_changed)
        self._assignments.connect("applied", self._on_assignment_applied)

        GLib.timeout_add_seconds(5, self._poll_nm)
        GLib.timeout_add_seconds(60, self._poll_activity)

    def refresh(self):
        self._refresh_active_connections()
        self._refresh_overview()
        self._refresh_logging_mode()
        self._refresh_layers()
        self._refresh_hardening()
        self._fw.query_panic_mode(self._on_initial_panic_state)

    def _poll_nm(self):
        # Skip this tick if the previous nmcli is still running. Without the
        # guard a slow nmcli (which a VPN can easily cause) means overlapping
        # spawns pile up every five seconds for as long as the app is open.
        if not self._nm_poll_in_flight:
            self._refresh_active_connections()
        return True

    def _on_assignment_applied(self, *_args):
        self._refresh_active_connections()
        self._refresh_overview()

    def _poll_activity(self):
        if self._log_mode and self._log_mode != "off" and not self._activity_requires_helper:
            self._read_activity()
        return True

    def _build_activity_group(self):
        group = Adw.PreferencesGroup(
            title="Logged denials",
            description="Packets firewalld logged as denied in the last 24 hours. Counts are not unique attacks and can be limited by journal retention.",
        )
        self.add(group)
        self._activity_total = Adw.ActionRow(title="Checking activity logging…")
        self._activity_total.set_subtitle_lines(0)
        group.add(self._activity_total)

        chart = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=3)
        chart.set_size_request(-1, 88)
        chart.add_css_class("activity-chart")
        chart.set_tooltip_text("Hourly logged denials, oldest on the left and newest on the right")
        self._activity_chart = chart
        group.add(chart)
        axis = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        axis.add_css_class("dim-label")
        axis.append(Gtk.Label(label="24 hours ago", xalign=0, hexpand=True))
        axis.append(Gtk.Label(label="Now", xalign=1))
        group.add(axis)
        self._activity_ports = Adw.ActionRow(title="Top destination ports", subtitle="No activity loaded")
        group.add(self._activity_ports)

        self._monitor_row = Adw.SwitchRow(
            title="Log denied unicast packets",
            subtitle="Optional. Applies to all firewalld zones and reloads firewall rules when changed.",
        )
        self._monitor_syncing = False
        self._monitor_model = PendingValue()
        self._monitor_model.connect(self._sync_monitor_row)
        self._monitor_row.connect("notify::active", self._on_monitor_selected)
        self._monitor_row.add_suffix(ApplyControls(self._monitor_model, self._apply_monitoring))
        group.add(self._monitor_row)

        access_row = Adw.ActionRow(
            title="Activity access",
            subtitle="Refresh the log summary. Administrator access is offered only if direct journal access is restricted.",
        )
        self._activity_refresh = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        self._activity_refresh.connect("clicked", lambda *_: self._read_activity(self._activity_requires_helper))
        access_row.add_suffix(self._activity_refresh)
        self._activity_access = access_row
        group.add(access_row)

    def _sync_monitor_row(self, model):
        self._monitor_syncing = True
        self._monitor_row.set_active(bool(model.draft))
        self._monitor_syncing = False

    def _on_monitor_selected(self, row, _pspec):
        if not self._monitor_syncing:
            self._monitor_model.stage(row.get_active())

    def _refresh_logging_mode(self):
        def received(mode, error):
            if error:
                self._activity_total.set_title("Activity logging unavailable")
                self._activity_total.set_subtitle(str(error))
                return
            self._log_mode = mode
            self._monitor_model.observe(mode != "off")
            external = mode != "off" and (not self._settings.monitoring_owned or mode != "unicast")
            self._monitor_row.set_sensitive(not external)
            if external:
                self._monitor_row.set_subtitle(f"Logging is already set to {mode} outside this app. Counts follow that mode.")
            else:
                self._monitor_row.set_subtitle("Optional. Applies to all zones and reloads firewall rules when changed.")
            if mode == "off":
                self._activity_total.set_title("Activity logging is off")
                self._activity_total.set_subtitle("Enable it below and Apply to start collecting denied-packet events.")
                self._activity_ports.set_subtitle("No activity being collected")
                self._render_activity_chart([0] * 24)
            else:
                if not self._activity_requires_helper:
                    self._read_activity()

        self._fw.get_log_denied(received)

    def _apply_monitoring(self, wanted, done):
        if not wanted and (not self._settings.monitoring_owned or self._log_mode != "unicast"):
            done(False, "Logging changed outside this app; it was left unchanged")
            return
        mode = "unicast" if wanted else "off"

        def written(ok, error):
            if not ok:
                done(False, error)
                return

            def verified(actual, read_error):
                if read_error or actual != mode:
                    done(False, read_error or f"firewalld still reports {actual}")
                    return
                self._log_mode = actual
                saved, save_error = self._settings.apply("monitoring_owned", wanted)
                if not saved:
                    done(False, f"firewalld changed, but monitoring ownership could not be saved: {save_error}")
                    return
                done(True)
                show_toast(self._window.toast_overlay, "Denied-packet logging enabled." if wanted else "Denied-packet logging disabled.")
                self._refresh_logging_mode()

            self._fw.get_log_denied(verified)

        self._fw.set_log_denied(mode, written)

    def _read_activity(self, privileged=False):
        if self._activity_in_flight or not self._log_mode or self._log_mode == "off":
            return
        self._activity_in_flight = True
        self._activity_refresh.set_sensitive(False)
        self._activity_total.set_title("Reading logged denials…")

        def received(report, error):
            self._activity_in_flight = False
            self._activity_refresh.set_sensitive(True)
            if error:
                self._activity_total.set_title("Denied activity unavailable")
                self._activity_total.set_subtitle(str(error))
                permission_error = any(word in str(error).lower() for word in ("permission", "access", "not authorized"))
                if not privileged and permission_error:
                    if os.path.exists(HELPER_PATH):
                        self._activity_requires_helper = True
                        self._activity_access.set_subtitle("Direct journal access is restricted. Refresh with administrator access.")
                        self._activity_refresh.set_label("Load with admin access")
                    else:
                        self._activity_access.set_subtitle(
                            "Journal access is restricted. Install the optional system helper to view aggregate activity."
                        )
                return
            self._activity_requires_helper = bool(privileged)
            self._activity_refresh.set_label("Load with admin access" if privileged else "Refresh")
            total = report["total"]
            qualifier = "At least " if report.get("limited") else ""
            self._activity_total.set_title(f"{qualifier}{total:,} denied packets logged")
            try:
                refreshed = dt.datetime.fromisoformat(report["updated_at"]).astimezone().strftime("%b %-d, %-I:%M %p")
            except (KeyError, TypeError, ValueError):
                refreshed = "time unavailable"
            self._activity_total.set_subtitle(
                f"Last 24 hours • {self._log_mode} logging • refreshed {refreshed}"
            )
            self._render_activity_chart(report["hourly"])
            ports = report.get("top_ports") or []
            self._activity_ports.set_subtitle(
                ", ".join(f"{port}: {count}" for port, count in ports) if ports else "No destination ports recorded"
            )

        self._activity_reader.read(received, privileged=privileged)

    def _render_activity_chart(self, hourly):
        child = self._activity_chart.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self._activity_chart.remove(child)
            child = next_child
        highest = max(hourly) if hourly else 0
        for count in hourly:
            holder = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.END, hexpand=True)
            bar = Gtk.Box()
            bar.add_css_class("activity-bar")
            bar.set_size_request(-1, max(3, round(68 * count / highest)) if highest else 3)
            holder.append(bar)
            self._activity_chart.append(holder)

    # -- Active Connection ---------------------------------------------------

    def _build_overview_group(self):
        group = Adw.PreferencesGroup(
            title="Protection overview",
            description="Live firewall state. Allowed entries counts services and custom ports across active zones; logged denials are shown below.",
        )
        self.add(group)
        cards = Gtk.FlowBox()
        cards.set_selection_mode(Gtk.SelectionMode.NONE)
        cards.set_max_children_per_line(4)
        cards.set_min_children_per_line(1)
        cards.set_column_spacing(10)
        cards.set_row_spacing(10)
        self._overview_values = {}
        for key, title, icon in (
            ("status", "Firewall", "security-high-symbolic"),
            ("networks", "Active networks", "network-wireless-symbolic"),
            ("zones", "Active zones", "network-workgroup-symbolic"),
            ("exposure", "Allowed entries", "network-server-symbolic"),
        ):
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            card.add_css_class("metric-card")
            image = Gtk.Image.new_from_icon_name(icon)
            image.set_halign(Gtk.Align.START)
            card.append(image)
            value = Gtk.Label(label="—", xalign=0)
            value.add_css_class("title-2")
            card.append(value)
            label = Gtk.Label(label=title, xalign=0)
            label.add_css_class("dim-label")
            card.append(label)
            self._overview_values[key] = value
            cards.insert(card, -1)
        group.add(cards)

    def _refresh_overview(self):
        def active(zones, error):
            if error or zones is None:
                self._overview_values["zones"].set_label("Unavailable")
                self._overview_values["exposure"].set_label("Unavailable")
                return
            names = sorted(zones)
            self._overview_values["zones"].set_label(str(len(names)))
            if not names:
                self._overview_values["exposure"].set_label("0")
                return
            state = {"remaining": len(names), "count": 0, "failed": False}

            def one(settings, read_error):
                if read_error or settings is None:
                    state["failed"] = True
                else:
                    state["count"] += len(settings.get("services") or []) + len(settings.get("ports") or [])
                state["remaining"] -= 1
                if not state["remaining"]:
                    self._overview_values["exposure"].set_label(
                        "Unavailable" if state["failed"] else str(state["count"])
                    )

            for name in names:
                self._fw.get_zone_settings(name, one)

        self._fw.get_active_zones(active)

    def _build_active_connections_group(self):
        self._active_group = Adw.PreferencesGroup(
            title="Active connections",
            description="Choose a zone, then Apply to use it now and save it to the network profile.",
        )
        self.add(self._active_group)

    def _build_layers_group(self):
        group = Adw.PreferencesGroup(
            title="Protection layers",
            description="Current hardening and tunnel state. Open a page to review the exact settings.",
        )
        self.add(group)
        self._dns_layer = Adw.ActionRow(title="DNS hardening", subtitle="Checking…")
        self._encryption_layer = Adw.ActionRow(title="Encryption hardening", subtitle="Checking…")
        self._ssh_layer = Adw.ActionRow(title="SSH server", subtitle="Checking…")
        self._vpn_layer = Adw.ActionRow(title="VPN tunnel", subtitle="Checking…")
        for row, icon in (
            (self._dns_layer, "network-server-symbolic"),
            (self._encryption_layer, "channel-secure-symbolic"),
            (self._ssh_layer, "utilities-terminal-symbolic"),
            (self._vpn_layer, "network-vpn-symbolic"),
        ):
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            group.add(row)

    def _refresh_layers(self):
        hardening = getattr(self._window, "hardening", None)
        if hardening is None or not hardening.is_installed():
            self._dns_layer.set_subtitle("System helper unavailable; see Hardening")
            self._encryption_layer.set_subtitle("System helper unavailable; see Hardening")
        else:
            def status_loaded(status, error):
                if error or status is None:
                    self._dns_layer.set_subtitle("Could not read current DNS hardening")
                    self._encryption_layer.set_subtitle("Could not read current encryption hardening")
                    return
                recorded = status.get("state", {})
                self._dns_layer.set_subtitle(
                    "Level: " + recorded.get("dns", {}).get("level", "off").title()
                )
                self._encryption_layer.set_subtitle(
                    "Level: " + recorded.get("crypto", {}).get("level", "off").title()
                    + " • current policy: " + str(status.get("crypto_policy") or "unknown")
                )

            hardening.get_status(status_loaded)

        systemd = getattr(self._window, "systemd", None)
        if systemd is None:
            self._ssh_layer.set_subtitle("See Hardening for status")
        else:
            def connected(error):
                if error:
                    self._ssh_layer.set_subtitle("Could not read SSH server state")
                    return
                systemd.get_service_state(
                    "sshd.service",
                    lambda state, read_error: self._ssh_layer.set_subtitle(
                        "Unavailable" if read_error or not state else
                        "Not installed" if not state["exists"] else
                        "Running" if state["active"] else
                        "Enabled, currently stopped" if state["enabled"] else "Off"
                    ),
                )

            systemd.ensure_connected(connected)

    def _refresh_active_connections(self):
        if self._nm_poll_in_flight:
            return
        self._nm_poll_in_flight = True

        def on_connections(connections, error):
            self._nm_poll_in_flight = False
            if error is not None:
                show_error_toast(self._window.toast_overlay, error, "Couldn't list network connections")
                return

            seen_keys = set()
            for conn in connections or []:
                if not conn["device"]:
                    continue
                key = (conn["uuid"], conn["device"])
                seen_keys.add(key)
                if key not in self._connection_rows:
                    self._add_connection_row(conn)
                else:
                    self._refresh_connection_state(self._connection_rows[key])

            for key in list(self._connection_rows):
                if key not in seen_keys:
                    entry = self._connection_rows.pop(key)
                    if entry.get("model_listener"):
                        entry["model"].disconnect(entry["model_listener"])
                    if entry.get("controls"):
                        entry["controls"].detach()
                    self._active_group.remove(entry["row"])
                    if self._rows_by_iface.get(entry["iface"]) == key:
                        del self._rows_by_iface[entry["iface"]]
            self._overview_values["networks"].set_label(str(len(seen_keys)))
            tunnels = [c["name"] for c in connections or [] if c["type"] in ("vpn", "wireguard")]
            self._vpn_layer.set_subtitle(
                "Active: " + ", ".join(sorted(tunnels)) if tunnels else "No NetworkManager VPN profile active"
            )

        self._nm.get_active_connections(on_connections)

    def _add_connection_row(self, conn):
        iface = conn["device"]
        kind = "VPN / virtual" if self._nm.is_vpn_like(conn["type"]) else "physical"
        row = Adw.ActionRow(title=escape_markup(conn["name"]), subtitle=f"{iface} ({kind}) • checking zone…")
        self._active_group.add(row)

        entry = {
            "row": row,
            "iface": iface,
            "uuid": conn["uuid"],
            "dropdown": None,
            "all_zones": None,
            "displayed_zones": None,
            "enforced_zone": None,
            "state": {"syncing": False},
            "model": self._assignments.model_for(conn["uuid"]),
        }
        key = (conn["uuid"], iface)
        self._connection_rows[key] = entry
        self._rows_by_iface[iface] = key

        def on_zone_of_iface(enforced_zone, error):
            if self._connection_rows.get(key) is not entry:
                return
            if error is not None:
                row.set_subtitle(f"{iface} • couldn't read firewall zone")
                return

            def on_zones(zones, error2):
                if self._connection_rows.get(key) is not entry:
                    return
                if error2 is not None or not zones:
                    row.set_subtitle(f"{iface} • couldn't load zone list")
                    return
                self._wire_zone_dropdown(entry, zones, enforced_zone)
                self._refresh_connection_state(entry)

            self._fw.get_zones(on_zones)

        self._fw.get_zone_of_interface(iface, on_zone_of_iface)

    def _wire_zone_dropdown(self, entry, zones, enforced_zone):
        row, iface = entry["row"], entry["iface"]
        entry["all_zones"] = zones
        entry["enforced_zone"] = enforced_zone
        dropdown = Gtk.DropDown.new_from_strings(zones)
        dropdown.set_valign(Gtk.Align.CENTER)
        entry["dropdown"] = dropdown
        state = entry["state"]
        row.add_suffix(dropdown)
        controls = ApplyControls(entry["model"], lambda zone, done: self._apply_zone(entry, zone, done))
        entry["controls"] = controls
        row.add_suffix(controls)
        entry["model_listener"] = entry["model"].connect(
            lambda _model: self._rebuild_row_zone_model(entry)
        )

        def on_selected(dd, _pspec):
            if state["syncing"]:
                return
            new_index = dd.get_selected()
            if 0 <= new_index < len(entry["displayed_zones"]):
                entry["model"].stage(entry["displayed_zones"][new_index])

        dropdown.connect("notify::selected", on_selected)
        self._rebuild_row_zone_model(entry)

    def _apply_zone(self, entry, zone, done):
        def on_result(ok, error):
            if error:
                show_error_toast(self._window.toast_overlay, error, "Couldn't fully apply zone")
            if ok:
                self._refresh_connection_state(entry)
                self._refresh_overview()
            done(ok, error)

        self._assignments.apply(entry["uuid"], zone, on_result)

    def _refresh_connection_state(self, entry):
        key = (entry["uuid"], entry["iface"])
        if entry.get("checking") or self._connection_rows.get(key) is not entry:
            return
        entry["checking"] = 2

        def current():
            return self._connection_rows.get(key) is entry

        def finished():
            entry["checking"] -= 1

        def on_runtime(zone, error):
            if current() and error is None:
                entry["enforced_zone"] = zone
                self._update_zone_display(entry)
            finished()

        def on_saved(zone, error):
            if not current():
                finished()
                return
            if error:
                self._update_zone_display(entry)
                finished()
            elif zone:
                self._assignments.observe(entry["uuid"], zone)
                self._update_zone_display(entry)
                finished()
            else:
                def on_default(default, failure):
                    if current() and failure is None and default:
                        self._assignments.observe(entry["uuid"], default)
                        self._update_zone_display(entry)
                    finished()

                self._fw.get_default_zone(on_default)

        self._fw.get_zone_of_interface(entry["iface"], on_runtime)
        self._nm.get_connection_zone(entry["uuid"], on_saved)

    def _update_zone_display(self, entry):
        zone = entry["enforced_zone"]
        saved = entry["model"].applied
        info = get_zone_info(zone or "")
        detail = f"{entry['iface']} • active: {zone or 'unknown'} ({info.trust_label})"
        if saved and saved != zone:
            detail += f" • saved profile: {saved}"
        entry["row"].set_subtitle(detail)
        if entry["dropdown"] is not None:
            entry["dropdown"].set_tooltip_text(get_zone_info(entry["model"].draft or zone or "").guidance)

    def _on_interface_zone_changed(self, _fw, zone, iface):
        key = self._rows_by_iface.get(iface)
        entry = self._connection_rows.get(key) if key else None
        if entry is None or entry["dropdown"] is None:
            self._refresh_active_connections()
            return
        entry["enforced_zone"] = zone
        if entry["all_zones"] is not None and zone not in entry["all_zones"]:
            entry["all_zones"] = entry["all_zones"] + [zone]
        self._rebuild_row_zone_model(entry)
        self._update_zone_display(entry)
        self._refresh_overview()

    def _rebuild_row_zone_model(self, entry):
        if not entry["all_zones"] or entry["dropdown"] is None:
            return
        selected = entry["model"].draft or entry["enforced_zone"]
        displayed = filter_zones(entry["all_zones"], self._settings.show_all_zones, must_keep=selected)
        for zone in (entry["enforced_zone"], entry["model"].applied):
            if zone and zone in entry["all_zones"] and zone not in displayed:
                displayed.append(zone)
        displayed.sort()
        entry["displayed_zones"] = displayed
        index = displayed.index(selected) if selected in displayed else 0
        entry["state"]["syncing"] = True
        entry["dropdown"].set_model(Gtk.StringList.new(displayed))
        entry["dropdown"].set_selected(index)
        entry["state"]["syncing"] = False
        self._update_zone_display(entry)

    def _on_show_all_zones_changed(self, *_args):
        for entry in self._connection_rows.values():
            if entry["dropdown"] is not None:
                self._rebuild_row_zone_model(entry)

    # -- Panic Mode -------------------------------------------------------------

    def _build_panic_group(self):
        group = Adw.PreferencesGroup(
            title="Panic Mode",
            description="Instantly blocks all incoming and outgoing network traffic on every interface.",
        )
        self.add(group)
        self._panic_row = Adw.SwitchRow(
            title="Block all network traffic",
            subtitle="Stage the emergency block, then Apply. This app remains available to turn it off.",
        )
        self._panic_model = PendingValue()
        self._panic_syncing = False
        self._panic_model.connect(self._sync_panic_row)
        self._panic_row.connect("notify::active", self._on_panic_selected)
        self._panic_row.add_suffix(ApplyControls(self._panic_model, self._request_panic))
        group.add(self._panic_row)

    def _sync_panic_row(self, model):
        self._panic_syncing = True
        self._panic_row.set_active(bool(model.draft))
        self._panic_syncing = False

    def _on_panic_selected(self, row, _pspec):
        if not self._panic_syncing:
            self._panic_model.stage(row.get_active())

    def _request_panic(self, requested, done):
        """Apply a staged emergency setting and verify firewalld's state."""
        def do_apply():
            def on_result(ok, error):
                if not ok and error is not None:
                    show_error_toast(self._window.toast_overlay, error, "Couldn't change panic mode")
                    done(False, error)
                    return

                def verified(actual, read_error):
                    if read_error or bool(actual) != requested:
                        done(False, read_error or "firewalld did not report the requested panic state")
                    else:
                        done(True)
                        show_toast(self._window.toast_overlay, "Panic Mode applied." if requested else "Panic Mode turned off.")

                self._fw.query_panic_mode(verified)

            self._fw.set_panic_mode(requested, on_result)

        if requested:
            confirm(
                self._window,
                "Enable Panic Mode?",
                "This immediately blocks ALL incoming and outgoing network traffic on every interface — "
                "WiFi, Ethernet, and your VPN tunnel included. Nothing will be reachable until you turn this "
                "back off.\n\nThis app keeps working the whole time, because it talks to firewalld over the "
                "local system bus, not the network — so you can always come back here and switch it off.",
                "Enable Panic Mode",
                do_apply,
                destructive=True,
                on_cancel=lambda: done(False, "Still pending"),
            )
        else:
            do_apply()

    def _on_panic_result(self, ok, error):
        if not ok and error is not None:
            show_error_toast(self._window.toast_overlay, error, "Couldn't change panic mode")

    def _on_panic_mode_changed(self, fw, enabled):
        self._panic_model.observe(enabled)
        self._overview_values["status"].set_label("Traffic blocked" if enabled else "Active")

    def _on_initial_panic_state(self, enabled, error):
        if error is not None:
            return
        self._on_panic_mode_changed(self._fw, bool(enabled))

    # -- Recommended Hardening ---------------------------------------------------

    def _build_hardening_group(self):
        group = Adw.PreferencesGroup(
            title="Recommended Hardening",
            description="Specific, editable suggestions based on your firewall's default zone right now.",
        )
        self.add(group)
        self._hardening_row = Adw.ActionRow(title="Checking…", activatable=True)
        self._hardening_row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        self._hardening_row.connect("activated", self._on_hardening_activated)
        group.add(self._hardening_row)

    def _refresh_hardening(self):
        def on_default_zone(zone, error):
            if error is not None or zone is None:
                self._hardening_row.set_title("Couldn't check for suggestions")
                self._hardening_zone = None
                self._hardening_rules = []
                return
            self._hardening_zone = zone

            def on_settings(settings, error2):
                if error2 is not None or settings is None:
                    self._hardening_row.set_title("Couldn't check for suggestions")
                    self._hardening_rules = []
                    return
                self._hardening_rules = get_applicable_rules(settings)
                n = len(self._hardening_rules)
                if n == 0:
                    self._hardening_row.set_title("No suggestions right now")
                else:
                    self._hardening_row.set_title(f"{n} suggestion{'s' if n != 1 else ''} available")
                self._hardening_row.set_subtitle(f"Default zone: {zone}")

            self._fw.get_zone_settings(zone, on_settings)

        self._fw.get_default_zone(on_default_zone)

    def _on_hardening_activated(self, row):
        if not self._hardening_rules:
            return
        dialog = Adw.Dialog(title="Recommended Hardening", content_width=480)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(18)
        box.set_margin_end(18)

        intro = Gtk.Label(
            label=f"Suggestions for the “{self._hardening_zone}” zone. Uncheck anything you'd rather keep.",
            wrap=True,
            xalign=0,
        )
        intro.add_css_class("dim-label")
        box.append(intro)

        checks = []
        for rule in self._hardening_rules:
            item_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            check = Gtk.CheckButton(label=rule.title, active=True)
            desc = Gtk.Label(label=rule.description, wrap=True, xalign=0)
            desc.add_css_class("dim-label")
            desc.set_margin_start(28)
            item_box.append(check)
            item_box.append(desc)
            box.append(item_box)
            checks.append((rule, check))

        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda b: dialog.close())
        apply_btn = Gtk.Button(label="Apply Selected")
        apply_btn.add_css_class("suggested-action")

        def on_apply(button):
            selected = [rule for rule, check in checks if check.get_active()]
            dialog.close()
            self._apply_hardening_rules(selected)

        apply_btn.connect("clicked", on_apply)
        button_box.append(cancel_btn)
        button_box.append(apply_btn)
        box.append(button_box)

        dialog.set_child(box)
        dialog.present(self._window)

    def _apply_hardening_rules(self, rules):
        if not rules or self._hardening_zone is None:
            return
        zone = self._hardening_zone
        state = {"pending": len(rules), "errors": []}

        def on_one(ok, error, partial):
            state["pending"] -= 1
            if not ok or partial:
                state["errors"].append(str(error or "runtime and saved rules differ"))
            if state["pending"] == 0:
                if state["errors"]:
                    show_error_toast(self._window.toast_overlay, "; ".join(state["errors"]), "Some steps failed")
                else:
                    show_toast(self._window.toast_overlay, "Hardening suggestions applied.")
                self._refresh_hardening()

        for rule in rules:
            rule.fix(self._fw, zone, on_one)
