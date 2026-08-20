import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, GLib

from ..data.hardening_rules import get_applicable_rules
from ..data.zones_catalog import filter_zones, get_zone_info
from ..widgets.confirm import confirm, escape_markup, show_error_toast, show_toast


class DashboardPage(Adw.PreferencesPage):
    def __init__(self, window, firewalld, netmgr, settings):
        super().__init__(title="Dashboard", icon_name="security-high-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._connection_rows = {}
        self._rows_by_iface = {}
        self._hardening_zone = None
        self._hardening_rules = []
        self._panic_syncing = False

        self._build_active_connections_group()
        self._build_panic_group()
        self._build_hardening_group()

        self._fw.connect("interface-zone-changed", self._on_interface_zone_changed)
        self._fw.connect("zone-updated", lambda *_a: self._refresh_hardening())
        self._fw.connect("service-added", lambda *_a: self._refresh_hardening())
        self._fw.connect("service-removed", lambda *_a: self._refresh_hardening())
        self._fw.connect("port-added", lambda *_a: self._refresh_hardening())
        self._fw.connect("port-removed", lambda *_a: self._refresh_hardening())
        self._fw.connect("panic-mode-changed", self._on_panic_mode_changed)
        self._settings.connect("notify::show-all-zones", self._on_show_all_zones_changed)

        GLib.timeout_add_seconds(5, self._poll_nm)

    def refresh(self):
        self._refresh_active_connections()
        self._refresh_hardening()
        self._fw.query_panic_mode(self._on_initial_panic_state)

    def _poll_nm(self):
        self._refresh_active_connections()
        return True

    # -- Active Connection ---------------------------------------------------

    def _build_active_connections_group(self):
        self._active_group = Adw.PreferencesGroup(
            title="Active Connection",
            description="What's connected right now and which firewall zone is protecting it.",
        )
        self.add(self._active_group)

    def _refresh_active_connections(self):
        def on_connections(connections, error):
            if error is not None:
                show_error_toast(self._window.toast_overlay, error, "Couldn't list network connections")
                return

            seen_uuids = set()
            for conn in connections or []:
                if not conn["device"]:
                    continue
                seen_uuids.add(conn["uuid"])
                if conn["uuid"] not in self._connection_rows:
                    self._add_connection_row(conn)

            for uuid in list(self._connection_rows):
                if uuid not in seen_uuids:
                    entry = self._connection_rows.pop(uuid)
                    self._active_group.remove(entry["row"])
                    if self._rows_by_iface.get(entry["iface"]) == uuid:
                        del self._rows_by_iface[entry["iface"]]

        self._nm.get_active_connections(on_connections)

    def _add_connection_row(self, conn):
        iface = conn["device"]
        kind = "VPN / virtual" if self._nm.is_vpn_like(conn["type"]) else "physical"
        row = Adw.ActionRow(title=escape_markup(conn["name"]), subtitle=f"{iface} ({kind}) • checking zone…")
        self._active_group.add(row)

        entry = {
            "row": row,
            "iface": iface,
            "dropdown": None,
            "all_zones": None,
            "displayed_zones": None,
            "enforced_zone": None,
            "state": {},
        }
        self._connection_rows[conn["uuid"]] = entry
        self._rows_by_iface[iface] = conn["uuid"]

        def on_zone_of_iface(enforced_zone, error):
            if error is not None:
                row.set_subtitle(f"{iface} • couldn't read firewall zone")
                return

            def on_zones(zones, error2):
                if error2 is not None or not zones:
                    row.set_subtitle(f"{iface} • couldn't load zone list")
                    return
                self._wire_zone_dropdown(entry, zones, enforced_zone)

            self._fw.get_zones(on_zones)

        self._fw.get_zone_of_interface(iface, on_zone_of_iface)

    def _wire_zone_dropdown(self, entry, zones, enforced_zone):
        row, iface = entry["row"], entry["iface"]
        entry["all_zones"] = zones
        entry["enforced_zone"] = enforced_zone
        displayed = filter_zones(zones, self._settings.show_all_zones, must_keep=enforced_zone)
        entry["displayed_zones"] = displayed

        dropdown = Gtk.DropDown.new_from_strings(displayed)
        dropdown.set_valign(Gtk.Align.CENTER)
        entry["dropdown"] = dropdown
        state = entry["state"]
        state["syncing"] = True
        state["index"] = displayed.index(enforced_zone) if enforced_zone in displayed else 0
        dropdown.set_selected(state["index"])
        state["syncing"] = False
        row.add_suffix(dropdown)
        self._update_zone_display(row, dropdown, iface, enforced_zone)

        def revert():
            state["syncing"] = True
            dropdown.set_selected(state["index"])
            state["syncing"] = False

        def on_selected(dd, _pspec):
            if state["syncing"]:
                return
            new_index = dd.get_selected()
            zone = entry["displayed_zones"][new_index]
            revert()

            def apply():
                def on_result(ok, error):
                    if ok:
                        state["index"] = new_index
                        state["syncing"] = True
                        dropdown.set_selected(new_index)
                        state["syncing"] = False
                        entry["enforced_zone"] = zone
                        self._update_zone_display(row, dropdown, iface, zone)
                    elif error is not None:
                        show_error_toast(self._window.toast_overlay, error, "Couldn't switch zone")

                self._fw.change_zone_of_interface(zone, iface, on_result)

            confirm(
                self._window,
                f"Switch {iface} to the “{zone}” zone?",
                "This changes the firewall zone for this interface right now, for this session only. "
                "It reverts to whatever's configured on the Network Profiles page the next time this "
                "network reconnects.",
                "Switch Zone",
                apply,
                destructive=False,
            )

        dropdown.connect("notify::selected", on_selected)

    def _update_zone_display(self, row, dropdown, iface, zone):
        info = get_zone_info(zone or "")
        row.set_subtitle(f"{iface} • zone: {zone or 'unknown'} ({info.trust_label}) — quick-switch is temporary")
        dropdown.set_tooltip_text(info.guidance)

    def _on_interface_zone_changed(self, _fw, zone, iface):
        uuid = self._rows_by_iface.get(iface)
        entry = self._connection_rows.get(uuid) if uuid else None
        if entry is None or entry["dropdown"] is None:
            self._refresh_active_connections()
            return
        entry["enforced_zone"] = zone
        if entry["all_zones"] is not None and zone not in entry["all_zones"]:
            entry["all_zones"] = entry["all_zones"] + [zone]
        self._rebuild_row_zone_model(entry)
        self._update_zone_display(entry["row"], entry["dropdown"], entry["iface"], zone)

    def _rebuild_row_zone_model(self, entry):
        displayed = filter_zones(entry["all_zones"], self._settings.show_all_zones, must_keep=entry["enforced_zone"])
        entry["displayed_zones"] = displayed
        index = displayed.index(entry["enforced_zone"]) if entry["enforced_zone"] in displayed else 0
        entry["state"]["syncing"] = True
        entry["dropdown"].set_model(Gtk.StringList.new(displayed))
        entry["dropdown"].set_selected(index)
        entry["state"]["syncing"] = False
        entry["state"]["index"] = index

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
            subtitle="Use this if you think this laptop is under active attack, or you need to disconnect "
            "everything right now. This app keeps working the whole time so you can switch it back off.",
        )
        self._panic_row.add_css_class("error")
        self._panic_row.connect("notify::active", self._on_panic_switch_notify)
        group.add(self._panic_row)

    def _on_panic_switch_notify(self, row, _pspec):
        if self._panic_syncing:
            return
        requested = row.get_active()
        self._panic_syncing = True
        row.set_active(not requested)
        self._panic_syncing = False

        if requested:
            def do_enable():
                self._fw.set_panic_mode(True, self._on_panic_result)

            confirm(
                self._window,
                "Enable Panic Mode?",
                "This immediately blocks ALL incoming and outgoing network traffic on every interface — "
                "WiFi, Ethernet, and your VPN tunnel included. Nothing will be reachable until you turn this "
                "back off.\n\nThis app keeps working the whole time, because it talks to firewalld over the "
                "local system bus, not the network — so you can always come back here and switch it off.",
                "Enable Panic Mode",
                do_enable,
                destructive=True,
            )
        else:
            self._fw.set_panic_mode(False, self._on_panic_result)

    def _on_panic_result(self, ok, error):
        if not ok and error is not None:
            show_error_toast(self._window.toast_overlay, error, "Couldn't change panic mode")

    def _on_panic_mode_changed(self, fw, enabled):
        self._panic_syncing = True
        self._panic_row.set_active(enabled)
        self._panic_syncing = False

    def _on_initial_panic_state(self, enabled, error):
        if error is not None:
            return
        self._panic_syncing = True
        self._panic_row.set_active(bool(enabled))
        self._panic_syncing = False

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
            if not ok and error is not None:
                state["errors"].append(str(error))
            if state["pending"] == 0:
                if state["errors"]:
                    show_error_toast(self._window.toast_overlay, "; ".join(state["errors"]), "Some steps failed")
                else:
                    show_toast(self._window.toast_overlay, "Hardening suggestions applied.")
                self._refresh_hardening()

        for rule in rules:
            rule.fix(self._fw, zone, on_one)
