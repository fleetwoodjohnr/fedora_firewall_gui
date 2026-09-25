import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..data.zones_catalog import filter_zones, get_zone_info, summarize_zone_settings
from ..widgets.confirm import escape_markup, show_error_toast, show_toast
from ..widgets.pending import ApplyControls
from ..widgets.page_intro import page_intro

PHYSICAL_TYPES = {"802-11-wireless", "802-3-ethernet", "wifi", "ethernet"}


class NetworkProfilesPage(Adw.PreferencesPage):
    def __init__(self, window, firewalld, netmgr, settings, zone_assignments):
        super().__init__(title="Network Profiles", icon_name="network-wireless-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._assignments = zone_assignments
        self._all_zones_raw = []
        self._row_entries = {}
        self._default_zone = None

        self.add(page_intro("Network profiles", "Set a lasting firewall zone for each saved Wi-Fi, wired, or VPN connection.", "network-wireless-symbolic"))

        self._intro_group = Adw.PreferencesGroup()
        self._intro_row = Adw.ActionRow(title="Loading…")
        self._intro_row.set_subtitle_lines(0)
        self._intro_group.add(self._intro_row)
        self._search_entry = Gtk.SearchEntry()
        self._search_entry.set_placeholder_text("Find a saved network…")
        self._search_entry.connect("search-changed", lambda *_: self._filter_rows())
        self._intro_group.add(self._search_entry)
        self.add(self._intro_group)

        self._physical_group = Adw.PreferencesGroup(
            title="Wi-Fi and Wired",
            description="Choose a zone, then Apply. Active connections update now; saved profiles use it again next time.",
        )
        self._vpn_group = Adw.PreferencesGroup(
            title="VPN and Virtual",
            description="Tunnel and virtual interfaces. These often deserve more trust than the physical link "
            "underneath them, since traffic inside a VPN tunnel is already protected end to end.",
        )
        self._other_group = Adw.PreferencesGroup(title="Other")
        self.add(self._physical_group)
        self.add(self._vpn_group)
        self.add(self._other_group)
        self._other_group.set_visible(False)

        self._fw.get_zones(self._on_zones_loaded)
        self._fw.get_default_zone(self._on_default_zone_loaded)
        self._settings.connect("notify::show-all-zones", self._on_show_all_zones_changed)
        self._assignments.connect("applied", self._on_assignment_applied)

    def _on_assignment_applied(self, _controller, uuid, _zone):
        entry = self._row_entries.get(uuid)
        if entry is not None:
            self._nm.get_connection_zone(uuid, entry["on_zone"])

    def _on_zones_loaded(self, zones, error):
        if error is not None or not zones:
            show_error_toast(self._window.toast_overlay, error or "no zones returned", "Couldn't load zones")
            return
        self._all_zones_raw = sorted(zones)
        self.refresh()

    def _on_default_zone_loaded(self, zone, error):
        if error is not None:
            self._intro_row.set_title("Couldn't read your system's default zone")
            return
        self._default_zone = zone
        self._intro_row.set_title("A network with no zone assigned uses your system default")
        self._intro_row.set_subtitle(
            f"That includes any brand-new network you connect to for the first time — it gets your system's "
            f"overall default zone, currently “{zone}”, not a cautious zone like “public”. If you want new or "
            f"unrecognized networks to start out locked down, assign them “public” here as soon as you connect."
        )
        self.refresh()

    def refresh(self):
        if not self._all_zones_raw:
            return
        self._nm.list_connections(self._on_connections_loaded)

    def _on_connections_loaded(self, connections, error):
        if error is not None:
            show_error_toast(self._window.toast_overlay, error, "Couldn't list saved networks")
            return
        seen = {c["uuid"] for c in connections or [] if c["type"] != "loopback"}
        for uuid in list(self._row_entries):
            if uuid not in seen:
                entry = self._row_entries.pop(uuid)
                entry["model"].disconnect(entry["model_listener"])
                entry["controls"].detach()
                entry["group"].remove(entry["row"])
        for conn in connections or []:
            if conn["type"] == "loopback":
                continue
            if conn["uuid"] in self._row_entries:
                entry = self._row_entries[conn["uuid"]]
                entry["conn"] = conn
                entry["row"].set_title(escape_markup(conn["name"]))
                self._nm.get_connection_zone(conn["uuid"], entry["on_zone"])
                continue
            if self._nm.is_vpn_like(conn["type"]):
                group = self._vpn_group
            elif conn["type"] in PHYSICAL_TYPES:
                group = self._physical_group
            else:
                group = self._other_group
                self._other_group.set_visible(True)
            self._add_connection_row(group, conn)
        self._filter_rows()

    def _filter_rows(self):
        query = self._search_entry.get_text().strip().casefold()
        counts = {self._physical_group: 0, self._vpn_group: 0, self._other_group: 0}
        for entry in self._row_entries.values():
            conn = entry["conn"]
            matches = query in (conn["name"] + " " + conn["type"] + " " + conn["device"]).casefold()
            entry["row"].set_visible(matches)
            counts[entry["group"]] += int(matches)
        for group, count in counts.items():
            group.set_visible(bool(count))

    def _add_connection_row(self, group, conn):
        name = escape_markup(conn["name"])
        row = Adw.ComboRow(title=name)
        row.set_subtitle_lines(2)
        group.add(row)

        model = self._assignments.model_for(conn["uuid"])
        entry = {"row": row, "group": group, "conn": conn, "model": model,
                 "displayed_zones": [], "state": {"syncing": True},
                 "effective_zone": None, "was_unset": False}
        self._row_entries[conn["uuid"]] = entry
        controls = ApplyControls(model, lambda zone, done: self._apply_zone(conn["uuid"], zone, done))
        entry["controls"] = controls
        row.add_suffix(controls)

        def base_subtitle():
            current = entry["conn"]
            return escape_markup(
                f"{current['type']} • "
                f"{'active on ' + current['device'] if current['device'] else 'saved for next connection'}"
            )

        def describe(zone, was_unset):
            info = get_zone_info(zone)
            if was_unset:
                row.set_subtitle(f"{base_subtitle()} • no zone set — currently using “{zone}” ({info.trust_label})")
            else:
                row.set_subtitle(f"{base_subtitle()} • {zone} — {info.trust_label}")
            row.set_tooltip_text(info.guidance)

            def on_settings(settings, error):
                if error is not None or settings is None:
                    return
                row.set_tooltip_text(f"{info.guidance}\n\n{summarize_zone_settings(settings)}")

            self._fw.get_zone_settings(zone, on_settings)

        def apply_effective_zone(effective_zone, was_unset):
            entry["effective_zone"] = effective_zone
            entry["was_unset"] = was_unset
            self._assignments.observe(conn["uuid"], effective_zone)
            self._rebuild_row_zone_model(entry)
            describe(effective_zone, was_unset)

        def on_selected(r, _pspec):
            state = entry["state"]
            if state["syncing"]:
                return
            new_index = r.get_selected()
            if 0 <= new_index < len(entry["displayed_zones"]):
                model.stage(entry["displayed_zones"][new_index])

        row.connect("notify::selected", on_selected)
        entry["model_listener"] = model.connect(lambda _model: self._rebuild_row_zone_model(entry))

        def on_zone(zone, error):
            if self._row_entries.get(conn["uuid"]) is not entry:
                return
            if error is not None:
                row.set_subtitle(f"{base_subtitle()} • couldn't read assigned zone")
                return
            effective_zone = zone or self._default_zone or "public"
            apply_effective_zone(effective_zone, was_unset=not zone)

        entry["on_zone"] = on_zone
        self._nm.get_connection_zone(conn["uuid"], on_zone)

    def _apply_zone(self, uuid, zone, done):
        def on_result(ok, error):
            if ok:
                show_toast(self._window.toast_overlay, f"Zone {zone} applied to the network profile.")
            else:
                show_error_toast(self._window.toast_overlay, error, "Couldn't fully apply zone")
            done(ok, error)

        self._assignments.apply(uuid, zone, on_result)

    def _on_show_all_zones_changed(self, *_args):
        for entry in self._row_entries.values():
            self._rebuild_row_zone_model(entry)

    def _rebuild_row_zone_model(self, entry):
        effective_zone = entry["model"].draft or entry["effective_zone"]
        if effective_zone is None or not self._all_zones_raw:
            return
        displayed = filter_zones(self._all_zones_raw, self._settings.show_all_zones, must_keep=effective_zone)
        current = entry["model"].applied
        if current in self._all_zones_raw and current not in displayed:
            displayed.append(current)
            displayed.sort()
        entry["displayed_zones"] = displayed
        index = displayed.index(effective_zone) if effective_zone in displayed else 0
        entry["state"]["syncing"] = True
        entry["row"].set_model(Gtk.StringList.new(displayed))
        entry["row"].set_selected(index)
        entry["state"]["syncing"] = False
