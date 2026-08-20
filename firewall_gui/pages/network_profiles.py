import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..data.zones_catalog import filter_zones, get_zone_info, summarize_zone_settings
from ..widgets.confirm import confirm, escape_markup, show_error_toast

PHYSICAL_TYPES = {"802-11-wireless", "802-3-ethernet", "wifi", "ethernet"}


class NetworkProfilesPage(Adw.PreferencesPage):
    def __init__(self, window, firewalld, netmgr, settings):
        super().__init__(title="Network Profiles", icon_name="network-wireless-symbolic")
        self._window = window
        self._fw = firewalld
        self._nm = netmgr
        self._settings = settings
        self._all_zones_raw = []
        self._rows = []
        self._row_entries = {}
        self._default_zone = None

        self._intro_group = Adw.PreferencesGroup()
        self._intro_row = Adw.ActionRow(title="Loading…")
        self._intro_row.set_subtitle_lines(0)
        self._intro_group.add(self._intro_row)
        self.add(self._intro_group)

        self._physical_group = Adw.PreferencesGroup(
            title="Wi-Fi and Wired",
            description="Assign a firewall zone to each saved network. It applies immediately if you're "
            "connected to that network right now, or the next time you connect otherwise.",
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
        for group, row in self._rows:
            group.remove(row)
        self._rows.clear()
        self._row_entries.clear()
        if error is not None:
            show_error_toast(self._window.toast_overlay, error, "Couldn't list saved networks")
            return
        for conn in connections or []:
            if conn["type"] == "loopback":
                continue
            if self._nm.is_vpn_like(conn["type"]):
                group = self._vpn_group
            elif conn["type"] in PHYSICAL_TYPES:
                group = self._physical_group
            else:
                group = self._other_group
                self._other_group.set_visible(True)
            self._add_connection_row(group, conn)

    def _add_connection_row(self, group, conn):
        name = escape_markup(conn["name"])
        base_subtitle = escape_markup(f"{conn['type']} • {conn['device'] or 'not connected'}")
        row = Adw.ComboRow(title=name, subtitle=base_subtitle)
        row.set_subtitle_lines(2)
        group.add(row)
        self._rows.append((group, row))

        entry = {"row": row, "displayed_zones": [], "state": {"syncing": True, "index": 0}, "effective_zone": None}
        self._row_entries[conn["uuid"]] = entry

        def describe(zone, was_unset):
            info = get_zone_info(zone)
            if was_unset:
                row.set_subtitle(f"{base_subtitle} • no zone set — currently using “{zone}” ({info.trust_label})")
            else:
                row.set_subtitle(f"{base_subtitle} • {zone} — {info.trust_label}")
            row.set_tooltip_text(info.guidance)

            def on_settings(settings, error):
                if error is not None or settings is None:
                    return
                row.set_tooltip_text(f"{info.guidance}\n\n{summarize_zone_settings(settings)}")

            self._fw.get_zone_settings(zone, on_settings)

        def apply_effective_zone(effective_zone, was_unset):
            entry["effective_zone"] = effective_zone
            displayed = filter_zones(self._all_zones_raw, self._settings.show_all_zones, must_keep=effective_zone)
            entry["displayed_zones"] = displayed
            index = displayed.index(effective_zone) if effective_zone in displayed else 0
            state = entry["state"]
            state["syncing"] = True
            row.set_model(Gtk.StringList.new(displayed))
            row.set_selected(index)
            state["index"] = index
            state["syncing"] = False
            describe(effective_zone, was_unset)

        def on_selected(r, _pspec):
            state = entry["state"]
            if state["syncing"]:
                return
            new_index = r.get_selected()
            new_zone = entry["displayed_zones"][new_index]
            state["syncing"] = True
            r.set_selected(state["index"])
            state["syncing"] = False

            def apply():
                def on_result(ok, error2):
                    if ok:
                        apply_effective_zone(new_zone, was_unset=False)
                    elif error2 is not None:
                        show_error_toast(self._window.toast_overlay, error2, "Couldn't assign zone")

                self._nm.set_connection_zone(conn["uuid"], new_zone, on_result)

            confirm(
                self._window,
                f"Assign “{new_zone}” to {name}?",
                f"Whenever this laptop connects to {name}, firewalld will automatically switch "
                f"to the “{new_zone}” zone.\n\n{get_zone_info(new_zone).guidance}",
                "Assign Zone",
                apply,
                destructive=False,
            )

        row.connect("notify::selected", on_selected)

        def on_zone(zone, error):
            if error is not None:
                row.set_subtitle(f"{base_subtitle} • couldn't read assigned zone")
                return
            effective_zone = zone or self._default_zone or "public"
            apply_effective_zone(effective_zone, was_unset=not zone)

        self._nm.get_connection_zone(conn["uuid"], on_zone)

    def _on_show_all_zones_changed(self, *_args):
        for entry in self._row_entries.values():
            self._rebuild_row_zone_model(entry)

    def _rebuild_row_zone_model(self, entry):
        effective_zone = entry["effective_zone"]
        if effective_zone is None:
            return
        displayed = filter_zones(self._all_zones_raw, self._settings.show_all_zones, must_keep=effective_zone)
        entry["displayed_zones"] = displayed
        index = displayed.index(effective_zone) if effective_zone in displayed else 0
        entry["state"]["syncing"] = True
        entry["row"].set_model(Gtk.StringList.new(displayed))
        entry["row"].set_selected(index)
        entry["state"]["syncing"] = False
        entry["state"]["index"] = index
