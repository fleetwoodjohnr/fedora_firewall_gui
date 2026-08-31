import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..data.services_catalog import COMMON_SERVICES, get_service_info
from ..data.zones_catalog import filter_zones, get_zone_info, summarize_zone_settings
from ..widgets.debounce import Debouncer
from ..widgets.confirm import confirm, show_error_toast
from ..widgets.service_row import ServiceRow

CHIP_COMMON = "common"
CHIP_REMOTE = "remote"
CHIP_SHARING = "sharing"
CHIP_ALL = "all"


class ZoneEditorPage(Adw.PreferencesPage):
    def __init__(self, window, firewalld, settings):
        super().__init__(title="Zone Editor", icon_name="preferences-system-symbolic")
        self._window = window
        self._fw = firewalld
        self._settings = settings
        self._all_zones_raw = []
        self._zones = []
        self._filter_syncing = False
        self._current_zone = None
        self._current_settings = {}
        self._all_service_names = []
        self._chip_filter = CHIP_COMMON
        self._port_rows = []

        self._build_header_group()
        self._build_services_group()
        self._build_custom_ports_group()

        # Debounced: _on_backend_signal rebuilds a row for every service
        # firewalld knows about (265 here, ~0.29s), and a single hardening
        # change emits several signals in a burst. Undebounced, those rebuilds
        # run back to back and lock up the UI.
        self._on_backend_signal_debounced = Debouncer(self._on_backend_signal)
        for _signal in ("zone-updated", "service-added", "service-removed", "port-added", "port-removed"):
            self._fw.connect(_signal, self._on_backend_signal_debounced)
        self._settings.connect("notify::show-all-zones", self._on_show_all_zones_changed)

        self._fw.list_all_services(self._on_all_services_loaded)
        self._fw.get_zones(self._on_zones_loaded)

    def _on_backend_signal(self, *args):
        if self._current_zone is not None:
            self._load_zone(self._current_zone)

    # -- header: zone picker, search, chips, description ------------------------

    def _build_header_group(self):
        group = Adw.PreferencesGroup()
        self.add(group)

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(8)
        controls.set_margin_bottom(4)
        controls.set_margin_start(4)
        controls.set_margin_end(4)

        self._zone_dropdown = Gtk.DropDown(hexpand=True)
        controls.append(self._zone_dropdown)

        self._search_entry = Gtk.SearchEntry(hexpand=True)
        self._search_entry.set_placeholder_text("Search services…")
        self._search_entry.connect("search-changed", lambda e: self._services_list.invalidate_filter())
        controls.append(self._search_entry)
        group.add(controls)

        chip_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        chip_row.set_margin_bottom(8)
        chip_row.set_margin_start(4)
        chip_row.set_margin_end(4)
        self._chip_common = Gtk.ToggleButton(label="Common", active=True)
        self._chip_remote = Gtk.ToggleButton(label="Remote Access")
        self._chip_sharing = Gtk.ToggleButton(label="Sharing")
        self._chip_all = Gtk.ToggleButton(label="All")
        self._chip_remote.set_group(self._chip_common)
        self._chip_sharing.set_group(self._chip_common)
        self._chip_all.set_group(self._chip_common)
        self._chip_common.connect("toggled", self._on_chip_toggled, CHIP_COMMON)
        self._chip_remote.connect("toggled", self._on_chip_toggled, CHIP_REMOTE)
        self._chip_sharing.connect("toggled", self._on_chip_toggled, CHIP_SHARING)
        self._chip_all.connect("toggled", self._on_chip_toggled, CHIP_ALL)
        for chip in (self._chip_common, self._chip_remote, self._chip_sharing, self._chip_all):
            chip_row.append(chip)
        group.add(chip_row)

        self._zone_trust_label = Gtk.Label(xalign=0)
        self._zone_trust_label.add_css_class("heading")
        self._zone_description_label = Gtk.Label(wrap=True, xalign=0)
        self._zone_description_label.add_css_class("dim-label")
        self._zone_description_label.set_margin_start(4)
        self._zone_description_label.set_margin_end(4)
        self._zone_summary_label = Gtk.Label(wrap=True, xalign=0)
        self._zone_summary_label.add_css_class("dim-label")
        self._zone_summary_label.set_margin_bottom(8)
        self._zone_summary_label.set_margin_start(4)
        self._zone_summary_label.set_margin_end(4)
        desc_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        desc_box.append(self._zone_trust_label)
        desc_box.append(self._zone_description_label)
        desc_box.append(self._zone_summary_label)
        group.add(desc_box)

    def _on_chip_toggled(self, button, chip):
        if button.get_active():
            self._chip_filter = chip
            self._services_list.invalidate_filter()

    # -- services list ------------------------------------------------------

    def _build_services_group(self):
        group = Adw.PreferencesGroup(
            title="Services",
            description="Controls which other devices on a network using this zone can reach these services "
            "on this laptop. It never affects this laptop reaching its own services via localhost/127.0.0.1 — "
            "that's always allowed, regardless of these settings.",
        )
        self.add(group)
        self._services_list = Gtk.ListBox()
        self._services_list.add_css_class("boxed-list")
        self._services_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._services_list.set_filter_func(self._filter_row, None)
        group.add(self._services_list)

    def _filter_row(self, row, _data):
        if not row.matches(self._search_entry.get_text()):
            return False
        if self._chip_filter == CHIP_ALL:
            return True
        if self._chip_filter == CHIP_COMMON:
            return row.name in COMMON_SERVICES
        if self._chip_filter == CHIP_REMOTE:
            return row.info.category == "Remote Access"
        if self._chip_filter == CHIP_SHARING:
            return row.info.category == "File & Printer Sharing"
        return True

    def _on_all_services_loaded(self, services, error):
        if error is not None:
            show_error_toast(self._window.toast_overlay, error, "Couldn't load service list")
            return
        self._all_service_names = sorted(services or [])
        if self._current_zone is not None:
            self._load_zone(self._current_zone)

    def _populate_services(self, settings):
        enabled = set(settings.get("services", []))
        child = self._services_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._services_list.remove(child)
            child = nxt
        for name in self._all_service_names:
            info = get_service_info(name)
            on_expand = self._make_lazy_expand(name) if info.category == "Other" else None
            row = ServiceRow(name, info, name in enabled, self._on_service_toggle, self._on_service_error, on_expand)
            self._services_list.append(row)
        self._services_list.invalidate_filter()

    def _make_lazy_expand(self, name):
        def on_expand(row):
            def on_settings(settings, error):
                if error is not None or settings is None:
                    return
                info = get_service_info(name, raw_ports=settings.get("ports", []))
                row.set_detail_text(info.summary, info.recommendation)

            self._fw.get_service_settings(name, on_settings)

        return on_expand

    def _on_service_toggle(self, name, enabled, backend_callback):
        if self._current_zone is None:
            return
        if enabled:
            self._fw.add_service(self._current_zone, name, backend_callback)
        else:
            self._fw.remove_service(self._current_zone, name, backend_callback)

    def _on_service_error(self, name, requested_state, error, partial):
        if error is not None:
            show_error_toast(self._window.toast_overlay, error, f"Couldn't update {name}")
        elif partial:
            show_error_toast(
                self._window.toast_overlay,
                "applied now, but may not survive a reboot",
                f"{name}",
            )

    # -- custom ports ---------------------------------------------------------

    def _build_custom_ports_group(self):
        self._ports_group = Adw.PreferencesGroup(
            title="Custom Ports",
            description="Open a specific port beyond the predefined services above. Anything reachable here "
            "is reachable by any device on a network using this zone — but not by this laptop reaching "
            "itself via localhost/127.0.0.1, which is always allowed regardless of these settings.",
        )
        self.add(self._ports_group)
        self._add_port_row = Adw.ActionRow(title="Add a custom port…", activatable=True)
        self._add_port_row.add_suffix(Gtk.Image.new_from_icon_name("list-add-symbolic"))
        self._add_port_row.connect("activated", self._on_add_port_activated)
        self._ports_group.add(self._add_port_row)

    def _populate_custom_ports(self, settings):
        for row in self._port_rows:
            self._ports_group.remove(row)
        self._port_rows.clear()
        for port, protocol in settings.get("ports", []):
            row = Adw.ActionRow(title=f"{port} / {protocol}")
            remove_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            remove_btn.add_css_class("flat")
            remove_btn.connect("clicked", lambda b, p=port, proto=protocol: self._on_remove_port(p, proto))
            row.add_suffix(remove_btn)
            self._ports_group.add(row)
            self._port_rows.append(row)

    def _on_remove_port(self, port, protocol):
        if self._current_zone is None:
            return

        def on_result(ok, error, partial):
            if not ok and error is not None:
                show_error_toast(self._window.toast_overlay, error, "Couldn't remove port")

        self._fw.remove_port(self._current_zone, port, protocol, on_result)

    def _on_add_port_activated(self, row):
        dialog = Adw.Dialog(title="Add a Custom Port", content_width=420)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(18)
        box.set_margin_end(18)

        explain = Gtk.Label(
            label="Opening a custom port lets any device on a network using this zone reach that port on "
            "this laptop. Only do this for something you're specifically running and expecting connections to.",
            wrap=True,
            xalign=0,
        )
        explain.add_css_class("dim-label")
        box.append(explain)

        port_entry = Adw.EntryRow(title="Port or range (e.g. 8080 or 8000-8010)")
        box.append(port_entry)

        protocol_dropdown = Gtk.DropDown.new_from_strings(["tcp", "udp"])
        protocol_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        protocol_box.append(Gtk.Label(label="Protocol:"))
        protocol_box.append(protocol_dropdown)
        box.append(protocol_box)

        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda b: dialog.close())
        add_btn = Gtk.Button(label="Add Port")
        add_btn.add_css_class("suggested-action")

        def on_add(button):
            port = port_entry.get_text().strip()
            protocol = ["tcp", "udp"][protocol_dropdown.get_selected()]
            if not port:
                return
            dialog.close()

            def apply():
                def on_result(ok, error, partial):
                    if not ok and error is not None:
                        show_error_toast(self._window.toast_overlay, error, "Couldn't add port")

                self._fw.add_port(self._current_zone, port, protocol, on_result)

            confirm(
                self._window,
                f"Open port {port}/{protocol}?",
                f"This will accept incoming {protocol.upper()} connections on port {port} from any device on "
                f"a network using the “{self._current_zone}” zone.",
                "Open Port",
                apply,
                destructive=False,
            )

        add_btn.connect("clicked", on_add)
        button_box.append(cancel_btn)
        button_box.append(add_btn)
        box.append(button_box)

        dialog.set_child(box)
        dialog.present(self._window)

    # -- zone loading -----------------------------------------------------------

    def _on_zones_loaded(self, zones, error):
        if error is not None or not zones:
            show_error_toast(self._window.toast_overlay, error or "no zones returned", "Couldn't load zones")
            return
        self._all_zones_raw = sorted(zones)
        self._apply_zone_filter(initial=True)
        self._zone_dropdown.connect("notify::selected", self._on_zone_selected)

    def _apply_zone_filter(self, initial=False):
        must_keep = self._current_zone
        self._zones = filter_zones(self._all_zones_raw, self._settings.show_all_zones, must_keep=must_keep)
        self._filter_syncing = True
        self._zone_dropdown.set_model(Gtk.StringList.new(self._zones))
        if must_keep and must_keep in self._zones:
            index = self._zones.index(must_keep)
        else:
            index = self._zones.index("public") if "public" in self._zones else 0
        self._zone_dropdown.set_selected(index)
        self._filter_syncing = False
        if initial:
            self._load_zone(self._zones[index])

    def _on_show_all_zones_changed(self, *_args):
        if self._all_zones_raw:
            self._apply_zone_filter()

    def _on_zone_selected(self, dropdown, _pspec):
        if self._filter_syncing:
            return
        index = dropdown.get_selected()
        if 0 <= index < len(self._zones):
            self._load_zone(self._zones[index])

    def _load_zone(self, zone):
        self._current_zone = zone

        def on_settings(settings, error):
            if error is not None or settings is None:
                show_error_toast(self._window.toast_overlay, error or "unknown error", "Couldn't load zone")
                return
            self._current_settings = settings
            info = get_zone_info(zone)
            self._zone_trust_label.set_label(f"{zone} — {info.trust_label}")
            description = settings.get("description") or info.guidance
            self._zone_description_label.set_label(description)
            self._zone_summary_label.set_label(summarize_zone_settings(settings))
            self._populate_services(settings)
            self._populate_custom_ports(settings)

        self._fw.get_zone_settings(zone, on_settings)
