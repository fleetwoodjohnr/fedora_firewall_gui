import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .backend.firewalld import FirewalldClient
from .backend.hardening import HardeningClient
from .backend.networkmanager import NetworkManagerClient
from .backend.systemd import SystemdClient
from .pages.dashboard import DashboardPage
from .pages.hardening import HardeningPage
from .pages.network_profiles import NetworkProfilesPage
from .pages.zone_editor import ZoneEditorPage
from .settings import AppSettings


class FirewallGuiWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_default_size(760, 680)
        self.set_title("Firewall")

        self.firewalld = FirewalldClient()
        self.netmgr = NetworkManagerClient()
        self.hardening = HardeningClient()
        self.systemd = SystemdClient()
        self.settings = AppSettings()

        self.toast_overlay = Adw.ToastOverlay()

        self._toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self._view_switcher_title = Adw.ViewSwitcherTitle(title="Firewall")
        header.set_title_widget(self._view_switcher_title)
        self._build_menu_button(header)
        self._toolbar_view.add_top_bar(header)

        self._status_page = Adw.StatusPage(
            title="Connecting to firewalld…",
            icon_name="security-high-symbolic",
        )
        self._toolbar_view.set_content(self._status_page)
        self.toast_overlay.set_child(self._toolbar_view)
        self.set_content(self.toast_overlay)

        self.firewalld.connect_async(self._on_firewalld_ready)

    def _build_menu_button(self, header):
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Main Menu")

        switch_row = Adw.SwitchRow(
            title="Show all firewall zones",
            subtitle="Also list system and virtualization zones (libvirt, nm-shared, "
            "FedoraServer, etc.) in every zone picker.",
        )
        switch_row.set_active(self.settings.show_all_zones)
        switch_row.connect(
            "notify::active",
            lambda row, _pspec: setattr(self.settings, "show_all_zones", row.get_active()),
        )

        group = Adw.PreferencesGroup()
        group.add(switch_row)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.append(group)

        popover = Gtk.Popover()
        popover.set_child(box)
        menu_button.set_popover(popover)
        header.pack_end(menu_button)

    def _on_firewalld_ready(self, error):
        if error is not None:
            self._show_connection_error(error)
            return

        view_stack = Adw.ViewStack(vexpand=True)
        self._view_switcher_title.set_stack(view_stack)
        switcher_bar = Adw.ViewSwitcherBar(stack=view_stack)
        switcher_bar.set_reveal(True)

        dashboard = DashboardPage(self, self.firewalld, self.netmgr, self.settings)
        zone_editor = ZoneEditorPage(self, self.firewalld, self.settings)
        network_profiles = NetworkProfilesPage(self, self.firewalld, self.netmgr, self.settings)
        hardening = HardeningPage(
            self, self.firewalld, self.netmgr, self.settings, self.hardening, self.systemd
        )

        view_stack.add_titled_with_icon(dashboard, "dashboard", "Dashboard", "security-high-symbolic")
        view_stack.add_titled_with_icon(zone_editor, "zone-editor", "Zone Editor", "preferences-system-symbolic")
        view_stack.add_titled_with_icon(
            network_profiles, "network-profiles", "Network Profiles", "network-wireless-symbolic"
        )
        view_stack.add_titled_with_icon(hardening, "hardening", "Hardening", "channel-secure-symbolic")

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(view_stack)
        content_box.append(switcher_bar)
        self._toolbar_view.set_content(content_box)

        dashboard.refresh()
        hardening.refresh()

    def _show_connection_error(self, error):
        self._status_page.set_title("Couldn't connect to firewalld")
        self._status_page.set_description(
            f"{error}\n\nMake sure firewalld is installed and running (systemctl status firewalld), then "
            "restart this app."
        )
        self._status_page.set_icon_name("dialog-error-symbolic")
