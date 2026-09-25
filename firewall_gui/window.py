import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .backend.firewalld import FirewalldClient
from .backend.hardening import HardeningClient
from .backend.networkmanager import NetworkManagerClient
from .backend.zone_assignment import ZoneAssignmentController
from .backend.protonvpn import ProtonVpnClient
from .backend.systemd import SystemdClient
from .pages.dashboard import DashboardPage
from .pages.hardening import HardeningPage
from .pages.network_profiles import NetworkProfilesPage
from .pages.proton_vpn import ProtonVpnPage
from .pages.zone_editor import ZoneEditorPage
from .settings import AppSettings
from .widgets.pending import ApplyControls, PendingValue


class FirewallGuiWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_default_size(980, 740)
        self.set_title("Firewall")

        self.firewalld = FirewalldClient()
        self.netmgr = NetworkManagerClient()
        self.zone_assignments = ZoneAssignmentController(self.netmgr, self.firewalld)
        self.proton = ProtonVpnClient(self.netmgr)
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
        preference = PendingValue(self.settings.show_all_zones)
        state = {"syncing": False}

        def sync(model):
            state["syncing"] = True
            switch_row.set_active(bool(model.draft))
            state["syncing"] = False

        def changed(row, _pspec):
            if not state["syncing"]:
                preference.stage(row.get_active())

        def apply(value, done):
            ok, error = self.settings.apply("show_all_zones", value)
            done(ok, error)

        preference.connect(sync)
        switch_row.connect("notify::active", changed)
        switch_row.add_suffix(ApplyControls(preference, apply))

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
        switcher_bar.set_reveal(self._view_switcher_title.get_title_visible())
        self._view_switcher_title.connect(
            "notify::title-visible",
            lambda title, _pspec: switcher_bar.set_reveal(title.get_title_visible()),
        )

        dashboard = DashboardPage(self, self.firewalld, self.netmgr, self.settings, self.zone_assignments)
        zone_editor = ZoneEditorPage(self, self.firewalld, self.settings)
        network_profiles = NetworkProfilesPage(self, self.firewalld, self.netmgr, self.settings, self.zone_assignments)
        proton_vpn = ProtonVpnPage(self, self.proton)
        hardening = HardeningPage(
            self, self.firewalld, self.netmgr, self.settings, self.hardening, self.systemd
        )

        view_stack.add_titled_with_icon(dashboard, "dashboard", "Dashboard", "security-high-symbolic")
        view_stack.add_titled_with_icon(zone_editor, "zone-editor", "Zone Editor", "preferences-system-symbolic")
        view_stack.add_titled_with_icon(
            network_profiles, "network-profiles", "Network Profiles", "network-wireless-symbolic"
        )
        view_stack.add_titled_with_icon(
            proton_vpn, "proton-vpn", "Proton VPN", "network-vpn-symbolic"
        )
        view_stack.add_titled_with_icon(hardening, "hardening", "Hardening", "channel-secure-symbolic")
        view_stack.connect("notify::visible-child", lambda stack, _pspec: getattr(stack.get_visible_child(), "refresh", lambda: None)())

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(view_stack)
        content_box.append(switcher_bar)
        self._toolbar_view.set_content(content_box)

        dashboard.refresh()
        proton_vpn.refresh()
        hardening.refresh()

    def _show_connection_error(self, error):
        self._status_page.set_title("Couldn't connect to firewalld")
        self._status_page.set_description(
            f"{error}\n\nMake sure firewalld is installed and running (systemctl status firewalld), then "
            "restart this app."
        )
        self._status_page.set_icon_name("dialog-error-symbolic")
