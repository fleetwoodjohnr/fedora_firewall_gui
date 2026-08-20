import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib, GObject

from .errors import translate_dbus_error

BUS_NAME = "org.fedoraproject.FirewallD1"
MAIN_PATH = "/org/fedoraproject/FirewallD1"
CONFIG_PATH = "/org/fedoraproject/FirewallD1/config"

IFACE_ROOT = "org.fedoraproject.FirewallD1"
IFACE_ZONE = "org.fedoraproject.FirewallD1.zone"
IFACE_CONFIG = "org.fedoraproject.FirewallD1.config"
IFACE_CONFIG_ZONE = "org.fedoraproject.FirewallD1.config.zone"

# getZoneSettings2 returns a sparse a{sv} dict: keys holding an empty/default
# value are simply omitted rather than present with a zero value, so callers
# must merge onto these defaults rather than indexing the raw result.
ZONE_SETTINGS_DEFAULTS = {
    "short": "",
    "description": "",
    "target": "default",
    "services": [],
    "ports": [],
    "protocols": [],
    "source_ports": [],
    "icmp_blocks": [],
    "rich_rules": [],
    "interfaces": [],
    "sources": [],
    "masquerade": False,
    "forward": False,
    "icmp_block_inversion": False,
    "ingress_priority": 0,
    "egress_priority": 0,
}


class FirewalldClient(GObject.Object):
    """Async wrapper around firewalld's D-Bus API (org.fedoraproject.FirewallD1).

    All calls are async and dispatched on the caller's GLib main context, so no
    call ever blocks the UI thread while a PolicyKit prompt is pending. Signals
    from firewalld are re-emitted as GObject signals with plain Python types so
    page code doesn't need to know about D-Bus/GVariant wire details.
    """

    __gsignals__ = {
        "zone-updated": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "service-added": (GObject.SignalFlags.RUN_FIRST, None, (str, str)),
        "service-removed": (GObject.SignalFlags.RUN_FIRST, None, (str, str)),
        "port-added": (GObject.SignalFlags.RUN_FIRST, None, (str, str, str)),
        "port-removed": (GObject.SignalFlags.RUN_FIRST, None, (str, str, str)),
        "interface-zone-changed": (GObject.SignalFlags.RUN_FIRST, None, (str, str)),
        "panic-mode-changed": (GObject.SignalFlags.RUN_FIRST, None, (bool,)),
        "default-zone-changed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "reloaded": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(self):
        super().__init__()
        self._root_proxy = None
        self._zone_proxy = None
        self._config_proxy = None
        self._config_zone_proxies = {}

    # -- connection setup ---------------------------------------------------

    def connect_async(self, callback):
        """callback(error: FirewallGuiError | None), called once all three
        top-level proxies have been attempted."""
        state = {"pending": 3, "error": None}

        def maybe_finish():
            state["pending"] -= 1
            if state["pending"] == 0:
                callback(state["error"])

        def on_root(source, result, _data=None):
            try:
                self._root_proxy = Gio.DBusProxy.new_for_bus_finish(result)
            except GLib.Error as e:
                state["error"] = translate_dbus_error(e)
            else:
                self._root_proxy.connect("g-signal", self._on_root_signal)
            maybe_finish()

        def on_zone(source, result, _data=None):
            try:
                self._zone_proxy = Gio.DBusProxy.new_for_bus_finish(result)
            except GLib.Error as e:
                state["error"] = translate_dbus_error(e)
            else:
                self._zone_proxy.connect("g-signal", self._on_zone_signal)
            maybe_finish()

        def on_config(source, result, _data=None):
            try:
                self._config_proxy = Gio.DBusProxy.new_for_bus_finish(result)
            except GLib.Error as e:
                state["error"] = translate_dbus_error(e)
            maybe_finish()

        Gio.DBusProxy.new_for_bus(
            Gio.BusType.SYSTEM, Gio.DBusProxyFlags.NONE, None,
            BUS_NAME, MAIN_PATH, IFACE_ROOT, None, on_root, None,
        )
        Gio.DBusProxy.new_for_bus(
            Gio.BusType.SYSTEM, Gio.DBusProxyFlags.NONE, None,
            BUS_NAME, MAIN_PATH, IFACE_ZONE, None, on_zone, None,
        )
        Gio.DBusProxy.new_for_bus(
            Gio.BusType.SYSTEM, Gio.DBusProxyFlags.NONE, None,
            BUS_NAME, CONFIG_PATH, IFACE_CONFIG, None, on_config, None,
        )

    # -- signal dispatch ------------------------------------------------------

    def _on_root_signal(self, proxy, sender_name, signal_name, params):
        if signal_name == "PanicModeEnabled":
            self.emit("panic-mode-changed", True)
        elif signal_name == "PanicModeDisabled":
            self.emit("panic-mode-changed", False)
        elif signal_name == "DefaultZoneChanged":
            (zone,) = params.unpack()
            self.emit("default-zone-changed", zone)
        elif signal_name == "Reloaded":
            # Permanent-config object paths are not guaranteed stable across a
            # firewalld reload, so drop the cache and re-resolve lazily.
            self._config_zone_proxies.clear()
            self.emit("reloaded")

    def _on_zone_signal(self, proxy, sender_name, signal_name, params):
        values = params.unpack()
        if signal_name == "ZoneOfInterfaceChanged":
            zone, iface = values
            self.emit("interface-zone-changed", zone, iface)
        elif signal_name == "ServiceAdded":
            zone, service, _timeout = values
            self.emit("service-added", zone, service)
        elif signal_name == "ServiceRemoved":
            zone, service = values
            self.emit("service-removed", zone, service)
        elif signal_name == "PortAdded":
            zone, port, protocol, _timeout = values
            self.emit("port-added", zone, port, protocol)
        elif signal_name == "PortRemoved":
            zone, port, protocol = values
            self.emit("port-removed", zone, port, protocol)
        elif signal_name in ("ZoneUpdated", "InterfaceAdded", "InterfaceRemoved", "ZoneChanged"):
            zone = values[0]
            self.emit("zone-updated", zone)

    # -- low-level call helper -------------------------------------------------

    def _call(self, proxy, method, args, callback):
        """callback(result: tuple | None, error: FirewallGuiError | None)"""

        def on_done(source, result, _data=None):
            try:
                variant = proxy.call_finish(result)
            except GLib.Error as e:
                callback(None, translate_dbus_error(e))
                return
            callback(variant.unpack(), None)

        proxy.call(method, args, Gio.DBusCallFlags.NONE, -1, None, on_done, None)

    def _get_config_zone_proxy(self, zone, callback):
        """callback(proxy: Gio.DBusProxy | None, error: FirewallGuiError | None)"""
        cached = self._config_zone_proxies.get(zone)
        if cached is not None:
            callback(cached, None)
            return

        def on_path(result, error):
            if error:
                callback(None, error)
                return
            (path,) = result

            def on_proxy(source, res, _data=None):
                try:
                    proxy = Gio.DBusProxy.new_for_bus_finish(res)
                except GLib.Error as e:
                    callback(None, translate_dbus_error(e))
                    return
                self._config_zone_proxies[zone] = proxy
                callback(proxy, None)

            Gio.DBusProxy.new_for_bus(
                Gio.BusType.SYSTEM, Gio.DBusProxyFlags.NONE, None,
                BUS_NAME, path, IFACE_CONFIG_ZONE, None, on_proxy, None,
            )

        self._call(self._config_proxy, "getZoneByName", GLib.Variant("(s)", (zone,)), on_path)

    # -- paired runtime + permanent writes --------------------------------------

    def _apply_paired(self, zone, runtime_method, runtime_args, config_method, config_args, callback):
        """callback(ok: bool, error: FirewallGuiError | None, partial: bool)

        `partial` is True when the runtime write succeeded but the permanent
        write could not be resolved/applied (or vice versa) -- the one outcome
        that must never be collapsed into a plain success/failure, since it
        means the change will silently revert on the next reboot or reload.
        """

        def on_runtime(result, error):
            if error:
                callback(False, error, False)
                return
            self._get_config_zone_proxy(zone, on_config_zone_resolved)

        def on_config_zone_resolved(proxy, error):
            if proxy is None:
                callback(True, error, True)
                return

            def on_config_done(source, res, _data=None):
                try:
                    proxy.call_finish(res)
                except GLib.Error as e:
                    callback(True, translate_dbus_error(e), True)
                    return
                callback(True, None, False)

            proxy.call(config_method, config_args, Gio.DBusCallFlags.NONE, -1, None, on_config_done, None)

        self._call(self._zone_proxy, runtime_method, runtime_args, on_runtime)

    def add_service(self, zone, service, callback):
        self._apply_paired(
            zone,
            "addService", GLib.Variant("(ssi)", (zone, service, 0)),
            "addService", GLib.Variant("(s)", (service,)),
            callback,
        )

    def remove_service(self, zone, service, callback):
        self._apply_paired(
            zone,
            "removeService", GLib.Variant("(ss)", (zone, service)),
            "removeService", GLib.Variant("(s)", (service,)),
            callback,
        )

    def add_port(self, zone, port, protocol, callback):
        self._apply_paired(
            zone,
            "addPort", GLib.Variant("(sssi)", (zone, port, protocol, 0)),
            "addPort", GLib.Variant("(ss)", (port, protocol)),
            callback,
        )

    def remove_port(self, zone, port, protocol, callback):
        self._apply_paired(
            zone,
            "removePort", GLib.Variant("(sss)", (zone, port, protocol)),
            "removePort", GLib.Variant("(ss)", (port, protocol)),
            callback,
        )

    # -- reads -----------------------------------------------------------------

    def get_zones(self, callback):
        """callback(zones: list[str] | None, error)"""
        self._call(self._zone_proxy, "getZones", None, lambda r, e: callback(None if e else r[0], e))

    def get_active_zones(self, callback):
        """callback(active: dict[str, dict] | None, error) -- zone name ->
        {"interfaces": [...], "sources": [...]}"""
        self._call(self._zone_proxy, "getActiveZones", None, lambda r, e: callback(None if e else r[0], e))

    def get_zone_of_interface(self, interface, callback):
        self._call(
            self._zone_proxy, "getZoneOfInterface", GLib.Variant("(s)", (interface,)),
            lambda r, e: callback(None if e else r[0], e),
        )

    def get_zone_settings(self, zone, callback):
        """callback(settings: dict | None, error) -- merged onto ZONE_SETTINGS_DEFAULTS."""

        def on_result(result, error):
            if error:
                callback(None, error)
                return
            (raw,) = result
            settings = dict(ZONE_SETTINGS_DEFAULTS)
            settings.update(raw)
            callback(settings, None)

        self._call(self._zone_proxy, "getZoneSettings2", GLib.Variant("(s)", (zone,)), on_result)

    def change_zone_of_interface(self, zone, interface, callback):
        """Runtime-only, session-scoped move of an interface to a zone."""
        self._call(
            self._zone_proxy, "changeZoneOfInterface", GLib.Variant("(ss)", (zone, interface)),
            lambda r, e: callback(e is None, e),
        )

    def query_panic_mode(self, callback):
        self._call(self._root_proxy, "queryPanicMode", None, lambda r, e: callback(None if e else r[0], e))

    def set_panic_mode(self, enabled, callback):
        method = "enablePanicMode" if enabled else "disablePanicMode"
        self._call(self._root_proxy, method, None, lambda r, e: callback(e is None, e))

    def get_default_zone(self, callback):
        self._call(self._root_proxy, "getDefaultZone", None, lambda r, e: callback(None if e else r[0], e))

    def list_all_services(self, callback):
        """callback(services: list[str] | None, error) -- every service name
        firewalld knows about (predefined + any custom ones), for populating
        the Zone Editor's full service list."""
        self._call(self._root_proxy, "listServices", None, lambda r, e: callback(None if e else r[0], e))

    def get_service_settings(self, service, callback):
        """callback(settings: dict | None, error) -- raw firewalld service
        definition (ports, protocols, etc.), used to fill in the generic
        fallback description for services not in the curated catalog."""
        self._call(
            self._root_proxy, "getServiceSettings2", GLib.Variant("(s)", (service,)),
            lambda r, e: callback(None if e else r[0], e),
        )
