import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib, GObject

from .errors import translate_dbus_error

BUS_NAME = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
IFACE_MANAGER = "org.freedesktop.systemd1.Manager"


class SystemdClient(GObject.Object):
    """Async wrapper around the bits of systemd's D-Bus API needed to switch a
    system service on and off.

    Deliberately not routed through this app's privileged helper. systemd
    already exposes these operations with its own PolicyKit actions
    (org.freedesktop.systemd1.manage-units and manage-unit-files, both
    auth_admin_keep for an active local session), so this is the same
    arrangement the app uses for firewalld: let the service authorize the
    caller itself, and add no root code of our own.

    The practical payoff is that the SSH toggle keeps working on a machine where
    the optional hardening helper was never installed -- which matters, because
    turning off an SSH server nobody uses is worth more than most of what the
    helper does.
    """

    # We only ever call methods on this proxy: nothing reads a cached property
    # and nothing connects to g-signal. With the default flags GDBus would do a
    # GetAll of systemd's ~126 Manager properties and install a match rule for
    # every Manager signal -- which means a daemon-reload dumps unit and
    # property churn for all ~550 units onto our main context. Both
    # subscriptions are pure cost, so opt out of both.
    PROXY_FLAGS = (
        Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES | Gio.DBusProxyFlags.DO_NOT_CONNECT_SIGNALS
    )

    # Generous, because a PolicyKit password prompt sits inside the call. The
    # GDBus default of 25s would abort a sequence half-applied if the user were
    # slow to type, leaving a unit stopped but still enabled.
    CALL_TIMEOUT_MS = 120_000

    def __init__(self):
        super().__init__()
        self._manager = None
        self._pending_callbacks = None

    def connect_async(self, callback):
        """callback(error | None)"""

        def on_proxy(source, result, _data=None):
            try:
                self._manager = Gio.DBusProxy.new_for_bus_finish(result)
            except GLib.Error as e:
                callback(translate_dbus_error(e))
                return
            callback(None)

        Gio.DBusProxy.new_for_bus(
            Gio.BusType.SYSTEM, self.PROXY_FLAGS, None,
            BUS_NAME, MANAGER_PATH, IFACE_MANAGER, None, on_proxy, None,
        )

    def ensure_connected(self, callback):
        """callback(error | None) -- connects on first use, then no-ops.

        Callers that arrive while a connection is already in flight are queued
        rather than starting their own. _refresh_sshd runs both at page load and
        after every toggle, so without this two overlapping calls would each
        build a full proxy; only the last would be kept, and the other would
        leak with its match rules still live on the system bus.
        """
        if self._manager is not None:
            callback(None)
            return
        if self._pending_callbacks is not None:
            self._pending_callbacks.append(callback)
            return
        self._pending_callbacks = [callback]

        def on_connected(error):
            waiting, self._pending_callbacks = self._pending_callbacks, None
            for cb in waiting or ():
                cb(error)

        self.connect_async(on_connected)

    def _call(self, method, args, callback):
        """callback(result: tuple | None, error)"""
        if self._manager is None:
            callback(None, translate_dbus_error(GLib.Error("not connected to systemd")))
            return

        def on_done(source, result, _data=None):
            try:
                variant = self._manager.call_finish(result)
            except GLib.Error as e:
                callback(None, translate_dbus_error(e))
                return
            callback(variant.unpack(), None)

        self._manager.call(
            method, args, Gio.DBusCallFlags.NONE, self.CALL_TIMEOUT_MS, None, on_done, None
        )

    # -- reads (no prompt) --------------------------------------------------------

    def get_service_state(self, unit, callback):
        """callback(state: dict | None, error)

        Keys: exists (a unit file is installed), enabled (starts at boot),
        active (running right now).

        Uses ListUnitsByNames rather than GetUnit because GetUnit raises for a
        unit that isn't currently loaded, which is exactly the case we most need
        to report on -- a service that is installed but switched off.
        """

        def on_file_state(result, error):
            # A missing unit file is a legitimate answer ("not installed"), not
            # a failure worth surfacing to the user.
            file_state = result[0] if (result and not error) else None
            exists = file_state is not None
            enabled = file_state in ("enabled", "enabled-runtime", "static", "indirect")

            def on_units(units_result, units_error):
                active = False
                if not units_error and units_result:
                    for entry in units_result[0]:
                        # (name, description, load_state, active_state, ...)
                        if entry[0] == unit:
                            active = entry[3] == "active"
                            if entry[2] == "not-found":
                                pass
                            break
                callback({"exists": exists, "enabled": enabled, "active": active}, None)

            self._call("ListUnitsByNames", GLib.Variant("(as)", ([unit],)), on_units)

        self._call("GetUnitFileState", GLib.Variant("(s)", (unit,)), on_file_state)

    # -- writes (PolicyKit-authorized by systemd) -------------------------------------

    def set_service_enabled(self, unit, enabled, also_disable=(), callback=None):
        """Turn a service on or off, at boot and right now -- the equivalent of
        `systemctl enable --now` / `systemctl disable --now`.

        `also_disable` names extra units to switch off alongside the main one
        when turning it off. That exists for socket activation: disabling only
        sshd.service on a machine where sshd.socket is enabled leaves systemd
        able to spawn sshd on demand anyway, so the server would still be
        reachable and the toggle would be lying.

        callback(ok: bool, error)
        """
        # No Reload() step. `systemctl enable --now` doesn't run daemon-reload
        # either: EnableUnitFiles/DisableUnitFiles already update the unit-file
        # state and Start/StopUnit act on the live unit. Calling it made systemd
        # re-read every unit on the system and emit the churn that froze the UI.
        steps = []
        if enabled:
            steps.append(("EnableUnitFiles", GLib.Variant("(asbb)", ([unit], False, True))))
            steps.append(("StartUnit", GLib.Variant("(ss)", (unit, "replace"))))
        else:
            targets = [unit] + [u for u in also_disable]
            for target in targets:
                # Tolerated failure: a unit that isn't loaded can't be stopped,
                # which is the outcome we wanted anyway.
                steps.append(("StopUnit", GLib.Variant("(ss)", (target, "replace")), True))
            steps.append(("DisableUnitFiles", GLib.Variant("(asb)", (targets, False))))

        self._run_sequence(steps, callback or (lambda *_a: None))

    def _run_sequence(self, steps, callback):
        """Run D-Bus calls in order, stopping at the first real failure.

        Strictly sequential rather than fanned out: a unit file has to be
        enabled before it can be started, and stopped before it is disabled.
        """
        remaining = list(steps)

        def next_step(_result=None, error=None):
            if error is not None:
                callback(False, error)
                return
            if not remaining:
                callback(True, None)
                return
            step = remaining.pop(0)
            method, args = step[0], step[1]
            tolerate_failure = len(step) > 2 and step[2]

            def on_done(result, step_error):
                if step_error is not None and tolerate_failure:
                    next_step()
                    return
                next_step(result, step_error)

            self._call(method, args, on_done)

        next_step()
