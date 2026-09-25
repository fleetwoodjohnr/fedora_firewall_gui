"""Keep saved NetworkManager zones and active firewalld zones together."""

import gi

gi.require_version("GObject", "2.0")
from gi.repository import GObject

from ..widgets.pending import PendingValue


class ZoneAssignmentController(GObject.Object):
    __gsignals__ = {
        "applied": (GObject.SignalFlags.RUN_FIRST, None, (str, str)),
    }

    def __init__(self, netmgr, firewalld):
        super().__init__()
        self._nm = netmgr
        self._fw = firewalld
        self._models = {}

    def model_for(self, uuid):
        if uuid not in self._models:
            self._models[uuid] = PendingValue()
        return self._models[uuid]

    def observe(self, uuid, zone):
        self.model_for(uuid).observe(zone)

    def apply(self, uuid, zone, callback):
        """callback(ok, error); a successful result was read back from both services."""

        def saved(ok, error):
            if not ok:
                callback(False, error)
                return
            self._nm.get_connection_zone(uuid, read_saved)

        def read_saved(observed, error):
            if error or observed != zone:
                callback(False, error or f"profile still reports {observed or 'the default zone'}")
                return
            self._nm.get_active_connections(active_connections)

        def active_connections(connections, error):
            if error:
                callback(False, f"Saved to profile, but active interfaces could not be checked: {error}")
                return
            interfaces = sorted({c["device"] for c in connections or [] if c["uuid"] == uuid and c["device"]})
            if not interfaces:
                self.observe(uuid, zone)
                self.emit("applied", uuid, zone)
                callback(True, None)
                return
            state = {"remaining": len(interfaces), "errors": []}

            def one_finished(iface, observed, error):
                if error or observed != zone:
                    detail = str(error) if error else f"active zone is {observed or 'unknown'}"
                    state["errors"].append(f"{iface}: {detail}")
                state["remaining"] -= 1
                if state["remaining"]:
                    return
                if state["errors"]:
                    callback(False, "Saved to profile, but " + "; ".join(state["errors"]))
                else:
                    self.observe(uuid, zone)
                    self.emit("applied", uuid, zone)
                    callback(True, None)

            for iface in interfaces:
                def checked(observed, error, device=iface):
                    if error is None and observed == zone:
                        one_finished(device, observed, None)
                        return

                    def moved(ok, move_error):
                        if not ok:
                            one_finished(device, observed, move_error)
                        else:
                            self._fw.get_zone_of_interface(
                                device, lambda actual, read_error: one_finished(device, actual, read_error)
                            )

                    self._fw.change_zone_of_interface(zone, device, moved)

                self._fw.get_zone_of_interface(iface, checked)

        self._nm.set_connection_zone(uuid, zone, saved)
