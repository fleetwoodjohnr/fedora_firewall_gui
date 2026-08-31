import gi

gi.require_version("Adw", "1")
from gi.repository import Adw  # noqa: F401  (ensures the Adw types are registered)


class StateBackedSwitch:
    """Drives an Adw.SwitchRow whose position always reflects confirmed system
    state, never an unconfirmed request.

    The obvious way to write this is to revert the switch inside its own
    notify::active handler, wrapped in a boolean "syncing" guard. That is what
    this app did everywhere, and it is broken: when set_active() is called from
    inside the handler, GObject can deliver the resulting notification *after*
    the guard has been cleared. The revert then reads as a brand-new user
    toggle, which reverts again, and the two states ping-pong forever -- each
    iteration putting up another confirmation dialog and another privileged
    call, until the app stops responding.

    Comparing against the last known applied state is immune to when the
    notification is delivered, because it never depends on a window of time:
    a notification whose value already matches reality is not a request, no
    matter who caused it or when it lands. (LevelSelector never had this bug
    precisely because it compares against its own _active_index.)
    """

    def __init__(self, row, on_request):
        """on_request(wanted: bool, done: callable(ok: bool)) -> None

        Called only for a genuine user request. Call done(True) once the change
        is confirmed applied; call done(False), or simply never call it, to
        leave the switch showing the unchanged state.
        """
        self._row = row
        self._on_request = on_request
        self._applied = None
        row.connect("notify::active", self._on_notify)

    @property
    def applied(self):
        return self._applied

    def set_applied(self, value):
        """Point the switch at confirmed system state without asking anything."""
        self._applied = bool(value)
        self._row.set_active(self._applied)

    def _on_notify(self, row, _pspec):
        wanted = row.get_active()
        # Before the first set_applied we don't know what reality is, so we
        # can't tell a request from an initialisation. Do nothing.
        if self._applied is None or wanted == self._applied:
            return

        # Snap back to reality. The notification this causes re-enters here and
        # hits the equality check above, so it stops cleanly.
        row.set_active(self._applied)

        def done(ok):
            if ok:
                self.set_applied(wanted)

        self._on_request(wanted, done)
