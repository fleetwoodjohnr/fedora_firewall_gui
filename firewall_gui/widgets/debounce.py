import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib


class Debouncer:
    """Collapse a burst of signals into a single deferred call.

    firewalld emits one signal per change, and three pages each answer every
    one of them with a refresh. The Zone Editor's refresh is the expensive one:
    it tears down and rebuilds an Adw.ExpanderRow (plus a switch, two labels and
    an image) for all 265 services firewalld knows about -- measured at 0.29s of
    uninterrupted main-loop time per rebuild. Applying a hardening level changes
    several services at once, so those costs land back to back with nothing else
    able to run in between, and the compositor puts up "Application is not
    responding" after five seconds of that.

    Debouncing turns N signals from one user action into one refresh. The delay
    is deliberately longer than the gap between signals in a burst but short
    enough to feel immediate.
    """

    def __init__(self, func, delay_ms=250):
        self._func = func
        self._delay_ms = delay_ms
        self._source_id = None

    def __call__(self, *_args):
        """Signal-handler shaped: swallows whatever arguments it is given."""
        if self._source_id is not None:
            GLib.source_remove(self._source_id)
        self._source_id = GLib.timeout_add(self._delay_ms, self._fire)

    def _fire(self):
        self._source_id = None
        self._func()
        return GLib.SOURCE_REMOVE

    def cancel(self):
        if self._source_id is not None:
            GLib.source_remove(self._source_id)
            self._source_id = None
