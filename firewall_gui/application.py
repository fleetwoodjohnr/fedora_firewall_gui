import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio

from .window import FirewallGuiWindow

APP_ID = "org.jrf.FirewallGui"


class FirewallGuiApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._window = None

    def do_activate(self):
        if self._window is None:
            self._window = FirewallGuiWindow(application=self)
        self._window.present()
