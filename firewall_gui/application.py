import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from .window import FirewallGuiWindow

APP_ID = "org.jrf.FirewallGui"
STYLE_PATH = os.path.join(os.path.dirname(__file__), "style.css")


class FirewallGuiApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._window = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        self._load_stylesheet()

    def _load_stylesheet(self):
        """Load style.css at APPLICATION priority, so it overrides Adwaita's
        defaults but a user's own ~/.config/gtk-4.0/gtk.css can still win.

        A missing or broken stylesheet must never stop the app starting -- the
        app is fully usable unstyled, and a colour is not worth a crash.
        """
        display = Gdk.Display.get_default()
        if display is None:
            return
        provider = Gtk.CssProvider()
        try:
            provider.load_from_path(STYLE_PATH)
        except GLib.Error:
            return
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def do_activate(self):
        if self._window is None:
            self._window = FirewallGuiWindow(application=self)
        self._window.present()
