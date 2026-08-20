import json
import os

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib, GObject

SETTINGS_DIR = os.path.join(GLib.get_user_config_dir(), "firewall-gui")
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "settings.json")


class AppSettings(GObject.Object):
    show_all_zones = GObject.Property(type=bool, default=False)

    def __init__(self):
        super().__init__()
        self._loading = False
        self._load()
        self.connect("notify::show-all-zones", self._on_changed)

    def _load(self):
        data = {}
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            pass
        self._loading = True
        self.show_all_zones = bool(data.get("show_all_zones", False))
        self._loading = False

    def _on_changed(self, *_args):
        if not self._loading:
            self._save()

    def _save(self):
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            tmp_path = SETTINGS_PATH + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"show_all_zones": self.show_all_zones}, f)
            os.replace(tmp_path, SETTINGS_PATH)
        except OSError:
            pass
