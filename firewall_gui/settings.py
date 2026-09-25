import json
import os

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib, GObject

SETTINGS_DIR = os.path.join(GLib.get_user_config_dir(), "firewall-gui")
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "settings.json")


class AppSettings(GObject.Object):
    show_all_zones = GObject.Property(type=bool, default=False)
    monitoring_owned = GObject.Property(type=bool, default=False)

    # Which resolver the Hardening page pins, and on which saved connections.
    # Both are app-side preferences: the system state itself lives in
    # NetworkManager, and is re-read from there rather than trusted from here.
    dns_provider = GObject.Property(type=str, default="automatic")

    # GObject has no list property type, so these hold a JSON array as a string.
    # Use the pinned_uuids / removed_services accessors below rather than
    # touching them directly.
    dns_pinned_uuids = GObject.Property(type=str, default="[]")

    # The services the encryption level removed from the default zone, recorded
    # so that going back to Off puts back exactly what was taken away instead of
    # guessing from the level tables -- the user may have closed some of them
    # by hand in the Zone Editor first, and those should stay closed.
    encryption_removed_services = GObject.Property(type=str, default="[]")

    # name -> default. Both _load and _save iterate this, so adding a setting
    # means adding one line here and one GObject.Property above.
    _KEYS = {
        "show_all_zones": False,
        "monitoring_owned": False,
        "dns_provider": "automatic",
        "dns_pinned_uuids": "[]",
        "encryption_removed_services": "[]",
    }

    def __init__(self):
        super().__init__()
        self._loading = False
        self._load()
        for name in self._KEYS:
            self.connect(f"notify::{name.replace('_', '-')}", self._on_changed)

    def _load(self):
        data = {}
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            pass
        self._loading = True
        for name, default in self._KEYS.items():
            value = data.get(name, default)
            # A settings file edited by hand (or written by an older version)
            # shouldn't be able to hand a page the wrong type.
            setattr(self, name, bool(value) if isinstance(default, bool) else str(value))
        self._loading = False

    def _on_changed(self, *_args):
        if not self._loading:
            self._save()

    def _save(self):
        try:
            self._write_data({name: getattr(self, name) for name in self._KEYS})
        except OSError:
            pass

    @staticmethod
    def _write_data(data):
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        tmp_path = SETTINGS_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, SETTINGS_PATH)

    def apply(self, name, value):
        """Persist a UI preference before reporting it applied to its control."""
        if name not in self._KEYS:
            return False, f"unknown preference: {name}"
        data = {key: getattr(self, key) for key in self._KEYS}
        data[name] = value
        try:
            self._write_data(data)
        except OSError as error:
            return False, error
        self._loading = True
        try:
            setattr(self, name, value)
        finally:
            self._loading = False
        return True, None

    # -- JSON-backed list accessors ---------------------------------------------

    @staticmethod
    def _decode_list(raw):
        try:
            value = json.loads(raw)
        except ValueError:
            return []
        return [str(item) for item in value] if isinstance(value, list) else []

    def get_pinned_uuids(self):
        return self._decode_list(self.dns_pinned_uuids)

    def set_pinned_uuids(self, uuids):
        self.dns_pinned_uuids = json.dumps(sorted(set(uuids)))

    def get_removed_services(self):
        return self._decode_list(self.encryption_removed_services)

    def set_removed_services(self, services):
        self.encryption_removed_services = json.dumps(sorted(set(services)))
