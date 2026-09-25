import gi

gi.require_version("Adw", "1")
gi.require_version("GLib", "2.0")
from gi.repository import Adw, GLib


def escape_markup(text):
    """Adw title/subtitle/heading/body setters parse their text as Pango
    markup, so any external text (e.g. a NetworkManager connection name a
    user could set to anything) must be escaped before display."""
    return GLib.markup_escape_text(str(text))


def confirm(parent, heading, body, confirm_label, on_confirm, destructive=True, on_cancel=None):
    """Show a Cancel/Confirm Adw.AlertDialog. `on_confirm` is called with no
    arguments only if the user picks the confirm response."""
    dialog = Adw.AlertDialog.new(heading, body)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", confirm_label)
    dialog.set_response_appearance(
        "confirm", Adw.ResponseAppearance.DESTRUCTIVE if destructive else Adw.ResponseAppearance.SUGGESTED
    )
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(source, result, _data=None):
        if dialog.choose_finish(result) == "confirm":
            on_confirm()
        elif on_cancel is not None:
            on_cancel()

    dialog.choose(parent, None, on_response, None)


def show_toast(overlay, message, timeout=4):
    toast = Adw.Toast.new(message)
    toast.set_timeout(timeout)
    overlay.add_toast(toast)


def show_error_toast(overlay, error, prefix="Error"):
    show_toast(overlay, f"{prefix}: {error}", timeout=6)
