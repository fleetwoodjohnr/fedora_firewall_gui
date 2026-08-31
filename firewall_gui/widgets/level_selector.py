import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .confirm import escape_markup

# Adw.ToggleGroup arrived in libadwaita 1.7. Fedora 41/42 ship 1.6, and this app
# is installed from a git checkout onto whatever the machine already has, so it
# has to keep working there.
HAVE_TOGGLE_GROUP = hasattr(Adw, "ToggleGroup")


class LevelSelector(Gtk.Box):
    """A hardening level picker: one switch with four notches, plus the plain-English
    consequences of whichever notch you're looking at.

    The description below the control is the reason this widget exists. Picking
    "Strict" out of a dropdown tells you nothing; the point is to read what it
    turns on and what it will break *before* you commit to it. So clicking a
    notch doesn't apply anything -- it swaps the description to that level and
    asks for confirmation, and the control only moves once the change has
    actually landed.

    That last part is the same non-optimistic rule every other control in this
    app follows (see widgets/service_row.py and the Panic Mode switch): the
    visible position always reflects the system, never the request.
    """

    def __init__(self, levels, on_apply, window, confirm_heading):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._levels = levels
        self._on_apply = on_apply
        self._window = window
        self._confirm_heading = confirm_heading
        self._active_index = 0
        self._syncing = False
        self._buttons = []

        self._build_control()

        self._description = Gtk.Label(wrap=True, xalign=0, use_markup=True)
        self._description.add_css_class("dim-label")
        self.append(self._description)

        self._show_description(0)

    # -- control construction ---------------------------------------------------

    def _build_control(self):
        if HAVE_TOGGLE_GROUP:
            self._group = Adw.ToggleGroup(halign=Gtk.Align.FILL, hexpand=True)
            for level in self._levels:
                self._group.add(Adw.Toggle(label=level.label))
            self._group.set_active(0)
            self._group.connect("notify::active", self._on_toggle_group_changed)
            self.append(self._group)
            return

        self._group = None
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, homogeneous=True)
        box.add_css_class("linked")
        first = None
        for index, level in enumerate(self._levels):
            button = Gtk.ToggleButton(label=level.label, hexpand=True)
            if first is None:
                first = button
                button.set_active(True)
            else:
                button.set_group(first)
            button.connect("toggled", self._on_fallback_toggled, index)
            self._buttons.append(button)
            box.append(button)
        self._fallback_box = box
        self.append(box)

    def _get_index(self):
        if self._group is not None:
            return self._group.get_active()
        for index, button in enumerate(self._buttons):
            if button.get_active():
                return index
        return 0

    def _set_index(self, index):
        """Move the control without triggering an apply."""
        self._syncing = True
        if self._group is not None:
            self._group.set_active(index)
        else:
            self._buttons[index].set_active(True)
        self._syncing = False

    # -- selection handling --------------------------------------------------------

    def _on_toggle_group_changed(self, group, _pspec):
        if self._syncing:
            return
        self._requested(group.get_active())

    def _on_fallback_toggled(self, button, index):
        # Gtk.ToggleButton groups emit for the button being switched off too.
        if self._syncing or not button.get_active():
            return
        self._requested(index)

    def _requested(self, index):
        if index == self._active_index:
            return
        level = self._levels[index]

        # Show what they just clicked on straight away, so the confirmation
        # dialog isn't the first place they read it -- then put the control back
        # where the system actually is until the change succeeds.
        self._show_description(index)
        self._set_index(self._active_index)

        def apply():
            self._set_sensitive_during_apply(False)

            def done(ok, error):
                self._set_sensitive_during_apply(True)
                if ok:
                    self._active_index = index
                    self._set_index(index)
                    self._show_description(index)
                else:
                    self._show_description(self._active_index)

            self._on_apply(level, done)

        def cancelled():
            self._show_description(self._active_index)

        confirm_dialog(
            self._window,
            f"{self._confirm_heading}: {level.label}?",
            f"{level.detail}\n\nWhat this might break:\n{level.breaks}",
            f"Switch to {level.label}",
            apply,
            cancelled,
            destructive=level.id == "strict",
        )

    def _set_sensitive_during_apply(self, sensitive):
        if self._group is not None:
            self._group.set_sensitive(sensitive)
        else:
            self._fallback_box.set_sensitive(sensitive)

    def _show_description(self, index):
        level = self._levels[index]
        current = " (current)" if index == self._active_index else ""
        self._description.set_markup(
            f"<b>{escape_markup(level.label)}{current}</b> — {escape_markup(level.summary)}\n\n"
            f"{escape_markup(level.detail)}\n\n"
            f"<b>What this might break:</b> {escape_markup(level.breaks)}"
        )

    # -- external state sync ----------------------------------------------------------

    def set_active_level(self, level_id):
        """Point the control at what the system actually reports, without
        applying anything. Used on load and whenever status is re-read."""
        for index, level in enumerate(self._levels):
            if level.id == level_id:
                self._active_index = index
                self._set_index(index)
                self._show_description(index)
                return
        self._active_index = 0
        self._set_index(0)
        self._show_description(0)

    def get_active_level(self):
        return self._levels[self._active_index]



def confirm_dialog(parent, heading, body, confirm_label, on_confirm, on_cancel, destructive=True):
    """confirm() from widgets/confirm.py with a cancel callback, which this
    widget needs so a dismissed dialog can put the description text back."""
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
        else:
            on_cancel()

    dialog.choose(parent, None, on_response, None)
