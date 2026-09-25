"""Small, reusable model and controls for explicit settings changes."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


class PendingValue:
    def __init__(self, applied=None):
        self.applied = applied
        self.draft = applied
        self.busy = False
        self.conflict = False
        self.error = None
        self.retryable = False
        self.applied_message = None
        self._listeners = []

    @property
    def dirty(self):
        return self.draft != self.applied

    def connect(self, listener):
        self._listeners.append(listener)
        listener(self)
        return listener

    def disconnect(self, listener):
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _emit(self):
        for listener in tuple(self._listeners):
            listener(self)

    def stage(self, value):
        if self.busy:
            return
        if value == self.draft:
            return
        self.draft = value
        self.error = None
        self.retryable = False
        self.applied_message = None
        self.conflict = False
        self._emit()

    def discard(self):
        if self.busy:
            return
        self.draft = self.applied
        self.error = None
        self.retryable = False
        self.conflict = False
        self._emit()

    def observe(self, value):
        old = self.applied
        self.applied = value
        if self.draft == old or self.draft == value:
            self.draft = value
            self.conflict = False
        elif value != old:
            self.conflict = True
        self._emit()

    def begin(self):
        if self.busy or not (self.dirty or self.retryable):
            return False
        self.busy = True
        self.error = None
        self._emit()
        return True

    def finish(self, ok, error=None, applied=None):
        self.busy = False
        if ok:
            self.applied = self.draft if applied is None else applied
            self.draft = self.applied
            self.conflict = False
            self.error = None
            self.retryable = False
            self.applied_message = "Applied"
        else:
            self.error = None if error == "Still pending" else str(error or "Could not verify this change")
            self.retryable = self.error is not None
        self._emit()


class ApplyControls(Gtk.Box):
    """Reveals Apply/Discard only for a pending value, with a text status."""

    def __init__(self, model, on_apply):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=3, valign=Gtk.Align.CENTER)
        self._model = model
        self._on_apply = on_apply
        self.add_css_class("apply-controls")
        self.status = Gtk.Label(xalign=1)
        self.status.add_css_class("caption")
        self.append(self.status)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4, halign=Gtk.Align.END)
        self.discard_button = Gtk.Button(label="Discard")
        self.discard_button.add_css_class("flat")
        self.discard_button.connect("clicked", lambda *_: self._model.discard())
        self.apply_button = Gtk.Button(label="Apply")
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._apply)
        actions.append(self.discard_button)
        actions.append(self.apply_button)
        self.append(actions)
        self._actions = actions
        self._listener = model.connect(self._sync)

    def detach(self):
        self._model.disconnect(self._listener)

    def _apply(self, *_args):
        if self._model.conflict:
            dialog = Adw.AlertDialog.new(
                "Setting changed elsewhere",
                "The current value changed while this edit was pending. Apply your choice anyway?",
            )
            dialog.add_response("cancel", "Keep Editing")
            dialog.add_response("apply", "Apply My Choice")
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

            def answered(_source, result, _data=None):
                if dialog.choose_finish(result) == "apply":
                    self._do_apply()

            dialog.choose(self.get_root(), None, answered, None)
            return
        self._do_apply()

    def _do_apply(self):
        if not self._model.begin():
            return
        value = self._model.draft
        self._on_apply(value, lambda ok, error=None, applied=None: self._model.finish(ok, error, applied))

    def _sync(self, model):
        self._actions.set_visible(model.dirty or model.retryable)
        self.apply_button.set_label("Retry" if model.retryable else "Apply")
        self.apply_button.set_sensitive(not model.busy)
        self.discard_button.set_sensitive(not model.busy)
        if model.busy:
            message = "Applying…"
        elif model.error:
            message = model.error
        elif model.conflict:
            message = "Changed elsewhere • review before applying"
        elif model.dirty:
            message = "Pending"
        else:
            message = model.applied_message or "Current"
        self.status.set_label(message)
        self.status.remove_css_class("error")
        self.status.remove_css_class("warning")
        if model.error:
            self.status.add_css_class("error")
        elif model.conflict or model.dirty:
            self.status.add_css_class("warning")
