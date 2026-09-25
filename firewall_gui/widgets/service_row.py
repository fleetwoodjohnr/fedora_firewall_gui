import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .pending import ApplyControls, PendingValue

RISK_STYLE = {"low": "success", "medium": "warning", "high": "error"}


class ServiceRow(Adw.ExpanderRow):
    """One service in the Zone Editor's list: a collapsed row with a risk dot
    and an on/off switch, expanding to show the curated explanation.

    The switch previews a draft. Apply writes it to the runtime and permanent
    zone settings; the row reports success only after both are read back.
    """

    def __init__(self, name, info, enabled, on_toggle, on_result_error, on_first_expand=None, model=None):
        super().__init__()
        self._name = name
        self.name = name
        self.info = info
        self._on_toggle = on_toggle
        self._on_result_error = on_result_error
        self._on_first_expand = on_first_expand
        self._expanded_once = False
        self._syncing = False
        self._model = model or PendingValue(enabled)
        self._model.observe(enabled)

        self.set_title(info.label)
        self.set_subtitle(info.summary)
        self.add_css_class(f"service-risk-{info.risk}")

        dot = Gtk.Image.new_from_icon_name("media-record-symbolic")
        dot.add_css_class(RISK_STYLE.get(info.risk, "warning"))
        dot.set_tooltip_text(f"Risk if enabled on an untrusted network: {info.risk}")
        self.add_prefix(dot)

        self._switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self._switch.connect("notify::active", self._on_active_changed)
        self.add_suffix(self._switch)
        self._controls = ApplyControls(self._model, self._apply)
        self.add_suffix(self._controls)
        self._listener = self._model.connect(self._sync_switch)

        self._recommendation_label = Gtk.Label(
            label=f"{info.recommendation}\n\nCategory: {info.category}",
            wrap=True,
            xalign=0,
        )
        self._recommendation_label.add_css_class("dim-label")
        self._recommendation_label.set_margin_top(4)
        self._recommendation_label.set_margin_bottom(12)
        self._recommendation_label.set_margin_start(12)
        self._recommendation_label.set_margin_end(12)
        detail_row = Gtk.ListBoxRow(selectable=False, activatable=False)
        detail_row.set_child(self._recommendation_label)
        self.add_row(detail_row)

        if on_first_expand is not None:
            self.connect("notify::expanded", self._on_expanded_notify)

    def set_enabled(self, enabled):
        """Sync the row to backend state without triggering a write."""
        self._model.observe(enabled)

    def detach(self):
        self._model.disconnect(self._listener)
        self._controls.detach()

    def _sync_switch(self, model):
        self._syncing = True
        self._switch.set_state(bool(model.draft))
        self._switch.set_active(bool(model.draft))
        self._syncing = False

    def set_detail_text(self, summary, recommendation_text):
        self.set_subtitle(summary)
        self._recommendation_label.set_label(f"{recommendation_text}\n\nCategory: {self.info.category}")

    def _on_expanded_notify(self, row, _pspec):
        if self.get_expanded() and not self._expanded_once:
            self._expanded_once = True
            self._on_first_expand(self)

    def matches(self, query):
        if not query:
            return True
        query = query.lower()
        return query in self._name.lower() or query in self.info.label.lower() or query in self.info.summary.lower()

    def _on_active_changed(self, switch, _pspec):
        if not self._syncing:
            self._model.stage(switch.get_active())

    def _apply(self, requested_state, done):
        def on_result(ok, error, partial):
            if error is not None or partial:
                self._on_result_error(self._name, requested_state, error, partial)
            done(ok and not partial, error or ("runtime and saved rules differ" if partial else None))

        self._on_toggle(self._name, requested_state, on_result)
