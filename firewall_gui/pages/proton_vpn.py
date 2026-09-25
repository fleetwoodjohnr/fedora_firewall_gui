import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..widgets.confirm import confirm, escape_markup, show_error_toast, show_toast
from ..widgets.page_intro import page_intro


STATE_ICONS = {
    "connected": "emblem-ok-symbolic",
    "connected-limited": "dialog-warning-symbolic",
    "connecting": "content-loading-symbolic",
    "credential-error": "dialog-error-symbolic",
    "retryable-error": "dialog-warning-symbolic",
    "keyring-locked": "changes-prevent-symbolic",
    "signed-out": "system-log-out-symbolic",
    "disconnected": "network-offline-symbolic",
    "not-installed": "dialog-information-symbolic",
}


class ProtonVpnPage(Adw.PreferencesPage):
    def __init__(self, window, proton):
        super().__init__(title="Proton VPN", icon_name="network-vpn-symbolic")
        self._window = window
        self._proton = proton
        self._diagnosis = None
        self._busy = False
        self._refresh_generation = 0

        self.add(page_intro("Proton VPN", "See tunnel health and the next useful repair action in one place.", "network-vpn-symbolic"))

        self._build_status_group()
        self._build_actions_group()

    def _build_status_group(self):
        group = Adw.PreferencesGroup(
            title="VPN Health",
            description=(
                "Checks Proton's tunnel, NetworkManager connectivity, recent Proton events, "
                "and whether an entry exists in your desktop keyring. Secret values are never read."
            ),
        )
        self.add(group)

        self._connection_row = Adw.ActionRow(title="Checking Proton VPN…")
        self._connection_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
        self._connection_row.add_prefix(self._connection_icon)
        self._connection_row.set_subtitle_lines(0)
        group.add(self._connection_row)

        self._credential_row = Adw.ActionRow(title="Stored sign-in", subtitle="Checking desktop keyring…")
        self._credential_row.set_subtitle_lines(0)
        group.add(self._credential_row)

        self._problem_row = Adw.ActionRow(title="Recent Proton log", subtitle="Checking recent events…")
        self._problem_row.set_subtitle_lines(0)
        group.add(self._problem_row)

    def _build_actions_group(self):
        group = Adw.PreferencesGroup(
            title="Repair",
            description="Actions are enabled only when the matching current problem is detected.",
        )
        self.add(group)

        recheck_row = Adw.ActionRow(
            title="Run diagnostics again",
            subtitle="Refresh connection, connectivity, keyring metadata, and recent Proton events.",
        )
        self._recheck_button = Gtk.Button(label="Recheck", valign=Gtk.Align.CENTER)
        self._recheck_button.connect("clicked", lambda *_args: self.refresh())
        recheck_row.add_suffix(self._recheck_button)
        group.add(recheck_row)

        self._retry_row = Adw.ActionRow(
            title="Retry Proton VPN connection",
            subtitle=(
                "Available for a current server-session failure, timeout, or connected tunnel "
                "with limited internet."
            ),
        )
        self._retry_row.set_subtitle_lines(0)
        self._retry_button = Gtk.Button(label="Retry Connection", valign=Gtk.Align.CENTER)
        self._retry_button.add_css_class("suggested-action")
        self._retry_button.set_sensitive(False)
        self._retry_button.connect("clicked", self._on_retry_clicked)
        self._retry_row.add_suffix(self._retry_button)
        group.add(self._retry_row)

        self._reset_row = Adw.ActionRow(
            title="Reset Proton sign-in",
            subtitle="Available only when Proton reports an unresolved credential or certificate failure.",
        )
        self._reset_row.set_subtitle_lines(0)
        self._reset_button = Gtk.Button(label="Reset Sign-in", valign=Gtk.Align.CENTER)
        self._reset_button.add_css_class("destructive-action")
        self._reset_button.set_sensitive(False)
        self._reset_button.connect("clicked", self._on_reset_clicked)
        self._reset_row.add_suffix(self._reset_button)
        group.add(self._reset_row)

    def refresh(self):
        if self._busy:
            return
        self._refresh_generation += 1
        generation = self._refresh_generation
        self._set_controls_sensitive(False)
        self._connection_row.set_title("Checking Proton VPN…")
        self._connection_row.set_subtitle("Reading current tunnel and internet state.")
        self._connection_icon.set_from_icon_name("content-loading-symbolic")
        self._credential_row.set_subtitle("Checking desktop keyring metadata…")
        self._problem_row.set_subtitle("Checking recent normalized events…")

        def on_diagnosis(diagnosis, error):
            if generation != self._refresh_generation:
                return
            self._diagnosis = diagnosis
            self._apply_diagnosis(diagnosis)
            if error is not None:
                show_error_toast(self._window.toast_overlay, error, "Some Proton checks failed")

        self._proton.diagnose(on_diagnosis)

    def _apply_diagnosis(self, diagnosis):
        self._connection_row.set_title(escape_markup(diagnosis.title))
        detail = diagnosis.detail
        if diagnosis.connection_name:
            detail = f"{detail} Active profile: {diagnosis.connection_name}."
        self._connection_row.set_subtitle(escape_markup(detail))
        self._connection_icon.set_from_icon_name(
            STATE_ICONS.get(diagnosis.state, "dialog-question-symbolic")
        )

        credential_titles = {
            "found": "Stored sign-in found",
            "locked": "Desktop keyring locked",
            "missing": "No stored Proton sign-in",
            "unavailable": "Credential status unavailable",
        }
        self._credential_row.set_title(
            credential_titles.get(diagnosis.credential_state, "Credential status unknown")
        )
        self._credential_row.set_subtitle(escape_markup(diagnosis.credential_detail))

        current_problem = diagnosis.retry_allowed or diagnosis.credential_reset_allowed
        if current_problem:
            self._problem_row.set_title("Current detected problem")
        elif diagnosis.last_problem_time:
            self._problem_row.set_title("Most recent problem (resolved)")
        else:
            self._problem_row.set_title("Recent Proton log")
        problem = diagnosis.last_problem
        if diagnosis.last_problem_time:
            problem = f"{problem} Event time: {diagnosis.last_problem_time}."
        self._problem_row.set_subtitle(escape_markup(problem))

        self._set_controls_sensitive(True)

    def _set_controls_sensitive(self, sensitive):
        self._recheck_button.set_sensitive(sensitive and not self._busy)
        self._retry_button.set_sensitive(
            sensitive and not self._busy and bool(self._diagnosis and self._diagnosis.retry_allowed)
        )
        self._reset_button.set_sensitive(
            sensitive
            and not self._busy
            and bool(self._diagnosis and self._diagnosis.credential_reset_allowed)
        )

    def _on_retry_clicked(self, *_args):
        if not self._diagnosis or not self._diagnosis.retry_allowed:
            return

        confirm(
            self._window,
            "Retry the Proton VPN connection?",
            "This closes the Proton VPN window, disconnects any incomplete tunnel, connects to "
            "Proton's fastest available server with the official CLI, and reopens Proton VPN.",
            "Retry Connection",
            lambda: self._run_repair("retry"),
            destructive=False,
        )

    def _on_reset_clicked(self, *_args):
        if not self._diagnosis or not self._diagnosis.credential_reset_allowed:
            return

        confirm(
            self._window,
            "Reset Proton VPN sign-in?",
            "This disconnects Proton VPN, closes its window, and uses Proton's official sign-out "
            "command to clear the broken local session. Proton VPN will reopen at its login screen, "
            "where you must sign in again.",
            "Reset Sign-in",
            lambda: self._run_repair("reset"),
            destructive=True,
        )

    def _run_repair(self, operation):
        self._busy = True
        self._set_controls_sensitive(False)
        if operation == "reset":
            self._reset_row.set_subtitle("Closing Proton VPN and resetting its stored sign-in…")
            action = self._proton.reset_credentials
            success_message = "Proton sign-in reset. Sign in again in the reopened Proton VPN app."
            error_prefix = "Couldn't reset Proton sign-in"
        else:
            self._retry_row.set_subtitle("Closing Proton VPN and starting a fresh fastest-server connection…")
            action = self._proton.retry_connection
            success_message = "Proton VPN reconnected and reopened."
            error_prefix = "Couldn't retry Proton VPN"

        def on_finished(ok, error):
            self._busy = False
            if ok:
                show_toast(self._window.toast_overlay, success_message, timeout=6)
            else:
                show_error_toast(self._window.toast_overlay, error or "unknown error", error_prefix)
            self.refresh()

        action(on_finished)
