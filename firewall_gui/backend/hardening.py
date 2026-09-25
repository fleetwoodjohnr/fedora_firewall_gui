import json
import os

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

from .errors import HelperError, HelperNotInstalled, HelperVersionMismatch, translate_helper_error

HELPER_PATH = "/usr/libexec/firewall-gui-helper"

# Must match PROTOCOL_VERSION in packaging/helper/firewall-gui-helper. The app
# updates itself from git on a user timer, but the helper lives in /usr/libexec
# and can only be replaced with sudo, so the two will drift apart eventually.
# Detecting that is much better than misreading a status payload.
PROTOCOL_VERSION = 2

# A PolicyKit prompt sits inside a privileged run, so this has to allow for a
# person finding their password. It exists only so that a prompt that never
# resolves can't leave the control greyed out forever -- previously there was
# no timeout at all and no path back to a usable UI.
CALL_TIMEOUT_SECONDS = 180


class HardeningClient:
    """Async wrapper around the privileged hardening helper.

    Same shape as NetworkManagerClient: argv lists, never a shell, Gio.Subprocess
    so nothing blocks the GTK main loop while a PolicyKit prompt is on screen.

    Reads and writes take different routes on purpose. `get_status` runs the
    helper directly as the current user -- everything it reports is either
    world-readable or recorded in a world-readable state file -- so opening the
    Hardening page never triggers a password prompt. Only the apply/revert verbs
    go through pkexec.
    """

    def __init__(self):
        self._protocol_ok = None

    # -- capability probe ------------------------------------------------------

    def is_installed(self):
        """Whether system-level hardening is available at all. The app is
        installed into ~/.local without root, so the helper is an optional
        extra step; the page degrades to a banner rather than an error when it
        is missing."""
        return os.path.exists(HELPER_PATH)

    @staticmethod
    def install_command(src_dir=None):
        """The exact command that installs the helper, shown to the user
        verbatim whenever it's missing or out of date."""
        src = src_dir or "~/.local/share/firewall-gui-src"
        return f"cd {src} && ./install.sh"

    # -- process plumbing --------------------------------------------------------

    def _run(self, args, privileged, callback):
        """callback(stdout: str | None, error: HelperError | None)"""
        if not self.is_installed():
            callback(None, HelperNotInstalled(
                "the privileged helper isn't installed, so system-level hardening is unavailable"
            ))
            return

        argv = (["pkexec", HELPER_PATH] if privileged else [HELPER_PATH]) + args
        try:
            proc = Gio.Subprocess.new(
                argv, Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            )
        except GLib.Error as e:
            callback(None, translate_helper_error(-1, str(e)))
            return

        # Guard against a call that never comes back. `finished` makes the two
        # paths mutually exclusive, so a late timeout can't fire after success
        # and a completion can't run after we've already reported a timeout.
        state = {"finished": False, "timeout_id": None}

        def finish(stdout, error):
            if state["finished"]:
                return
            state["finished"] = True
            if state["timeout_id"] is not None:
                GLib.source_remove(state["timeout_id"])
                state["timeout_id"] = None
            callback(stdout, error)

        def on_timeout():
            state["timeout_id"] = None
            proc.force_exit()
            finish(None, HelperError(
                f"the helper didn't respond within {CALL_TIMEOUT_SECONDS} seconds and was stopped. "
                "If an authentication prompt appeared, it may have been dismissed or missed."
            ))
            return GLib.SOURCE_REMOVE

        def on_done(source, result, _data=None):
            # After a timeout we've already reported and force-killed the child;
            # returning early keeps us from asking a signal-killed process for an
            # exit status, which GLib rightly complains about.
            if state["finished"]:
                return
            try:
                _ok, stdout, stderr = proc.communicate_utf8_finish(result)
            except GLib.Error as e:
                finish(None, translate_helper_error(-1, str(e)))
                return
            if not proc.get_if_exited():
                finish(None, HelperError("the helper was terminated before it could finish"))
                return
            status = proc.get_exit_status()
            if status != 0:
                finish(None, translate_helper_error(status, stderr))
                return
            finish(stdout, None)

        state["timeout_id"] = GLib.timeout_add_seconds(CALL_TIMEOUT_SECONDS, on_timeout)
        proc.communicate_utf8_async(None, None, on_done, None)

    def _run_json(self, args, privileged, callback):
        """callback(payload: dict | None, error)"""

        def on_result(stdout, error):
            if error is not None:
                callback(None, error)
                return
            try:
                callback(json.loads(stdout), None)
            except ValueError as e:
                callback(None, translate_helper_error(0, f"unreadable response from the helper: {e}"))

        self._run(args, privileged, on_result)

    # -- reads ---------------------------------------------------------------------

    def get_status(self, callback):
        """callback(status: dict | None, error) -- unprivileged, no prompt.

        See the helper's own status() docstring for what each field means. Of
        note: `ssh_dropin` is always None here because /etc/ssh/sshd_config.d is
        mode 0700, so the recorded state under `state.crypto` is what the page
        should trust for SSH.
        """

        def on_payload(payload, error):
            if error is not None:
                callback(None, error)
                return
            protocol = payload.get("protocol")
            if protocol != PROTOCOL_VERSION:
                callback(None, HelperVersionMismatch(
                    f"the installed helper speaks protocol {protocol}, but this version of the app "
                    f"expects {PROTOCOL_VERSION}. Reinstall it with:\n  {self.install_command()}"
                ))
                return
            callback(payload, None)

        self._run_json(["status"], privileged=False, callback=on_payload)

    # -- writes -----------------------------------------------------------------------

    def apply_dns(self, level, callback):
        """callback(ok: bool, error)"""
        verb = ["revert-dns"] if level == "off" else ["apply-dns", level]
        self._run_json(verb, privileged=True, callback=lambda r, e: callback(e is None, e))

    def apply_crypto(self, level, callback):
        """callback(ok: bool, error)"""
        verb = ["revert-crypto"] if level == "off" else ["apply-crypto", level]
        self._run_json(verb, privileged=True, callback=lambda r, e: callback(e is None, e))
