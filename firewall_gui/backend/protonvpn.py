"""Proton VPN health diagnostics and guarded repair actions.

The diagnostic side deliberately never asks Secret Service for a secret.  It
only searches for item object paths, then combines that metadata with
NetworkManager state and normalized events from Proton's own application log.

Repair actions use Proton's public CLI.  The GUI and CLI refuse to run at the
same time, so the Proton desktop process is located through D-Bus, verified to
belong to this user and to have Proton's launcher in its command line, and then
stopped before a command is run.  No shell or privileged helper is involved.
"""

from dataclasses import dataclass
import os
import shutil
import signal
from typing import Callable, Optional

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GioUnix", "2.0")
from gi.repository import Gio, GioUnix, GLib

from .errors import ProtonVpnError


PROTON_APP_BUS_NAME = "proton.vpn.app.gtk"
PROTON_DESKTOP_ID = "proton.vpn.app.gtk.desktop"
PROTON_CONNECTION_PREFIX = "ProtonVPN "
PROTON_DEVICE = "proton0"
LOG_TAIL_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ParsedProtonLog:
    connection_state: str = "unknown"
    issue: str = "none"
    issue_time: str = ""
    issue_detail: str = "No unresolved Proton VPN problem was found in the recent log."


@dataclass(frozen=True)
class KeyringProbe:
    state: str
    item_count: int = 0


@dataclass(frozen=True)
class ProtonVpnDiagnosis:
    state: str
    title: str
    detail: str
    connection_name: str = ""
    connectivity: str = "unknown"
    credential_state: str = "unknown"
    credential_detail: str = "Credential status could not be checked."
    last_problem: str = "No unresolved Proton VPN problem was found."
    last_problem_time: str = ""
    retry_allowed: bool = False
    credential_reset_allowed: bool = False


def _line_timestamp(line: str) -> str:
    first, separator, _rest = line.partition(" | ")
    return first if separator else ""


def parse_proton_log(text: str) -> ParsedProtonLog:
    """Reduce Proton's log to safe state labels without retaining raw lines.

    Events are processed in file order.  A later successful connection clears
    a connection/session failure, and a later successful certificate refresh
    clears an expired-certificate failure.  This prevents an old incident from
    enabling a destructive repair indefinitely.
    """

    connection_state = "unknown"
    issue = "none"
    issue_time = ""
    issue_detail = "No unresolved Proton VPN problem was found in the recent log."

    for line in text.splitlines():
        lowered = line.lower()
        timestamp = _line_timestamp(line)

        if "conn:state_changed | connected" in lowered:
            connection_state = "connected"
            issue = "none"
            continue
        if "conn:state_changed | connecting" in lowered:
            connection_state = "connecting"
        elif "conn:state_changed | disconnected" in lowered:
            connection_state = "disconnected"
        elif "conn:state_changed | error" in lowered:
            connection_state = "error"

        # A successful /vpn/v1/certificate response is followed by this
        # message.  It is stronger evidence than the earlier "requires refresh"
        # warning, which is normal shortly before renewal.
        if "certificate_refresher" in lowered and "next certificate refresh scheduled" in lowered:
            if issue == "credential":
                issue = "none"
            continue

        credential_markers = (
            "expiredcertificate",
            "protonapiauthenticationneeded",
            "authentication needed",
            "incorrect credentials",
            "invalid credentials",
            "missing scope",
            "keyring credential is not valid",
        )
        if any(marker in lowered for marker in credential_markers):
            issue = "credential"
            issue_time = timestamp
            issue_detail = (
                "Proton reported an expired or invalid local login or certificate."
            )
            continue

        if "86203" in lowered or "session not found" in lowered:
            issue = "retryable"
            issue_time = timestamp
            issue_detail = (
                "The Proton server could not find the temporary VPN session. "
                "This is a tunnel-session error, not a stored-password error."
            )
            continue

        if "connect timeout" in lowered or "error state: timeout" in lowered:
            issue = "retryable"
            issue_time = timestamp
            issue_detail = (
                "The Proton tunnel timed out while waiting for the selected server."
            )

    return ParsedProtonLog(connection_state, issue, issue_time, issue_detail)


def is_proton_connection(connection: dict) -> bool:
    name = connection.get("name", "")
    device = connection.get("device", "")
    return device == PROTON_DEVICE or name.startswith(PROTON_CONNECTION_PREFIX)


def build_diagnosis(
    *,
    installed: bool,
    active_connections: list[dict],
    connectivity: str,
    keyring: KeyringProbe,
    parsed_log: ParsedProtonLog,
) -> ProtonVpnDiagnosis:
    """Build the user-facing state and, critically, the repair action gates."""

    if not installed:
        return ProtonVpnDiagnosis(
            state="not-installed",
            title="Proton VPN is not installed",
            detail="Install Proton VPN's desktop app and CLI to use these diagnostics and repairs.",
            connectivity=connectivity,
            credential_state="unavailable",
            credential_detail="No Proton credential store is available.",
        )

    proton_connection = next((c for c in active_connections if is_proton_connection(c)), None)
    connection_name = proton_connection.get("name", "") if proton_connection else ""

    if keyring.state == "found":
        credential_detail = "A Proton sign-in is stored in your unlocked desktop keyring."
    elif keyring.state == "locked":
        credential_detail = "Proton credentials exist, but your desktop keyring is locked."
    elif keyring.state == "missing":
        credential_detail = "No Proton sign-in is stored; open Proton VPN and sign in."
    else:
        credential_detail = "The desktop keyring could not be inspected. No secret was requested."

    common = {
        "connection_name": connection_name,
        "connectivity": connectivity,
        "credential_state": keyring.state,
        "credential_detail": credential_detail,
        "last_problem": parsed_log.issue_detail,
        "last_problem_time": parsed_log.issue_time,
    }

    if parsed_log.issue == "credential":
        return ProtonVpnDiagnosis(
            state="credential-error",
            title="Proton credentials need repair",
            detail="The latest unresolved Proton failure is a login or certificate problem.",
            credential_reset_allowed=True,
            **common,
        )

    # A locked keyring needs to be unlocked by the desktop session.  Deleting
    # it cannot fix that and could lose credentials, so reset stays gated off.
    if keyring.state == "locked":
        return ProtonVpnDiagnosis(
            state="keyring-locked",
            title="Desktop keyring is locked",
            detail="Unlock your login keyring, then recheck Proton VPN.",
            **common,
        )

    if proton_connection is not None and connectivity == "full":
        return ProtonVpnDiagnosis(
            state="connected",
            title="Proton VPN is connected",
            detail=f"{connection_name or 'The Proton tunnel'} is active and NetworkManager reports full connectivity.",
            **common,
        )

    if proton_connection is not None:
        limited = connectivity in {"none", "limited", "portal"}
        limited_common = dict(common)
        if limited:
            limited_common["last_problem"] = (
                "NetworkManager reports limited internet access through the active Proton tunnel."
            )
            limited_common["last_problem_time"] = ""
        return ProtonVpnDiagnosis(
            state="connected-limited" if limited else "connected",
            title="Proton VPN is connected, but internet access is limited" if limited else "Proton VPN is connected",
            detail=(
                "The tunnel is active, but NetworkManager does not report full internet connectivity."
                if limited
                else "The Proton tunnel is active; NetworkManager connectivity could not be confirmed."
            ),
            retry_allowed=limited,
            **limited_common,
        )

    if parsed_log.issue == "retryable":
        return ProtonVpnDiagnosis(
            state="retryable-error",
            title="Proton VPN connection needs a retry",
            detail="The latest attempt failed before Proton established a healthy tunnel.",
            retry_allowed=True,
            **common,
        )

    if parsed_log.connection_state == "connecting":
        return ProtonVpnDiagnosis(
            state="connecting",
            title="Proton VPN is connecting",
            detail="Wait for the current attempt to finish, then recheck if it does not connect.",
            **common,
        )

    if keyring.state == "missing":
        return ProtonVpnDiagnosis(
            state="signed-out",
            title="Proton VPN is signed out",
            detail="Open Proton VPN and sign in before attempting a connection.",
            **common,
        )

    return ProtonVpnDiagnosis(
        state="disconnected",
        title="Proton VPN is disconnected",
        detail="No active Proton tunnel or unresolved credential failure was found.",
        **common,
    )


class ProtonVpnClient:
    def __init__(self, netmgr, log_path: Optional[str] = None):
        self._nm = netmgr
        self._log_path = log_path or os.path.join(
            GLib.get_user_cache_dir(), "Proton", "VPN", "logs", "vpn-app.log"
        )

    # -- diagnostics ---------------------------------------------------------

    def diagnose(self, callback: Callable[[ProtonVpnDiagnosis, Optional[Exception]], None]):
        installed = shutil.which("protonvpn") is not None
        state = {
            "pending": 3,
            "connections": [],
            "connectivity": "unknown",
            "keyring": KeyringProbe("unavailable"),
            "log": ParsedProtonLog(),
            "failed_sources": set(),
            "nm_pending": 2,
            "nm_success": False,
        }

        def done():
            state["pending"] -= 1
            if state["pending"]:
                return
            diagnosis = build_diagnosis(
                installed=installed,
                active_connections=state["connections"],
                connectivity=state["connectivity"],
                keyring=state["keyring"],
                parsed_log=state["log"],
            )
            # Partial failures are already represented as "unknown" rows.  A
            # diagnosis is still useful, so only return an error if every live
            # source failed and Proton itself is installed.
            error = None
            if installed and len(state["failed_sources"]) == 3:
                error = ProtonVpnError("couldn't read Proton VPN, NetworkManager, or keyring status")
            callback(diagnosis, error)

        def on_general(general, error):
            if error is None:
                state["connectivity"] = (general or {}).get("connectivity", "unknown")
                state["nm_success"] = True
            networkmanager_done()

        def on_active(connections, error):
            if error is None:
                state["connections"] = connections or []
                state["nm_success"] = True
            networkmanager_done()

        def networkmanager_done():
            # NetworkManager's two queries count as one diagnostic source.
            state["nm_pending"] -= 1
            if state["nm_pending"] == 0:
                if not state["nm_success"]:
                    state["failed_sources"].add("networkmanager")
                done()

        def on_keyring(probe, error):
            if error is not None:
                state["failed_sources"].add("keyring")
            else:
                state["keyring"] = probe
            done()

        def on_log(stdout, error):
            if error is not None:
                state["failed_sources"].add("log")
            else:
                state["log"] = parse_proton_log(stdout or "")
            done()

        self._nm.get_active_connections(on_active)
        self._nm.get_connectivity(on_general)
        self._probe_keyring(on_keyring)
        self._read_log(on_log)

    def _read_log(self, callback):
        if not os.path.isfile(self._log_path):
            callback("", None)
            return
        self._run_process(["tail", "-c", str(LOG_TAIL_BYTES), self._log_path], callback)

    def _probe_keyring(self, callback):
        try:
            connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error as error:
            callback(None, ProtonVpnError(f"desktop keyring unavailable: {error.message}"))
            return

        parameters = GLib.Variant("(a{ss})", ({"service": "Proton"},))

        def on_result(source, result, _data=None):
            try:
                reply = source.call_finish(result)
                unlocked, locked = reply.unpack()
            except GLib.Error as error:
                callback(None, ProtonVpnError(f"couldn't inspect desktop keyring: {error.message}"))
                return
            if locked:
                callback(KeyringProbe("locked", len(unlocked) + len(locked)), None)
            elif unlocked:
                callback(KeyringProbe("found", len(unlocked)), None)
            else:
                callback(KeyringProbe("missing", 0), None)

        connection.call(
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
            "SearchItems",
            parameters,
            GLib.VariantType.new("(aoao)"),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            on_result,
            None,
        )

    # -- repair --------------------------------------------------------------

    def retry_connection(self, callback):
        """Restart Proton on its fastest server. callback(ok: bool, error)"""

        def after_stop(ok, error):
            if not ok:
                callback(False, error)
                return

            def on_connections(connections, nm_error):
                if nm_error is not None:
                    self._finish_repair(False, nm_error, callback)
                    return
                active = any(is_proton_connection(conn) for conn in connections or [])
                if active:
                    self._run_cli(["disconnect"], after_disconnect)
                else:
                    self._run_cli(["connect"], after_connect)

            def after_disconnect(_stdout, cli_error):
                if cli_error is not None:
                    self._finish_repair(False, cli_error, callback)
                    return
                self._run_cli(["connect"], after_connect)

            def after_connect(_stdout, cli_error):
                self._finish_repair(cli_error is None, cli_error, callback)

            self._nm.get_active_connections(on_connections)

        self._stop_proton_gui(after_stop)

    def reset_credentials(self, callback):
        """Use Proton's official full sign-out. callback(ok: bool, error)"""

        def after_stop(ok, error):
            if not ok:
                callback(False, error)
                return

            def after_signout(_stdout, cli_error):
                self._finish_repair(cli_error is None, cli_error, callback)

            self._run_cli(["signout"], after_signout)

        self._stop_proton_gui(after_stop)

    def _finish_repair(self, ok, error, callback):
        launch_error = self._launch_proton_gui()
        if error is not None:
            callback(False, error)
        elif launch_error is not None:
            callback(False, launch_error)
        else:
            callback(ok, None)

    def _run_cli(self, args, callback):
        executable = shutil.which("protonvpn")
        if executable is None:
            callback(None, ProtonVpnError("the Proton VPN CLI is not installed"))
            return
        self._run_process([executable] + list(args), callback)

    def _run_process(self, argv, callback):
        """Run a fixed argv list asynchronously; never return raw log secrets."""
        try:
            proc = Gio.Subprocess.new(
                argv,
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE,
            )
        except GLib.Error as error:
            callback(None, ProtonVpnError(error.message))
            return

        def on_done(_source, result, _data=None):
            try:
                _ok, stdout, stderr = proc.communicate_utf8_finish(result)
            except GLib.Error as error:
                callback(None, ProtonVpnError(error.message))
                return
            status = proc.get_exit_status()
            if status != 0:
                # CLI errors are intended for users, unlike the app log.  Keep
                # the final line and cap it so a traceback cannot flood a toast.
                lines = [line.strip() for line in (stderr or stdout or "").splitlines() if line.strip()]
                message = lines[-1][:300] if lines else f"Proton VPN exited with status {status}"
                callback(None, ProtonVpnError(message))
                return
            callback(stdout or "", None)

        proc.communicate_utf8_async(None, None, on_done, None)

    def _stop_proton_gui(self, callback):
        """Stop the verified same-user Proton GTK process, if it is running."""
        try:
            connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error as error:
            callback(False, ProtonVpnError(f"couldn't inspect the Proton VPN app: {error.message}"))
            return

        def on_pid(source, result, _data=None):
            try:
                reply = source.call_finish(result)
                pid = int(reply.unpack()[0])
            except GLib.Error as error:
                # NameHasNoOwner means Proton's desktop app is already closed.
                if "NameHasNoOwner" in error.message or "no owner" in error.message.lower():
                    callback(True, None)
                else:
                    callback(False, ProtonVpnError(f"couldn't locate the Proton VPN app: {error.message}"))
                return

            verification_error = self._verify_proton_process(pid)
            if verification_error is not None:
                callback(False, verification_error)
                return
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                callback(True, None)
                return
            except (PermissionError, OSError) as error:
                callback(False, ProtonVpnError(f"couldn't close the Proton VPN app: {error}"))
                return

            attempts = {"remaining": 50}

            def poll_exit():
                if not os.path.exists(f"/proc/{pid}"):
                    callback(True, None)
                    return False
                attempts["remaining"] -= 1
                if attempts["remaining"] <= 0:
                    callback(False, ProtonVpnError("the Proton VPN app did not close within five seconds"))
                    return False
                return True

            GLib.timeout_add(100, poll_exit)

        connection.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixProcessID",
            GLib.Variant("(s)", (PROTON_APP_BUS_NAME,)),
            GLib.VariantType.new("(u)"),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            on_pid,
            None,
        )

    @staticmethod
    def _verify_proton_process(pid):
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as status_file:
                uid_line = next(line for line in status_file if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
            with open(f"/proc/{pid}/cmdline", "rb") as command_file:
                command = command_file.read(8192).replace(b"\0", b" ").decode("utf-8", "replace")
        except (OSError, StopIteration, ValueError) as error:
            return ProtonVpnError(f"couldn't verify the Proton VPN process: {error}")
        if real_uid != os.getuid():
            return ProtonVpnError("refusing to stop a Proton VPN process owned by another user")
        if "protonvpn-app" not in command:
            return ProtonVpnError("refusing to stop a process that is not the Proton VPN desktop app")
        return None

    @staticmethod
    def _launch_proton_gui():
        try:
            app_info = GioUnix.DesktopAppInfo.new(PROTON_DESKTOP_ID)
            if app_info is not None:
                app_info.launch([], None)
                return None
            executable = shutil.which("protonvpn-app")
            if executable is None:
                return ProtonVpnError("Proton was repaired, but its desktop app could not be found")
            Gio.Subprocess.new([executable], Gio.SubprocessFlags.NONE)
            return None
        except GLib.Error as error:
            return ProtonVpnError(f"Proton was repaired, but its desktop app could not be reopened: {error.message}")
