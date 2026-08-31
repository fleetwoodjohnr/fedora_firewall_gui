class FirewallGuiError(Exception):
    """Base class for all backend errors."""


class PolkitAuthCancelled(FirewallGuiError):
    """The user dismissed a PolicyKit authentication prompt."""


class FirewalldCallFailed(FirewallGuiError):
    """A D-Bus call to firewalld failed for a reason other than auth cancellation."""


class NmcliError(FirewallGuiError):
    """An nmcli invocation failed."""


class NmcliPermissionDenied(NmcliError):
    """nmcli reported insufficient privileges to modify a connection."""


def translate_dbus_error(err) -> FirewallGuiError:
    """Classify a GLib.Error raised by a firewalld D-Bus call.

    Firewalld authorizes each D-Bus call against PolicyKit itself and raises a
    D-Bus error rather than going through a separate pkexec step. The exact
    remote error name/text for a dismissed-vs-denied prompt is not fully
    documented, so this is a best-effort classifier based on known PolicyKit
    and firewalld error substrings; it should be revisited if real prompts are
    observed to fail classification.
    """
    text = getattr(err, "message", None) or str(err)
    lowered = text.lower()
    auth_markers = (
        "notauthorized",
        "not authorized",
        "authentication",
        "authorization failed",
        "polkit",
        "dismissed",
        "cancelled",
        "canceled",
    )
    if any(marker in lowered for marker in auth_markers):
        return PolkitAuthCancelled(text)
    return FirewalldCallFailed(text)


class HelperError(FirewallGuiError):
    """The privileged hardening helper failed for a reason other than the ones below."""


class HelperNotInstalled(HelperError):
    """The helper isn't present, so system-level hardening can't be applied."""


class HelperAuthCancelled(HelperError):
    """The user dismissed pkexec's authentication prompt."""


class HelperVersionMismatch(HelperError):
    """The installed helper speaks a different protocol than this app expects."""


# pkexec's own exit codes, distinct from anything the helper itself returns.
PKEXEC_NOT_AUTHORIZED = 126
PKEXEC_NOT_RUNNABLE = 127


def translate_helper_error(status: int, stderr: str) -> HelperError:
    """Classify a failed run of the privileged helper.

    Unlike nmcli (see NetworkManagerClient._run) this needs no substring
    guesswork: pkexec reserves 126 for "dismissed or not authorized" and 127 for
    "couldn't run the program", and passes anything else through from the helper
    unchanged. The helper's own failures always carry a written explanation on
    stderr, which is user-facing text by design.
    """
    message = (stderr or "").strip()
    if status == PKEXEC_NOT_AUTHORIZED:
        return HelperAuthCancelled(message or "authentication was dismissed or refused")
    if status == PKEXEC_NOT_RUNNABLE:
        return HelperNotInstalled(
            message or "the privileged helper couldn't be run — it may not be installed"
        )
    return HelperError(message or f"the privileged helper exited with status {status}")
