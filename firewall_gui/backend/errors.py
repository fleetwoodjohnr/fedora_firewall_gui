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
