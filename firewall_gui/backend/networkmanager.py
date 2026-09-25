import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

from .errors import NmcliError, NmcliPermissionDenied

CONNECTION_FIELDS = ("NAME", "TYPE", "UUID", "DEVICE")

# Connection types NetworkManager reports that represent a VPN tunnel or a
# supporting virtual interface (e.g. ProtonVPN's IPv6 leak-block dummy iface)
# rather than a physical network link.
VPN_LIKE_TYPES = {"vpn", "wireguard", "dummy", "tun", "tap"}


def _split_terse_line(line):
    """Split one line of `nmcli -t` output on unescaped ':' separators.

    nmcli's terse (-t) format backslash-escapes literal ':' and '\\' inside
    field values, so a naive str.split(":") would corrupt values that contain
    a colon (uncommon for these fields, but not impossible for a connection
    name).
    """
    fields = []
    current = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


class NetworkManagerClient:
    """Thin async wrapper around the NetworkManager settings used by the app.

    All calls run via Gio.Subprocess (argv list, never a shell) so connection
    status, zone, and DNS operations never block the GTK main loop.
    """

    def _run(self, args, callback):
        """callback(stdout: str | None, error: NmcliError | None)"""
        try:
            proc = Gio.Subprocess.new(
                ["nmcli"] + args,
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE,
            )
        except GLib.Error as e:
            callback(None, NmcliError(str(e)))
            return

        def on_done(source, result, _data=None):
            try:
                ok, stdout, stderr = proc.communicate_utf8_finish(result)
            except GLib.Error as e:
                callback(None, NmcliError(str(e)))
                return
            status = proc.get_exit_status()
            if status != 0:
                message = (stderr or "").strip() or f"nmcli exited with status {status}"
                lowered = message.lower()
                if "insufficient privileges" in lowered or "not authorized" in lowered or "permission" in lowered:
                    callback(None, NmcliPermissionDenied(message))
                else:
                    callback(None, NmcliError(message))
                return
            callback(stdout, None)

        proc.communicate_utf8_async(None, None, on_done, None)

    def list_connections(self, callback):
        """callback(connections: list[dict] | None, error)

        Each connection dict has keys: name, type, uuid, device (device is ""
        when the connection is not currently active).
        """

        def on_result(stdout, error):
            if error:
                callback(None, error)
                return
            connections = []
            for line in stdout.splitlines():
                if not line:
                    continue
                fields = _split_terse_line(line)
                fields += [""] * (len(CONNECTION_FIELDS) - len(fields))
                name, conn_type, uuid, device = fields[:4]
                connections.append({"name": name, "type": conn_type, "uuid": uuid, "device": device})
            callback(connections, None)

        self._run(["-t", "-f", ",".join(CONNECTION_FIELDS), "connection", "show"], on_result)

    def get_active_connections(self, callback):
        def on_result(stdout, error):
            if error:
                callback(None, error)
                return
            connections = []
            for line in stdout.splitlines():
                if not line:
                    continue
                fields = _split_terse_line(line)
                fields += [""] * (len(CONNECTION_FIELDS) - len(fields))
                name, conn_type, uuid, device = fields[:4]
                connections.append({"name": name, "type": conn_type, "uuid": uuid, "device": device})
            callback(connections, None)

        self._run(["-t", "-f", ",".join(CONNECTION_FIELDS), "connection", "show", "--active"], on_result)

    def get_connectivity(self, callback):
        """callback({state, connectivity}: dict | None, error)

        `connectivity` is NetworkManager's own reachability result (none,
        portal, limited, full, or unknown).  It is preferable to making this
        app phone a new third-party test endpoint merely to check the VPN.
        """

        def on_result(stdout, error):
            if error:
                callback(None, error)
                return
            fields = _split_terse_line((stdout or "").strip())
            fields += ["unknown", "unknown"]
            callback({"state": fields[0], "connectivity": fields[1]}, None)

        self._run(["-t", "-f", "STATE,CONNECTIVITY", "general", "status"], on_result)

    def get_connection_zone(self, uuid, callback):
        """callback(zone: str, error) -- zone is "" when unset."""

        def on_result(stdout, error):
            if error:
                callback(None, error)
                return
            zone = stdout.strip()
            callback(zone, None)

        self._run(["-t", "-f", "connection.zone", "connection", "show", uuid], on_result)

    def set_connection_zone(self, uuid, zone, callback):
        """callback(ok: bool, error)"""

        def on_result(stdout, error):
            callback(error is None, error)

        self._run(["connection", "modify", uuid, "connection.zone", zone], on_result)

    # -- per-connection DNS ---------------------------------------------------
    #
    # Pinning a resolver has to happen per connection, not globally. A global
    # `DNS=` in resolved.conf is only consulted when no link supplies its own,
    # so with DHCP or a VPN up it is silently ignored -- the setting appears to
    # apply and does nothing. NetworkManager writes these per-link into
    # systemd-resolved, which is the only place they actually take effect.

    def get_connection_dns(self, uuid, callback):
        """callback(dns: dict | None, error)

        Keys: ipv4, ipv6 (comma-joined server strings, "" when unpinned),
        ignore_auto (bool), dns_over_tls (nmcli's int-as-string: -1 default,
        0 no, 1 opportunistic, 2 yes).
        """

        def on_result(stdout, error):
            if error:
                callback(None, error)
                return
            values = {}
            for line in (stdout or "").splitlines():
                if not line:
                    continue
                fields = _split_terse_line(line)
                if len(fields) < 2:
                    continue
                # Re-join the tail: nmcli escapes ':' inside values (IPv6
                # addresses are full of them), but be defensive about one
                # slipping through unescaped rather than truncating an address.
                values[fields[0]] = ":".join(fields[1:])
            callback(
                {
                    "ipv4": values.get("ipv4.dns", ""),
                    "ipv6": values.get("ipv6.dns", ""),
                    "ignore_auto": values.get("ipv4.ignore-auto-dns", "no") == "yes",
                    "dns_over_tls": values.get("connection.dns-over-tls", "-1"),
                },
                None,
            )

        self._run(
            ["-t", "-f", "ipv4.dns,ipv6.dns,ipv4.ignore-auto-dns,connection.dns-over-tls",
             "connection", "show", uuid],
            on_result,
        )

    def set_connection_dns(self, uuid, ipv4, ipv6, dns_over_tls, callback):
        """Pin (or unpin) this connection's resolver. callback(ok: bool, error)

        Pass "" for ipv4/ipv6 and "" for dns_over_tls to unpin: NetworkManager
        treats an empty value as "back to the default", which restores the
        network's own DNS rather than leaving an empty override behind.

        `ignore-auto-dns` is the half people forget. Without it NetworkManager
        appends your chosen servers to the ones DHCP handed out instead of
        replacing them, and lookups quietly keep going to the network's resolver
        whenever it answers first.
        """
        pinning = bool(ipv4 or ipv6)
        ignore = "yes" if pinning else "no"

        def on_result(stdout, error):
            callback(error is None, error)

        self._run(
            ["connection", "modify", uuid,
             "ipv4.dns", ipv4, "ipv4.ignore-auto-dns", ignore,
             "ipv6.dns", ipv6, "ipv6.ignore-auto-dns", ignore,
             "connection.dns-over-tls", dns_over_tls],
            on_result,
        )

    @staticmethod
    def is_vpn_like(conn_type):
        return conn_type in VPN_LIKE_TYPES
