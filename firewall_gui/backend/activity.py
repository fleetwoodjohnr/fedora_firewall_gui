"""Aggregate firewalld's kernel denial logs without keeping source addresses."""

import datetime as dt
import json
import re

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

from .hardening import HELPER_PATH, PROTOCOL_VERSION

MAX_LINES = 20000
PREFIX = re.compile(
    r"^(?:FINAL_REJECT|STATE_INVALID_DROP|rpfilter_DROP|RFC3964_IPv4_REJECT|"
    r"filter_[A-Za-z0-9_-]+_(?:DROP|REJECT|ICMP_BLOCK)): "
)
PORT = re.compile(r"(?:^|\s)DPT=(\d{1,5})(?:\s|$)")


def summarize_journal(lines, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    counts = [0] * 24
    ports = {}
    total = 0
    inspected = 0
    for line in lines:
        if not line.strip():
            continue
        inspected += 1
        try:
            record = json.loads(line)
            message = record["MESSAGE"]
            when = dt.datetime.fromtimestamp(int(record["__REALTIME_TIMESTAMP"]) / 1_000_000, dt.timezone.utc)
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
        if not isinstance(message, str) or not PREFIX.match(message):
            continue
        age = (now - when).total_seconds()
        if not 0 <= age < 24 * 3600:
            continue
        counts[23 - int(age // 3600)] += 1
        total += 1
        match = PORT.search(message)
        if match and 0 < int(match.group(1)) <= 65535:
            port = match.group(1)
            ports[port] = ports.get(port, 0) + 1
    return {
        "total": total,
        "hourly": counts,
        "top_ports": sorted(ports.items(), key=lambda item: (-item[1], int(item[0])))[:5],
        "limited": inspected >= MAX_LINES,
        "updated_at": now.isoformat(),
    }


class ActivityClient:
    def _run(self, argv, callback):
        try:
            process = Gio.Subprocess.new(
                argv, Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            )
        except GLib.Error as error:
            callback(None, error)
            return

        def finished(_source, result, _data=None):
            try:
                _ok, stdout, stderr = process.communicate_utf8_finish(result)
            except GLib.Error as error:
                callback(None, error)
                return
            if process.get_exit_status() != 0:
                callback(None, (stderr or "Activity report failed").strip())
            else:
                callback(stdout or "", None)

        process.communicate_utf8_async(None, None, finished, None)

    def read(self, callback, privileged=False):
        """callback(report, error); privileged=True is only for an explicit user action."""
        if privileged:
            def on_helper(stdout, error):
                if error:
                    callback(None, error)
                    return
                try:
                    payload = json.loads(stdout)
                    if payload.get("protocol") != PROTOCOL_VERSION:
                        raise ValueError("Activity helper is out of date; reinstall it from the app menu")
                    callback(payload["activity"], None)
                except (ValueError, KeyError, TypeError) as parse_error:
                    callback(None, parse_error)

            self._run(["pkexec", HELPER_PATH, "activity"], on_helper)
            return

        def on_journal(stdout, error):
            if error:
                callback(None, error)
            else:
                callback(summarize_journal(stdout.splitlines()), None)

        self._run(
            ["journalctl", "--system", "_TRANSPORT=kernel", "--since=-24h",
             f"--lines={MAX_LINES}", "--output=json", "--no-pager"],
            on_journal,
        )
