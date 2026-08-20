from dataclasses import dataclass
from typing import Callable

WIDE_OPEN_HIGH_PORTS = (("1025-65535", "tcp"), ("1025-65535", "udp"))


@dataclass(frozen=True)
class HardeningRule:
    id: str
    title: str
    description: str
    applies_to: Callable[[dict], bool]
    fix: Callable  # (backend, zone, callback) -> None


def _wide_open_high_ports_applies(settings: dict) -> bool:
    ports = settings.get("ports", [])
    return any(tuple(p) in WIDE_OPEN_HIGH_PORTS for p in ports)


def _wide_open_high_ports_fix(backend, zone, callback):
    targets = [p for p in WIDE_OPEN_HIGH_PORTS]
    state = {"pending": len(targets), "error": None, "partial": False}

    def on_one(ok, error, partial):
        state["pending"] -= 1
        if error is not None:
            state["error"] = error
        if partial:
            state["partial"] = True
        if state["pending"] == 0:
            callback(state["error"] is None, state["error"], state["partial"])

    for port, protocol in targets:
        backend.remove_port(zone, port, protocol, on_one)


def _samba_client_applies(settings: dict) -> bool:
    return "samba-client" in settings.get("services", [])


def _samba_client_fix(backend, zone, callback):
    backend.remove_service(zone, "samba-client", callback)


RULES = [
    HardeningRule(
        id="wide-open-high-ports",
        title="Close the wide-open 1025-65535 port range",
        description=(
            "This zone currently accepts incoming connections on every port from 1025 to 65535 "
            "(TCP and UDP) — Fedora's default convenience setting. On an untrusted network this is "
            "a large attack surface for little benefit; most apps that need incoming connections "
            "request a specific service or port instead."
        ),
        applies_to=_wide_open_high_ports_applies,
        fix=_wide_open_high_ports_fix,
    ),
    HardeningRule(
        id="samba-client-enabled",
        title="Disable Samba client browsing",
        description=(
            "This zone allows this laptop to browse Windows-style (SMB) file shares on the network, "
            "which isn't needed unless you're actively connecting to shared folders. If this zone also "
            "covers your VPN tunnel interface, disabling it here affects both your WiFi and VPN traffic."
        ),
        applies_to=_samba_client_applies,
        fix=_samba_client_fix,
    ),
]


def get_applicable_rules(settings: dict):
    return [rule for rule in RULES if rule.applies_to(settings)]
