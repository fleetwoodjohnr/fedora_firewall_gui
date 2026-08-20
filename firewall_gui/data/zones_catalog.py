from dataclasses import dataclass


@dataclass(frozen=True)
class ZoneInfo:
    trust_label: str
    guidance: str
    common: bool = True


# firewalld ships real human-readable text for its built-in zones (visible via
# the D-Bus getZoneSettings2 "description" field), so that live text is used
# as the primary description in the UI. This catalog only adds a short
# trust-level badge and laptop-specific guidance on top of it.
ZONES: dict[str, ZoneInfo] = {
    "drop": ZoneInfo(
        "Locked down",
        "Every incoming packet is silently dropped, with no reply of any kind; only connections you start are allowed back in. Good for an emergency lockdown on a network you actively distrust.",
    ),
    "block": ZoneInfo(
        "Locked down",
        "Nearly as strict as Drop, but sends back a rejection instead of silently discarding incoming packets, so the other side knows immediately you refused the connection.",
    ),
    "public": ZoneInfo(
        "Restrictive",
        "Fedora's built-in default for untrusted/public networks — coffee shops, airports, hotel WiFi. Assume every other device on the network is potentially hostile.",
    ),
    "external": ZoneInfo(
        "Restrictive",
        "Meant for a machine acting as a router's external/WAN-facing interface with masquerading enabled. Not typically relevant to a laptop.",
        common=False,
    ),
    "dmz": ZoneInfo(
        "Restrictive",
        "For publicly reachable servers that are intentionally isolated from the rest of your internal network. Not typically relevant to a laptop.",
        common=False,
    ),
    "work": ZoneInfo(
        "Balanced",
        "For a network where you mostly trust the other devices, such as a workplace LAN, but don't fully trust every device on it.",
    ),
    "home": ZoneInfo(
        "Balanced",
        "For a network where you mostly trust the other devices, such as your home WiFi.",
    ),
    "internal": ZoneInfo(
        "Balanced",
        "Similar to Home/Work — for an internal network segment where you mostly trust the other machines.",
    ),
    "FedoraWorkstation": ZoneInfo(
        "Balanced (Fedora default)",
        "Fedora's own out-of-the-box default. More permissive than it looks: it allows a few convenience services and opens every unprivileged port (1025-65535) for incoming connections. Worth reviewing with the Dashboard's hardening checklist if this zone ever applies to an untrusted network.",
    ),
    "FedoraServer": ZoneInfo(
        "Balanced (Fedora default)",
        "Fedora Server's own default — similar convenience-oriented defaults to FedoraWorkstation. Less relevant to a laptop.",
        common=False,
    ),
    "nm-shared": ZoneInfo(
        "Permissive",
        "Used automatically by NetworkManager when you share this laptop's connection with other devices (e.g. a WiFi hotspot). Not meant to be assigned to your own uplink connection.",
        common=False,
    ),
    "libvirt": ZoneInfo(
        "Permissive",
        "Used automatically for virtual machine networking (libvirt/QEMU). Not typically relevant unless you run VMs.",
        common=False,
    ),
    "libvirt-routed": ZoneInfo(
        "Permissive",
        "A routed-networking variant of the libvirt zone, used automatically for certain VM network configurations.",
        common=False,
    ),
    "trusted": ZoneInfo(
        "Fully open",
        "Allows all incoming traffic from anywhere — effectively no firewall on this zone's interfaces. Only appropriate for an interface you fully control end-to-end, such as a private VPN tunnel where the other end is only ever you.",
    ),
}


def get_zone_info(name: str) -> ZoneInfo:
    return ZONES.get(
        name,
        ZoneInfo("Custom zone", "A custom, user-created zone with no built-in trust-level guidance available."),
    )


def filter_zones(zones: list[str], show_all: bool, must_keep: str | None = None) -> list[str]:
    """Zones to display in a zone-picker dropdown, sorted.

    With show_all=False, only zones marked `common` are included — unknown/custom
    zone names default to common via get_zone_info's fallback, so a user's own zone
    is never hidden. `must_keep`, when given and present in `zones`, is always
    included even if it's an advanced zone, so the zone currently selected/assigned
    on this specific dropdown is never pulled out from under the user.
    """
    if show_all:
        result = set(zones)
    else:
        result = {z for z in zones if get_zone_info(z).common}
    if must_keep and must_keep in zones:
        result.add(must_keep)
    return sorted(result)


def summarize_zone_settings(settings: dict) -> str:
    """One-line summary of what a zone already allows, from its firewalld settings."""
    services = settings.get("services") or []
    ports = settings.get("ports") or []
    total = len(services) + len(ports)
    if total == 0:
        return "Nothing allowed in — fully locked down."

    preview = list(services[:2])
    if len(preview) < 2:
        needed = 2 - len(preview)
        preview += [f"{port}/{protocol}" for port, protocol in ports[:needed]]
    remaining = total - len(preview)

    text = "Already allows: " + ", ".join(preview)
    if remaining > 0:
        text += f" + {remaining} more"
    return text
