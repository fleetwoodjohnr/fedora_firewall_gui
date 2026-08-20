from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceInfo:
    label: str
    summary: str
    risk: str  # "low" | "medium" | "high"
    recommendation: str
    category: str


SERVICES: dict[str, ServiceInfo] = {
    "ssh": ServiceInfo(
        "SSH (Secure Shell)",
        "Lets other computers log into a command-line session on this laptop over an encrypted connection.",
        "medium",
        "Only enable on networks you trust, or if you specifically need to remote into this laptop. SSH itself requires a valid password/key to get in, but leaving it reachable everywhere puts your login on the radar of anyone scanning the network.",
        "Remote Access",
    ),
    "mosh": ServiceInfo(
        "Mosh (Mobile Shell)",
        "A more robust alternative to SSH for flaky or roaming connections (WiFi hand-offs, cellular). Uses SSH to start a session, then hands off to its own UDP ports.",
        "medium",
        "Only useful if you actually use mosh instead of/alongside SSH. Safe to leave off otherwise.",
        "Remote Access",
    ),
    "rdp": ServiceInfo(
        "RDP (Remote Desktop)",
        "Lets another computer take over this machine's desktop, if remote-desktop server software is running (e.g. GNOME Remote Desktop).",
        "high",
        "Only enable if you're actively using remote desktop right now and intend to connect from elsewhere. Never leave on for a public network.",
        "Remote Access",
    ),
    "vnc-server": ServiceInfo(
        "VNC server",
        "Lets another computer view or control this machine's desktop over VNC, if a VNC server is running.",
        "high",
        "Only enable while you're actively using a VNC session. GNOME's built-in remote desktop normally uses RDP instead, so most users won't need this at all.",
        "Remote Access",
    ),
    "cockpit": ServiceInfo(
        "Cockpit",
        "A browser-based admin console for managing this Linux system remotely — users, services, logs, storage.",
        "medium",
        "Powerful, so treat it like SSH: fine on networks you trust, avoid leaving it open on public ones unless you're actively using it.",
        "Remote Access",
    ),
    "mdns": ServiceInfo(
        "mDNS (Bonjour/Avahi)",
        "Multicast DNS — lets this laptop discover, and be discovered by, other devices on the local network by name (printers, Chromecasts, AirPlay, etc.).",
        "medium",
        "Convenient on a trusted home network, but it actively announces this machine's presence to everyone on the local segment — including public WiFi.",
        "Network Discovery",
    ),
    "upnp-client": ServiceInfo(
        "UPnP client",
        "Lets apps on this laptop automatically ask your router to open ports for things like games or media servers.",
        "medium",
        "Convenient at home. UPnP implementations in consumer routers have a history of security issues, so it's best kept off on networks you don't control.",
        "Network Discovery",
    ),
    "bittorrent-lsd": ServiceInfo(
        "BitTorrent LSD",
        "BitTorrent Local Service Discovery — lets a BitTorrent client on this laptop find other local peers sharing the same torrent, to speed up transfers.",
        "low",
        "Irrelevant unless you're actively using a BitTorrent client. Harmless to leave off.",
        "Network Discovery",
    ),
    "samba": ServiceInfo(
        "Samba (file/printer server)",
        "Runs a Windows-compatible (SMB/CIFS) file and printer server on this machine, so other devices can connect to folders/printers you've shared.",
        "high",
        "Only useful if you're actively sharing files or a printer from this laptop. A common target for scanning and attacks on public WiFi — keep it off there.",
        "File & Printer Sharing",
    ),
    "samba-client": ServiceInfo(
        "Samba client browsing",
        "Lets this laptop browse and connect to other computers' shared Windows-style (SMB/CIFS) folders and printers. Doesn't share anything of yours.",
        "medium",
        "Needed mainly on a trusted home/work LAN where you actually connect to shared drives. Rarely needed on public networks.",
        "File & Printer Sharing",
    ),
    "nfs": ServiceInfo(
        "NFS (Network File System)",
        "Unix/Linux-native file sharing, typically used between machines you own on a home or work LAN.",
        "high",
        "NFS has no user-authentication layer by default, only IP-based trust — high risk to leave open anywhere outside a LAN of machines you control.",
        "File & Printer Sharing",
    ),
    "nfs3": ServiceInfo(
        "NFSv3",
        "The older NFSv3 protocol variant for Unix/Linux-native file sharing.",
        "high",
        "Same guidance as NFS: fine on a trusted home/work LAN of machines you own, high risk anywhere else.",
        "File & Printer Sharing",
    ),
    "ipp": ServiceInfo(
        "IPP (print server)",
        "Internet Printing Protocol — lets this laptop act as a network print server other devices can send jobs to.",
        "low",
        "Only needed if you're sharing a printer connected to this laptop. Low risk, safe to leave off otherwise.",
        "File & Printer Sharing",
    ),
    "ipp-client": ServiceInfo(
        "IPP client (printer discovery)",
        "Lets this laptop discover and send print jobs to network printers.",
        "low",
        "Generally safe and low-risk convenience feature for home/office use.",
        "File & Printer Sharing",
    ),
    "syncthing": ServiceInfo(
        "Syncthing",
        "Continuous, peer-to-peer file synchronization between your own devices — a self-hosted Dropbox alternative.",
        "medium",
        "Needs this reachable to sync directly with your other devices. Safe if you actually use Syncthing; otherwise just an unnecessary open door.",
        "File & Printer Sharing",
    ),
    "dhcp": ServiceInfo(
        "DHCP server",
        "Runs a DHCP server on this laptop, handing out IP addresses to other devices on the network.",
        "high",
        "Almost never something a laptop should do. Enabling this by accident on someone else's network can disrupt their connectivity for everyone. Leave off unless you specifically know you need it (e.g. sharing a hotspot).",
        "Time & Network Services",
    ),
    "dhcpv6-client": ServiceInfo(
        "DHCPv6 client",
        "Lets this laptop request an IPv6 address and network configuration from the network's own DHCPv6 server.",
        "low",
        "Standard and low-risk — generally needed everywhere for normal IPv6 connectivity.",
        "Time & Network Services",
    ),
    "dns": ServiceInfo(
        "DNS server",
        "Runs a DNS server on this laptop that other devices on the network could query.",
        "high",
        "Not something a laptop normally needs to expose. Leave off unless you're intentionally running local DNS infrastructure.",
        "Time & Network Services",
    ),
    "ntp": ServiceInfo(
        "NTP (time server)",
        "Network Time Protocol server — lets other devices sync their clock from this laptop.",
        "low",
        "Low risk, but rarely needed on a laptop — normally you're the client, which doesn't require an inbound rule at all.",
        "Time & Network Services",
    ),
    "http": ServiceInfo(
        "HTTP (port 80)",
        "Lets other devices reach a plain web server running on this laptop.",
        "medium",
        "Only relevant if you're actively developing or testing a website/service locally. As secure as whatever is actually listening on the port — nothing more.",
        "Web & Dev",
    ),
    "https": ServiceInfo(
        "HTTPS (port 443)",
        "Lets other devices reach an encrypted web server running on this laptop.",
        "medium",
        "Same guidance as HTTP: only relevant if you're actively serving something locally.",
        "Web & Dev",
    ),
    "telnet": ServiceInfo(
        "Telnet",
        "An old, unencrypted remote-login protocol — anything typed, including passwords, is sent in plain text.",
        "high",
        "There's essentially never a good reason to enable this on a modern laptop. Use SSH instead.",
        "Legacy / Insecure",
    ),
    "ftp": ServiceInfo(
        "FTP",
        "File Transfer Protocol — an old, largely unencrypted way to serve files, including credentials sent in plain text.",
        "high",
        "Avoid unless you have a specific legacy need. Prefer SFTP (just needs the SSH service) instead.",
        "Legacy / Insecure",
    ),
}

COMMON_SERVICES = (
    "ssh", "mdns", "samba-client", "dhcpv6-client", "http", "https",
    "cockpit", "syncthing", "ipp-client",
)

CATEGORIES = (
    "Remote Access", "Network Discovery", "File & Printer Sharing",
    "Time & Network Services", "Web & Dev", "Legacy / Insecure", "Other",
)


def get_service_info(name: str, raw_ports=None) -> ServiceInfo:
    info = SERVICES.get(name)
    if info is not None:
        return info
    ports = raw_ports or []
    port_text = ", ".join(f"{p}/{proto}" for p, proto in ports) if ports else "no fixed ports listed"
    return ServiceInfo(
        label=name,
        summary=f"A predefined firewalld service not yet curated in this app. Ports: {port_text}.",
        risk="medium",
        recommendation="Review the ports above before enabling this on an untrusted network — treat any unfamiliar service as something to look up first.",
        category="Other",
    )
