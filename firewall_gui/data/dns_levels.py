"""Curated copy and settings for the DNS half of the Hardening page.

Two independent axes, deliberately kept apart because they use different
mechanisms and have different failure modes:

  * A *level* controls how lookups are protected (encryption, validation,
    local-network chatter). These are global `systemd-resolved` settings and
    need the privileged helper.
  * A *provider* controls who answers them. That is a per-connection
    NetworkManager setting and needs no root at all.

The split is not cosmetic. A global `DNS=` in resolved.conf is only consulted
when no link supplies its own DNS, so with DHCP or a VPN up it is silently
ignored -- pinning a resolver only actually works per-link, via NetworkManager.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DnsLevel:
    id: str
    label: str
    summary: str
    detail: str
    breaks: str
    # Written verbatim into /etc/systemd/resolved.conf.d/90-firewall-gui.conf by
    # the helper. Empty dict means "write no drop-in at all" (the Off level).
    resolved_settings: dict


DNS_LEVELS = [
    DnsLevel(
        id="off",
        label="Off",
        summary="Fedora's default. No changes.",
        detail=(
            "Your lookups leave this laptop the way Fedora ships them: in plain text, over UDP port 53, "
            "to whichever DNS server your WiFi router, your ISP, or your VPN handed you. Nothing checks "
            "that the answers coming back are genuine."
        ),
        breaks=(
            "Nothing breaks, because nothing changes — but anyone sharing your WiFi, anyone running the "
            "network you're on, and your ISP can all read every domain name you look up, and can quietly "
            "forge answers to send you somewhere else."
        ),
        resolved_settings={},
    ),
    DnsLevel(
        id="basic",
        label="Basic",
        summary="Encrypt lookups when the network allows it. Nothing breaks.",
        detail=(
            "Turns on DNS-over-TLS in opportunistic mode and DNSSEC in allow-downgrade mode. In plain "
            "terms: your laptop now tries to encrypt every lookup and tries to verify every answer, but "
            "if the DNS server it was given can't do either, it quietly falls back to the old behaviour "
            "instead of failing. Answers are also cached locally, so repeat lookups get faster."
        ),
        breaks=(
            "Nothing. This is the safe first step — it is strictly better than Off on networks that "
            "support encryption, and identical to Off on the ones that don't. Captive portals, hotel "
            "WiFi, and corporate networks all keep working."
        ),
        resolved_settings={
            "DNSOverTLS": "opportunistic",
            "DNSSEC": "allow-downgrade",
            "Cache": "yes",
        },
    ),
    DnsLevel(
        id="balanced",
        label="Balanced",
        summary="Encrypt when possible, and stop announcing yourself on the local network.",
        detail=(
            "Everything Basic does, plus it switches off LLMNR and multicast DNS. Those are the two "
            "protocols that make your laptop shout its own name onto the local network and trust "
            "whatever shouts back — a well-worn trick for tricking a machine into handing over "
            "credentials on a shared or public network."
        ),
        breaks=(
            "Reaching other machines by their bare hostname stops working, so if you type something "
            "like \"ssh my-desktop\" on your home network you'll need the full name or IP instead. "
            "Printers and Chromecast-style devices are usually unaffected, because Avahi handles those "
            "separately from systemd-resolved. This is the right setting for a laptop that leaves the house."
        ),
        resolved_settings={
            "DNSOverTLS": "opportunistic",
            "DNSSEC": "allow-downgrade",
            "LLMNR": "no",
            "MulticastDNS": "no",
            "Cache": "yes",
        },
    ),
    DnsLevel(
        id="strict",
        label="Strict",
        summary="Encrypted and verified, or no answer at all. Will break some networks.",
        detail=(
            "Everything Balanced does, but with the fallbacks removed. DNS-over-TLS becomes mandatory "
            "and DNSSEC validation becomes strict, so a lookup that can't be encrypted, or an answer "
            "that fails its signature check, is refused rather than downgraded. Nothing can watch or "
            "tamper with your lookups — and nothing gets resolved if it can't be done safely."
        ),
        breaks=(
            "Quite a lot, on the wrong network. If the DNS server you were handed doesn't speak "
            "DNS-over-TLS, name resolution stops dead until you pin a resolver that does (below) or "
            "drop back to Balanced. Captive portals — hotels, airports, cafés, trains — will not let "
            "you log in. A handful of real websites have broken DNSSEC records and will fail too. "
            "Pair this level with a pinned resolver, and expect to step down when you travel."
        ),
        resolved_settings={
            "DNSOverTLS": "yes",
            "DNSSEC": "yes",
            "LLMNR": "no",
            "MulticastDNS": "no",
            "Cache": "yes",
        },
    ),
]

DNS_LEVEL_IDS = [level.id for level in DNS_LEVELS]


@dataclass(frozen=True)
class DnsProvider:
    id: str
    label: str
    # nmcli ipv4.dns / ipv6.dns values. The "IP#hostname" form tells
    # systemd-resolved which certificate name to expect, which is what makes
    # strict DNS-over-TLS actually verifiable rather than just encrypted.
    ipv4: tuple
    ipv6: tuple
    dot_hostname: str
    detail: str


DNS_PROVIDERS = [
    DnsProvider(
        id="automatic",
        label="Automatic — whatever the network gives you",
        ipv4=(),
        ipv6=(),
        dot_hostname="",
        detail=(
            "Keep using the DNS server handed out by whichever network or VPN you're connected to. "
            "Only the protection level above changes; nothing is pinned.\n\n"
            "This is the right choice while you're on a VPN. The tunnel resolves names at the far end, "
            "so your lookups stay inside it — pinning a public resolver instead would send them out "
            "around the tunnel, telling that provider (and anyone between you and it) exactly which "
            "sites you visit while you believe you're private."
        ),
    ),
    DnsProvider(
        id="quad9",
        label="Quad9 — blocks known-malicious domains",
        ipv4=("9.9.9.9", "149.112.112.112"),
        ipv6=("2620:fe::fe", "2620:fe::9"),
        dot_hostname="dns.quad9.net",
        detail=(
            "Run by a Swiss non-profit. Quad9 simply refuses to answer for domains on a shared "
            "threat-intelligence list, so a phishing link or malware callback fails at the lookup — "
            "before your laptop ever opens a connection to it. That is a genuine layer of protection "
            "no firewall rule gives you.\n\n"
            "No personal data logged, and Swiss privacy law applies. Marginally slower than Cloudflare, "
            "and very occasionally it blocks something you actually wanted."
        ),
    ),
    DnsProvider(
        id="cloudflare",
        label="Cloudflare — fastest, filters nothing",
        ipv4=("1.1.1.1", "1.0.0.1"),
        ipv6=("2606:4700:4700::1111", "2606:4700:4700::1001"),
        dot_hostname="cloudflare-dns.com",
        detail=(
            "Usually the fastest resolver available from most places, with servers nearly everywhere.\n\n"
            "It filters nothing at all: you get the honest answer for every domain, malicious ones "
            "included. That's a feature if you want your DNS to stay out of the way, and a gap if you "
            "wanted the malware blocking Quad9 or AdGuard give you. US company, with published "
            "third-party audits of its no-logging claims."
        ),
    ),
    DnsProvider(
        id="mullvad",
        label="Mullvad — privacy-first, blocks ads and trackers",
        ipv4=("194.242.2.2",),
        ipv6=("2a07:e340::2",),
        dot_hostname="dns.mullvad.net",
        detail=(
            "Run by the Swedish VPN company, and free to use without an account, a payment, or any "
            "identifier at all. Blocks ads and trackers as well as resolving names. Their whole business "
            "is built on not keeping records, and they've been audited on it.\n\n"
            "The smallest operator of the four, so if you're a long way from Europe expect lookups to be "
            "a little slower than Cloudflare or Quad9."
        ),
    ),
    DnsProvider(
        id="adguard",
        label="AdGuard — blocks ads and trackers everywhere",
        ipv4=("94.140.14.14", "94.140.15.15"),
        ipv6=("2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
        dot_hostname="dns.adguard-dns.com",
        detail=(
            "Blocks ad and tracker domains for every app on this laptop, not just the browser — so it "
            "covers the things a browser extension can't reach, like phone-home telemetry from desktop "
            "apps and anything running in a Flatpak.\n\n"
            "The trade is the usual one for aggressive blocking: now and then a site loads its images or "
            "checkout flow from a domain on the blocklist and half-breaks. If a site misbehaves, this is "
            "the first thing to switch off."
        ),
    ),
]


def get_dns_level(level_id: str) -> DnsLevel:
    for level in DNS_LEVELS:
        if level.id == level_id:
            return level
    return DNS_LEVELS[0]


def get_dns_provider(provider_id: str) -> DnsProvider:
    for provider in DNS_PROVIDERS:
        if provider.id == provider_id:
            return provider
    return DNS_PROVIDERS[0]


def provider_dns_values(provider: DnsProvider):
    """(ipv4_value, ipv6_value) as nmcli expects them: comma-separated, with the
    DNS-over-TLS certificate name appended so strict DoT can be verified rather
    than merely encrypted. Empty strings mean "clear the pin"."""
    if not provider.ipv4 and not provider.ipv6:
        return "", ""
    suffix = f"#{provider.dot_hostname}" if provider.dot_hostname else ""
    return (
        ",".join(f"{addr}{suffix}" for addr in provider.ipv4),
        ",".join(f"{addr}{suffix}" for addr in provider.ipv6),
    )
