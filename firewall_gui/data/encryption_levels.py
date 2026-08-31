"""Curated copy and settings for the encryption half of the Hardening page.

One level moves three separate things at once:

  * the system-wide crypto policy (`update-crypto-policies`), which sets the
    floor for TLS versions, key sizes and algorithms across OpenSSL, GnuTLS,
    NSS, OpenSSH and Java all at once;
  * the SSH server's configuration;
  * which plaintext services this laptop will accept connections on.

Only the third is applied by this app directly, through the existing firewalld
client. The first two are written by the privileged helper.

`crypto_policy` and `ssh_directives` below are a MIRROR, kept for display only.
The helper defines its own authoritative copy of both, because it must never
take instructions from an unprivileged caller about what to write into /etc --
it accepts a level id and nothing else. Keep the two in step: the helper is at
packaging/helper/firewall-gui-helper.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class EncryptionLevel:
    id: str
    label: str
    summary: str
    detail: str
    breaks: str
    crypto_policy: str
    ssh_directives: dict
    # Removed from the default zone at this level, cumulatively. Applied by the
    # app over firewalld's D-Bus API, not by the helper.
    firewalld_services: tuple


# Written only when the helper finds a usable SSH key, so there is no way to
# lock yourself out of a machine you reach over the network.
KEY_GUARDED_DIRECTIVES = ("PasswordAuthentication",)

_BASIC_SSH = {
    "PermitRootLogin": "no",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "MaxAuthTries": "3",
}

_BALANCED_SSH = dict(_BASIC_SSH)
_BALANCED_SSH.update({
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "LoginGraceTime": "30",
})

_STRICT_SSH = dict(_BALANCED_SSH)
_STRICT_SSH.update({
    "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
    "KexAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512",
})

_BASIC_SERVICES = ("telnet", "rsh", "finger", "tftp")
_BALANCED_SERVICES = _BASIC_SERVICES + ("ftp", "pop3", "imap", "smtp")
_STRICT_SERVICES = _BALANCED_SERVICES + ("http",)


ENCRYPTION_LEVELS = [
    EncryptionLevel(
        id="off",
        label="Off",
        summary="Fedora's default. No changes.",
        detail=(
            "The system crypto policy goes back to whatever it was before this app touched it — on a "
            "normal Fedora install, DEFAULT. The SSH hardening file this app wrote is deleted, and any "
            "plaintext services it closed in your firewall's default zone are reopened."
        ),
        breaks=(
            "Nothing. This is the full undo: it puts every setting on this page back exactly where it "
            "started, including reopening the firewall services that higher levels closed."
        ),
        crypto_policy="",
        ssh_directives={},
        firewalld_services=(),
    ),
    EncryptionLevel(
        id="basic",
        label="Basic",
        summary="Close the obsolete stuff. No effect on anything you actually use.",
        detail=(
            "Leaves the system crypto policy at DEFAULT and changes nothing about how this laptop talks "
            "to websites. What it does is tidy up two things nobody needs on a laptop: it blocks incoming "
            "connections to genuinely obsolete plaintext services (telnet, rsh, finger, tftp), and it "
            "tells the SSH server to refuse root logins and empty passwords, to turn off X11 forwarding, "
            "and to allow only three password attempts per connection instead of six."
        ),
        breaks=(
            "In practice, nothing. These protocols were superseded decades ago and Fedora doesn't run "
            "them by default. The only way to notice this level is if you were deliberately logging in "
            "over SSH as root — use a normal account and sudo instead, which you should be doing anyway."
        ),
        crypto_policy="DEFAULT",
        ssh_directives=_BASIC_SSH,
        firewalld_services=_BASIC_SERVICES,
    ),
    EncryptionLevel(
        id="balanced",
        label="Balanced",
        summary="Drop SHA-1 signatures, require SSH keys, close plaintext mail. The daily driver.",
        detail=(
            "Moves the system crypto policy to DEFAULT:NO-SHA1, which stops this laptop accepting "
            "SHA-1 signatures anywhere — SHA-1 has been practically forgeable since 2017. Closes "
            "incoming plaintext mail and file transfer (ftp, pop3, imap, smtp) on top of the Basic list. "
            "For SSH it disables password logins entirely, so a key is required, and cuts the login "
            "grace window to 30 seconds.\n\n"
            "The password change is guarded: it is only written if a usable SSH key is already installed "
            "on this machine. If none is found, that one setting is skipped, everything else at this "
            "level still applies, and the page tells you it was skipped and why."
        ),
        breaks=(
            "Very little on a modern network. A server still presenting a SHA-1 certificate will fail to "
            "connect, but those are rare and genuinely unsafe. If you run a mail or FTP server on this "
            "laptop for other machines to reach, those stop being reachable — use the encrypted variants "
            "(imaps, pop3s, smtps), which stay open."
        ),
        crypto_policy="DEFAULT:NO-SHA1",
        ssh_directives=_BALANCED_SSH,
        firewalld_services=_BALANCED_SERVICES,
    ),
    EncryptionLevel(
        id="strict",
        label="Strict",
        summary="Modern cryptography only. Older servers and sites will stop connecting.",
        detail=(
            "Switches the system crypto policy to FUTURE. This is a large step, not a tweak: it raises "
            "the RSA minimum to 3072 bits, insists on TLS 1.2 or better with only forward-secret "
            "ciphers, and removes a long list of algorithms that are dated but still widely deployed. "
            "It applies to every program on the system that uses the shared crypto libraries. SSH is "
            "pinned to a short list of modern ciphers, MACs and key exchanges, and incoming plain HTTP "
            "is closed as well (HTTPS stays open)."
        ),
        breaks=(
            "Expect real breakage, and expect it in places you don't control: older HTTPS sites, "
            "corporate VPN concentrators, mail servers, embedded devices, printer web interfaces, and "
            "SSH to any host that hasn't been updated in a few years. Nothing is silently downgraded — "
            "connections simply fail. Choose this if you'd rather a connection fail than fall back to "
            "weak cryptography, and be ready to step down to Balanced when something you need refuses "
            "to work."
        ),
        crypto_policy="FUTURE",
        ssh_directives=_STRICT_SSH,
        firewalld_services=_STRICT_SERVICES,
    ),
]

ENCRYPTION_LEVEL_IDS = [level.id for level in ENCRYPTION_LEVELS]

# Shown as a permanent footnote on the page. FIPS is a crypto policy in the same
# list as FUTURE, so leaving it out without explanation reads like an oversight.
FIPS_NOTE = (
    "FIPS mode is deliberately not offered here. It isn't just a stricter version of Strict — it has to "
    "be switched on with fips-mode-setup, it changes how the kernel itself behaves, it needs a reboot, "
    "and on a system it doesn't agree with it can leave you unable to boot cleanly. It's a compliance "
    "requirement, not a hardening step, and it isn't something an app should flip for you."
)

REBOOT_NOTE = (
    "A crypto policy change applies to each program the next time that program starts. Reboot when "
    "convenient to be sure everything picked it up."
)

INBOUND_ONLY_NOTE = (
    "Closing a service only blocks connections coming in to this laptop. It does not stop this laptop "
    "from making plaintext connections out to somewhere else — that's what the crypto policy is for."
)


def get_encryption_level(level_id: str) -> EncryptionLevel:
    for level in ENCRYPTION_LEVELS:
        if level.id == level_id:
            return level
    return ENCRYPTION_LEVELS[0]
