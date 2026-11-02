"""Is DNS to outside servers blocked? VPNs and firewalls often allow DNS only to their own.

`trace`, `dnssec --server` and `propagation` send queries straight to servers on the
internet (root servers, public resolvers). Many VPNs (DNS leak protection) and firewalls
drop those and let DNS through only to the network's own DNS server, so the queries just
time out. This module tells that apart from being offline, and explains it.
"""

import errno
import socket
from dataclasses import dataclass

from dnskit.core.adapters import scan_adapters
from dnskit.core.diagnosis import Diagnosis
from dnskit.core.nameservers import PROBE_TIMEOUT_S, classify_nameservers, probe_all

# An outside DNS server used to test for a firewall on this computer (Quad9).
FIREWALL_TEST_SERVER = "9.9.9.9"

# errno values for "this computer isn't allowed to connect": a local firewall said no.
# Windows: 10013 WSAEACCES (e.g. a VPN's kill switch, Windows Firewall rules).
_DENIED_ERRNOS = {errno.EACCES, errno.EPERM, 10013}


@dataclass(frozen=True)
class DnsBlocking:
    """Why outside DNS servers might not answer, measured when they didn't."""

    working_nameservers: tuple[str, ...]  # this computer's own DNS servers that answered
    vpns: tuple[str, ...]  # names of connected VPN adapters
    local_firewall: bool  # this computer refused to even open a connection to port 53

    @property
    def system_works(self) -> bool:
        return bool(self.working_nameservers)


def check_blocking(timeout: float = PROBE_TIMEOUT_S) -> DnsBlocking:
    """Probe this computer's own DNS servers and look for a VPN and a local firewall."""
    scan = scan_adapters()
    nameservers = classify_nameservers(scan=scan).usable
    probes = probe_all(nameservers, timeout)
    return DnsBlocking(
        working_nameservers=tuple(p.nameserver for p in probes if p.latency_ms is not None),
        vpns=tuple(a.name for a in scan.connected_vpns),
        local_firewall=firewall_blocks(FIREWALL_TEST_SERVER, timeout),
    )


def firewall_blocks(address: str, timeout: float) -> bool:
    """True if this computer refuses a TCP connection to `address` port 53 outright."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((address, 53))
    except OSError as exc:
        return exc.errno in _DENIED_ERRNOS or getattr(exc, "winerror", None) in _DENIED_ERRNOS
    return False


def blocked_diagnosis(
    blocking: DnsBlocking, what: str, alternative: str = "", one: bool = False
) -> Diagnosis:
    """Explain why `what` (e.g. "the root servers"; one server if `one`) didn't answer.

    `alternative` is appended to the suggestion: what the command did or can do instead.
    """
    tail = f" {alternative}" if alternative else ""
    fine = (
        f" {_capitalize(what)} {'is' if one else 'are'} almost certainly fine; "
        f"{'it just can' if one else 'they just can'}'t be reached from here."
    )
    if not blocking.system_works:
        return Diagnosis(
            title="No DNS server answers: this computer looks offline",
            explanation=f"No reply from {what}, and this computer's own DNS servers don't "
            "answer either, so it probably has no working network connection.",
            suggestion="Check your Wi-Fi, Ethernet or VPN connection and try again. "
            "`dnskit local` checks this computer's DNS setup step by step." + tail,
        )

    own = ", ".join(blocking.working_nameservers)
    firewall = (
        " This computer itself refused to connect to an outside DNS server, so the block is "
        "a firewall on this computer" + (" (the VPN's kill switch)." if blocking.vpns else ".")
        if blocking.local_firewall
        else ""
    )
    if blocking.vpns:
        vpn = ", ".join(blocking.vpns)
        return Diagnosis(
            title="Direct DNS queries are blocked by the VPN",
            explanation=f"No reply from {what}, but this computer's own DNS server ({own}) "
            f"works. {vpn} (VPN) is connected, and VPNs usually block DNS to every server "
            "except their own, so DNS can't leak outside the tunnel (DNS leak protection)."
            f"{firewall}{fine}",
            suggestion=f"Disconnect {vpn} and run this again, or run it on another network." + tail,
        )
    return Diagnosis(
        title="Direct DNS queries are blocked by a firewall",
        explanation=f"No reply from {what}, but this computer's own DNS server ({own}) works. "
        "A firewall is probably blocking DNS (port 53) to outside servers and allowing only "
        f"the network's own DNS server: work, school, hotel and some home networks do this."
        f"{firewall}{fine}",
        suggestion="Run this on another network (a phone hotspot works), or ask the network's "
        "administrator. On your own network, look for firewall rules blocking outgoing port "
        "53." + tail,
    )


def _capitalize(text: str) -> str:
    return text[:1].upper() + text[1:]
