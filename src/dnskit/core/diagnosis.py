"""Plain-English explanations and next steps for lookup failures.

Returned as data so every front end (CLI now, web UI later) can present them its own way.
"""

import ipaddress
from dataclasses import dataclass

from dnskit.core.lookup import LookupStatus


@dataclass(frozen=True)
class Diagnosis:
    title: str
    explanation: str
    suggestion: str


def explain(
    status: LookupStatus, name: str, rtype: str, timeout: float | None = None
) -> Diagnosis | None:
    """Explain a lookup status for `name`/`rtype`. Returns None for a successful lookup."""
    match status:
        case LookupStatus.OK:
            return None
        case LookupStatus.NXDOMAIN:
            return Diagnosis(
                title="Domain doesn't exist",
                explanation=f"{name} isn't registered in DNS — the nameserver answered that "
                "no such name exists (NXDOMAIN).",
                suggestion="Check the spelling for typos. If this domain used to work, its "
                "registration may have expired — check it with a WHOIS lookup.",
            )
        case LookupStatus.NO_ANSWER:
            return Diagnosis(
                title=f"No {rtype} records",
                explanation=f"{name} exists, but has no {rtype} records.",
                suggestion="This is often normal (for example, many domains have no AAAA "
                f"records). Run `dnskit lookup {name}` to see which record types it does have.",
            )
        case LookupStatus.SERVFAIL:
            return Diagnosis(
                title="Nameserver failure (SERVFAIL)",
                explanation=f"The resolver tried to look up {name} but failed. This usually "
                "points to a problem with the domain's own nameservers or a broken DNSSEC "
                "signature, not with your connection.",
                suggestion="Try a different public resolver (such as 1.1.1.1 or 8.8.8.8). If "
                "they fail too, the domain's DNS hosting is broken — contact the domain owner "
                "or their DNS provider.",
            )
        case LookupStatus.TIMEOUT:
            within = f" within {timeout:g} seconds" if timeout is not None else " in time"
            return Diagnosis(
                title="Query timed out",
                explanation=f"No nameserver replied{within}.",
                suggestion="Check your internet connection, then try a different resolver "
                "(such as 1.1.1.1) or a longer timeout. A firewall or VPN blocking DNS "
                "(port 53) can also cause this.",
            )
        case LookupStatus.NO_NETWORK:
            return Diagnosis(
                title="No network connection",
                explanation="Couldn't reach any nameserver — this computer appears to be "
                "offline or has no route to the internet.",
                suggestion="Check your Wi-Fi, Ethernet or VPN connection and try again. "
                "`dnskit resolvers` shows which nameservers are reachable.",
            )
        case LookupStatus.NO_NAMESERVERS:
            return Diagnosis(
                title="All nameservers refused or failed",
                explanation=f"Every nameserver rejected the query for {name} or returned an error.",
                suggestion="The resolver may not accept queries from your network. Try a "
                "public resolver such as 1.1.1.1, or run `dnskit resolvers` to check which "
                "nameservers respond.",
            )


def explain_reverse(
    status: LookupStatus, ip: str, timeout: float | None = None
) -> Diagnosis | None:
    """Explain a PTR lookup status for `ip`, with advice specific to reverse DNS."""
    if status in (LookupStatus.NXDOMAIN, LookupStatus.NO_ANSWER):
        if ipaddress.ip_address(ip).is_private:
            suggestion = (
                f"{ip} is a private or reserved address, so public resolvers can't know its "
                "name. Ask your local network's DNS server (usually your router) by passing its "
                "IP as the resolver."
            )
        else:
            suggestion = (
                "Reverse DNS is set by whoever owns the IP address (usually the ISP or hosting "
                "provider). Ask them to add a PTR record if you need one — for example, mail "
                "servers often require it."
            )
        return Diagnosis(
            title="No reverse DNS name",
            explanation=f"{ip} has no PTR record, so there's no hostname registered for it.",
            suggestion=suggestion,
        )
    return explain(status, ip, "PTR", timeout)
