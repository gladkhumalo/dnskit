"""Reverse (PTR) lookups for IPv4 and IPv6 addresses."""

import ipaddress
import time
from dataclasses import dataclass

import dns.reversename

from dnskit.core.lookup import LookupResult, _choose_nameservers, _query_one
from dnskit.core.nameservers import ResolverChoice


@dataclass(frozen=True)
class ReverseReport:
    ip: str  # canonical form, e.g. "2001:db8::1"
    version: int  # 4 or 6
    ptr_name: str  # e.g. "1.0.0.127.in-addr.arpa."
    nameserver: str
    nameserver_source: str
    result: LookupResult
    elapsed_ms: float
    resolver_choice: ResolverChoice | None = None  # None with an explicit nameserver


def parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IPv4 or IPv6 address, dropping any IPv6 zone (e.g. "%eth0")."""
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ValueError(
            f"'{text}' is not a valid IP address. Use an IPv4 address like 8.8.8.8 or an "
            "IPv6 address like 2001:4860:4860::8888."
        ) from None
    # Rebuilding from the raw bytes strips the zone, which has no meaning in DNS.
    return ipaddress.ip_address(addr.packed)


def reverse_lookup(
    ip: str, nameserver: str | None = None, timeout: float = 5.0, refresh: bool = False
) -> ReverseReport:
    """Look up the PTR record for `ip`. An invalid address raises ValueError.

    Nameserver selection works as in `lookup()`.
    """
    addr = parse_ip(ip)
    ptr_name = dns.reversename.from_address(str(addr)).to_text()

    start = time.perf_counter()
    selection = _choose_nameservers(nameserver, refresh)
    result = _query_one(ptr_name, "PTR", selection.nameservers, timeout)

    return ReverseReport(
        ip=str(addr),
        version=addr.version,
        ptr_name=ptr_name,
        nameserver=selection.nameservers[0],
        nameserver_source=selection.source,
        result=result,
        elapsed_ms=(time.perf_counter() - start) * 1000,
        resolver_choice=selection.choice,
    )
