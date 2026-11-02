"""Can this computer reach a site? Resolve it, then try a TCP connection to each address.

The verdict says where the problem is: DNS (no usable address), the connection (addresses,
but none accepts a connection), or neither.
"""

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from dnskit.core.connectivity import ConnectAttempt, ConnectError, tcp_connect
from dnskit.core.diagnosis import Diagnosis, explain
from dnskit.core.local import HostsEntry, read_hosts
from dnskit.core.lookup import LookupResult, LookupStatus, _choose_nameservers, _query_one
from dnskit.core.mail import normalize_domain
from dnskit.core.nameservers import ResolverChoice

DEFAULT_PORT = 443
# Enough to tell "all down" from "some down" without hammering a site with many addresses.
MAX_ADDRESSES_PER_FAMILY = 4


class ReachVerdict(StrEnum):
    REACHABLE = "reachable"  # DNS and the connection both work
    DNS = "dns"  # no usable address: the problem is DNS
    CONNECTION = "connection"  # addresses, but no connection: the problem is the network/server


@dataclass(frozen=True)
class ReachReport:
    name: str
    port: int
    nameserver: str
    nameserver_source: str
    a: LookupResult
    aaaa: LookupResult
    attempts: tuple[ConnectAttempt, ...]  # IPv4 first, then IPv6
    hosts_entries: tuple[HostsEntry, ...]  # hosts file lines for this name (DNS bypassed)
    elapsed_ms: float
    resolver_choice: ResolverChoice | None = None  # None with an explicit nameserver

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(r.value for r in (*self.a.records, *self.aaaa.records))

    @property
    def blocked_by_dns(self) -> bool:
        """DNS answered only with 0.0.0.0 or a loopback address: a DNS filter's "blocked"."""
        return bool(self.addresses) and all(_is_sinkhole(a) for a in self.addresses)

    @property
    def verdict(self) -> ReachVerdict:
        if not self.addresses or self.blocked_by_dns:
            return ReachVerdict.DNS
        if any(a.ok for a in self.attempts):
            return ReachVerdict.REACHABLE
        return ReachVerdict.CONNECTION


def parse_target(text: str) -> str:
    """The domain in `text`, which may be a URL like https://example.com/page."""
    text = text.strip()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    return normalize_domain(text)


def reach(
    target: str,
    port: int = DEFAULT_PORT,
    nameserver: str | None = None,
    timeout: float = 5.0,
    refresh: bool = False,
) -> ReachReport:
    """Resolve `target` (A and AAAA) and try a TCP connection to `port` on its addresses.

    Nameserver selection works as in `lookup()`. An invalid name or port raises ValueError.
    """
    name = parse_target(target)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} is out of range. Use a port from 1 to 65535.")

    start = time.perf_counter()
    selection = _choose_nameservers(nameserver, refresh)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a, aaaa = pool.map(
            lambda rtype: _query_one(name, rtype, selection.nameservers, timeout), ("A", "AAAA")
        )

    targets = [r.value for r in a.records[:MAX_ADDRESSES_PER_FAMILY]]
    targets += [r.value for r in aaaa.records[:MAX_ADDRESSES_PER_FAMILY]]
    targets = [t for t in targets if not _is_sinkhole(t)]
    attempts: tuple[ConnectAttempt, ...] = ()
    if targets:
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            attempts = tuple(pool.map(lambda ip: tcp_connect(ip, port, timeout), targets))

    hosts = read_hosts()
    return ReachReport(
        name=name,
        port=port,
        nameserver=selection.nameservers[0],
        nameserver_source=selection.source,
        a=a,
        aaaa=aaaa,
        attempts=attempts,
        hosts_entries=tuple(e for e in hosts.entries if name in {n.lower() for n in e.names}),
        elapsed_ms=(time.perf_counter() - start) * 1000,
        resolver_choice=selection.choice,
    )


def _no_ipv6(attempt: ConnectAttempt) -> bool:
    """An IPv6 attempt that failed because this computer has no IPv6 route."""
    return attempt.version == 6 and attempt.error is ConnectError.UNREACHABLE


def _is_sinkhole(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_unspecified or ip.is_loopback


# --- Explanation --------------------------------------------------------------------------


def explain_reach(report: ReachReport, timeout: float | None = None) -> Diagnosis:
    """Where the problem is, in plain English, with the next step."""
    match report.verdict:
        case ReachVerdict.DNS:
            diagnosis = _dns_diagnosis(report, timeout)
        case ReachVerdict.CONNECTION:
            diagnosis = _connection_diagnosis(report)
        case _:
            diagnosis = _reachable_diagnosis(report)
    if report.hosts_entries:
        pointed = ", ".join(f"{e.ip} (line {e.line})" for e in report.hosts_entries)
        diagnosis = Diagnosis(
            diagnosis.title,
            f"{diagnosis.explanation} Note: this computer's hosts file points {report.name} at "
            f"{pointed}. Browsers and most apps use that instead of DNS, so they may behave "
            "differently from this test.",
            diagnosis.suggestion,
        )
    return diagnosis


def _dns_diagnosis(report: ReachReport, timeout: float | None) -> Diagnosis:
    name = report.name
    if report.blocked_by_dns:
        return Diagnosis(
            title="The problem is DNS: the name is blocked",
            explanation=f"The DNS server answered {', '.join(report.addresses)} for {name}, which "
            "is how DNS filters (ad blockers such as Pi-hole, parental controls, company or "
            "school filters) block a site.",
            suggestion="If the site should be allowed, ask whoever runs the filter to unblock "
            f"it, or check it with a public resolver: dnskit reach {name} --server 1.1.1.1.",
        )
    statuses = {report.a.status, report.aaaa.status}
    if statuses <= {LookupStatus.NO_ANSWER, LookupStatus.NXDOMAIN} and (
        LookupStatus.NO_ANSWER in statuses
    ):
        return Diagnosis(
            title="The problem is DNS: no addresses",
            explanation=f"{name} exists, but has no A (IPv4) or AAAA (IPv6) records, so there's "
            "no address to connect to.",
            suggestion=f"Check the spelling. If it's your domain, add an A record. Run dnskit "
            f"lookup {name} to see the records it does have.",
        )
    # The A lookup's failure is the more telling one (AAAA is often just absent).
    status = (
        report.a.status if report.a.status is not LookupStatus.NO_ANSWER else report.aaaa.status
    )
    reason = explain(status, name, "A", timeout)
    assert reason is not None  # status isn't OK: there were no addresses
    return Diagnosis(
        title=f"The problem is DNS: {reason.title[0].lower()}{reason.title[1:]}",
        explanation=reason.explanation,
        suggestion=reason.suggestion,
    )


def _connection_diagnosis(report: ReachReport) -> Diagnosis:
    port, name = report.port, report.name
    # Without IPv6, its addresses are unreachable by definition; judge by the IPv4 ones.
    relevant = [a for a in report.attempts if not _no_ipv6(a)] or list(report.attempts)
    errors = {a.error for a in relevant}
    shown = ", ".join(a.address for a in relevant)
    if errors == {ConnectError.REFUSED}:
        explanation = (
            f"DNS works: {name} resolved to {shown}. The server answered, but refused the "
            f"connection on port {port}, so nothing is accepting connections there."
        )
        suggestion = (
            "The web server is down or doesn't use this port"
            + (" (does the site support HTTPS?)" if port == 443 else "")
            + ". If it's your server, check that the service is running and listening on "
            f"port {port}."
        )
    elif errors == {ConnectError.UNREACHABLE}:
        explanation = (
            f"DNS works: {name} resolved to {shown}, but this computer has no network route "
            "to those addresses."
        )
        only_v6 = all(a.version == 6 for a in report.attempts)
        suggestion = (
            "The site only has IPv6 addresses and this computer has no IPv6 connection. Use a "
            "network with IPv6, or ask the site owner to add an IPv4 (A) record."
            if only_v6
            else "Check your network connection, VPN and routes."
        )
    else:
        explanation = (
            f"DNS works: {name} resolved to {shown}, but no connection to port {port} got a "
            "reply. Something between this computer and the server drops it: a firewall here "
            "or on the network, a VPN, or the server itself is down."
        )
        suggestion = (
            "Check whether other sites load. If they do, try another network (such as a phone "
            "hotspot) to see whether this network blocks it, and check the site's status page."
        )
    return Diagnosis(
        title=f"The problem is the connection: port {port} isn't reachable",
        explanation=explanation,
        suggestion=suggestion,
    )


def _reachable_diagnosis(report: ReachReport) -> Diagnosis:
    first = min((a for a in report.attempts if a.ok), key=lambda a: a.latency_ms or 0.0)
    explanation = (
        f"{report.name} resolved to {len(report.addresses)} address"
        f"{'' if len(report.addresses) == 1 else 'es'}, and {first.address} accepted a "
        f"connection on port {report.port} in {first.latency_ms:.0f} ms."
    )
    # Unreachable IPv6 just means this computer has none, so apps use IPv4; that's fine.
    # IPv6 that's routed but doesn't answer is what slows apps down (they try it first).
    broken_v6 = [a for a in report.attempts if a.version == 6 and not a.ok and not _no_ipv6(a)]
    if broken_v6 and any(a.ok and a.version == 4 for a in report.attempts):
        explanation += (
            " IPv6 connections failed, though, so programs that try IPv6 first may be slow. "
            "dnskit local checks IPv6 in more detail."
        )
    return Diagnosis(
        title="Neither: DNS and the connection both work",
        explanation=explanation,
        suggestion="If the site still doesn't load, the problem is past the connection: the "
        "web server, its certificate, or the browser. Try another browser or a private window, "
        "and flush the DNS cache (dnskit local shows the command).",
    )
