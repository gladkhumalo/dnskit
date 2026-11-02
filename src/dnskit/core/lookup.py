"""Record lookups across one or more record types."""

import errno
import re
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from dnskit.core.nameservers import ResolverChoice, choose_nameserver, system_nameservers

DEFAULT_RTYPES: tuple[str, ...] = ("A", "AAAA", "MX", "CNAME", "NS", "TXT")
# Record types whose values are character strings ("part one" "part two").
TEXT_RTYPES = frozenset({"TXT", "SPF"})

_TXT_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_TXT_ESCAPE = re.compile(r"\\(\d{3}|.)")

# errno values meaning "this machine has no route to the network". Windows socket errors
# carry WSA codes (10050 WSAENETDOWN, 10051 WSAENETUNREACH, 10065 WSAEHOSTUNREACH).
_NO_ROUTE_ERRNOS = {errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH, 10050, 10051, 10065}


class LookupStatus(StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NO_ANSWER = "no_answer"
    SERVFAIL = "servfail"
    TIMEOUT = "timeout"
    NO_NETWORK = "no_network"
    NO_NAMESERVERS = "no_nameservers"  # every nameserver refused or errored otherwise


@dataclass(frozen=True)
class Record:
    value: str
    ttl: int


@dataclass(frozen=True)
class LookupResult:
    rtype: str
    status: LookupStatus
    records: tuple[Record, ...] = ()
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class LookupReport:
    name: str
    nameserver: str
    nameserver_source: str
    results: tuple[LookupResult, ...]
    elapsed_ms: float
    # How the system nameserver was picked (probe results, cache use). None with --server.
    resolver_choice: ResolverChoice | None = None


def lookup(
    name: str,
    rtypes: Sequence[str] = DEFAULT_RTYPES,
    nameserver: str | None = None,
    timeout: float = 5.0,
    refresh: bool = False,
) -> LookupReport:
    """Query `name` for each of `rtypes` in parallel against one chosen resolver.

    Without `nameserver`, the fastest system nameserver is used (a recent choice is reused
    from the cache unless `refresh`), with the others as fallbacks. An explicit `nameserver`
    always wins and never touches the cache. Expected DNS failures are reported per type via
    `LookupResult.status`; an unknown record type raises ValueError.
    """
    rtypes = [_validate_rtype(rtype) for rtype in rtypes]

    start = time.perf_counter()
    selection = _choose_nameservers(nameserver, refresh)
    nameservers = selection.nameservers

    with ThreadPoolExecutor(max_workers=len(rtypes)) as pool:
        results = tuple(
            pool.map(lambda rtype: _query_one(name, rtype, nameservers, timeout), rtypes)
        )

    return LookupReport(
        name=name,
        nameserver=nameservers[0],
        nameserver_source=selection.source,
        results=results,
        elapsed_ms=(time.perf_counter() - start) * 1000,
        resolver_choice=selection.choice,
    )


def _validate_rtype(rtype: str) -> str:
    """Return `rtype` upper-cased, or raise ValueError if dnspython doesn't know it."""
    rtype = rtype.upper()
    try:
        dns.rdatatype.from_text(rtype)
    except dns.rdatatype.UnknownRdatatype as exc:
        raise ValueError(
            f"Unknown record type: {rtype}. Common types are {', '.join(DEFAULT_RTYPES)}."
        ) from exc
    return rtype


@dataclass(frozen=True)
class _Selection:
    nameservers: list[str]  # in the order to try them
    source: str  # how the first one was picked, for display
    choice: ResolverChoice | None  # None when an explicit nameserver was given


def _choose_nameservers(nameserver: str | None, refresh: bool = False) -> _Selection:
    if nameserver is not None:
        return _Selection([nameserver], "--server", None)

    candidates = system_nameservers()
    if not candidates:
        raise ValueError(
            "No nameservers are configured on this computer — it may be offline. Connect to "
            "a network, or pass a nameserver explicitly with --server."
        )

    choice = choose_nameserver(candidates, use_cache=not refresh)
    if choice.nameserver is None:
        return _Selection(candidates, "system order (no nameserver answered probe)", choice)

    source = f"auto: fastest of {len(candidates)} system nameservers"
    if choice.latency_ms is not None:
        source += f", {choice.latency_ms:.0f} ms"
    return _Selection(choice.ordered(), source, choice)


def _make_resolver(nameservers: Sequence[str], timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers)
    resolver.lifetime = timeout
    return resolver


def _query_one(
    name: str,
    rtype: str,
    nameservers: Sequence[str],
    timeout: float,
    retry_after: float | None = None,
) -> LookupResult:
    """One lookup, within `timeout` in total.

    dnspython re-sends an unanswered query only after 2 s, so with a shorter `timeout` one
    lost packet means a timeout. `retry_after` re-sends sooner, to ride out packet loss.
    """
    resolver = _make_resolver(nameservers, timeout)
    if retry_after is not None:
        resolver.timeout = retry_after
    start = time.perf_counter()

    def failed(status: LookupStatus) -> LookupResult:
        return LookupResult(rtype, status, elapsed_ms=(time.perf_counter() - start) * 1000)

    try:
        answer = resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return failed(LookupStatus.NXDOMAIN)
    except dns.resolver.NoAnswer:
        return failed(LookupStatus.NO_ANSWER)
    except dns.exception.Timeout:
        return failed(LookupStatus.TIMEOUT)
    except dns.resolver.NoNameservers as exc:
        return failed(_classify_nameserver_errors(exc.kwargs.get("errors") or []))
    except OSError as exc:
        no_route = _is_no_route(exc)
        return failed(LookupStatus.NO_NETWORK if no_route else LookupStatus.NO_NAMESERVERS)

    ttl = answer.rrset.ttl if answer.rrset is not None else 0
    records = tuple(Record(rdata.to_text(), ttl) for rdata in answer)
    return LookupResult(
        rtype, LookupStatus.OK, records, elapsed_ms=(time.perf_counter() - start) * 1000
    )


def txt_text(value: str) -> str:
    """A TXT record's text as dnspython prints it, unquoted: the strings joined, escapes undone.

    `"v=spf1 include:a" " -all"` becomes `v=spf1 include:a -all`. A value without quotes is
    returned unchanged.
    """
    parts = _TXT_STRING.findall(value)
    if not parts:
        return value
    unescape = _TXT_ESCAPE.sub
    return "".join(
        unescape(lambda m: chr(int(m[1])) if m[1].isdigit() else m[1], part) for part in parts
    )


def _classify_nameserver_errors(errors: Sequence[tuple[Any, ...]]) -> LookupStatus:
    """Work out why every nameserver failed, from dnspython's NoNameservers error list.

    Each entry is (nameserver, tcp, port, error, response); `error` is an exception, or the
    rcode text (e.g. "SERVFAIL") when the server answered with an error code.
    """
    reasons = [entry[3] for entry in errors]
    if any(str(reason) == "SERVFAIL" for reason in reasons):
        return LookupStatus.SERVFAIL
    if reasons and all(isinstance(r, OSError) and _is_no_route(r) for r in reasons):
        return LookupStatus.NO_NETWORK
    return LookupStatus.NO_NAMESERVERS


def _is_no_route(exc: OSError) -> bool:
    return exc.errno in _NO_ROUTE_ERRNOS or getattr(exc, "winerror", None) in _NO_ROUTE_ERRNOS
