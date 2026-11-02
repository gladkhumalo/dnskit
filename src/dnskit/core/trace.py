"""Follow a name's delegation from the root servers down, like `dig +trace`.

Each level's nameservers are asked directly, without recursion: the root servers refer to
the top-level domain's servers, those refer to the domain's own nameservers, and those give
the answer. When direct queries are blocked (a VPN or firewall that allows DNS only to the
network's own server), the delegation is followed through that resolver instead.
"""

import time
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from enum import StrEnum

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from dnskit.core.diagnosis import Diagnosis
from dnskit.core.lookup import LookupStatus, _is_no_route, _query_one, _validate_rtype
from dnskit.core.nameservers import system_nameservers
from dnskit.core.outside import _DENIED_ERRNOS, DnsBlocking, blocked_diagnosis, check_blocking
from dnskit.core.reach import parse_target

# The 13 root server identities (IANA root hints), as (name, IPv4 address).
ROOT_SERVERS: tuple[tuple[str, str], ...] = (
    ("a.root-servers.net.", "198.41.0.4"),
    ("b.root-servers.net.", "170.247.170.2"),
    ("c.root-servers.net.", "192.33.4.12"),
    ("d.root-servers.net.", "199.7.91.13"),
    ("e.root-servers.net.", "192.203.230.10"),
    ("f.root-servers.net.", "192.5.5.241"),
    ("g.root-servers.net.", "192.112.36.4"),
    ("h.root-servers.net.", "198.97.190.53"),
    ("i.root-servers.net.", "192.36.148.17"),
    ("j.root-servers.net.", "192.58.128.30"),
    ("k.root-servers.net.", "193.0.14.129"),
    ("l.root-servers.net.", "199.7.83.42"),
    ("m.root-servers.net.", "202.12.27.33"),
)

# Per query. Each level's servers are asked at once, so a dead level costs one timeout.
TRACE_TIMEOUT_S = 2.0
# How many of a level's nameservers are asked at once; the first usable reply is used.
SERVERS_PER_LEVEL = 3
# Real delegations are a handful of levels deep; more means a referral loop.
MAX_STEPS = 16


class StepStatus(StrEnum):
    REFERRAL = "referral"  # pointed to the next level's nameservers
    ANSWER = "answer"  # gave the records (or a CNAME)
    NXDOMAIN = "nxdomain"  # the name doesn't exist
    NO_ANSWER = "no_answer"  # the name exists but has no records of this type
    FAILED = "failed"  # no server at this level gave a usable reply


class FailReason(StrEnum):
    NO_RESPONSE = "no_response"  # timed out, no route, or blocked before leaving
    REFUSED = "refused"
    SERVFAIL = "servfail"
    LAME = "lame"  # answered, but with neither the records nor a referral
    NO_ADDRESS = "no_address"  # the next level's nameservers have no address
    TOO_DEEP = "too_deep"  # referral loop


class TraceMode(StrEnum):
    DIRECT = "direct"  # each level's servers were asked directly, from the root down
    VIA_RESOLVER = "via_resolver"  # direct queries blocked: asked a resolver about each level


@dataclass(frozen=True)
class Server:
    name: str  # e.g. "a.root-servers.net."; the address again for a resolver
    address: str


@dataclass(frozen=True)
class ServerFailure:
    server: Server
    reason: FailReason
    error: str  # in words, e.g. "timed out", "REFUSED"


@dataclass(frozen=True)
class TraceStep:
    zone: str  # the zone whose nameservers were asked, "." for the root
    status: StepStatus
    server: Server | None = None  # who gave the reply; None when the step failed
    latency_ms: float | None = None
    referral_zone: str | None = None  # REFERRAL: the next zone down
    referral_servers: tuple[str, ...] = ()  # REFERRAL: its nameserver names
    records: tuple[str, ...] = ()  # ANSWER: the values, e.g. "93.184.215.14", "CNAME x."
    failures: tuple[ServerFailure, ...] = ()  # servers at this level that didn't help
    reason: FailReason | None = None  # FAILED: why, summed up over `failures`
    note: str = ""  # e.g. that the nameservers' addresses had to be looked up


@dataclass(frozen=True)
class TraceReport:
    name: str  # fully qualified, with the trailing dot
    rtype: str
    mode: TraceMode
    steps: tuple[TraceStep, ...]
    elapsed_ms: float
    timeout: float
    # Set when the root servers didn't respond: why (VPN, firewall, offline).
    blocking: DnsBlocking | None = None
    resolver: str | None = None  # VIA_RESOLVER: the resolver that was asked

    @property
    def final(self) -> TraceStep:
        return self.steps[-1]

    @property
    def succeeded(self) -> bool:
        return self.final.status is StepStatus.ANSWER


def trace(target: str, rtype: str = "A", timeout: float = TRACE_TIMEOUT_S) -> TraceReport:
    """Follow `target`'s delegation from the root servers down to its records.

    An invalid name or record type raises ValueError; everything else is reported on the
    steps. If no root server responds, `check_blocking` finds out why, and when this
    computer's own DNS works the trace is redone through it (TraceMode.VIA_RESOLVER).
    """
    name = dns.name.from_text(parse_target(target)).to_text()
    rtype = _validate_rtype(rtype)
    start = time.perf_counter()

    steps = _trace_direct(name, rtype, timeout)
    blocking = None
    first = steps[0]
    if first.status is StepStatus.FAILED and first.reason is FailReason.NO_RESPONSE:
        blocking = check_blocking()
        if blocking.system_works:
            resolver = blocking.working_nameservers[0]
            return TraceReport(
                name,
                rtype,
                TraceMode.VIA_RESOLVER,
                tuple(_trace_via_resolver(name, rtype, resolver, timeout)),
                elapsed_ms=(time.perf_counter() - start) * 1000,
                timeout=timeout,
                blocking=blocking,
                resolver=resolver,
            )
    return TraceReport(
        name,
        rtype,
        TraceMode.DIRECT,
        tuple(steps),
        elapsed_ms=(time.perf_counter() - start) * 1000,
        timeout=timeout,
        blocking=blocking,
    )


# --- Asking one server --------------------------------------------------------------------


@dataclass(frozen=True)
class _Reply:
    server: Server
    response: dns.message.Message | None
    latency_ms: float
    failure: ServerFailure | None = None  # set when there's no response


def _send(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
    """One query to one server, over UDP, retried over TCP if the reply was truncated."""
    response, _ = dns.query.udp_with_fallback(query, address, timeout=timeout)
    return response


def _ask(server: Server, name: str, rtype: str, timeout: float, recursive: bool) -> _Reply:
    query = dns.message.make_query(name, rtype, use_edns=0, payload=1232)
    if not recursive:
        query.flags &= ~dns.flags.RD
    start = time.perf_counter()

    def failed(error: str) -> _Reply:
        latency = (time.perf_counter() - start) * 1000
        return _Reply(server, None, latency, ServerFailure(server, FailReason.NO_RESPONSE, error))

    try:
        response = _send(query, server.address, timeout)
    except dns.exception.Timeout:
        return failed("timed out")
    except OSError as exc:
        if exc.errno in _DENIED_ERRNOS or getattr(exc, "winerror", None) in _DENIED_ERRNOS:
            return failed("blocked by a firewall on this computer")
        return failed("no route to it" if _is_no_route(exc) else str(exc))
    except dns.exception.DNSException as exc:
        return failed(str(exc) or type(exc).__name__)
    return _Reply(server, response, (time.perf_counter() - start) * 1000)


# --- Direct trace -------------------------------------------------------------------------


def _trace_direct(name: str, rtype: str, timeout: float) -> list[TraceStep]:
    steps: list[TraceStep] = []
    zone = "."
    servers = [Server(n, a) for n, a in ROOT_SERVERS]
    for _ in range(MAX_STEPS):
        step, response = _ask_level(zone, servers, name, rtype, timeout)
        steps.append(step)
        if step.status is not StepStatus.REFERRAL or response is None:
            return steps
        servers, note = _next_servers(step, response, timeout)
        zone = step.referral_zone or zone
        if not servers:
            names = ", ".join(step.referral_servers)
            steps.append(
                TraceStep(
                    zone,
                    StepStatus.FAILED,
                    reason=FailReason.NO_ADDRESS,
                    note=f"none of its nameservers ({names}) has an address",
                )
            )
            return steps
        if note:
            steps[-1] = replace(step, note=note)
    steps.append(TraceStep(zone, StepStatus.FAILED, reason=FailReason.TOO_DEEP))
    return steps


def _ask_level(
    zone: str, servers: Sequence[Server], name: str, rtype: str, timeout: float
) -> tuple[TraceStep, dns.message.Message | None]:
    """Ask a few of `zone`'s servers at once; the first usable reply makes the step."""
    candidates = list(servers[:SERVERS_PER_LEVEL])
    failures: list[ServerFailure] = []
    pool = ThreadPoolExecutor(max_workers=len(candidates))
    try:
        pending = {pool.submit(_ask, s, name, rtype, timeout, False) for s in candidates}
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                reply = future.result()
                outcome = _interpret(zone, name, rtype, reply)
                if isinstance(outcome, ServerFailure):
                    failures.append(outcome)
                    continue
                return replace(outcome, failures=tuple(failures)), reply.response
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    order = {s: i for i, s in enumerate(candidates)}
    failures.sort(key=lambda f: order.get(f.server, 0))
    return (
        TraceStep(zone, StepStatus.FAILED, failures=tuple(failures), reason=_reason(failures)),
        None,
    )


def _interpret(zone: str, name: str, rtype: str, reply: _Reply) -> TraceStep | ServerFailure:
    """What one server's reply means for the trace: a step, or why it was no use."""
    if reply.response is None:
        assert reply.failure is not None
        return reply.failure
    response = reply.response
    server, latency = reply.server, reply.latency_ms
    rcode = response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return TraceStep(zone, StepStatus.NXDOMAIN, server, latency)
    if rcode != dns.rcode.NOERROR:
        text = dns.rcode.to_text(rcode)
        reason = {"REFUSED": FailReason.REFUSED, "SERVFAIL": FailReason.SERVFAIL}.get(
            text, FailReason.LAME
        )
        return ServerFailure(server, reason, text)

    records = _answer_values(response, name, rtype)
    if records:
        return TraceStep(zone, StepStatus.ANSWER, server, latency, records=records)

    qname = dns.name.from_text(name)
    zone_name = dns.name.from_text(zone)
    for rrset in response.authority:
        if (
            rrset.rdtype == dns.rdatatype.NS
            and rrset.name != zone_name
            and rrset.name.is_subdomain(zone_name)
            and qname.is_subdomain(rrset.name)
        ):
            return TraceStep(
                zone,
                StepStatus.REFERRAL,
                server,
                latency,
                referral_zone=rrset.name.to_text(),
                referral_servers=tuple(sorted(rdata.target.to_text() for rdata in rrset)),
            )
    authoritative = bool(response.flags & dns.flags.AA) or any(
        rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority
    )
    if authoritative:
        return TraceStep(zone, StepStatus.NO_ANSWER, server, latency)
    return ServerFailure(server, FailReason.LAME, "answered with neither records nor a referral")


def _answer_values(response: dns.message.Message, name: str, rtype: str) -> tuple[str, ...]:
    """The records answering `name`/`rtype`, plus any CNAMEs on the way."""
    wanted = dns.rdatatype.from_text(rtype)
    values = []
    for rrset in response.answer:
        if rrset.rdtype == wanted:
            values += [rdata.to_text() for rdata in rrset]
        elif rrset.rdtype == dns.rdatatype.CNAME:
            values += [f"CNAME {rdata.target}" for rdata in rrset]
    return tuple(values)


def _next_servers(
    step: TraceStep, response: dns.message.Message, timeout: float
) -> tuple[list[Server], str]:
    """The referred-to nameservers with IPv4 addresses: glue first, else looked up."""
    glue: dict[str, list[str]] = {}
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            glue.setdefault(rrset.name.to_text(), []).extend(r.address for r in rrset)
    servers = [Server(ns, glue[ns][0]) for ns in step.referral_servers if glue.get(ns)]
    if servers:
        return servers, ""

    # No glue (the nameservers are in another domain): look their addresses up normally.
    names = list(step.referral_servers[:SERVERS_PER_LEVEL])
    if not names:
        return [], ""
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        addresses = list(pool.map(lambda ns: _lookup_address(ns, timeout), names))
    servers = [Server(ns, address) for ns, address in zip(names, addresses, strict=True) if address]
    return servers, "no glue: looked up the nameservers' addresses separately"


def _lookup_address(ns: str, timeout: float) -> str | None:
    """`ns`'s first IPv4 address, through this computer's DNS servers."""
    nameservers = system_nameservers()
    if not nameservers:
        return None
    result = _query_one(ns, "A", nameservers, timeout)
    if result.status is not LookupStatus.OK or not result.records:
        return None
    return result.records[0].value


def _reason(failures: Sequence[ServerFailure]) -> FailReason:
    """One reason for a whole level: the most telling one any server gave."""
    priority = [FailReason.LAME, FailReason.REFUSED, FailReason.SERVFAIL, FailReason.NO_RESPONSE]
    reasons = {f.reason for f in failures}
    return next((r for r in priority if r in reasons), FailReason.NO_RESPONSE)


# --- Through a resolver -------------------------------------------------------------------


def _trace_via_resolver(name: str, rtype: str, resolver: str, timeout: float) -> list[TraceStep]:
    """Each level's nameservers as `resolver` sees them, then the records from it.

    For every parent of `name` (com., example.com., ...) an NS answer for exactly that name
    marks a delegation. This shows the chain, though not how each nameserver answers.
    """
    server = Server(resolver, resolver)
    qname = dns.name.from_text(name)
    steps: list[TraceStep] = []
    zone = "."
    for depth in range(2, len(qname) + 1):
        suffix = qname.split(depth)[1]
        reply = _ask(server, suffix.to_text(), "NS", timeout, recursive=True)
        if reply.response is None:
            assert reply.failure is not None
            steps.append(_failed_via(zone, reply.failure))
            return steps
        rcode = reply.response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            steps.append(TraceStep(zone, StepStatus.NXDOMAIN, server, reply.latency_ms))
            return steps
        if rcode != dns.rcode.NOERROR:
            text = dns.rcode.to_text(rcode)
            reason = FailReason.SERVFAIL if text == "SERVFAIL" else FailReason.REFUSED
            steps.append(_failed_via(zone, ServerFailure(server, reason, text)))
            return steps
        answer = reply.response.answer
        ns = next((r for r in answer if r.rdtype == dns.rdatatype.NS and r.name == suffix), None)
        if ns is not None:
            steps.append(
                TraceStep(
                    zone,
                    StepStatus.REFERRAL,
                    server,
                    reply.latency_ms,
                    referral_zone=suffix.to_text(),
                    referral_servers=tuple(sorted(r.target.to_text() for r in ns)),
                )
            )
            zone = suffix.to_text()
        elif any(r.rdtype == dns.rdatatype.CNAME and r.name == suffix for r in answer):
            break  # an alias: the final query shows where it points

    reply = _ask(server, name, rtype, timeout, recursive=True)
    if reply.response is None:
        assert reply.failure is not None
        steps.append(_failed_via(zone, reply.failure))
        return steps
    rcode = reply.response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        steps.append(TraceStep(zone, StepStatus.NXDOMAIN, server, reply.latency_ms))
    elif rcode != dns.rcode.NOERROR:
        text = dns.rcode.to_text(rcode)
        reason = FailReason.SERVFAIL if text == "SERVFAIL" else FailReason.REFUSED
        steps.append(_failed_via(zone, ServerFailure(server, reason, text)))
    elif records := _answer_values(reply.response, name, rtype):
        steps.append(TraceStep(zone, StepStatus.ANSWER, server, reply.latency_ms, records=records))
    else:
        steps.append(TraceStep(zone, StepStatus.NO_ANSWER, server, reply.latency_ms))
    return steps


def _failed_via(zone: str, failure: ServerFailure) -> TraceStep:
    return TraceStep(zone, StepStatus.FAILED, failures=(failure,), reason=failure.reason)


# --- Explanation --------------------------------------------------------------------------


def level_name(zone: str) -> str:
    """How to refer to a level of the DNS tree in a sentence."""
    if zone == ".":
        return "the root"
    labels = zone.rstrip(".").split(".")
    if len(labels) == 1:
        return f"the .{labels[0]} top-level domain"
    return zone.rstrip(".")


def _sentence_start(level: str) -> str:
    """`level` at the start of a sentence: "The root", but a domain name stays lowercase."""
    return "T" + level[1:] if level.startswith("the ") else level


def explain_trace(report: TraceReport) -> Diagnosis | None:
    """Where the trace ended, in plain English. None when it reached the records.

    The blocked-queries explanation for a trace done through a resolver is separate
    (`trace_blocked_diagnosis`), since that trace can still succeed.
    """
    step = report.final
    name = report.name.rstrip(".")
    zone = step.zone.rstrip(".") or "."
    asked = (
        f"the resolver {report.resolver}"
        if report.mode is TraceMode.VIA_RESOLVER
        else f"{zone}'s nameserver {step.server.name.rstrip('.')}"
        if step.server
        else f"{zone}'s nameservers"
    )
    match step.status:
        case StepStatus.ANSWER | StepStatus.REFERRAL:
            return None
        case StepStatus.NXDOMAIN:
            return Diagnosis(
                title="The name doesn't exist",
                explanation=f"{_sentence_start(asked)} answered that {name} doesn't "
                "exist (NXDOMAIN)."
                + (
                    " It's the authority for that part of DNS, so this is the final word, "
                    "not a caching problem."
                    if report.mode is TraceMode.DIRECT
                    else ""
                ),
                suggestion=_nxdomain_suggestion(step.zone, name),
            )
        case StepStatus.NO_ANSWER:
            return Diagnosis(
                title=f"No {report.rtype} records",
                explanation=f"{name} exists, but has no {report.rtype} records ({asked} "
                "answered with none).",
                suggestion=f"If you expected one, add it at the DNS host for {zone}. "
                f"`dnskit lookup {name}` shows which record types it has.",
            )
    return _failed_diagnosis(report, step)


def _nxdomain_suggestion(zone: str, name: str) -> str:
    """What to check, depending on which level said the name doesn't exist."""
    if zone == ".":
        tld = name.rsplit(".", 1)[-1]
        return f"Check the spelling: .{tld} isn't a top-level domain that exists."
    if len(zone.rstrip(".").split(".")) == 1:
        return (
            f"Check the spelling. The domain isn't registered: {level_name(zone)} has no "
            "record of it. If it should be, check its registration with a WHOIS lookup."
        )
    return (
        "Check the spelling. If you just created the record, check that it's saved at the DNS "
        f"host for {zone.rstrip('.')}."
    )


def trace_blocked_diagnosis(report: TraceReport) -> Diagnosis | None:
    """Why the root servers didn't answer, when that was checked."""
    if report.blocking is None:
        return None
    alternative = ""
    if report.mode is TraceMode.VIA_RESOLVER:
        alternative = (
            f"Meanwhile, the trace shown was done through {report.resolver} instead: it shows "
            "each level's nameservers, but not how each of them answers or how fast."
        )
    return blocked_diagnosis(report.blocking, "the root servers", alternative)


def _failed_diagnosis(report: TraceReport, step: TraceStep) -> Diagnosis | None:
    zone = step.zone.rstrip(".") or "."
    level = level_name(step.zone)
    index = report.steps.index(step)
    parent = level_name(report.steps[index - 1].zone) if index else None
    servers = "; ".join(f"{f.server.name.rstrip('.')} {f.error}" for f in step.failures)
    detail = f" ({servers})" if servers else ""

    if step.zone == "." and report.blocking is not None and report.mode is TraceMode.DIRECT:
        return trace_blocked_diagnosis(report)
    if report.mode is TraceMode.VIA_RESOLVER:
        return Diagnosis(
            title=f"The resolver couldn't follow {level}",
            explanation=f"{report.resolver} failed while asking about {level}{detail}.",
            suggestion="Try again in a minute. If it keeps failing, the domain's own DNS may "
            "be broken: disconnect the VPN or change networks and run the trace directly.",
        )
    match step.reason:
        case FailReason.NO_ADDRESS:
            return Diagnosis(
                title=f"{_sentence_start(level)}'s nameservers have no address",
                explanation=f"{parent} says {zone} is served by "
                f"{', '.join(n.rstrip('.') for n in report.steps[index - 1].referral_servers)}, "
                "but none of those names could be looked up, so nobody can reach them.",
                suggestion=f"The nameservers registered for {zone} at its registrar are "
                "misspelled or no longer exist. Correct them at the registrar.",
            )
        case FailReason.TOO_DEEP:
            return Diagnosis(
                title="Too many referrals",
                explanation=f"After {MAX_STEPS} levels the nameservers were still referring "
                "the query onwards, which means the delegation loops.",
                suggestion=f"Check the NS records of {zone} and its parent zones at the DNS "
                "host and registrar.",
            )
        case FailReason.REFUSED | FailReason.LAME:
            return Diagnosis(
                title=f"{zone}'s nameservers aren't serving it (lame delegation)",
                explanation=f"{parent} says {zone} is served by these nameservers, but they "
                f"don't answer for it{detail}. This usually happens after moving DNS to a new "
                "host while the registrar still lists the old nameservers. Everyone looking "
                f"up {report.name.rstrip('.')} gets errors, not just you.",
                suggestion=f"Make the nameservers listed for {zone} at the registrar match the "
                "DNS host that actually has the zone.",
            )
        case FailReason.SERVFAIL:
            return Diagnosis(
                title=f"{zone}'s nameservers returned a server failure",
                explanation=f"The nameservers for {zone} replied with SERVFAIL{detail}: they "
                "have a problem loading or serving the zone.",
                suggestion=f"Contact the DNS host for {zone}; the problem is on their side.",
            )
    within = f" within {report.timeout:g} s"
    if step.zone == ".":
        return Diagnosis(
            title="The root servers didn't respond",
            explanation=f"None of the root servers asked replied{within}{detail}.",
            suggestion="Check your connection and try again.",
        )
    where = (
        "This is usually a brief network problem, since top-level domain servers are very reliable."
        if len(zone.split(".")) == 1
        else f"The levels above worked, so your connection is fine: {zone}'s own nameservers "
        "are down or unreachable, or a firewall in front of them drops queries. Everyone "
        f"looking up {report.name.rstrip('.')} has the same problem."
    )
    return Diagnosis(
        title=f"{_sentence_start(level)}'s nameservers didn't respond",
        explanation=f"None of the nameservers for {zone} that were asked replied{within}"
        f"{detail}. {where}",
        suggestion=f"Try again in a few minutes. If it keeps failing, contact the owner of "
        f"{zone} or their DNS provider.",
    )
