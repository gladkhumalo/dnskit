"""Has a DNS change reached resolvers around the world? Ask public resolvers in many regions.

After a record changes, each resolver keeps serving its cached copy until that copy's TTL
runs out, so for a while some answer old and some new. This asks global anycast
resolvers plus resolvers in fixed countries, and reports what share give the most common
answer.
"""

import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from dnskit.core.compare import Agreement, rank_answers
from dnskit.core.diagnosis import Diagnosis
from dnskit.core.lookup import LookupResult, LookupStatus, _query_one, _validate_rtype
from dnskit.core.outside import DnsBlocking, blocked_diagnosis, check_blocking
from dnskit.core.reach import parse_target

GLOBAL_REGION = "Global (anycast)"
# Shown with the global group: where its answers come from.
ANYCAST_NOTE = (
    "Global (anycast) resolvers answer from their site nearest to you, so they show what "
    "people near you see, not what other regions see."
)


@dataclass(frozen=True)
class PublicResolver:
    name: str  # operator, e.g. "Quad9"
    address: str
    location: str  # the country it answers from; "nearest site" for anycast
    region: str  # for grouping: GLOBAL_REGION, "Americas", "Europe", "Asia"

    @property
    def anycast(self) -> bool:
        return self.region == GLOBAL_REGION


# Plain (port 53), unfiltered public resolvers. The global anycast services answer from
# whichever of their sites is nearest the user, so only resolvers with a fixed location
# are grouped by region.
PROPAGATION_RESOLVERS: tuple[PublicResolver, ...] = (
    PublicResolver("Google", "8.8.8.8", "nearest site", GLOBAL_REGION),
    PublicResolver("Cloudflare", "1.1.1.1", "nearest site", GLOBAL_REGION),
    PublicResolver("Quad9", "9.9.9.9", "nearest site", GLOBAL_REGION),
    PublicResolver("OpenDNS", "208.67.222.222", "nearest site", GLOBAL_REGION),
    PublicResolver("Hurricane Electric", "74.82.42.42", "nearest site", GLOBAL_REGION),
    PublicResolver("Control D", "76.76.2.0", "nearest site", GLOBAL_REGION),
    PublicResolver("AdGuard", "94.140.14.140", "nearest site", GLOBAL_REGION),
    PublicResolver("CIRA Shield", "149.112.121.10", "Canada", "Americas"),
    PublicResolver("DNS.WATCH", "84.200.69.80", "Germany", "Europe"),
    PublicResolver("Yandex", "77.88.8.8", "Russia", "Europe"),
    PublicResolver("KT", "168.126.63.1", "South Korea", "Asia"),
    PublicResolver("AliDNS", "223.5.5.5", "China", "Asia"),
    PublicResolver("DNSPod", "119.29.29.29", "China", "Asia"),
    PublicResolver("114DNS", "114.114.114.114", "China", "Asia"),
)

# Per resolver. Healthy ones answer in well under a second even from far away, and every
# resolver is asked at once, so a dead one costs this much on the total.
PROPAGATION_TIMEOUT_S = 1.5
# Re-send an unanswered query this often within the timeout: on a lossy path a
# single dropped packet would otherwise make a healthy far-away resolver time out.
PROPAGATION_RETRY_S = 0.5


@dataclass(frozen=True)
class PropagationAnswer:
    resolver: PublicResolver
    result: LookupResult
    agreement: Agreement

    @property
    def ttl(self) -> int | None:
        return self.result.records[0].ttl if self.result.records else None


@dataclass(frozen=True)
class PropagationReport:
    name: str
    rtype: str
    answers: tuple[PropagationAnswer, ...]  # in PROPAGATION_RESOLVERS order
    has_majority: bool
    distinct_answers: int
    elapsed_ms: float
    # Set when most resolvers didn't respond: whether a VPN or firewall blocks them.
    blocking: DnsBlocking | None = None

    @property
    def responded(self) -> tuple[PropagationAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is not Agreement.FAILED)

    @property
    def failed(self) -> tuple[PropagationAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.FAILED)

    @property
    def majority(self) -> tuple[PropagationAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.MAJORITY)

    @property
    def differing(self) -> tuple[PropagationAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.DIFFERS)

    @property
    def blocked(self) -> bool:
        """Too few resolvers could be reached to measure anything, because of a block."""
        return self.blocking is not None and len(self.responded) < 2

    @property
    def percent(self) -> float:
        """Share of the responding resolvers that give the most common answer."""
        if not self.responded or not self.has_majority:
            return 0.0
        return 100 * len(self.majority) / len(self.responded)

    @property
    def location_based(self) -> bool:
        """The differences look like geo-DNS (a CDN answering by region), not propagation.

        True for an A/AAAA lookup when every global anycast resolver that answered (at least
        two) gives the most common answer and only fixed-location resolvers give addresses
        that differ. Anycast resolvers spread over many networks would also lag if a change
        were still propagating; a CDN instead gives other countries their own addresses.
        """
        if self.rtype not in ("A", "AAAA") or not self.has_majority or not self.differing:
            return False
        anycast = [a for a in self.responded if a.resolver.anycast]
        return (
            len(anycast) >= 2
            and all(a.agreement is Agreement.MAJORITY for a in anycast)
            and self.majority[0].result.status is LookupStatus.OK
            and all(a.result.status is LookupStatus.OK for a in self.differing)
        )

    @property
    def complete(self) -> bool:
        """Every resolver that responded (at least two) gives the same answer."""
        return len(self.responded) >= 2 and not self.differing and not self.blocked


def propagation(
    target: str,
    rtype: str = "A",
    timeout: float = PROPAGATION_TIMEOUT_S,
    resolvers: Sequence[PublicResolver] | None = None,
) -> PropagationReport:
    """Ask every resolver in PROPAGATION_RESOLVERS (or `resolvers`, e.g. from the config
    file) for `target`/`rtype`, all at once.

    Each is asked on its own (no fallback). Answers compare as in `compare()`. When more
    than half don't respond, `check_blocking` finds out whether a VPN or firewall is the
    cause. An invalid name or record type raises ValueError.
    """
    name = parse_target(target)
    rtype = _validate_rtype(rtype)
    resolvers = PROPAGATION_RESOLVERS if resolvers is None else tuple(resolvers)
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(resolvers)) as pool:
        results = list(
            pool.map(
                lambda r: _query_one(
                    name, rtype, [r.address], timeout, retry_after=PROPAGATION_RETRY_S
                ),
                resolvers,
            )
        )
    ranking = rank_answers(results)
    answers = tuple(
        PropagationAnswer(resolver, result, agreement)
        for resolver, result, agreement in zip(resolvers, results, ranking.agreements, strict=True)
    )
    failed = sum(1 for a in answers if a.agreement is Agreement.FAILED)
    blocking = check_blocking() if failed > len(answers) / 2 else None
    return PropagationReport(
        name=name,
        rtype=rtype,
        answers=answers,
        has_majority=ranking.has_majority,
        distinct_answers=ranking.distinct_answers,
        elapsed_ms=(time.perf_counter() - start) * 1000,
        blocking=blocking,
    )


def explain_propagation(report: PropagationReport) -> Diagnosis:
    """What the spread of answers means, and what to do."""
    name, rtype = report.name, report.rtype
    responded = len(report.responded)
    if report.blocking is not None and responded < 2:
        reached = (
            f"Only {responded} of {len(report.answers)} resolvers could be reached"
            if responded
            else "None of the resolvers could be reached"
        )
        return blocked_diagnosis(
            report.blocking,
            f"{len(report.failed)} of the {len(report.answers)} public resolvers",
            f"{reached}, so propagation can't be measured from here. An online checker "
            '(search for "DNS propagation checker") works from anywhere.',
        )
    if responded == 0:
        return Diagnosis(
            title="No resolver answered",
            explanation=f"None of the {len(report.answers)} resolvers gave an answer for "
            f"{name} {rtype}.",
            suggestion="Check your connection and try again, perhaps with a longer --timeout.",
        )
    if not report.differing:
        if report.majority and report.majority[0].result.status is LookupStatus.NXDOMAIN:
            what = f"{name} doesn't exist"
        elif report.majority and report.majority[0].result.status is LookupStatus.NO_ANSWER:
            what = f"{name} has no {rtype} records"
        else:
            what = "the same records"
        return Diagnosis(
            title=f"Fully propagated: all {responded} resolvers agree",
            explanation=f"Every resolver that answered says {what}. If you changed this "
            "record, the change has reached all of them (or the old answer had expired "
            "everywhere already).",
            suggestion="If someone still sees the old answer, their own computer or router "
            "has it cached: flushing the DNS cache or restarting the router clears it "
            "(`dnskit local` shows the flush command).",
        )

    stale = [a.ttl for a in report.differing if a.ttl is not None]
    wait = (
        f" The others will update when their cached copies expire, within about "
        f"{_duration(max(stale))} (the longest remaining TTL among them)."
        if stale
        else " The others will update when their cached copies expire."
    )
    if report.location_based:
        return _location_based(report)
    if not report.has_majority:
        title = f"No consensus: {report.distinct_answers} different answers"
    else:
        title = f"Still propagating: {report.percent:.0f}% give the most common answer"
    others = len(report.differing)
    return Diagnosis(
        title=title,
        explanation=f"{len(report.majority)} of {responded} resolvers that answered give the "
        f"most common answer and {others} {'gives' if others == 1 else 'give'} another."
        f"{wait} The most "
        "common answer isn't necessarily the new one: check it against what you set. "
        "Domains on a CDN or geo-DNS give different addresses by region on purpose, so for "
        "them differences are normal.",
        suggestion="Wait and run this again. To speed up future changes, lower the record's "
        "TTL a day before changing it.",
    )


def _location_based(report: PropagationReport) -> Diagnosis:
    anycast = sum(1 for a in report.responded if a.resolver.anycast)
    where = ", ".join(f"{a.resolver.name} in {a.resolver.location}" for a in report.differing)
    others = len(report.differing)
    return Diagnosis(
        title="Probably location-based DNS, not propagation",
        explanation=f"All {anycast} global resolvers agree, and the {others} "
        f"{'resolver that differs is' if others == 1 else 'resolvers that differ are all'} "
        f"in another country ({where}). Sites on a CDN or geo-DNS give each region its "
        "own nearby servers on purpose, so this is normal for them. If you didn't just "
        "change this record, nothing is wrong.",
        suggestion="If you did change it, check that the most common answer is the value "
        "you set: if it is, the change has reached the resolvers near you. Run this again "
        "later: answers that are location-based stay different, while stale ones catch up "
        "when their TTL runs out.",
    )


def _duration(seconds: int) -> str:
    if seconds < 120:
        return f"{seconds} seconds"
    if seconds < 7200:
        return f"{round(seconds / 60)} minutes"
    return f"{round(seconds / 3600)} hours"
