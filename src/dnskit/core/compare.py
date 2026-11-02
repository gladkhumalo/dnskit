"""Compare one record's answer across several resolvers."""

import time
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum

from dnskit.core.lookup import LookupResult, LookupStatus, _query_one, _validate_rtype
from dnskit.core.nameservers import system_nameservers

# Public resolvers always included in a comparison, as (label, IP).
PUBLIC_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
)

# Shorter than lookup's default: every resolver is queried at once, so the slowest one sets
# the total time, and a healthy resolver answers in well under a second.
COMPARE_TIMEOUT_S = 2.0

# Statuses that are a real answer from DNS (comparable between resolvers). Anything else
# means the resolver failed to give one.
_ANSWERED = {LookupStatus.OK, LookupStatus.NXDOMAIN, LookupStatus.NO_ANSWER}

# Record types whose values are case-sensitive text; other values are DNS names or numbers.
_CASE_SENSITIVE_RTYPES = {"TXT", "SPF", "CAA"}


class Agreement(StrEnum):
    MAJORITY = "majority"  # gave the most common answer
    DIFFERS = "differs"  # answered, but not with the most common answer (or there is none)
    FAILED = "failed"  # gave no usable answer: timeout, SERVFAIL, refused, no network


@dataclass(frozen=True)
class ResolverAnswer:
    label: str  # e.g. "Google", "System #2", or "Cloudflare / system #3"
    nameserver: str
    result: LookupResult
    agreement: Agreement

    @property
    def ttl(self) -> int | None:
        return self.result.records[0].ttl if self.result.records else None


@dataclass(frozen=True)
class CompareReport:
    name: str
    rtype: str
    answers: tuple[ResolverAnswer, ...]  # public resolvers first, then system order
    has_majority: bool  # False when no resolver answered, or the top answers are tied
    distinct_answers: int  # how many different answers the responding resolvers gave
    elapsed_ms: float

    @property
    def responded(self) -> tuple[ResolverAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is not Agreement.FAILED)

    @property
    def failed(self) -> tuple[ResolverAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.FAILED)

    @property
    def majority(self) -> tuple[ResolverAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.MAJORITY)

    @property
    def differing(self) -> tuple[ResolverAnswer, ...]:
        return tuple(a for a in self.answers if a.agreement is Agreement.DIFFERS)

    @property
    def all_agree(self) -> bool:
        """Every resolver that answered gave the same answer. Failures don't count."""
        return bool(self.responded) and not self.differing


def compare(
    name: str,
    rtype: str = "A",
    timeout: float = COMPARE_TIMEOUT_S,
    resolvers: Sequence[tuple[str, str]] | None = None,
) -> CompareReport:
    """Query `name`/`rtype` through the public resolvers and each system nameserver.

    `resolvers` replaces PUBLIC_RESOLVERS as (label, IP) pairs, e.g. from the config file.

    Every resolver is queried on its own (no fallback to another server), all in parallel.
    Answers are compared by status and record values, ignoring order, TTL and the case of
    DNS names; resolvers that failed are left out of the comparison. An unknown record type
    raises ValueError.
    """
    rtype = _validate_rtype(rtype)
    asked = _resolvers_to_compare(PUBLIC_RESOLVERS if resolvers is None else resolvers)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(asked)) as pool:
        results = list(pool.map(lambda r: _query_one(name, rtype, [r[1]], timeout), asked))

    ranking = rank_answers(results)
    answers = tuple(
        ResolverAnswer(label, nameserver, result, agreement)
        for (label, nameserver), result, agreement in zip(
            asked, results, ranking.agreements, strict=True
        )
    )
    return CompareReport(
        name=name,
        rtype=rtype,
        answers=answers,
        has_majority=ranking.has_majority,
        distinct_answers=ranking.distinct_answers,
        elapsed_ms=(time.perf_counter() - start) * 1000,
    )


@dataclass(frozen=True)
class Ranking:
    agreements: tuple[Agreement, ...]  # one per result, in the same order
    has_majority: bool
    distinct_answers: int


def rank_answers(results: Sequence[LookupResult]) -> Ranking:
    """Which results gave the most common answer. A tie for most common means no majority."""
    keys = [answer_key(result) for result in results]
    counts = Counter(key for key in keys if key is not None)
    ranked = counts.most_common(2)
    has_majority = bool(ranked) and (len(ranked) == 1 or ranked[0][1] > ranked[1][1])
    majority = ranked[0][0] if has_majority else None

    agreements = []
    for key in keys:
        if key is None:
            agreements.append(Agreement.FAILED)
        elif key == majority:
            agreements.append(Agreement.MAJORITY)
        else:
            agreements.append(Agreement.DIFFERS)
    return Ranking(tuple(agreements), has_majority, len(counts))


def _resolvers_to_compare(public: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    """Public resolvers, then system nameservers, as (label, IP), each IP only once.

    System nameservers are numbered in system order, matching `dnskit resolvers`. One that is
    also a public resolver keeps the public resolver's row, labelled with both.
    """
    labels = {ip: label for label, ip in public}
    for i, ip in enumerate(system_nameservers(), start=1):
        if ip not in labels:
            labels[ip] = f"System #{i}"
        elif "system" not in labels[ip].lower():
            labels[ip] += f" / system #{i}"
    return [(label, ip) for ip, label in labels.items()]


def answer_key(result: LookupResult) -> tuple[LookupStatus, frozenset[str]] | None:
    """What a resolver answered, in a form that compares equal for equivalent answers."""
    if result.status not in _ANSWERED:
        return None
    values = (record.value for record in result.records)
    if result.rtype not in _CASE_SENSITIVE_RTYPES:
        values = (value.lower() for value in values)
    return result.status, frozenset(values)
