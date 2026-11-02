"""A full health check: this computer's DNS setup, then one domain, from the other checks.

Nothing here queries DNS itself: `doctor()` runs `local_check`, `lookup`, `compare`,
`reach`, `email_check` and `dnssec_check` in parallel and turns their results into
`Issue`s, each about either this computer or the domain, ranked by `Impact`. The score
starts at 100 and loses points per issue.
"""

import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from dnskit.core.compare import CompareReport, ResolverAnswer, compare
from dnskit.core.connectivity import ConnectAttempt, tcp_connect
from dnskit.core.diagnosis import Diagnosis, explain
from dnskit.core.dnssec import (
    ClockState,
    DnssecReport,
    DnssecStatus,
    clock_diagnosis,
    dnssec_check,
    explain_dnssec,
)
from dnskit.core.local import LocalReport, Problem, ProblemKind, Severity, local_check
from dnskit.core.lookup import LookupReport, LookupResult, LookupStatus, lookup
from dnskit.core.mail import CheckStatus, EmailReport, email_check
from dnskit.core.nameservers import choose_nameserver, system_nameservers
from dnskit.core.reach import (
    DEFAULT_PORT,
    ReachReport,
    ReachVerdict,
    explain_reach,
    parse_target,
    reach,
)

# Seconds per query for the domain checks. Lower than the single commands' 5 s: a doctor
# run waits for its slowest check.
DOCTOR_TIMEOUT_S = 3.0
# Public resolvers asked to confirm that a name doesn't exist, when this computer's DNS
# server says so. (`dnssec_check` has its own fallback for servers that strip signatures.)
FALLBACK_RESOLVERS: tuple[str, ...] = ("8.8.8.8", "1.1.1.1")
# Seconds for each connection to a resolver's answer, when resolvers give different
# addresses (doctor checks that every one of them works).
ANSWER_CONNECT_TIMEOUT_S = 2.0
# How long the domain checks wait for the lookup before starting anyway. "Doesn't exist"
# comes back fast; a slow lookup is a timeout or a failure, so waiting longer only adds time.
LOOKUP_WAIT_S = 0.5


class Check(StrEnum):
    LOCAL = "local"
    LOOKUP = "lookup"
    COMPARE = "compare"
    REACH = "reach"
    EMAIL = "email"
    DNSSEC = "dnssec"


CHECK_LABELS: dict[Check, str] = {
    Check.LOCAL: "This computer: adapters, DNS servers, VPN, hijacking, interception, IPv6",
    Check.LOOKUP: "Records (A, AAAA, MX, CNAME, NS, TXT)",
    Check.COMPARE: "Answers from public resolvers and this computer's DNS servers",
    Check.REACH: "Connection to the domain (port 443)",
    Check.EMAIL: "Email: MX, SPF, DMARC, DKIM",
    Check.DNSSEC: "DNSSEC chain of trust",
}
# Skipped by --quick: each makes many queries or waits on far-away servers.
SLOW_CHECKS: tuple[Check, ...] = (Check.COMPARE, Check.EMAIL, Check.DNSSEC)
# Need the domain to exist: skipped when the lookup says it doesn't.
NEEDS_DOMAIN: tuple[Check, ...] = (Check.COMPARE, Check.REACH, Check.EMAIL, Check.DNSSEC)
SKIP_QUICK = "--quick"
SKIP_NO_DOMAIN = "domain doesn't exist"
# How the verdict names a skipped check.
_SHORT_NAMES: dict[Check, str] = {
    Check.COMPARE: "the resolver comparison",
    Check.EMAIL: "email",
    Check.DNSSEC: "DNSSEC",
}


class CheckState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"  # --quick, or the domain doesn't exist (CheckRun.reason)
    ERROR = "error"  # the check itself crashed; its result is missing


@dataclass(frozen=True)
class CheckRun:
    check: Check
    state: CheckState
    elapsed_ms: float = 0.0
    error: str | None = None
    reason: str = ""  # why it was skipped: SKIP_QUICK or SKIP_NO_DOMAIN


class Area(StrEnum):
    MACHINE = "machine"  # this computer or its network
    DOMAIN = "domain"  # the domain's own DNS or servers


class Impact(StrEnum):
    CRITICAL = "critical"  # something doesn't work at all
    MAJOR = "major"  # works badly, or for some people
    MINOR = "minor"  # worth tidying up
    NOTE = "note"  # good to know, nothing to fix: costs no points


IMPACT_PENALTY: dict[Impact, int] = {
    Impact.CRITICAL: 40,
    Impact.MAJOR: 15,
    Impact.MINOR: 5,
    Impact.NOTE: 0,
}
# One check can't take more than this off the score, so a handful of email warnings
# doesn't outweigh a broken website.
MAX_PENALTY_PER_CHECK = 40
_IMPACT_ORDER = list(Impact)


@dataclass(frozen=True)
class Issue:
    area: Area
    impact: Impact
    title: str
    detail: str
    fix: str
    check: Check  # where it was found


@dataclass(frozen=True)
class DoctorReport:
    name: str
    quick: bool
    runs: tuple[CheckRun, ...]  # in Check order
    issues: tuple[Issue, ...]  # most important first
    elapsed_ms: float
    local: LocalReport | None = None
    lookup: LookupReport | None = None
    compare: CompareReport | None = None
    reach: ReachReport | None = None
    email: EmailReport | None = None
    dnssec: DnssecReport | None = None
    # NXDOMAIN, and no public resolver found the name either (or none could be asked).
    name_missing: bool = False
    # This computer's DNS said NXDOMAIN, but this public resolver found the name.
    found_by: str | None = None
    # One connection per distinct address answer in `compare`, when they differ.
    answer_checks: tuple[ConnectAttempt, ...] = ()

    @property
    def problems(self) -> tuple[Issue, ...]:
        """The issues that need fixing (not notes)."""
        return tuple(i for i in self.issues if i.impact is not Impact.NOTE)

    @property
    def machine_issues(self) -> tuple[Issue, ...]:
        return tuple(i for i in self.issues if i.area is Area.MACHINE)

    @property
    def domain_issues(self) -> tuple[Issue, ...]:
        return tuple(i for i in self.issues if i.area is Area.DOMAIN)

    @property
    def dns_broken_here(self) -> bool:
        """This computer can't use DNS at all, so the domain couldn't really be checked."""
        return self.local is not None and self.local.has_errors

    @property
    def skipped(self) -> tuple[Check, ...]:
        return tuple(r.check for r in self.runs if r.state is CheckState.SKIPPED)

    @property
    def quick_skipped(self) -> tuple[Check, ...]:
        return tuple(r.check for r in self.runs if r.reason == SKIP_QUICK)

    @property
    def dnssec_via(self) -> str | None:
        """The public resolver DNSSEC was checked through, because this computer's strips it."""
        if self.dnssec and self.dnssec.stripped_by and not self.dnssec.signatures_stripped:
            return self.dnssec.nameserver
        return None

    @property
    def score(self) -> int:
        """100 minus each issue's penalty, at most MAX_PENALTY_PER_CHECK per check; 0 for a
        domain that doesn't exist."""
        if self.name_missing:
            return 0
        per_check: dict[Check, int] = {}
        for issue in self.issues:
            per_check[issue.check] = per_check.get(issue.check, 0) + IMPACT_PENALTY[issue.impact]
        lost = sum(min(p, MAX_PENALTY_PER_CHECK) for p in per_check.values())
        return max(0, 100 - lost)

    def failed(self, check: Check) -> bool:
        """Whether `check` itself failed, even when another issue explains it (say a lookup
        that fails because of broken DNSSEC), so it isn't shown as OK."""
        match check:
            case Check.LOOKUP:
                ok = (LookupStatus.OK, LookupStatus.NO_ANSWER)
                return self.lookup is not None and not any(
                    r.status in ok for r in self.lookup.results
                )
            case Check.REACH:
                return self.reach is not None and self.reach.verdict is not ReachVerdict.REACHABLE
            case Check.EMAIL:
                return self.email is not None and self.email.domain_status is not LookupStatus.OK
            case Check.DNSSEC:
                return self.dnssec is not None and self.dnssec.status is DnssecStatus.BOGUS
            case Check.LOCAL:
                return self.dns_broken_here
        return False

    @property
    def healthy(self) -> bool:
        """No critical or major issue."""
        return all(i.impact in (Impact.MINOR, Impact.NOTE) for i in self.issues)


Progress = Callable[[Check, CheckState], None]


def doctor(
    target: str,
    quick: bool = False,
    timeout: float = DOCTOR_TIMEOUT_S,
    on_progress: Progress | None = None,
    resolvers: Sequence[tuple[str, str]] | None = None,
    local: LocalReport | None = None,
) -> DoctorReport:
    """Check this computer and `target` (a domain or URL) and rank what's wrong.

    This computer and the lookup start first; the other domain checks start when the lookup
    shows the domain exists, or after LOOKUP_WAIT_S. A domain that doesn't exist skips them
    (CheckState.SKIPPED, reason SKIP_NO_DOMAIN); if a slow lookup only says so after they
    started, their results are dropped and they're reported as skipped all the same.
    `on_progress(check, state)` is called from worker threads as each starts and finishes,
    and for each skipped check. A check that crashes is reported as CheckState.ERROR, not
    raised. An invalid name raises ValueError.

    `resolvers` replaces the comparison's public resolvers. A `local` report (one check of
    this computer shared by several doctor runs, as in `dnskit batch`) is used as is.
    """
    name = parse_target(target)
    notify = on_progress or (lambda check, state: None)
    planned = [c for c in Check if not (quick and c in SLOW_CHECKS)]
    skipped = {c: SKIP_QUICK for c in Check if c not in planned}
    for check in Check:
        notify(check, CheckState.SKIPPED if check in skipped else CheckState.PENDING)

    jobs: dict[Check, Callable[[], Any]] = {
        # Ghost servers are ignored anyway: probing them only waits for the dead ones.
        Check.LOCAL: lambda: local or local_check(probe_ghosts=False),
        Check.LOOKUP: lambda: lookup(name, timeout=timeout),
        Check.COMPARE: lambda: _compare_and_connect(name, timeout, resolvers),
        Check.REACH: lambda: reach(name, timeout=timeout),
        Check.EMAIL: lambda: email_check(name, timeout=timeout),
        Check.DNSSEC: lambda: dnssec_check(name, timeout=timeout),
    }

    def run(check: Check) -> tuple[Any, CheckRun]:
        notify(check, CheckState.RUNNING)
        begun = time.perf_counter()
        try:
            result, state, error = jobs[check](), CheckState.DONE, None
        except Exception as exc:  # one broken check mustn't sink the whole report
            result, state, error = None, CheckState.ERROR, str(exc) or type(exc).__name__
        notify(check, state)
        return result, CheckRun(check, state, (time.perf_counter() - begun) * 1000, error)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(planned)) as pool:
        futures = {Check.LOCAL: pool.submit(run, Check.LOCAL)}
        # Pick the system nameserver once, so the domain checks share the cached choice
        # instead of each probing every server at the same time.
        _warm_resolver_choice()
        futures[Check.LOOKUP] = pool.submit(run, Check.LOOKUP)
        try:
            looked_up = futures[Check.LOOKUP].result(timeout=LOOKUP_WAIT_S)[0]
            missing, found_by = _confirm_missing(looked_up, timeout)
            decided = True
        except FuturesTimeout:
            missing, found_by, decided = False, None, False
        for check in planned:
            if check in futures:
                continue
            if missing and check in NEEDS_DOMAIN:
                skipped[check] = SKIP_NO_DOMAIN
                notify(check, CheckState.SKIPPED)
            else:
                futures[check] = pool.submit(run, check)
        done = {check: future.result() for check, future in futures.items()}

    if not decided:
        missing, found_by = _confirm_missing(done[Check.LOOKUP][0], timeout)
        if missing:
            for check in NEEDS_DOMAIN:
                if done.pop(check, None) is not None:
                    skipped[check] = SKIP_NO_DOMAIN
                    notify(check, CheckState.SKIPPED)
    results = {check: result for check, (result, _) in done.items()}
    runs = tuple(
        done[c][1] if c in done else CheckRun(c, CheckState.SKIPPED, reason=skipped[c])
        for c in Check
    )
    compared, answer_checks = results.get(Check.COMPARE) or (None, ())
    report = DoctorReport(
        name=name,
        quick=quick,
        runs=runs,
        issues=(),
        elapsed_ms=(time.perf_counter() - start) * 1000,
        local=results.get(Check.LOCAL),
        lookup=results.get(Check.LOOKUP),
        compare=compared,
        reach=results.get(Check.REACH),
        email=results.get(Check.EMAIL),
        dnssec=results.get(Check.DNSSEC),
        name_missing=missing,
        found_by=found_by,
        answer_checks=answer_checks,
    )
    return replace(report, issues=find_issues(report, timeout))


_ANSWERED = (LookupStatus.OK, LookupStatus.NO_ANSWER)


def _confirm_missing(report: LookupReport | None, timeout: float) -> tuple[bool, str | None]:
    """Whether the name doesn't exist, and the public resolver that found it if this
    computer's DNS server wrongly says it doesn't (a filter, or a stale cached answer)."""
    if report is None:
        return False, None
    statuses = {r.status for r in report.results}
    if LookupStatus.NXDOMAIN not in statuses or statuses & set(_ANSWERED):
        return False, None
    for server in FALLBACK_RESOLVERS:
        status = lookup(report.name, ("A",), nameserver=server, timeout=timeout).results[0].status
        if status in _ANSWERED:
            return False, server
        if status is LookupStatus.NXDOMAIN:
            return True, None
    return True, None  # no public resolver could be asked: trust this computer's answer


def _compare_and_connect(
    name: str, timeout: float, resolvers: Sequence[tuple[str, str]] | None = None
) -> tuple[CompareReport, tuple[ConnectAttempt, ...]]:
    """`compare`, then a connection to each different address answer, to see they all work."""
    report = compare(name, "A", resolvers=resolvers)
    addresses = [_first_address(a.result) for a in _distinct_address_answers(report)]
    if len(addresses) < 2:
        return report, ()
    connect_timeout = min(timeout, ANSWER_CONNECT_TIMEOUT_S)
    with ThreadPoolExecutor(max_workers=len(addresses)) as pool:
        attempts = pool.map(lambda a: tcp_connect(a, DEFAULT_PORT, connect_timeout), addresses)
        return report, tuple(attempts)


def _warm_resolver_choice() -> None:
    try:
        candidates = system_nameservers()
        if candidates:
            choose_nameserver(candidates)
    except Exception:  # the checks themselves will report what's wrong
        pass


# --- issues ---------------------------------------------------------------------------------


def find_issues(report: DoctorReport, timeout: float = DOCTOR_TIMEOUT_S) -> tuple[Issue, ...]:
    """Every issue in `report`'s results, most important first (this computer first on ties)."""
    issues: list[Issue] = []
    if report.local is not None:
        issues += [_local_issue(p) for p in report.local.problems]
    broken_here = report.dns_broken_here
    name_fails = False  # the name itself doesn't resolve: later checks would only repeat it
    # Validating resolvers fail a domain whose DNSSEC is broken: that issue explains it.
    bogus = report.dnssec is not None and report.dnssec.status is DnssecStatus.BOGUS
    if report.found_by is not None and report.lookup is not None:
        issues.append(_missing_here_issue(report.name, report.lookup.nameserver, report.found_by))
        name_fails = True  # through this computer's DNS: its issue explains everything else
    elif report.lookup is not None:
        found, name_fails = _lookup_issues(report.lookup, broken_here, bogus, timeout)
        issues += found
    if report.reach is not None:
        issues += _reach_issues(report.reach, name_fails, broken_here)
    if report.compare is not None and not name_fails:
        issues += _compare_issues(report.compare, report.answer_checks, bogus)
    # When the name doesn't resolve, email's "couldn't check" findings only repeat that.
    if report.email is not None and not broken_here and not name_fails:
        issues += _email_issues(report.email)
    if report.dnssec is not None and not broken_here:
        issues += _dnssec_issues(report.dnssec, name_fails)
    for run in report.runs:
        if run.state is CheckState.ERROR:
            issues.append(
                Issue(
                    Area.MACHINE,
                    Impact.MINOR,
                    f"The {run.check.value} check couldn't run",
                    f"It stopped with an error: {run.error}.",
                    f"Run dnskit {run.check.value} {report.name} on its own to see more.",
                    run.check,
                )
            )
    order = {issue: n for n, issue in enumerate(issues)}
    return tuple(
        sorted(
            issues,
            key=lambda i: (_IMPACT_ORDER.index(i.impact), i.area is not Area.MACHINE, order[i]),
        )
    )


_LOCAL_IMPACT: dict[ProblemKind, Impact] = {
    ProblemKind.NO_ADAPTER: Impact.CRITICAL,
    ProblemKind.NO_DNS_SERVERS: Impact.CRITICAL,
    ProblemKind.NO_RESPONSE: Impact.CRITICAL,
    ProblemKind.HIJACK: Impact.MAJOR,
    ProblemKind.INTERCEPTION: Impact.MAJOR,
    ProblemKind.IPV6_BROKEN: Impact.MAJOR,
    ProblemKind.SERVER_FAILED: Impact.MAJOR,
    # dnskit and the OS already work around these; the user needn't change anything.
    ProblemKind.GHOST: Impact.NOTE,
    ProblemKind.VPN_BLOCKED: Impact.NOTE,
}


def _local_issue(problem: Problem) -> Issue:
    impact = _LOCAL_IMPACT.get(problem.kind, Impact.MINOR)
    if problem.severity is Severity.ERROR:
        impact = Impact.CRITICAL
    return Issue(Area.MACHINE, impact, problem.title, problem.detail, problem.fix, Check.LOCAL)


# Lookup failures that mean "couldn't ask", as opposed to an answer about the domain.
_UNREACHABLE = {LookupStatus.TIMEOUT, LookupStatus.NO_NETWORK, LookupStatus.NO_NAMESERVERS}


def _lookup_issues(
    report: LookupReport, broken_here: bool, bogus: bool, timeout: float
) -> tuple[list[Issue], bool]:
    """Issues from the record lookups, and whether the name itself fails to resolve."""
    name = report.name
    statuses = [r.status for r in report.results]
    answered = [s for s in statuses if s in (LookupStatus.OK, LookupStatus.NO_ANSWER)]
    if answered:
        failed = [
            r for r in report.results if r.status not in (LookupStatus.OK, LookupStatus.NO_ANSWER)
        ]
        if not failed or broken_here:
            return [], False
        types = ", ".join(f"{r.rtype} ({r.status.value.replace('_', ' ')})" for r in failed)
        return [
            Issue(
                Area.DOMAIN,
                Impact.MINOR,
                "Some record lookups failed",
                f"{name} answers, but these lookups failed: {types}.",
                f"Run dnskit lookup {name} again; if the same types keep failing, check them "
                "with the domain's DNS host.",
                Check.LOOKUP,
            )
        ], False

    # Nothing answered: the name doesn't resolve at all.
    status = statuses[0] if len(set(statuses)) == 1 else _worst_failure(statuses)
    if status in _UNREACHABLE and broken_here:
        return [], True  # this computer's DNS is the problem, already reported
    if bogus and status is not LookupStatus.NXDOMAIN:
        return [], True  # the DNSSEC issue says why resolvers fail it
    diagnosis = explain(status, name, "A", timeout)
    assert diagnosis is not None
    return [
        Issue(
            Area.DOMAIN,
            Impact.CRITICAL,
            f"{name}: {_lower_first(diagnosis.title)}",
            diagnosis.explanation,
            diagnosis.suggestion,
            Check.LOOKUP,
        )
    ], True


def _worst_failure(statuses: list[LookupStatus]) -> LookupStatus:
    for status in (LookupStatus.NXDOMAIN, LookupStatus.SERVFAIL, LookupStatus.TIMEOUT):
        if status in statuses:
            return status
    return statuses[0]


def _reach_issues(report: ReachReport, name_fails: bool, broken_here: bool) -> list[Issue]:
    issues: list[Issue] = []
    if report.hosts_entries:
        pointed = ", ".join(f"{e.ip} (line {e.line})" for e in report.hosts_entries)
        issues.append(
            Issue(
                Area.MACHINE,
                Impact.MAJOR,
                f"This computer's hosts file overrides {report.name}",
                f"The hosts file points {report.name} at {pointed}, so browsers and most apps "
                "on this computer go there instead of where DNS says.",
                "If that's not intended, remove or comment out the line (needs administrator "
                "rights), then flush the DNS cache.",
                Check.REACH,
            )
        )
    verdict = report.verdict
    if verdict is ReachVerdict.REACHABLE:
        return issues
    if verdict is ReachVerdict.DNS and not report.blocked_by_dns and (name_fails or broken_here):
        return issues  # the lookup issue (or this computer's) already says it
    diagnosis = explain_reach(report)
    area = Area.MACHINE if report.blocked_by_dns else Area.DOMAIN
    issues.append(
        Issue(
            area,
            Impact.MAJOR,
            diagnosis.title,
            diagnosis.explanation,
            diagnosis.suggestion,
            Check.REACH,
        )
    )
    return issues


def _missing_here_issue(name: str, server: str, found_by: str) -> Issue:
    return Issue(
        Area.MACHINE,
        Impact.MAJOR,
        f"This computer's DNS server says {name} doesn't exist, but public resolvers find it",
        f"{server} answered that {name} doesn't exist (NXDOMAIN), while {found_by} found it. "
        "The DNS server is probably blocking it (an ad blocker, parental controls or a "
        'company filter), or still has an old "doesn\'t exist" answer cached from before '
        "the domain was set up. The domain checks were done through this computer's DNS, so "
        "they couldn't see it either.",
        "If the site should be allowed, ask whoever runs the filter to unblock it. Otherwise "
        "flush the DNS cache (dnskit local shows how) and restart the router, or use 1.1.1.1 "
        "or 8.8.8.8 as the DNS server.",
        Check.LOOKUP,
    )


# Answers that mean "can't find it" or "can't answer", against resolvers that give addresses.
_NOT_FOUND = (LookupStatus.NXDOMAIN, LookupStatus.NO_ANSWER)
_ERRORS = (LookupStatus.SERVFAIL, LookupStatus.NO_NAMESERVERS)


def _compare_issues(
    report: CompareReport, attempts: tuple[ConnectAttempt, ...], bogus: bool
) -> list[Issue]:
    """Different answers only matter when some resolvers can't find the name (or fail) while
    others answer, or when an answer's address doesn't work. Different working addresses are
    normal for a CDN, so they're a note. Timeouts aren't counted: a VPN or firewall blocking
    the public resolvers is `local`'s business."""
    name = report.name
    answering = [a for a in report.responded if a.result.status is LookupStatus.OK]
    odd = [a for a in report.responded if a.result.status in _NOT_FOUND]
    odd += [a for a in report.failed if a.result.status in _ERRORS]
    if answering and odd:
        if bogus and all(a.result.status is LookupStatus.SERVFAIL for a in odd):
            return []  # validating resolvers failing a broken DNSSEC domain: that issue says so
        mine = all(_is_system(a) for a in odd)
        listed = ", ".join(f"{a.label} ({_answer_text(a.result)})" for a in odd)
        counted = f"{len(answering)} resolver{'s' if len(answering) > 1 else ''}"
        detail = f"{counted} answered with an address, but {listed}."
        if mine:
            return [
                Issue(
                    Area.MACHINE,
                    Impact.MAJOR,
                    f"This computer's DNS server can't find {name}, but public resolvers can",
                    f"{detail} The DNS server is probably filtering this name, or has an old "
                    "answer cached.",
                    "If the site should be allowed, ask whoever runs the filter to unblock it. "
                    "Otherwise flush the DNS cache and restart the router, or use 1.1.1.1 or "
                    "8.8.8.8 as the DNS server.",
                    Check.COMPARE,
                )
            ]
        return [
            Issue(
                Area.DOMAIN,
                Impact.MAJOR,
                f"Some resolvers can't find {name}",
                f"{detail} So some people can't reach it. Usually one of the domain's "
                "nameservers is out of date or not serving it, or the record was created "
                "moments ago and some resolvers still remember that it didn't exist.",
                f"Run dnskit trace {name} a few times to find a nameserver that fails, and "
                "check that every nameserver at the DNS host has the record.",
                Check.COMPARE,
            )
        ]

    distinct = _distinct_address_answers(report)
    if len(distinct) < 2:
        return []
    by_address = {a.address: a for a in attempts}
    tried = [(a, by_address.get(_first_address(a.result))) for a in distinct]
    works = [a for a, attempt in tried if attempt is not None and attempt.ok]
    dead = [(a, attempt) for a, attempt in tried if attempt is not None and not attempt.ok]
    if works and dead:
        # Every resolver that gave the same answer as a dead one is affected.
        dead_keys = {_answer_key(a.result) for a, _ in dead}
        affected = [a for a in answering if _answer_key(a.result) in dead_keys]
        listed = ", ".join(
            f"{a.label} ({_first_address(a.result)}: {attempt.error or 'failed'})"
            for a, attempt in dead
        )
        mine = all(_is_system(a) for a in affected)
        fix = (
            "This computer's DNS server has an address that doesn't work: flush the DNS cache "
            "and restart the router, or use 1.1.1.1 or 8.8.8.8 as the DNS server."
            if mine
            else "If you moved the site recently, the old address is still cached: keep the "
            "old server running until the record's TTL has passed. Otherwise check the "
            "addresses at the DNS host."
        )
        return [
            Issue(
                Area.MACHINE if mine else Area.DOMAIN,
                Impact.MAJOR,
                f"Some resolvers send visitors of {name} to an address that doesn't respond",
                f"Resolvers give different addresses for {name}, and not all of them work on "
                f"port {DEFAULT_PORT}: {listed}. Others answered with addresses that do.",
                fix,
                Check.COMPARE,
            )
        ]
    return [
        Issue(
            Area.DOMAIN,
            Impact.NOTE,
            f"Resolvers give different addresses for {name}",
            "Every resolver answered, with addresses that work. That's normal for a site on a "
            "CDN, which gives each resolver servers near it.",
            "Nothing to do.",
            Check.COMPARE,
        )
    ]


def _is_system(answer: ResolverAnswer) -> bool:
    """One of this computer's DNS servers that isn't also a public resolver."""
    return answer.label.startswith("System #")


def _answer_key(result: LookupResult) -> frozenset[str]:
    return frozenset(r.value.lower() for r in result.records)


def _distinct_address_answers(report: CompareReport) -> list[ResolverAnswer]:
    """One resolver per different address answer, in the report's order."""
    seen: dict[frozenset[str], ResolverAnswer] = {}
    for answer in report.responded:
        if answer.result.status is LookupStatus.OK and answer.result.records:
            seen.setdefault(_answer_key(answer.result), answer)
    return list(seen.values())


def _first_address(result: LookupResult) -> str:
    return min(r.value for r in result.records)


def _answer_text(result: LookupResult) -> str:
    if result.status is LookupStatus.OK:
        return ", ".join(r.value for r in result.records)
    return {
        LookupStatus.NXDOMAIN: "it doesn't exist",
        LookupStatus.NO_ANSWER: "no address",
        LookupStatus.SERVFAIL: "server failure",
        LookupStatus.NO_NAMESERVERS: "refused",
    }.get(result.status, result.status.value)


def _email_issues(report: EmailReport) -> list[Issue]:
    if report.domain_status is not LookupStatus.OK:
        return []  # the lookup issue already says the name doesn't resolve
    no_mail = report.mx is not None and report.mx.lookup_status is LookupStatus.NO_ANSWER
    # DNS can't list a domain's DKIM selectors, so none at the common ones proves nothing.
    no_dkim_found = report.dkim is not None and not any(s.found for s in report.dkim.selectors)
    issues = []
    for label, section in report.checks:
        for finding in section.findings:
            if finding.status is CheckStatus.PASS:
                continue
            impact = Impact.MAJOR if finding.status is CheckStatus.FAIL else Impact.MINOR
            if no_mail:
                impact = Impact.MINOR  # a domain that doesn't take email
            if label == "DKIM" and finding.status is CheckStatus.WARN and no_dkim_found:
                impact = Impact.NOTE
            issues.append(
                Issue(
                    Area.DOMAIN,
                    impact,
                    f"Email ({label}): {_lower_first(finding.title)}",
                    finding.explanation,
                    finding.fix or f"Run dnskit email {report.domain} for details.",
                    Check.EMAIL,
                )
            )
    return issues


def _dnssec_issues(report: DnssecReport, name_fails: bool) -> list[Issue]:
    if report.signatures_stripped:
        # This computer's DNS strips signatures and no fallback could stand in: that's about
        # the network, not the domain.
        return [_from_diagnosis(explain_dnssec(report), Area.MACHINE, Impact.NOTE, Check.DNSSEC)]
    clock = clock_diagnosis(report.clock)
    clock_wrong = report.clock.state is ClockState.WRONG
    issues = []
    status = report.status
    if status is DnssecStatus.BOGUS:
        diagnosis = explain_dnssec(report)
        issues.append(
            Issue(
                Area.MACHINE if clock_wrong else Area.DOMAIN,
                Impact.CRITICAL,
                diagnosis.title,
                diagnosis.explanation,
                diagnosis.suggestion,
                Check.DNSSEC,
            )
        )
    elif clock_wrong and clock is not None:
        issues.append(_from_diagnosis(clock, Area.MACHINE, Impact.MAJOR, Check.DNSSEC))
    if name_fails or report.name_missing:
        return issues  # nothing of its own to protect: the lookup issue says why
    if status is DnssecStatus.INSECURE or (
        status is DnssecStatus.UNKNOWN and report.blocking is None
    ):
        diagnosis = explain_dnssec(report)
        issues.append(_from_diagnosis(diagnosis, Area.DOMAIN, Impact.MINOR, Check.DNSSEC))
    return issues


def _from_diagnosis(diagnosis: Diagnosis, area: Area, impact: Impact, check: Check) -> Issue:
    return Issue(area, impact, diagnosis.title, diagnosis.explanation, diagnosis.suggestion, check)


def _lower_first(text: str) -> str:
    """Lower-case a title's first letter to follow a prefix, unless it starts a name."""
    if len(text) > 1 and text[1].isupper():  # e.g. "MX records", "SPF …"
        return text
    return text[:1].lower() + text[1:]


# --- verdict --------------------------------------------------------------------------------


def doctor_verdict(report: DoctorReport) -> Diagnosis:
    """A short plain-English summary of the result, with the next step."""
    name = report.name
    skipped = [_SHORT_NAMES.get(c, c.value) for c in report.quick_skipped]
    listed = (
        ", ".join(skipped[:-1]) + (" and " if len(skipped) > 1 else "") + skipped[-1]
        if skipped
        else ""
    )
    quick = f" This was a quick check, so {listed} weren't checked." if skipped else ""
    if report.name_missing:
        nxdomain = explain(LookupStatus.NXDOMAIN, name, "A")
        assert nxdomain is not None
        here = [i for i in report.problems if i.area is Area.MACHINE]
        machine = (
            f" Separately, this computer has {len(here)} issue{'s' if len(here) > 1 else ''}."
            if here
            else ""
        )
        return Diagnosis(
            title=f"{name} doesn't exist",
            explanation="DNS says there's no such domain (NXDOMAIN), so it can't work for "
            "anyone, and the checks that need it (the resolver comparison, the connection, "
            f"email and DNSSEC) were skipped. The score is 0.{machine}",
            suggestion=nxdomain.suggestion,
        )
    if report.dns_broken_here:
        top = report.machine_issues[0]
        return Diagnosis(
            title="This computer can't use DNS",
            explanation=f"{top.title}. Until DNS works here, {name} can't be checked, so "
            "any failures for it are probably not the domain's fault." + quick,
            suggestion=top.fix,
        )
    problems = report.problems
    if not problems:
        notes = len(report.issues)
        noted = (
            f" {notes} note{'' if notes == 1 else 's'} below for information; nothing needs "
            "changing."
            if notes
            else ""
        )
        return Diagnosis(
            title="Healthy: no problems found",
            explanation=f"This computer's DNS setup and {name} both checked out.{noted}" + quick,
            suggestion="Nothing to do.",
        )

    def summary(issues: tuple[Issue, ...], where: str) -> str:
        if not issues:
            return f"{where} looks fine."
        count = f"{len(issues)} issue" + ("" if len(issues) == 1 else "s")
        return f"{where} has {count}; the most important: {_lower_first(issues[0].title)}."

    parts = (
        summary(tuple(i for i in problems if i.area is Area.MACHINE), "This computer"),
        summary(tuple(i for i in problems if i.area is Area.DOMAIN), name),
    )
    score = report.score
    critical = any(i.impact is Impact.CRITICAL for i in problems)
    if critical:
        title = "Something is broken"
    elif score >= 90:
        title = "Healthy, with a few things to tidy up"
    elif score >= 70:
        title = "Mostly healthy, but some things need fixing"
    else:
        title = "Several problems need fixing"
    return Diagnosis(
        title=title,
        explanation=" ".join(parts) + quick,
        suggestion=f"Start at the top of the list: {problems[0].fix}",
    )
