import importlib
import threading
import time
from types import SimpleNamespace

import pytest

from dnskit.core import (
    Agreement,
    CheckStatus,
    ClockState,
    ConnectAttempt,
    ConnectError,
    Diagnosis,
    DnssecStatus,
    LookupReport,
    LookupResult,
    LookupStatus,
    Problem,
    ProblemKind,
    Record,
    Severity,
)
from dnskit.core.compare import CompareReport, ResolverAnswer
from dnskit.core.doctor import (
    MAX_PENALTY_PER_CHECK,
    NEEDS_DOMAIN,
    SKIP_NO_DOMAIN,
    SLOW_CHECKS,
    Area,
    Check,
    CheckState,
    Impact,
    doctor,
    doctor_verdict,
)
from dnskit.core.mail import (
    DkimCheck,
    DkimSelector,
    DmarcCheck,
    EmailReport,
    Finding,
    MxCheck,
)
from dnskit.core.reach import ReachReport

doctor_mod = importlib.import_module("dnskit.core.doctor")

NAME = "example.com"
A = LookupResult("A", LookupStatus.OK, (Record("192.0.2.10", 300),))
AAAA = LookupResult("AAAA", LookupStatus.NO_ANSWER)
OTHER_A = LookupResult("A", LookupStatus.OK, (Record("198.51.100.7", 300),))


def problem(kind: ProblemKind, severity: Severity = Severity.WARNING) -> Problem:
    return Problem(severity, f"{kind.value} problem", "Details.", "Fix it.", kind)


def lookup_report(*results: LookupResult) -> LookupReport:
    return LookupReport(NAME, "192.0.2.53", "auto", results or (A, AAAA), 20.0)


def reach_report(a: LookupResult = A, connected: bool = True, hosts: tuple = ()) -> ReachReport:
    attempts = ()
    if a.records:
        error = None if connected else ConnectError.TIMEOUT
        attempts = (ConnectAttempt(a.records[0].value, 443, 20.0 if connected else None, error),)
    return ReachReport(NAME, 443, "192.0.2.53", "auto", a, AAAA, attempts, hosts, 30.0)


def compare_report(*answers: tuple[str, LookupResult, Agreement]) -> CompareReport:
    rows = tuple(ResolverAnswer(label, "192.0.2.1", r, agr) for label, r, agr in answers)
    has_majority = any(a.agreement is Agreement.MAJORITY for a in rows)
    distinct = len({tuple(r.records) for _, r, _ in answers})
    return CompareReport(NAME, "A", rows, has_majority, distinct, 50.0)


def email_report(
    *findings: Finding, mx_status: LookupStatus = LookupStatus.OK, dkim: DkimCheck | None = None
) -> EmailReport:
    passing = Finding(CheckStatus.PASS, "MX records found", "Fine.")
    return EmailReport(
        NAME,
        LookupStatus.OK,
        "192.0.2.53",
        "auto",
        40.0,
        mx=MxCheck(mx_status, (), (passing,)),
        dmarc=DmarcCheck(f"_dmarc.{NAME}", LookupStatus.OK, (), (), findings or (passing,)),
        dkim=dkim,
    )


def dkim_selector(selector: str, record: str | None = None, **fields: object) -> DkimSelector:
    status = LookupStatus.OK if record else LookupStatus.NXDOMAIN
    name = f"{selector}._domainkey.{NAME}"
    return DkimSelector(selector, name, status, record, **fields)


def dnssec_report(
    status: DnssecStatus = DnssecStatus.SECURE,
    clock: ClockState = ClockState.OK,
    nameserver: str = "192.0.2.53",
    stripped: bool = False,
    error: str = "",
    stripped_by: str | None = None,
) -> SimpleNamespace:
    # Only what doctor reads; the wording comes from the patched explain_dnssec.
    return SimpleNamespace(
        name=NAME,
        status=DnssecStatus.UNKNOWN if stripped or error else status,
        clock=SimpleNamespace(state=clock),
        name_missing=False,
        blocking=None,
        nameserver=nameserver,
        signatures_stripped=stripped,
        error="no signatures" if stripped else error,
        stripped_by=stripped_by,
    )


@pytest.fixture
def checks(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Every check returns a healthy result unless a knob says otherwise."""
    state = SimpleNamespace(
        local=SimpleNamespace(problems=(), has_errors=False),
        lookup=lookup_report(),
        compare=compare_report(
            ("Google", A, Agreement.MAJORITY), ("System #1", A, Agreement.MAJORITY)
        ),
        reach=reach_report(),
        email=email_report(),
        dnssec=dnssec_report(),
        calls=[],
        threads=set(),
        crash=None,
        barrier=None,
        public={},  # nameserver -> LookupReport for a lookup with nameserver= (default: lookup)
        dead=set(),  # addresses that refuse connections
        lookup_delay=0.0,  # seconds the system lookup takes
        connected=[],
    )

    def job(check: Check):
        def run(*args: object, **kwargs: object) -> object:
            server = kwargs.get("nameserver")
            state.calls.append((check, args, kwargs))
            if server is None:
                state.threads.add(threading.get_ident())
                if state.barrier is not None and check is not Check.LOOKUP:
                    state.barrier.wait()  # every check must be running at once to get past
            if state.crash is check:
                raise RuntimeError("boom")
            if check is Check.LOOKUP and server is None and state.lookup_delay:
                time.sleep(state.lookup_delay)
            if server is not None and check is Check.LOOKUP:
                return state.public.get(server, state.lookup)
            return getattr(state, check.value)

        return run

    def tcp_connect(address: str, port: int, timeout: float) -> ConnectAttempt:
        state.connected.append(address)
        if address in state.dead:
            return ConnectAttempt(address, port, None, ConnectError.REFUSED)
        return ConnectAttempt(address, port, 20.0)

    for check, function in (
        (Check.LOCAL, "local_check"),
        (Check.LOOKUP, "lookup"),
        (Check.COMPARE, "compare"),
        (Check.REACH, "reach"),
        (Check.EMAIL, "email_check"),
        (Check.DNSSEC, "dnssec_check"),
    ):
        monkeypatch.setattr(doctor_mod, function, job(check))
    monkeypatch.setattr(doctor_mod, "tcp_connect", tcp_connect)
    monkeypatch.setattr(doctor_mod, "system_nameservers", lambda: ["192.0.2.53"])
    monkeypatch.setattr(doctor_mod, "choose_nameserver", lambda candidates: None)
    monkeypatch.setattr(
        doctor_mod,
        "explain_dnssec",
        lambda report: Diagnosis(f"DNSSEC {report.status.value}", "Why.", "Do this."),
    )
    monkeypatch.setattr(
        doctor_mod,
        "clock_diagnosis",
        lambda clock: (
            Diagnosis("The clock is wrong", "Why.", "Set it.")
            if clock.state is ClockState.WRONG
            else None
        ),
    )
    return state


def titles(report) -> list[str]:
    return [i.title for i in report.issues]


def test_healthy_domain_scores_100(checks: SimpleNamespace) -> None:
    report = doctor("https://Example.com/page")

    assert report.name == NAME
    assert {c for c, _, _ in checks.calls} == set(Check)
    assert all(r.state is CheckState.DONE for r in report.runs)
    assert report.issues == ()
    assert report.score == 100
    assert report.healthy
    assert doctor_verdict(report).title == "Healthy: no problems found"


def test_checks_run_in_parallel_and_report_progress(checks: SimpleNamespace) -> None:
    events: list[tuple[Check, CheckState]] = []
    lock = threading.Lock()

    def on_progress(check: Check, state: CheckState) -> None:
        with lock:
            events.append((check, state))

    # The lookup comes first; this computer and the other domain checks then overlap.
    checks.barrier = threading.Barrier(len(Check) - 1, timeout=5)

    report = doctor(NAME, on_progress=on_progress)

    assert all(r.state is CheckState.DONE for r in report.runs)  # none hit the timeout
    assert len(checks.threads) >= len(Check) - 1
    for check in Check:
        states = [s for c, s in events if c is check]
        assert states == [CheckState.PENDING, CheckState.RUNNING, CheckState.DONE]


def test_domain_checks_get_the_timeout(checks: SimpleNamespace) -> None:
    doctor(NAME, timeout=1.5)

    by_check = {c: kwargs for c, _, kwargs in checks.calls}
    for check in (Check.LOOKUP, Check.REACH, Check.EMAIL, Check.DNSSEC):
        assert by_check[check]["timeout"] == 1.5


def test_quick_skips_the_slow_checks(checks: SimpleNamespace) -> None:
    events: list[tuple[Check, CheckState]] = []

    report = doctor(NAME, quick=True, on_progress=lambda c, s: events.append((c, s)))

    assert {c for c, _, _ in checks.calls} == set(Check) - set(SLOW_CHECKS)
    assert report.skipped == SLOW_CHECKS
    assert {c for c, s in events if s is CheckState.SKIPPED} == set(SLOW_CHECKS)
    assert report.email is None and report.dnssec is None
    explanation = doctor_verdict(report).explanation
    assert "quick check, so the resolver comparison, email and DNSSEC weren't checked" in (
        explanation
    )


def test_invalid_name_raises_before_any_check(checks: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="is not a valid domain name"):
        doctor("not a domain!")
    assert checks.calls == []


def test_a_crashing_check_is_reported_not_raised(checks: SimpleNamespace) -> None:
    checks.crash = Check.EMAIL

    report = doctor(NAME)

    run = next(r for r in report.runs if r.check is Check.EMAIL)
    assert run.state is CheckState.ERROR
    assert run.error == "boom"
    assert report.email is None
    assert titles(report) == ["The email check couldn't run"]


def test_local_problems_are_ranked_by_kind(checks: SimpleNamespace) -> None:
    checks.local.problems = (
        problem(ProblemKind.SLOW),
        problem(ProblemKind.GHOST),
        problem(ProblemKind.HIJACK),
    )

    report = doctor(NAME)

    assert [(i.impact, i.title) for i in report.issues] == [
        (Impact.MAJOR, "hijack problem"),
        (Impact.MINOR, "slow problem"),
        (Impact.NOTE, "ghost problem"),
    ]
    assert all(i.area is Area.MACHINE for i in report.issues)
    assert report.score == 100 - 15 - 5  # a note costs nothing
    assert not report.healthy


def test_only_notes_is_healthy(checks: SimpleNamespace) -> None:
    checks.local.problems = (problem(ProblemKind.GHOST), problem(ProblemKind.VPN_BLOCKED))

    report = doctor(NAME)

    assert report.score == 100
    assert report.healthy
    verdict = doctor_verdict(report)
    assert verdict.title == "Healthy: no problems found"
    assert "2 notes below for information" in verdict.explanation


def test_dns_broken_here_blames_this_computer(checks: SimpleNamespace) -> None:
    checks.local = SimpleNamespace(
        problems=(problem(ProblemKind.NO_RESPONSE, Severity.ERROR),), has_errors=True
    )
    timeout = LookupResult("A", LookupStatus.TIMEOUT)
    checks.lookup = lookup_report(timeout, LookupResult("AAAA", LookupStatus.TIMEOUT))
    checks.reach = reach_report(timeout)

    report = doctor(NAME)

    assert [(i.area, i.impact) for i in report.issues] == [(Area.MACHINE, Impact.CRITICAL)]
    verdict = doctor_verdict(report)
    assert verdict.title == "This computer can't use DNS"
    assert "probably not the domain's fault" in verdict.explanation


MISSING = (LookupResult("A", LookupStatus.NXDOMAIN), LookupResult("AAAA", LookupStatus.NXDOMAIN))


def test_a_domain_that_doesnt_exist_skips_what_needs_it_and_scores_0(
    checks: SimpleNamespace,
) -> None:
    checks.lookup = lookup_report(*MISSING)
    events: list[tuple[Check, CheckState]] = []

    report = doctor(NAME, on_progress=lambda c, s: events.append((c, s)))

    ran = {c for c, _, kwargs in checks.calls if not kwargs.get("nameserver")}
    assert ran == {Check.LOCAL, Check.LOOKUP}
    asked = [kwargs["nameserver"] for c, _, kwargs in checks.calls if kwargs.get("nameserver")]
    assert asked == ["8.8.8.8"]  # a public resolver agrees: no need to ask the second
    for run in report.runs:
        if run.check in NEEDS_DOMAIN:
            assert (run.state, run.reason) == (CheckState.SKIPPED, SKIP_NO_DOMAIN)
            assert (run.check, CheckState.SKIPPED) in events
    assert report.name_missing
    assert report.score == 0
    assert titles(report) == ["example.com: domain doesn't exist"]
    assert (report.issues[0].area, report.issues[0].impact) == (Area.DOMAIN, Impact.CRITICAL)
    verdict = doctor_verdict(report)
    assert verdict.title == "example.com doesn't exist"
    assert "were skipped. The score is 0." in verdict.explanation
    assert "Check the spelling" in verdict.suggestion


def test_a_missing_domain_with_issues_here_still_scores_0(checks: SimpleNamespace) -> None:
    checks.lookup = lookup_report(*MISSING)
    checks.local.problems = (problem(ProblemKind.SLOW),)

    report = doctor(NAME)

    assert report.score == 0
    assert "Separately, this computer has 1 issue." in doctor_verdict(report).explanation


def test_a_slow_lookup_that_says_missing_still_skips_the_rest(
    checks: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor_mod, "LOOKUP_WAIT_S", 0.01)
    checks.lookup = lookup_report(*MISSING)
    checks.lookup_delay = 0.2  # the other checks start before the answer arrives
    events: list[tuple[Check, CheckState]] = []

    report = doctor(NAME, on_progress=lambda c, s: events.append((c, s)))

    assert {c for c, _, _ in checks.calls} == set(Check)  # they did run...
    for run in report.runs:  # ...but their results are dropped
        if run.check in NEEDS_DOMAIN:
            assert (run.state, run.reason) == (CheckState.SKIPPED, SKIP_NO_DOMAIN)
            assert (run.check, CheckState.SKIPPED) in events
    assert report.reach is None and report.email is None and report.dnssec is None
    assert report.score == 0


def test_email_doesnt_repeat_a_name_that_fails(checks: SimpleNamespace) -> None:
    failed = LookupResult("A", LookupStatus.SERVFAIL)
    checks.lookup = lookup_report(failed)
    checks.reach = reach_report(failed)
    checks.dnssec = dnssec_report(DnssecStatus.BOGUS)
    checks.email = email_report(
        Finding(CheckStatus.FAIL, "Couldn't check DMARC: query timed out", "Why.", "Retry.")
    )

    assert titles(doctor(NAME)) == ["DNSSEC bogus"]


def test_missing_when_no_public_resolver_can_be_asked(checks: SimpleNamespace) -> None:
    checks.lookup = lookup_report(*MISSING)
    blocked = lookup_report(LookupResult("A", LookupStatus.TIMEOUT))
    checks.public = {"8.8.8.8": blocked, "1.1.1.1": blocked}

    report = doctor(NAME)

    assert report.name_missing  # nothing contradicts this computer's answer
    assert report.score == 0


def test_missing_only_through_this_computers_dns(checks: SimpleNamespace) -> None:
    checks.lookup = lookup_report(*MISSING)
    checks.public = {"8.8.8.8": lookup_report(A)}
    checks.reach = reach_report(MISSING[0])

    report = doctor(NAME)

    assert not report.name_missing
    assert report.found_by == "8.8.8.8"
    assert all(r.state is CheckState.DONE for r in report.runs)  # the domain exists
    assert [(i.area, i.impact, i.title) for i in report.issues] == [
        (
            Area.MACHINE,
            Impact.MAJOR,
            "This computer's DNS server says example.com doesn't exist, but public resolvers "
            "find it",
        )
    ]
    assert "192.0.2.53 answered that example.com doesn't exist" in report.issues[0].detail
    assert report.score == 85


def test_a_timeout_only_for_the_domain_blames_the_domain(checks: SimpleNamespace) -> None:
    timeout = LookupResult("A", LookupStatus.TIMEOUT)
    checks.lookup = lookup_report(timeout)
    checks.reach = reach_report(timeout)

    report = doctor(NAME)

    assert titles(report) == ["example.com: query timed out"]
    assert report.issues[0].area is Area.DOMAIN


def test_broken_dnssec_explains_the_failing_lookup(checks: SimpleNamespace) -> None:
    failed = LookupResult("A", LookupStatus.SERVFAIL)
    checks.lookup = lookup_report(failed)
    checks.reach = reach_report(failed)
    checks.dnssec = dnssec_report(DnssecStatus.BOGUS)

    report = doctor(NAME)

    assert titles(report) == ["DNSSEC bogus"]
    assert (report.issues[0].area, report.issues[0].impact) == (Area.DOMAIN, Impact.CRITICAL)


def test_bogus_because_of_the_clock_is_this_computers_fault(checks: SimpleNamespace) -> None:
    checks.dnssec = dnssec_report(DnssecStatus.BOGUS, ClockState.WRONG)

    report = doctor(NAME)

    assert report.issues[0].area is Area.MACHINE


def test_a_wrong_clock_alone_is_a_major_machine_issue(checks: SimpleNamespace) -> None:
    checks.dnssec = dnssec_report(clock=ClockState.WRONG)

    report = doctor(NAME)

    assert [(i.area, i.impact, i.title) for i in report.issues] == [
        (Area.MACHINE, Impact.MAJOR, "The clock is wrong")
    ]


def test_dnssec_off_is_minor(checks: SimpleNamespace) -> None:
    checks.dnssec = dnssec_report(DnssecStatus.INSECURE)

    report = doctor(NAME)

    assert [(i.impact, i.title) for i in report.issues] == [(Impact.MINOR, "DNSSEC insecure")]
    assert report.score == 95
    assert doctor_verdict(report).title == "Healthy, with a few things to tidy up"


def test_connection_failure_is_a_domain_issue(checks: SimpleNamespace) -> None:
    checks.reach = reach_report(connected=False)

    report = doctor(NAME)

    assert len(report.issues) == 1
    issue = report.issues[0]
    assert (issue.area, issue.impact, issue.check) == (Area.DOMAIN, Impact.MAJOR, Check.REACH)
    assert issue.title.startswith("The problem is the connection")


def test_a_dns_filter_block_is_this_computers_issue(checks: SimpleNamespace) -> None:
    checks.reach = reach_report(LookupResult("A", LookupStatus.OK, (Record("0.0.0.0", 60),)))

    report = doctor(NAME)

    assert report.issues[0].area is Area.MACHINE
    assert report.issues[0].title == "The problem is DNS: the name is blocked"


def test_a_hosts_file_override_for_the_domain(checks: SimpleNamespace) -> None:
    entry = SimpleNamespace(ip="127.0.0.1", line=22)
    checks.reach = reach_report(hosts=(entry,))

    report = doctor(NAME)

    assert titles(report) == ["This computer's hosts file overrides example.com"]
    assert "127.0.0.1 (line 22)" in report.issues[0].detail


def test_different_working_addresses_are_a_note(checks: SimpleNamespace) -> None:
    checks.compare = compare_report(
        ("Google", A, Agreement.MAJORITY),
        ("Cloudflare", OTHER_A, Agreement.DIFFERS),
        ("System #1", A, Agreement.MAJORITY),
    )

    report = doctor(NAME)

    assert sorted(checks.connected) == ["192.0.2.10", "198.51.100.7"]  # one per answer
    assert [(i.area, i.impact) for i in report.issues] == [(Area.DOMAIN, Impact.NOTE)]
    assert report.issues[0].title == "Resolvers give different addresses for example.com"
    assert "normal for a site on a CDN" in report.issues[0].detail
    assert report.score == 100
    assert report.healthy


def test_same_answers_connect_to_nothing(checks: SimpleNamespace) -> None:
    report = doctor(NAME)

    assert checks.connected == []
    assert report.issues == ()


def test_an_answer_that_doesnt_respond_is_major(checks: SimpleNamespace) -> None:
    checks.compare = compare_report(
        ("Google", A, Agreement.MAJORITY),
        ("Quad9", A, Agreement.MAJORITY),
        ("Cloudflare", OTHER_A, Agreement.DIFFERS),
    )
    checks.dead = {"198.51.100.7"}

    report = doctor(NAME)

    issue = report.issues[0]
    assert (issue.area, issue.impact) == (Area.DOMAIN, Impact.MAJOR)
    assert issue.title == (
        "Some resolvers send visitors of example.com to an address that doesn't respond"
    )
    assert "Cloudflare (198.51.100.7: refused)" in issue.detail
    assert report.score == 85


def test_only_this_computers_answer_not_responding_is_its_issue(
    checks: SimpleNamespace,
) -> None:
    checks.compare = compare_report(
        ("Google", A, Agreement.MAJORITY),
        ("System #1", OTHER_A, Agreement.DIFFERS),
    )
    checks.dead = {"198.51.100.7"}

    report = doctor(NAME)

    assert (report.issues[0].area, report.issues[0].impact) == (Area.MACHINE, Impact.MAJOR)


@pytest.mark.parametrize("status", [LookupStatus.NXDOMAIN, LookupStatus.SERVFAIL])
def test_public_resolvers_not_finding_it_while_others_do(
    checks: SimpleNamespace, status: LookupStatus
) -> None:
    odd = LookupResult("A", status)
    agreement = Agreement.DIFFERS if status is LookupStatus.NXDOMAIN else Agreement.FAILED
    checks.compare = compare_report(
        ("Google", A, Agreement.MAJORITY),
        ("Cloudflare", odd, agreement),
        ("System #1", A, Agreement.MAJORITY),
    )

    report = doctor(NAME)

    issue = report.issues[0]
    assert (issue.area, issue.impact, issue.title) == (
        Area.DOMAIN,
        Impact.MAJOR,
        "Some resolvers can't find example.com",
    )
    assert "2 resolvers answered with an address, but Cloudflare (" in issue.detail


def test_own_dns_server_saying_the_name_is_missing(checks: SimpleNamespace) -> None:
    checks.compare = compare_report(
        ("Google", A, Agreement.MAJORITY),
        ("Cloudflare", A, Agreement.MAJORITY),
        ("System #1", LookupResult("A", LookupStatus.NXDOMAIN), Agreement.DIFFERS),
    )

    report = doctor(NAME)

    issue = report.issues[0]
    assert (issue.area, issue.impact) == (Area.MACHINE, Impact.MAJOR)
    assert (
        issue.title == "This computer's DNS server can't find example.com, but public resolvers can"
    )
    assert "but System #1 (it doesn't exist)" in issue.detail


def test_public_resolvers_timing_out_isnt_a_domain_issue(checks: SimpleNamespace) -> None:
    # A VPN blocking outside DNS: local reports that, compare shouldn't blame the domain.
    timeout = LookupResult("A", LookupStatus.TIMEOUT)
    checks.compare = compare_report(
        ("Google", timeout, Agreement.FAILED),
        ("Cloudflare", timeout, Agreement.FAILED),
        ("System #1", A, Agreement.MAJORITY),
    )

    assert doctor(NAME).issues == ()


def test_servfail_from_broken_dnssec_is_only_the_dnssec_issue(checks: SimpleNamespace) -> None:
    checks.compare = compare_report(
        ("Google", LookupResult("A", LookupStatus.SERVFAIL), Agreement.FAILED),
        ("System #1", A, Agreement.MAJORITY),
    )
    checks.dnssec = dnssec_report(DnssecStatus.BOGUS)

    assert titles(doctor(NAME)) == ["DNSSEC bogus"]


def test_email_findings(checks: SimpleNamespace) -> None:
    checks.email = email_report(
        Finding(CheckStatus.WARN, "No DMARC report address (rua)", "Why.", "Add rua."),
        Finding(CheckStatus.FAIL, "Policy is broken", "Why.", ""),
    )

    report = doctor(NAME)

    assert [(i.impact, i.title) for i in report.issues] == [
        (Impact.MAJOR, "Email (DMARC): policy is broken"),
        (Impact.MINOR, "Email (DMARC): no DMARC report address (rua)"),
    ]
    assert report.issues[0].fix == "Run dnskit email example.com for details."


def test_email_findings_are_minor_without_mx(checks: SimpleNamespace) -> None:
    checks.email = email_report(
        Finding(CheckStatus.FAIL, "No DMARC record", "Why.", "Add one."),
        mx_status=LookupStatus.NO_ANSWER,
    )

    report = doctor(NAME)

    assert [i.impact for i in report.issues] == [Impact.MINOR]


def test_one_check_cant_take_more_than_its_cap(checks: SimpleNamespace) -> None:
    fails = tuple(Finding(CheckStatus.FAIL, f"Problem {n}", "Why.", "Fix.") for n in range(5))
    checks.email = email_report(*fails)

    report = doctor(NAME)

    assert report.score == 100 - MAX_PENALTY_PER_CHECK


def test_most_important_first_and_this_computer_first_on_ties(
    checks: SimpleNamespace,
) -> None:
    checks.local.problems = (problem(ProblemKind.SLOW), problem(ProblemKind.IPV6_BROKEN))
    checks.reach = reach_report(connected=False)
    checks.dnssec = dnssec_report(DnssecStatus.INSECURE)

    report = doctor(NAME)

    assert [(i.impact, i.area) for i in report.issues] == [
        (Impact.MAJOR, Area.MACHINE),
        (Impact.MAJOR, Area.DOMAIN),
        (Impact.MINOR, Area.MACHINE),
        (Impact.MINOR, Area.DOMAIN),
    ]
    assert report.score == 100 - 15 - 15 - 5 - 5
    verdict = doctor_verdict(report)
    assert verdict.title == "Several problems need fixing"
    assert "This computer has 2 issues; the most important: ipv6_broken problem." in (
        verdict.explanation
    )
    assert "example.com has 2 issues" in verdict.explanation
    assert verdict.suggestion == "Start at the top of the list: Fix it."


def test_checks_failing_for_another_issues_reason_still_count_as_failed(
    checks: SimpleNamespace,
) -> None:
    failed = LookupResult("A", LookupStatus.SERVFAIL)
    checks.lookup = lookup_report(failed)
    checks.reach = reach_report(failed)
    checks.dnssec = dnssec_report(DnssecStatus.BOGUS)

    report = doctor(NAME)

    assert report.failed(Check.LOOKUP)
    assert report.failed(Check.REACH)
    assert report.failed(Check.DNSSEC)
    assert not report.failed(Check.EMAIL)
    assert not report.failed(Check.LOCAL)


# --- DNSSEC through a resolver that strips signatures ----------------------------------------
# dnssec_check retries through public resolvers itself (tests/test_dnssec.py); doctor only
# reads the result.


def test_dnssec_checked_through_a_public_resolver_judges_the_domain(
    checks: SimpleNamespace,
) -> None:
    checks.dnssec = dnssec_report(
        DnssecStatus.INSECURE, nameserver="8.8.8.8", stripped_by="192.0.2.53"
    )

    report = doctor(NAME)

    assert report.dnssec_via == "8.8.8.8"
    assert [(i.area, i.impact, i.title) for i in report.issues] == [
        (Area.DOMAIN, Impact.MINOR, "DNSSEC insecure")
    ]


def test_stripped_everywhere_is_a_note_about_this_computer(checks: SimpleNamespace) -> None:
    checks.dnssec = dnssec_report(stripped=True, stripped_by="192.0.2.53")

    report = doctor(NAME)

    assert report.dnssec_via is None
    assert [(i.area, i.impact, i.check) for i in report.issues] == [
        (Area.MACHINE, Impact.NOTE, Check.DNSSEC)
    ]
    assert report.score == 100


# --- DKIM ---------------------------------------------------------------------------------


def test_no_dkim_at_the_common_selectors_is_a_note(checks: SimpleNamespace) -> None:
    not_found = Finding(CheckStatus.WARN, "No DKIM key at the common selectors", "Why.", "Look.")
    selectors = (dkim_selector("default"), dkim_selector("google"))
    checks.email = email_report(dkim=DkimCheck(selectors, (not_found,)))

    report = doctor(NAME)

    assert [(i.impact, i.title) for i in report.issues] == [
        (Impact.NOTE, "Email (DKIM): no DKIM key at the common selectors")
    ]
    assert report.score == 100


def test_real_dkim_findings_stay_issues(checks: SimpleNamespace) -> None:
    weak = Finding(CheckStatus.FAIL, "DKIM key at s1 is too short (512-bit)", "Why.", "Fix.")
    revoked = Finding(CheckStatus.WARN, "DKIM key revoked", "Why.", "Fix.")
    selectors = (
        dkim_selector("s1", "v=DKIM1; p=MFww", key_type="rsa", key_bits=512),
        dkim_selector("s2", "v=DKIM1; p=", revoked=True),
    )
    checks.email = email_report(dkim=DkimCheck(selectors, (weak, revoked)))

    report = doctor(NAME)

    assert [i.impact for i in report.issues] == [Impact.MAJOR, Impact.MINOR]
    assert report.score == 80


# --- This computer ------------------------------------------------------------------------


def test_doctor_doesnt_probe_ghost_servers(checks: SimpleNamespace) -> None:
    doctor(NAME)

    local = [kwargs for c, _, kwargs in checks.calls if c is Check.LOCAL]
    assert local == [{"probe_ghosts": False}]
