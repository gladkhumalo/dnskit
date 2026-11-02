import importlib
import threading
from types import SimpleNamespace

import pytest

from dnskit.core import LookupReport, LookupResult, LookupStatus, Record
from dnskit.core.batch import (
    BatchCheck,
    read_domains,
    run_batch,
    summarize_doctor,
    summarize_email,
    summarize_lookup,
)
from dnskit.core.doctor import Area, Check, DoctorReport, Impact, Issue
from dnskit.core.mail import CheckStatus, DmarcCheck, EmailReport, Finding, MxCheck

batch_mod = importlib.import_module("dnskit.core.batch")

A = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 300), Record("192.0.2.2", 300)))
MX = LookupResult("MX", LookupStatus.OK, (Record("10 mail.example.com.", 300),))
EMPTY = LookupResult("TXT", LookupStatus.NO_ANSWER)
MISSING = LookupResult("A", LookupStatus.NXDOMAIN)


def lookup_report(name: str, *results: LookupResult) -> LookupReport:
    return LookupReport(name, "192.0.2.53", "auto", results, 10.0)


def email_report(*findings: Finding, status: LookupStatus = LookupStatus.OK) -> EmailReport:
    passing = Finding(CheckStatus.PASS, "MX records found", "Fine.")
    if status is not LookupStatus.OK:
        return EmailReport("example.com", status, "192.0.2.53", "auto", 5.0)
    return EmailReport(
        "example.com",
        status,
        "192.0.2.53",
        "auto",
        5.0,
        mx=MxCheck(LookupStatus.OK, (), (passing,)),
        dmarc=DmarcCheck("_dmarc.example.com", LookupStatus.OK, (), (), findings or (passing,)),
    )


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Every check answers from `reports[name]`; calls are recorded."""
    state = SimpleNamespace(reports={}, calls=[], local_calls=0, crash=set())
    lock = threading.Lock()

    def record(kind: str, name: str, kwargs: dict) -> object:
        with lock:
            state.calls.append((kind, name, kwargs))
        if name in state.crash:
            raise RuntimeError("boom")
        return state.reports[name]

    def fake_local_check(**kwargs: object) -> object:
        state.local_calls += 1
        state.local_kwargs = kwargs
        return SimpleNamespace(problems=())

    monkeypatch.setattr(batch_mod, "lookup", lambda name, rtypes, **kw: record("lookup", name, kw))
    monkeypatch.setattr(batch_mod, "doctor", lambda name, **kw: record("doctor", name, kw))
    monkeypatch.setattr(
        batch_mod,
        "email_check",
        lambda name, selectors, **kw: record("email", name, {**kw, "selectors": selectors}),
    )
    monkeypatch.setattr(batch_mod, "local_check", fake_local_check)
    monkeypatch.setattr(
        batch_mod, "summarize_doctor", lambda report: (report.healthy, f"{report.score}/100")
    )
    return state


def test_read_domains_skips_blanks_and_comments_and_keeps_line_numbers() -> None:
    lines = read_domains(
        "example.com\n\n# my sites\n  https://www.Example.org/page  # the blog\nnot a domain\n"
    )

    assert [(line.line, line.name) for line in lines] == [
        (1, "example.com"),
        (4, "www.example.org"),
        (5, None),
    ]
    assert lines[1].text == "https://www.Example.org/page"
    assert "not a valid domain name" in lines[2].error


def test_lookup_batch_in_file_order_with_summaries(fakes: SimpleNamespace) -> None:
    fakes.reports = {
        "a.example": lookup_report("a.example", A, MX, EMPTY),
        "b.example": lookup_report("b.example", MISSING),
        "c.example": lookup_report("c.example", EMPTY),
    }
    done = []

    report = run_batch(
        read_domains("a.example\nb.example\nc.example\n"),
        BatchCheck.LOOKUP,
        server="1.1.1.1",
        on_done=done.append,
    )

    assert [(i.line, i.name, i.ok, i.summary) for i in report.items] == [
        (1, "a.example", True, "A 2, MX 1"),
        (2, "b.example", False, "Domain doesn't exist"),
        (3, "c.example", True, "exists, but has none of these records"),
    ]
    assert {i.name for i in done} == {"a.example", "b.example", "c.example"}
    assert all(kwargs["nameserver"] == "1.1.1.1" for _, _, kwargs in fakes.calls)
    assert (len(report.passed), len(report.failed), report.all_ok) == (2, 1, False)


def test_duplicates_are_checked_once_and_invalid_lines_kept(fakes: SimpleNamespace) -> None:
    fakes.reports = {"a.example": lookup_report("a.example", A)}

    report = run_batch(read_domains("a.example\nbad name!\nA.EXAMPLE\n"), BatchCheck.LOOKUP)

    assert [c[1] for c in fakes.calls] == ["a.example"]
    assert [i.name for i in report.items] == ["a.example"]
    assert [line.line for line in report.duplicates] == [3]
    assert [line.line for line in report.invalid] == [2]
    assert not report.all_ok  # an invalid line counts against it


def test_doctor_batch_checks_this_computer_once(fakes: SimpleNamespace) -> None:
    healthy = SimpleNamespace(healthy=True, score=100)
    fakes.reports = {"a.example": healthy, "b.example": healthy}

    report = run_batch(
        read_domains("a.example\nb.example\n"),
        BatchCheck.DOCTOR,
        quick=True,
        resolvers=(("Office", "10.0.0.53"),),
        timeout=2.0,
    )

    assert fakes.local_calls == 1
    assert fakes.local_kwargs == {"probe_ghosts": False}
    assert report.local is not None
    for _, _, kwargs in fakes.calls:
        assert kwargs["local"] is report.local
        assert kwargs["quick"] is True
        assert kwargs["resolvers"] == (("Office", "10.0.0.53"),)
        assert kwargs["timeout"] == 2.0
    assert [i.summary for i in report.items] == ["100/100", "100/100"]


def test_email_batch_passes_selectors(fakes: SimpleNamespace) -> None:
    fakes.reports = {"a.example": email_report()}

    report = run_batch(read_domains("a.example\n"), BatchCheck.EMAIL, selectors=("s1",))

    assert fakes.calls[0][2]["selectors"] == ("s1",)
    assert report.items[0].summary == "all checks pass"


def test_a_crash_is_one_failed_item(fakes: SimpleNamespace) -> None:
    fakes.reports = {"b.example": lookup_report("b.example", A)}
    fakes.crash = {"a.example"}

    report = run_batch(read_domains("a.example\nb.example\n"), BatchCheck.LOOKUP)

    crashed, fine = report.items
    assert (crashed.ok, crashed.error, crashed.report) == (False, "boom", None)
    assert crashed.summary == "couldn't be checked"
    assert fine.ok


def test_checks_run_in_parallel_up_to_the_limit(
    fakes: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = [f"d{n}.example" for n in range(4)]
    fakes.reports = {n: lookup_report(n, A) for n in names}
    barrier = threading.Barrier(2, timeout=5)
    running = []

    def blocking_lookup(name: str, rtypes: object, **kwargs: object) -> LookupReport:
        running.append(name)
        barrier.wait()  # passes only when two run at once
        return fakes.reports[name]

    monkeypatch.setattr(batch_mod, "lookup", blocking_lookup)

    report = run_batch(read_domains("\n".join(names)), BatchCheck.LOOKUP, parallel=2)

    assert all(i.ok for i in report.items)


def test_nothing_to_check_skips_this_computer(fakes: SimpleNamespace) -> None:
    report = run_batch(read_domains("bad name!\n"), BatchCheck.DOCTOR)

    assert fakes.local_calls == 0
    assert report.items == () and len(report.invalid) == 1


def test_summarize_lookup_failure_wording() -> None:
    ok, summary = summarize_lookup(lookup_report("x", LookupResult("A", LookupStatus.TIMEOUT)))

    assert (ok, summary) == (False, "Query timed out")


def test_summarize_email() -> None:
    warn = Finding(CheckStatus.WARN, "No DMARC report address (rua)", "Why.", "Fix.")
    fail = Finding(CheckStatus.FAIL, "No DMARC record", "Why.", "Fix.")

    assert summarize_email(email_report(warn)) == (
        True,
        "warn: DMARC: No DMARC report address (rua)",
    )
    assert summarize_email(email_report(fail)) == (False, "fail: DMARC: No DMARC record")
    assert summarize_email(email_report(status=LookupStatus.NXDOMAIN)) == (
        False,
        "Domain doesn't exist",
    )


def doctor_report(*issues: Issue) -> DoctorReport:
    return DoctorReport("example.com", False, (), issues, 10.0)


def test_summarize_doctor_shows_the_most_important_issue() -> None:
    report = doctor_report(
        Issue(Area.MACHINE, Impact.NOTE, "Ghost DNS server 192.0.2.88", "", "", Check.LOCAL),
        Issue(
            Area.DOMAIN, Impact.MINOR, "DNSSEC isn't enabled for example.com", "", "", Check.DNSSEC
        ),
    )

    assert summarize_doctor(report) == (True, "95/100 · DNSSEC isn't enabled for example.com")


def test_summarize_doctor_with_only_notes_or_nothing() -> None:
    note = Issue(Area.MACHINE, Impact.NOTE, "Ghost DNS server 192.0.2.88", "", "", Check.LOCAL)

    assert summarize_doctor(doctor_report(note)) == (True, "100/100 · no issues")
    assert summarize_doctor(doctor_report()) == (True, "100/100 · no issues")


def test_summarize_doctor_not_ok_on_a_major_issue() -> None:
    major = Issue(
        Area.DOMAIN, Impact.MAJOR, "Some resolvers can't find example.com", "", "", Check.COMPARE
    )

    assert summarize_doctor(doctor_report(major)) == (
        False,
        "85/100 · Some resolvers can't find example.com",
    )
