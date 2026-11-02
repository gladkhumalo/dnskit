import dataclasses
import errno
import io
import json
import os
import re
import runpy
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

import dnskit
from conftest import make_choice
from dnskit import __version__
from dnskit.cli import app as cli_app
from dnskit.cli.render import DoctorProgress
from dnskit.core import (
    Adapter,
    AdapterScan,
    Agreement,
    BatchCheck,
    BatchItem,
    BatchLine,
    BatchReport,
    CheckStatus,
    CompareReport,
    DkimCheck,
    DkimSelector,
    DmarcCheck,
    DnssecStatus,
    EmailReport,
    Finding,
    FlushCommand,
    HostsEntry,
    HostsFile,
    HostsKind,
    LocalReport,
    LookupReport,
    LookupResult,
    LookupStatus,
    MxCheck,
    MxHost,
    Problem,
    ProblemKind,
    Record,
    ResolverAnswer,
    ResolverChoice,
    ReverseReport,
    ServerCheck,
    Severity,
    SpfCheck,
    SpfLookup,
    SystemNameservers,
    WatchSample,
)
from dnskit.core.compare import rank_answers
from dnskit.core.connectivity import ConnectAttempt, ConnectError, IPv6Check, IPv6State
from dnskit.core.dnssec import (
    BogusKind,
    ClockCheck,
    ClockState,
    DnssecReport,
    DsInfo,
    KeyInfo,
    RecordCheck,
    ZoneCheck,
    ZoneStatus,
)
from dnskit.core.doctor import (
    SLOW_CHECKS,
    Area,
    Check,
    CheckRun,
    CheckState,
    DoctorReport,
    Impact,
    Issue,
)
from dnskit.core.integrity import RawAnswer, classify_cloudflare, classify_google, classify_nxdomain
from dnskit.core.outside import DnsBlocking
from dnskit.core.propagation import PROPAGATION_RESOLVERS, PropagationAnswer, PropagationReport
from dnskit.core.reach import ReachReport
from dnskit.core.trace import (
    FailReason,
    Server,
    ServerFailure,
    StepStatus,
    TraceMode,
    TraceReport,
    TraceStep,
)

runner = CliRunner()


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def plain(output: str) -> str:
    """Output with ANSI colours and box-drawing removed and whitespace collapsed.

    Colours must be stripped because Typer forces coloured help when GITHUB_ACTIONS is set
    (as it is in CI), which splits strings like "--type" across escape codes.
    """
    text = ANSI_ESCAPE.sub("", output)
    return " ".join(re.sub(r"[│╭╮╰╯─┃]", " ", text).split())


def make_report(*results: LookupResult) -> LookupReport:
    return LookupReport("example.com", "192.0.2.53", "auto: test", results, 12.0)


def make_reverse(ip: str, result: LookupResult, version: int = 4) -> ReverseReport:
    return ReverseReport(ip, version, "x.in-addr.arpa.", "192.0.2.53", "auto: test", result, 9.0)


def patch_lookup(monkeypatch: pytest.MonkeyPatch, report: LookupReport) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_lookup(name, rtypes, **kwargs):
        calls.append(list(rtypes))
        return report

    monkeypatch.setattr(cli_app, "lookup", fake_lookup)
    return calls


def test_version() -> None:
    result = runner.invoke(cli_app.app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in plain(result.output)


def test_lookup_help() -> None:
    result = runner.invoke(cli_app.app, ["lookup", "--help"])

    assert result.exit_code == 0
    assert "--type" in plain(result.output)


def test_lookup_default_shows_all_types_grouped(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report(
        LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 60),)),
        LookupResult("MX", LookupStatus.OK, (Record("10 mail.example.com.", 60),)),
        LookupResult("TXT", LookupStatus.NO_ANSWER),
    )
    calls = patch_lookup(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["lookup", "example.com"])

    assert result.exit_code == 0
    assert calls == [["A", "AAAA", "MX", "CNAME", "NS", "TXT"]]
    for text in ("192.0.2.1", "mail.example.com.", "TXT", "no records", "Resolver: 192.0.2.53"):
        assert text in plain(result.output)


def test_lookup_type_limits_query(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_lookup(monkeypatch, make_report(LookupResult("MX", LookupStatus.NO_ANSWER)))

    result = runner.invoke(cli_app.app, ["lookup", "example.com", "--type", "MX"])

    assert result.exit_code == 0
    assert calls == [["MX"]]


def test_lookup_nxdomain_shows_resolver_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(
        LookupResult("A", LookupStatus.NXDOMAIN), LookupResult("MX", LookupStatus.NXDOMAIN)
    )
    patch_lookup(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["lookup", "nope.invalid"])

    assert result.exit_code == 1
    assert "NXDOMAIN" in plain(result.output)
    assert "Resolver: 192.0.2.53" in plain(result.output)


def test_lookup_all_timeouts_exit_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, make_report(LookupResult("A", LookupStatus.TIMEOUT)))

    result = runner.invoke(cli_app.app, ["lookup", "example.com"])

    assert result.exit_code == 1
    assert "timed out" in plain(result.output)


def patch_resolvers(
    monkeypatch: pytest.MonkeyPatch, choice: ResolverChoice, ignored: tuple[str, ...] = ()
) -> list[bool]:
    calls: list[bool] = []
    usable = tuple(p.nameserver for p in choice.probes)
    monkeypatch.setattr(
        cli_app,
        "classify_nameservers",
        lambda: SystemNameservers(usable + ignored, usable, ignored),
    )

    def fake_choose(candidates, *, use_cache=True, **kwargs):
        calls.append(use_cache)
        return choice

    monkeypatch.setattr(cli_app, "choose_nameserver", fake_choose)
    return calls


def test_resolvers_shows_failed_slow_and_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    choice = make_choice({"192.0.2.1": None, "192.0.2.2": 9.0, "192.0.2.3": 400.0})
    calls = patch_resolvers(monkeypatch, choice)

    result = runner.invoke(cli_app.app, ["resolvers"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [False]  # always a fresh probe, which also refreshes the cache
    assert "no response" in output
    assert "400 ms (slow)" in output
    assert "9 ms ← used by lookup" in output
    assert "cached as the lookup choice for 5 min" in output


def test_resolvers_none_answering_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_resolvers(monkeypatch, make_choice({"192.0.2.1": None, "192.0.2.2": None}))

    result = runner.invoke(cli_app.app, ["resolvers"])

    assert result.exit_code == 1
    assert "No nameserver answered" in plain(result.output)


def test_resolvers_lists_ignored_ghost_nameservers(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_resolvers(monkeypatch, make_choice({"192.0.2.2": 9.0}), ignored=("192.0.2.66",))

    result = runner.invoke(cli_app.app, ["resolvers"])

    assert result.exit_code == 0
    assert "Ignored (not on a connected adapter): 192.0.2.66" in plain(result.output)


# --- Resolver footer ----------------------------------------------------------------------


def ok_report(choice: ResolverChoice | None, source: str = "auto: test") -> LookupReport:
    result = LookupResult("A", LookupStatus.OK, (Record("192.0.2.10", 60),))
    return LookupReport("example.com", "192.0.2.2", source, (result,), 12.0, choice)


def test_footer_lists_failed_and_slow_nameservers(monkeypatch: pytest.MonkeyPatch) -> None:
    choice = make_choice({"192.0.2.1": None, "192.0.2.2": 9.0, "192.0.2.3": 400.0})
    patch_lookup(monkeypatch, ok_report(choice))

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com"]).output)

    assert "Nameserver problems" in output
    assert "no response from 192.0.2.1" in output
    assert "slow: 192.0.2.3 (400 ms)" in output


def test_footer_quiet_when_all_nameservers_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, ok_report(make_choice({"192.0.2.1": 9.0, "192.0.2.2": 12.0})))

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com"]).output)

    assert "Nameserver problems" not in output


def test_footer_shows_cache_age(monkeypatch: pytest.MonkeyPatch) -> None:
    choice = make_choice({"192.0.2.2": 9.0}, from_cache=True, probed_at=time.time() - 125)
    patch_lookup(monkeypatch, ok_report(choice))

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com"]).output)

    assert "cached, probed 2 min ago" in output


def test_explicit_server_footer_has_no_probe_info(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, ok_report(None, source="--server"))

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com", "-s", "192.0.2.2"]).output)

    assert "(--server)" in output
    assert "cached" not in output
    assert "Nameserver problems" not in output


@pytest.mark.parametrize("command", [["lookup", "example.com"], ["reverse", "8.8.8.8"]])
def test_server_and_refresh_are_passed_through(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    seen: dict = {}

    def capture(*args, **kwargs):
        seen.update(kwargs)
        raise ValueError("stop")

    monkeypatch.setattr(
        cli_app, command[0] if command[0] == "lookup" else "reverse_lookup", capture
    )

    runner.invoke(cli_app.app, [*command, "-s", "192.0.2.53", "--refresh"])

    assert seen["nameserver"] == "192.0.2.53"
    assert seen["refresh"] is True


# --- Error explanations -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "title", "next_step", "exit_code"),
    [
        (LookupStatus.NXDOMAIN, "Domain doesn't exist", "Check the spelling for typos", 1),
        (LookupStatus.NO_ANSWER, "No MX records", "dnskit lookup example.com", 0),
        (LookupStatus.SERVFAIL, "Nameserver failure (SERVFAIL)", "different public resolver", 1),
        (LookupStatus.TIMEOUT, "Query timed out", "Check your internet connection", 1),
        (LookupStatus.NO_NETWORK, "No network connection", "Wi-Fi, Ethernet or VPN", 1),
        (LookupStatus.NO_NAMESERVERS, "All nameservers refused or failed", "dnskit resolvers", 1),
    ],
)
def test_lookup_error_shows_explanation_and_next_step(
    monkeypatch: pytest.MonkeyPatch,
    status: LookupStatus,
    title: str,
    next_step: str,
    exit_code: int,
) -> None:
    patch_lookup(monkeypatch, make_report(LookupResult("MX", status)))

    result = runner.invoke(cli_app.app, ["lookup", "example.com", "-t", "MX"])
    output = plain(result.output)

    assert result.exit_code == exit_code
    assert title in output
    assert "Next step:" in output
    assert next_step in output
    assert "Resolver: 192.0.2.53" in output


def test_lookup_timeout_mentions_configured_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, make_report(LookupResult("A", LookupStatus.TIMEOUT)))

    result = runner.invoke(cli_app.app, ["lookup", "example.com", "-t", "A", "--timeout", "3"])

    assert "No nameserver replied within 3 seconds" in plain(result.output)


def test_multi_type_hides_routine_missing_records(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report(
        LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 60),)),
        LookupResult("CNAME", LookupStatus.NO_ANSWER),
    )
    patch_lookup(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com"]).output)

    assert "no records" in output
    assert "Next step:" not in output


def test_multi_type_groups_failures_in_one_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report(
        LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 60),)),
        LookupResult("AAAA", LookupStatus.TIMEOUT),
        LookupResult("MX", LookupStatus.TIMEOUT),
    )
    patch_lookup(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["lookup", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert output.count("Query timed out") == 1
    assert "(AAAA, MX)" in output


def test_multi_type_all_empty_is_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report(
        LookupResult("A", LookupStatus.NO_ANSWER), LookupResult("MX", LookupStatus.NO_ANSWER)
    )
    patch_lookup(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["lookup", "example.com"]).output)

    assert "Next step:" in output


def test_lookup_unknown_type_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    result = runner.invoke(cli_app.app, ["lookup", "example.com", "-t", "NOPE"])

    assert result.exit_code == 2
    assert "Unknown record type: NOPE" in plain(result.output)


# --- Reverse lookups --------------------------------------------------------------------


def patch_reverse(monkeypatch: pytest.MonkeyPatch, report: ReverseReport) -> None:
    monkeypatch.setattr(cli_app, "reverse_lookup", lambda ip, **kwargs: report)


def test_reverse_shows_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    ok = LookupResult("PTR", LookupStatus.OK, (Record("dns.google.", 3600),))
    patch_reverse(monkeypatch, make_reverse("8.8.8.8", ok))

    result = runner.invoke(cli_app.app, ["reverse", "8.8.8.8"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "dns.google." in output
    assert "8.8.8.8 (IPv4)" in output
    assert "Resolver: 192.0.2.53" in output


@pytest.mark.parametrize("ip", ["not-an-ip", "999.1.1.1", "2001:db8::zz"])
def test_reverse_invalid_ip_exits_2_without_querying(ip: str) -> None:
    result = runner.invoke(cli_app.app, ["reverse", ip])

    assert result.exit_code == 2
    assert "is not a valid IP address" in plain(result.output)


def test_reverse_missing_ptr_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_reverse(
        monkeypatch, make_reverse("192.168.1.10", LookupResult("PTR", LookupStatus.NXDOMAIN))
    )

    result = runner.invoke(cli_app.app, ["reverse", "192.168.1.10"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "No reverse DNS name" in output
    assert "private or reserved address" in output


def test_reverse_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_reverse(monkeypatch, make_reverse("8.8.8.8", LookupResult("PTR", LookupStatus.TIMEOUT)))

    result = runner.invoke(cli_app.app, ["reverse", "8.8.8.8"])

    assert result.exit_code == 1
    assert "Query timed out" in plain(result.output)


# --- Compare ------------------------------------------------------------------------------


def answer(
    label: str, ip: str, agreement: Agreement, *values: str, status: LookupStatus | None = None
) -> ResolverAnswer:
    if status is None:
        status = LookupStatus.OK if values else LookupStatus.TIMEOUT
    records = tuple(Record(v, 300) for v in values)
    return ResolverAnswer(label, ip, LookupResult("A", status, records, 15.0), agreement)


def make_compare(*answers: ResolverAnswer, has_majority: bool = True) -> CompareReport:
    distinct = len({a.result.records for a in answers if a.agreement is not Agreement.FAILED})
    return CompareReport("example.com", "A", answers, has_majority, distinct, 40.0)


def patch_compare(monkeypatch: pytest.MonkeyPatch, report: CompareReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_compare(name, rtype, **kwargs):
        calls.append((name, rtype, kwargs.get("timeout")))
        return report

    monkeypatch.setattr(cli_app, "compare", fake_compare)
    return calls


M, D, F = Agreement.MAJORITY, Agreement.DIFFERS, Agreement.FAILED


def test_compare_all_agree(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_compare(
        answer("Google", "8.8.8.8", M, "192.0.2.10", "192.0.2.9"),
        answer("Cloudflare", "1.1.1.1", M, "192.0.2.9", "192.0.2.10"),
    )
    calls = patch_compare(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["compare", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", "A", 2.0)]
    assert "example.com A across 2 resolvers" in output
    # Values are sorted, so both rows list .9 first (the second value is on its own line).
    assert "Google 8.8.8.8 192.0.2.9 300 15 ms 192.0.2.10" in output
    assert "Cloudflare 1.1.1.1 192.0.2.9 300 15 ms 192.0.2.10" in output
    assert "✓ All 2 resolvers agree." in output
    assert "majority" not in output  # nothing to single out when everyone agrees
    assert "Queried 2 resolvers in parallel" in output


def test_redirected_output_is_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    # Redirected output on Windows is cp1252, which can't encode ✓ or ≠: Rich used to crash
    # with UnicodeEncodeError and the exit code became 1.
    report = make_compare(
        answer("Google", "8.8.8.8", M, "192.0.2.10"),
        answer("Quad9", "9.9.9.9", D, "203.0.113.99"),
        has_majority=False,
    )
    patch_compare(monkeypatch, report)

    result = CliRunner(charset="cp1252").invoke(cli_app.app, ["compare", "example.com"])
    output = plain(result.stdout_bytes.decode("utf-8"))

    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.exit_code == 1  # resolvers disagree, not a crash
    assert "≠ Resolvers disagree" in output


def test_compare_highlights_resolver_that_differs(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_compare(
        answer("Google", "8.8.8.8", M, "192.0.2.10"),
        answer("Cloudflare", "1.1.1.1", M, "192.0.2.10"),
        answer("Quad9", "9.9.9.9", D, "203.0.113.99"),
    )
    patch_compare(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["compare", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "Quad9 9.9.9.9 203.0.113.99 300 15 ms ≠ differs" in output
    assert "Google 8.8.8.8 192.0.2.10 300 15 ms majority" in output
    assert "1 of 3 resolvers disagree with the majority answer (given by 2): Quad9." in output
    assert "CDN" in output


def test_compare_no_majority(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_compare(
        answer("Google", "8.8.8.8", D, "192.0.2.10"),
        answer("Quad9", "9.9.9.9", D, "203.0.113.99"),
        has_majority=False,
    )
    patch_compare(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["compare", "example.com"])

    output = plain(result.output)

    assert result.exit_code == 1
    assert "Google 8.8.8.8 192.0.2.10 300 15 ms varies" in output
    assert "Quad9 9.9.9.9 203.0.113.99 300 15 ms varies" in output
    assert "≠ differs" not in output  # nobody is the odd one out
    assert "no majority: 2 resolvers gave 2 different answers" in output


def test_compare_failures_are_marked_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_compare(
        answer("Google", "8.8.8.8", M, "192.0.2.10"),
        answer("System #1", "192.0.2.1", F),
        answer("System #2", "192.0.2.2", F, status=LookupStatus.SERVFAIL),
    )
    patch_compare(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["compare", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0  # everyone who answered agrees
    assert "System #1 192.0.2.1 timed out 15 ms ✗ failed" in output
    assert "System #2 192.0.2.2 server failure (SERVFAIL)" in output
    assert "✓ All 1 resolvers that answered agree." in output
    assert "2 failed: System #1 (timed out), System #2 (server failure (SERVFAIL))." in output


def test_compare_nothing_answered_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_compare(monkeypatch, make_compare(answer("Google", "8.8.8.8", F), has_majority=False))

    result = runner.invoke(cli_app.app, ["compare", "example.com"])

    assert result.exit_code == 1
    assert "No resolver answered." in plain(result.output)


def test_compare_shows_nxdomain_as_an_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_compare(
        answer("Google", "8.8.8.8", M, "192.0.2.10"),
        answer("Cloudflare", "1.1.1.1", M, "192.0.2.10"),
        answer("System #1", "192.0.2.1", D, status=LookupStatus.NXDOMAIN),
    )
    patch_compare(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["compare", "example.com"]).output)

    assert "System #1 192.0.2.1 domain does not exist" in output
    assert output.count("≠ differs") == 1


def test_compare_passes_type_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_compare(monkeypatch, make_compare(answer("Google", "8.8.8.8", M, "x")))

    runner.invoke(cli_app.app, ["compare", "example.com", "-t", "MX", "--timeout", "4"])

    assert calls == [("example.com", "MX", 4.0)]


def test_compare_unknown_type_exits_2() -> None:
    result = runner.invoke(cli_app.app, ["compare", "example.com", "--type", "NOPE"])

    assert result.exit_code == 2
    assert "Unknown record type: NOPE" in plain(result.output)


def test_compare_help_names_public_resolvers() -> None:
    output = plain(runner.invoke(cli_app.app, ["compare", "--help"]).output)

    for text in ("--type", "Google (8.8.8.8)", "Cloudflare (1.1.1.1)", "Quad9 (9.9.9.9)"):
        assert text in output


# --- local --------------------------------------------------------------------------------

WIFI = Adapter("w", "Wi-Fi", "", True, ("192.0.2.1", "192.0.2.2"))
CABLE = Adapter("e", "Ethernet", "", False, ("192.0.2.88",))


def make_local(*problems: Problem, **changes: object) -> LocalReport:
    report = LocalReport(
        platform="Windows",
        scan=AdapterScan((CABLE, WIFI), dns_per_adapter=True),
        nameservers=SystemNameservers(("192.0.2.88", "192.0.2.1"), ("192.0.2.1",), ("192.0.2.88",)),
        servers=(
            ServerCheck("192.0.2.1", (WIFI,), used=True, ghost=False, latency_ms=12.0),
            ServerCheck("192.0.2.2", (WIFI,), used=True, ghost=False, latency_ms=600.0),
            ServerCheck("192.0.2.88", (CABLE,), used=False, ghost=True, latency_ms=None),
        ),
        hosts=HostsFile(
            r"C:\hosts", (HostsEntry(3, "203.0.113.7", ("intranet.example",), HostsKind.REDIRECT),)
        ),
        flush=FlushCommand("ipconfig /flushdns", "Restart the browser too."),
        problems=problems,
        probe_timeout=1.0,
        elapsed_ms=1010.0,
    )
    return dataclasses.replace(report, **changes)


def patch_local(monkeypatch: pytest.MonkeyPatch, report: LocalReport) -> list[float]:
    calls: list[float] = []

    def fake_local_check(timeout: float) -> LocalReport:
        calls.append(timeout)
        return report

    monkeypatch.setattr(cli_app, "local_check", fake_local_check)
    return calls


def test_local_shows_adapters_servers_hosts_and_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_local(monkeypatch, make_local())

    result = runner.invoke(cli_app.app, ["local", "--timeout", "0.5"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [0.5]
    assert "Network adapters (Windows)" in output
    assert "Wi-Fi connected 192.0.2.1, 192.0.2.2" in output
    assert "Ethernet disconnected 192.0.2.88" in output
    assert "192.0.2.1 Wi-Fi 12 ms" in output
    assert "192.0.2.2 Wi-Fi 600 ms slow" in output
    assert "192.0.2.88 Ethernet (disconnected) no response ghost (ignored)" in output
    assert "3 203.0.113.7 intranet.example redirect" in output
    assert "Flush the DNS cache: ipconfig /flushdns" in output
    assert "✓ No problems found. 2 DNS servers in use, all responding." in output


def test_local_marks_vpns_public_resolvers_and_blocked_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vpn = Adapter("v", "OfficeVPN", "WireGuard Tunnel", True, ("8.8.8.8",))
    report = make_local(
        scan=AdapterScan((vpn, WIFI), dns_per_adapter=True),
        servers=(
            ServerCheck("8.8.8.8", (vpn,), True, False, 30.0, public="Google"),
            ServerCheck("192.0.2.1", (WIFI,), True, False, None, vpn_blocked=True),
        ),
    )
    patch_local(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["local"]).output)

    assert "OfficeVPN connected, VPN 8.8.8.8" in output
    assert "8.8.8.8 (Google) OfficeVPN 30 ms" in output
    assert "192.0.2.1 Wi-Fi no response blocked by VPN?" in output


def test_local_shows_bridge_members_under_their_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = Adapter("b", "Ethernet 2", "", True, ("192.0.2.1",))
    member = Adapter("m", "WiFi", "", True, (), bridged_into="Ethernet 2")
    scan = AdapterScan((member, CABLE, bridge), dns_per_adapter=True)
    patch_local(monkeypatch, make_local(scan=scan))

    output = plain(runner.invoke(cli_app.app, ["local"]).output)

    rows = [
        "Ethernet 2 connected 192.0.2.1",
        "WiFi connected, bridged into Ethernet 2 uses Ethernet 2's",
        "Ethernet disconnected 192.0.2.88",
    ]
    positions = [output.find(row) for row in rows]
    assert -1 not in positions
    assert positions == sorted(positions)  # the member right under its bridge


def test_local_lists_problems_with_fixes(monkeypatch: pytest.MonkeyPatch) -> None:
    ghost = Problem(
        Severity.WARNING,
        "Ghost DNS server 192.0.2.88",
        "It's stale.",
        "Remove it.",
        ProblemKind.GHOST,
    )
    patch_local(monkeypatch, make_local(ghost))

    result = runner.invoke(cli_app.app, ["local"])
    output = plain(result.output)

    assert result.exit_code == 0  # warnings only
    assert "! Ghost DNS server 192.0.2.88" in output
    assert "It's stale. Fix: Remove it." in output
    assert "DNS is working (2 of 2 servers in use responding), with 1 warning" in output


def test_local_exits_1_on_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    error = Problem(
        Severity.ERROR,
        "No DNS server is responding",
        "None answered.",
        "Reboot.",
        ProblemKind.NO_RESPONSE,
    )
    patch_local(monkeypatch, make_local(error))

    result = runner.invoke(cli_app.app, ["local"])

    assert result.exit_code == 1
    assert "✗ DNS isn't working properly: 1 error" in plain(result.output)


def test_local_without_per_adapter_dns_or_flush_command(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_local(
        scan=AdapterScan((WIFI,), dns_per_adapter=False),
        hosts=HostsFile("/etc/hosts", ()),
        flush=FlushCommand(None, "No DNS cache service was found."),
    )
    patch_local(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["local"]).output)

    assert "doesn't report DNS servers per adapter" in output
    assert "Hosts file: no entries override DNS (/etc/hosts)" in output
    assert "Flush the DNS cache: No DNS cache service was found." in output


class ClosedPipe(io.StringIO):
    """Stdout whose reader has gone, as Windows reports it: EINVAL, not BrokenPipeError."""

    def __init__(self, err: int = errno.EINVAL) -> None:
        super().__init__()
        self.err = err

    def write(self, text: str) -> int:
        raise OSError(self.err, os.strerror(self.err))


def test_closed_pipe_on_windows_is_a_broken_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_app, "_WINDOWS", True)
    console = cli_app.PipeSafeConsole(file=ClosedPipe())
    broken: list[bool] = []

    def on_broken_pipe() -> None:
        broken.append(True)
        raise SystemExit(1)

    monkeypatch.setattr(console, "on_broken_pipe", on_broken_pipe)

    with pytest.raises(SystemExit) as exc_info:
        console.print("example.com")

    assert broken == [True]
    assert exc_info.value.code == 1


@pytest.mark.parametrize(("windows", "err"), [(False, errno.EINVAL), (True, errno.ENOSPC)])
def test_other_write_errors_still_raise(
    monkeypatch: pytest.MonkeyPatch, windows: bool, err: int
) -> None:
    monkeypatch.setattr(cli_app, "_WINDOWS", windows)
    console = cli_app.PipeSafeConsole(file=ClosedPipe(err))

    with pytest.raises(OSError) as exc_info:  # noqa: PT011 (errno checked below)
        console.print("example.com")

    assert exc_info.value.errno == err


def test_reader_closing_the_pipe_exits_quietly() -> None:
    # `dnskit ... | head -3`: the reader stops early. Windows reports EINVAL, Linux and macOS
    # BrokenPipeError; either way there must be no traceback and no "Exception ignored".
    src = str(Path(dnskit.__file__).parents[1])
    env = {**os.environ, "PYTHONPATH": src}
    code = "from dnskit.cli.app import app; app()"
    proc = subprocess.Popen(
        [sys.executable, "-c", code, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    proc.stdout.close()  # long before the child has imported anything and printed
    stderr = proc.stderr.read().decode("utf-8", "replace")
    proc.stderr.close()

    assert proc.wait(timeout=30) == 1
    assert stderr == ""


# --- email --------------------------------------------------------------------------------

OK = LookupStatus.OK
SPF_RECORD = "v=spf1 include:_spf.mail.test ~all"


def passed(title: str, explanation: str = "Fine.") -> Finding:
    return Finding(CheckStatus.PASS, title, explanation)


def make_email(**changes: object) -> EmailReport:
    report = EmailReport(
        domain="example.com",
        domain_status=OK,
        nameserver="192.0.2.53",
        nameserver_source="auto: test",
        elapsed_ms=321.0,
        mx=MxCheck(
            OK,
            (
                MxHost(10, "mx1.example.com", ("192.0.2.10", "2001:db8::10"), OK),
                MxHost(20, "mx2.example.com", (), LookupStatus.NXDOMAIN),
            ),
            (passed("2 mail servers, all with IP addresses"),),
        ),
        spf=SpfCheck(
            OK,
            (SPF_RECORD,),
            (
                SpfLookup("include:_spf.mail.test", "example.com", 0),
                SpfLookup("include:more.mail.test", "_spf.mail.test", 1),
            ),
            True,
            (passed("SPF record is valid", "2 of 10 DNS lookups."),),
        ),
        dmarc=DmarcCheck(
            "_dmarc.example.com",
            OK,
            ("v=DMARC1; p=reject",),
            (("v", "DMARC1"), ("p", "reject")),
            (passed("DMARC policy: reject"),),
        ),
        dkim=DkimCheck(
            (
                DkimSelector("google", "google._domainkey.example.com", OK, "p=x", key_bits=2048),
                DkimSelector(
                    "selector1", "selector1._domainkey.example.com", OK, "p=", revoked=True
                ),
                DkimSelector("k1", "k1._domainkey.example.com", LookupStatus.NO_ANSWER, None),
                DkimSelector(
                    "s9", "s9._domainkey.example.com", LookupStatus.TIMEOUT, None, custom=True
                ),
            ),
            (passed("DKIM key found"),),
        ),
    )
    return dataclasses.replace(report, **changes)


def patch_email(monkeypatch: pytest.MonkeyPatch, report: EmailReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_email_check(domain, selectors, **kwargs):
        calls.append((domain, list(selectors), kwargs))
        return report

    monkeypatch.setattr(cli_app, "email_check", fake_email_check)
    return calls


def test_email_shows_every_check_and_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_email(monkeypatch, make_email())

    result = runner.invoke(cli_app.app, ["email", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "Email DNS check for example.com" in output
    assert "10 mx1.example.com 192.0.2.10 2001:db8::10" in output
    assert "20 mx2.example.com domain does not exist (NXDOMAIN)" in output
    assert f"Record: {SPF_RECORD}" in output
    assert "DNS lookups: 2 of 10 include:_spf.mail.test include:more.mail.test (in _spf" in output
    assert "Record at _dmarc.example.com: v=DMARC1; p=reject" in output
    assert "google RSA 2048-bit" in output
    assert "selector1 revoked (empty p=)" in output
    assert "k1 not found" in output
    assert "s9 (--selector) timed out" in output
    assert "✓ SPF record is valid — 2 of 10 DNS lookups." in output
    assert "MX ✓ pass 2 mail servers, all with IP addresses" in output
    assert "DKIM ✓ pass DKIM key found" in output
    assert "✓ All 4 checks passed." in output
    assert "Resolver: 192.0.2.53 (auto: test)" in output


def test_email_warnings_exit_0_with_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    warning = Finding(
        CheckStatus.WARN, "DMARC policy is monitoring only (p=none)", "Weak.", "Tighten."
    )
    dmarc = DmarcCheck("_dmarc.example.com", OK, ("v=DMARC1; p=none",), (), (warning,))
    patch_email(monkeypatch, make_email(dmarc=dmarc))

    result = runner.invoke(cli_app.app, ["email", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "! DMARC policy is monitoring only (p=none)" in output
    assert "Weak. Fix: Tighten." in output
    assert "DMARC ! warn DMARC policy is monitoring only (p=none)" in output
    assert "No check failed, but 1 of 4 has warnings. 3 passed." in output


def test_email_failed_check_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = Finding(CheckStatus.FAIL, "No DMARC record", "Missing.", "Publish one.")
    dmarc = DmarcCheck("_dmarc.example.com", LookupStatus.NXDOMAIN, (), (), (failure,))
    patch_email(monkeypatch, make_email(dmarc=dmarc))

    result = runner.invoke(cli_app.app, ["email", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "✗ No DMARC record" in output
    assert "Missing. Fix: Publish one." in output
    assert "DMARC ✗ fail No DMARC record" in output
    assert "✗ 1 of 4 checks failed. Fix the problems marked ✗ above." in output


def test_email_domain_that_does_not_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_email(
        domain_status=LookupStatus.NXDOMAIN, mx=None, spf=None, dmarc=None, dkim=None
    )
    patch_email(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["email", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "Domain doesn't exist" in output
    assert "Summary" not in output


def test_email_passes_options(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_email(monkeypatch, make_email())

    args = ["email", "example.com", "--selector", "s1", "--selector", "s2", "-s", "192.0.2.9"]
    runner.invoke(cli_app.app, [*args, "--timeout", "2", "--refresh"])

    assert calls == [
        (
            "example.com",
            ["s1", "s2"],
            {"nameserver": "192.0.2.9", "timeout": 2.0, "refresh": True},
        )
    ]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["email", "user@example.com"], "looks like an email address"),
        (["email", "not a domain"], "not a valid domain name"),
        (["email", "example.com", "--selector", "a b"], "not a valid DKIM selector"),
    ],
)
def test_email_invalid_input_exits_2(args: list[str], message: str) -> None:
    result = runner.invoke(cli_app.app, args)

    assert result.exit_code == 2
    assert message in plain(result.output)


def test_email_help_lists_selectors() -> None:
    result = runner.invoke(cli_app.app, ["email", "--help"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "google, selector1, selector2, default, k1" in output
    assert "--selector" in output


def test_local_shows_network_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_local(
        hijack=(
            classify_nxdomain("192.0.2.1", "nx.com", RawAnswer("NXDOMAIN")),
            classify_nxdomain("192.0.2.2", "nx.com", RawAnswer("NOERROR", ("198.51.100.80",))),
        ),
        interception=(
            classify_google(RawAnswer("NOERROR", ("172.253.1.2",))),
            classify_cloudflare(RawAnswer(None, error="no response")),
        ),
        ipv6=IPv6Check(IPv6State.NOT_AVAILABLE, None, "www.google.com", None, "not available"),
    )
    patch_local(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["local"]).output)

    assert "Network checks" in output
    assert 'NXDOMAIN hijacking: 192.0.2.1 ✓ answers "doesn\'t exist" honestly' in output
    assert "NXDOMAIN hijacking: 192.0.2.2 ! hijacked: a made-up name got 198.51.100.80" in output
    assert "Interception: 8.8.8.8 (Google) ✓ answered by Google (172.253.1.2)" in output
    assert "Interception: 1.1.1.1 (Cloudflare) ? couldn't tell (no response)" in output
    assert "IPv6 – not available" in output


# --- reach --------------------------------------------------------------------------------


def make_reach(
    a: tuple[str, ...] = ("192.0.2.10",),
    aaaa: tuple[str, ...] = (),
    attempts: tuple[ConnectAttempt, ...] | None = None,
    status: LookupStatus = LookupStatus.OK,
) -> ReachReport:
    def result(rtype: str, values: tuple[str, ...]) -> LookupResult:
        if not values:
            return LookupResult(
                rtype, status if status is not LookupStatus.OK else LookupStatus.NO_ANSWER
            )
        return LookupResult(rtype, LookupStatus.OK, tuple(Record(v, 300) for v in values))

    if attempts is None:
        attempts = tuple(ConnectAttempt(ip, 443, 20.0) for ip in (*a, *aaaa))
    return ReachReport(
        "example.com",
        443,
        "192.0.2.53",
        "auto: test",
        result("A", a),
        result("AAAA", aaaa),
        attempts,
        (),
        40.0,
    )


def patch_reach(monkeypatch: pytest.MonkeyPatch, report: ReachReport | Exception) -> list[tuple]:
    calls: list[tuple] = []

    def fake_reach(target: str, **kwargs: object) -> ReachReport:
        calls.append((target, kwargs))
        if isinstance(report, Exception):
            raise report
        return report

    monkeypatch.setattr(cli_app, "reach", fake_reach)
    return calls


def test_reach_reachable_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_reach(monkeypatch, make_reach(aaaa=("2001:db8::10",)))

    result = runner.invoke(cli_app.app, ["reach", "example.com", "-p", "443", "--timeout", "2"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [
        ("example.com", {"port": 443, "nameserver": None, "timeout": 2.0, "refresh": False})
    ]
    assert "example.com on port 443" in output
    assert "192.0.2.10 IPv4 ✓ 20 ms" in output
    assert "2001:db8::10 IPv6 ✓ 20 ms" in output
    assert "✓ Neither: DNS and the connection both work" in output
    assert "Resolver: 192.0.2.53 (auto: test)" in output


def test_reach_dns_problem_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_reach(monkeypatch, make_reach(a=(), status=LookupStatus.NXDOMAIN, attempts=()))

    result = runner.invoke(cli_app.app, ["reach", "nope.example"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "No addresses for example.com" in output
    assert "✗ The problem is DNS: domain doesn't exist" in output


def test_reach_connection_problem_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = (
        ConnectAttempt("192.0.2.10", 443, None, ConnectError.TIMEOUT, "no reply"),
        ConnectAttempt("2001:db8::10", 443, None, ConnectError.UNREACHABLE, "no route"),
    )
    patch_reach(monkeypatch, make_reach(aaaa=("2001:db8::10",), attempts=attempts))

    result = runner.invoke(cli_app.app, ["reach", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 3
    assert "192.0.2.10 IPv4 ✗ timed out" in output
    assert "2001:db8::10 IPv6 – no IPv6 route" in output
    assert "✗ The problem is the connection: port 443 isn't reachable" in output


def test_reach_shows_how_many_addresses_were_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    many = tuple(f"192.0.2.{i}" for i in range(1, 7))
    attempts = tuple(ConnectAttempt(ip, 443, 20.0) for ip in many[:4])
    patch_reach(monkeypatch, make_reach(a=many, attempts=attempts))

    output = plain(runner.invoke(cli_app.app, ["reach", "example.com"]).output)

    assert "… and 2 more addresses, not tried" in output
    assert "192.0.2.6" not in output


def test_reach_invalid_input_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_reach(monkeypatch, ValueError("'x' is not a valid domain name."))

    result = runner.invoke(cli_app.app, ["reach", "x"])

    assert result.exit_code == 2
    assert "Error: 'x' is not a valid domain name." in plain(result.output)


def test_reach_rejects_out_of_range_port() -> None:
    assert runner.invoke(cli_app.app, ["reach", "example.com", "--port", "0"]).exit_code == 2


# --- trace --------------------------------------------------------------------------------

ROOT = Server("a.root-servers.net.", "198.41.0.4")
GTLD = Server("a.gtld-servers.net.", "192.5.6.30")
NS1 = Server("ns1.example.com.", "192.0.2.20")


def make_trace(*steps: TraceStep, **changes: object) -> TraceReport:
    if not steps:
        slow = Server("b.gtld-servers.net.", "192.33.14.30")
        steps = (
            TraceStep(".", StepStatus.REFERRAL, ROOT, 21.0, "com.", ("a.gtld-servers.net.",)),
            TraceStep(
                "com.",
                StepStatus.REFERRAL,
                GTLD,
                34.0,
                "example.com.",
                ("ns1.example.com.", "ns2.example.com."),
                failures=(ServerFailure(slow, FailReason.NO_RESPONSE, "timed out"),),
            ),
            TraceStep("example.com.", StepStatus.ANSWER, NS1, 80.0, records=("192.0.2.80",)),
        )
    report = TraceReport("example.com.", "A", TraceMode.DIRECT, steps, 140.0, 2.0)
    return dataclasses.replace(report, **changes)


def patch_trace(monkeypatch: pytest.MonkeyPatch, report: TraceReport | Exception) -> list[tuple]:
    calls: list[tuple] = []

    def fake_trace(name: str, rtype: str, **kwargs: object) -> TraceReport:
        calls.append((name, rtype, kwargs))
        if isinstance(report, Exception):
            raise report
        return report

    monkeypatch.setattr(cli_app, "trace", fake_trace)
    return calls


def test_trace_shows_each_level_as_a_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_trace(monkeypatch, make_trace())

    result = runner.invoke(cli_app.app, ["trace", "example.com", "-t", "A", "--timeout", "3"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", "A", {"timeout": 3.0})]
    assert "example.com. A (from the root servers down)" in output
    assert ". (root) asked a.root-servers.net. (198.41.0.4) · 21 ms" in output
    assert "→ referral to com. a.gtld-servers.net." in output
    assert "→ referral to example.com. ns1.example.com., ns2.example.com." in output
    assert "b.gtld-servers.net. timed out; another server answered" in output
    assert "✓ answer: 192.0.2.80" in output
    assert "3 steps · 140 ms total" in output
    assert output.index("com. asked") < output.index("example.com. asked")


def test_trace_failure_says_which_level_and_why(monkeypatch: pytest.MonkeyPatch) -> None:
    failures = tuple(
        ServerFailure(Server(f"ns{i}.example.com.", f"192.0.2.2{i}"), FailReason.REFUSED, "REFUSED")
        for i in (1, 2)
    )
    report = make_trace(
        TraceStep(".", StepStatus.REFERRAL, ROOT, 21.0, "com.", ("a.gtld-servers.net.",)),
        TraceStep("com.", StepStatus.REFERRAL, GTLD, 34.0, "example.com.", ("ns1.example.com.",)),
        TraceStep("example.com.", StepStatus.FAILED, failures=failures, reason=FailReason.REFUSED),
    )
    patch_trace(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["trace", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "✗ failed at this level: refused" in output
    assert "✗ ns1.example.com. (192.0.2.21): REFUSED" in output
    assert "example.com's nameservers aren't serving it (lame delegation)" in output


def test_trace_through_the_resolver_explains_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = Server("192.0.2.53", "192.0.2.53")
    report = make_trace(
        TraceStep(".", StepStatus.REFERRAL, resolver, 20.0, "com.", ("a.gtld-servers.net.",)),
        TraceStep("com.", StepStatus.ANSWER, resolver, 22.0, records=("192.0.2.80",)),
        mode=TraceMode.VIA_RESOLVER,
        resolver="192.0.2.53",
        blocking=DnsBlocking(("192.0.2.53",), ("OfficeVPN",), local_firewall=True),
    )
    patch_trace(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["trace", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "(through 192.0.2.53: direct queries are blocked)" in output
    assert ". (root) asked 192.0.2.53 · 20 ms" in output
    assert "Direct DNS queries are blocked by the VPN" in output
    assert "kill switch" in output


def test_trace_invalid_input_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_trace(monkeypatch, ValueError("Unknown record type: NOPE."))

    result = runner.invoke(cli_app.app, ["trace", "example.com", "-t", "NOPE"])

    assert result.exit_code == 2
    assert "Error: Unknown record type: NOPE." in plain(result.output)


# --- dnssec -------------------------------------------------------------------------------

KSK = KeyInfo(2371, "ECDSAP256SHA256", True)
ZSK = KeyInfo(34505, "ECDSAP256SHA256", False)
CLOCK_OK = ClockCheck(
    ClockState.OK,
    datetime(2026, 10, 31, tzinfo=UTC),
    datetime(2026, 10, 30, tzinfo=UTC),
    "looks right (root zone from 2026-10-30)",
)


def make_dnssec(**changes: object) -> DnssecReport:
    root_key = KeyInfo(20326, "RSASHA256", True)
    com_key = KeyInfo(19718, "ECDSAP256SHA256", True)
    report = DnssecReport(
        name="example.com",
        zones=(
            ZoneCheck(
                ".",
                ZoneStatus.SECURE,
                (DsInfo(20326, "RSASHA256", 2),),
                (root_key,),
                "keys signed by trust anchor 20326",
            ),
            ZoneCheck(
                "com.",
                ZoneStatus.SECURE,
                (DsInfo(19718, "ECDSAP256SHA256", 2),),
                (com_key,),
                "DS at . matches key 19718",
            ),
            ZoneCheck(
                "example.com.",
                ZoneStatus.SECURE,
                (DsInfo(2371, "ECDSAP256SHA256", 2),),
                (KSK, ZSK),
                "DS at com. matches key 2371; keys signed",
            ),
        ),
        records=(RecordCheck("example.com.", "A", ZoneStatus.SECURE, "signed by key 34505"),),
        clock=CLOCK_OK,
        nameserver="192.0.2.53",
        nameserver_source="auto: test",
        elapsed_ms=120.0,
    )
    return dataclasses.replace(report, **changes)


def patch_dnssec(monkeypatch: pytest.MonkeyPatch, report: DnssecReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_dnssec(name: str, **kwargs: object) -> DnssecReport:
        calls.append((name, kwargs))
        return report

    monkeypatch.setattr(cli_app, "dnssec_check", fake_dnssec)
    return calls


def test_dnssec_secure_shows_the_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_dnssec(monkeypatch, make_dnssec())

    result = runner.invoke(cli_app.app, ["dnssec", "example.com", "-s", "1.1.1.1"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", {"nameserver": "1.1.1.1", "timeout": 5.0, "refresh": False})]
    assert "DNSSEC chain of trust for example.com" in output
    assert ". (root) trust anchors" in output and "20326" in output
    assert "example.com. 2371 1 KSK + 1 ZSK" in output
    assert "✓ DS at com." in output and "matches key 2371" in output
    assert "example.com. A ✓ signed by key" in output
    assert "Clock: ✓ looks right (root zone from 2026-10-30)" in output
    assert "✓ DNSSEC is on and validates for example.com" in output
    assert "forged" in output


def test_dnssec_not_enabled_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    base = make_dnssec()
    unsigned = ZoneCheck(
        "example.com.", ZoneStatus.UNSIGNED, summary="no DS record at com.: not signed"
    )
    patch_dnssec(monkeypatch, dataclasses.replace(base, zones=(*base.zones[:2], unsigned)))

    result = runner.invoke(cli_app.app, ["dnssec", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "– no DS record at com.: not signed" in output
    assert "DNSSEC isn't enabled for example.com" in output


def test_dnssec_broken_exits_1_and_warns_about_the_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    expired = RecordCheck(
        "example.com.",
        "A",
        ZoneStatus.BOGUS,
        "signature expired on 2026-10-01",
        BogusKind.EXPIRED,
    )
    clock = ClockCheck(
        ClockState.WRONG,
        datetime(2027, 6, 1, tzinfo=UTC),
        datetime(2026, 10, 30, tzinfo=UTC),
        "wrong: 2027-06-01, about 214 days ahead of the root zone (2026-10-30)",
    )
    patch_dnssec(monkeypatch, make_dnssec(records=(expired,), clock=clock))

    result = runner.invoke(cli_app.app, ["dnssec", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "✗ signature expired on 2026-10-01" in output
    assert "! This computer's clock looks wrong" in output
    assert "Validation failed: this computer's clock is wrong" in output


def test_dnssec_missing_name_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    base = make_dnssec()
    patch_dnssec(monkeypatch, dataclasses.replace(base, zones=base.zones[:2], name_missing=True))

    result = runner.invoke(cli_app.app, ["dnssec", "example.com"])

    assert result.exit_code == 1
    assert "example.com doesn't exist" in plain(result.output)


# --- propagation --------------------------------------------------------------------------


def make_propagation(
    *results: LookupResult, blocking: DnsBlocking | None = None
) -> PropagationReport:
    resolvers = PROPAGATION_RESOLVERS[: len(results)]
    ranking = rank_answers(results)
    answers = tuple(
        PropagationAnswer(r, result, agreement)
        for r, result, agreement in zip(resolvers, results, ranking.agreements, strict=True)
    )
    return PropagationReport(
        "example.com",
        "A",
        answers,
        ranking.has_majority,
        ranking.distinct_answers,
        900.0,
        blocking,
    )


def patch_propagation(monkeypatch: pytest.MonkeyPatch, report: PropagationReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_propagation(name: str, rtype: str, **kwargs: object) -> PropagationReport:
        calls.append((name, rtype, kwargs))
        return report

    monkeypatch.setattr(cli_app, "propagation", fake_propagation)
    return calls


NEW_A = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 300),))
OLD_A = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 1200),))
TIMED_OUT = LookupResult("A", LookupStatus.TIMEOUT)


def test_propagation_complete_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_propagation(monkeypatch, make_propagation(NEW_A, NEW_A, NEW_A))

    result = runner.invoke(cli_app.app, ["propagation", "example.com", "-t", "A"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", "A", {"timeout": 1.5, "resolvers": None})]
    assert "example.com A across 3 public resolvers" in output
    assert "Global (anycast) Google 8.8.8.8 nearest site 192.0.2.2 300" in output
    assert "anycast) resolvers answer from their site nearest to you" in output
    assert "100% of the resolvers that answered (3 of 3) give the most common answer" in output
    assert "✓ Fully propagated: all 3 resolvers agree" in output


def test_propagation_in_progress_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_propagation(NEW_A, NEW_A, NEW_A, OLD_A, TIMED_OUT)
    patch_propagation(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["propagation", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "192.0.2.1 1200 ≠ differs" in output
    assert "timed out ✗ failed" in output
    assert "75% of the resolvers that answered (3 of 4)" in output
    assert "1 didn't respond" in output
    assert "Still propagating: 75% give the most common answer" in output
    assert "within about 20 minutes" in output


def test_propagation_blocked_by_vpn(monkeypatch: pytest.MonkeyPatch) -> None:
    blocking = DnsBlocking(("8.8.8.8",), ("OfficeVPN",), local_firewall=False)
    report = make_propagation(NEW_A, TIMED_OUT, TIMED_OUT, blocking=blocking)
    patch_propagation(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["propagation", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "% of the resolvers" not in output
    assert "✗ Direct DNS queries are blocked by the VPN" in output
    assert "Only 1 of 3 resolvers could be reached" in output


@pytest.mark.parametrize("command", ["propagation", "dnssec", "trace"])
def test_new_commands_have_help(command: str) -> None:
    result = runner.invoke(cli_app.app, [command, "--help"])

    assert result.exit_code == 0


def test_propagation_differences_abroad_are_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    results = [OLD_A if r.name == "Yandex" else NEW_A for r in PROPAGATION_RESOLVERS]
    patch_propagation(monkeypatch, make_propagation(*results))

    result = runner.invoke(cli_app.app, ["propagation", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "… Probably location-based DNS, not propagation" in output
    assert "Yandex in Russia" in output


# --- doctor -------------------------------------------------------------------------------


def make_doctor(*issues: Issue, quick: bool = False) -> DoctorReport:
    runs = tuple(
        CheckRun(c, CheckState.SKIPPED, reason="--quick")
        if quick and c in SLOW_CHECKS
        else CheckRun(c, CheckState.DONE, 120.0)
        for c in Check
    )
    return DoctorReport("example.com", quick, runs, issues, 1300.0)


def patch_doctor(monkeypatch: pytest.MonkeyPatch, report: DoctorReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_doctor(name: str, **kwargs: object) -> DoctorReport:
        calls.append((name, kwargs))
        return report

    monkeypatch.setattr(cli_app, "doctor", fake_doctor)
    return calls


def doctor_issue(area: Area, impact: Impact, title: str, check: Check) -> Issue:
    return Issue(area, impact, title, f"About {title}.", f"Fix {title}.", check)


def test_doctor_healthy_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_doctor(monkeypatch, make_doctor())

    result = runner.invoke(cli_app.app, ["doctor", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", {"quick": False, "timeout": 3.0, "resolvers": None})]
    assert "Health check for example.com" in output
    assert "DNSSEC chain of trust ✓ OK 120 ms" in output
    assert "Health score: 100/100" in output
    assert "Healthy: no problems found" in output
    assert "Ran 6 checks in parallel · 1300 ms total" in output


def test_doctor_lists_issues_by_area_most_important_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_doctor(
        doctor_issue(Area.DOMAIN, Impact.CRITICAL, "DNSSEC is broken", Check.DNSSEC),
        doctor_issue(Area.MACHINE, Impact.MAJOR, "IPv6 is broken", Check.LOCAL),
        doctor_issue(Area.DOMAIN, Impact.MINOR, "No DMARC rua", Check.EMAIL),
        doctor_issue(Area.MACHINE, Impact.NOTE, "Ghost DNS server 192.0.2.88", Check.LOCAL),
    )
    patch_doctor(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["doctor", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "Health score: 40/100" in output
    assert "Something is broken" in output
    assert "DNSSEC chain of trust ✗ 1 issue" in output
    assert "! 1 issue (1 note)" in output
    # The domain has the most important issue, so its section comes first.
    domain = output.index("1. CRITICAL DNSSEC is broken")
    assert output.index("example.com 1.") < domain
    assert domain < output.index("2. MINOR No DMARC rua")
    assert output.index("This computer 3. MAJOR IPv6 is broken") > domain
    assert "Fix: Fix IPv6 is broken." in output
    assert "Notes, nothing to fix: · Ghost DNS server 192.0.2.88 — dnskit local" in output


def test_doctor_minor_issues_only_exit_0(monkeypatch: pytest.MonkeyPatch) -> None:
    issue = doctor_issue(Area.DOMAIN, Impact.MINOR, "DNSSEC is off", Check.DNSSEC)
    patch_doctor(monkeypatch, make_doctor(issue))

    result = runner.invoke(cli_app.app, ["doctor", "example.com"])

    assert result.exit_code == 0
    assert "Health score: 95/100" in plain(result.output)


def test_doctor_quick(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_doctor(monkeypatch, make_doctor(quick=True))

    result = runner.invoke(cli_app.app, ["doctor", "example.com", "--quick", "--timeout", "2"])
    output = plain(result.output)

    assert calls == [("example.com", {"quick": True, "timeout": 2.0, "resolvers": None})]
    assert "Email: MX, SPF, DMARC, DKIM skipped (--quick)" in output
    assert "Ran 3 checks in parallel" in output
    assert "the resolver comparison, email and DNSSEC weren't checked" in output


def test_doctor_bad_name_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_doctor(name: str, **kwargs: object) -> DoctorReport:
        raise ValueError("Not a valid domain name: 'not a domain'.")

    monkeypatch.setattr(cli_app, "doctor", fake_doctor)

    result = runner.invoke(cli_app.app, ["doctor", "not a domain"])

    assert result.exit_code == 2
    assert "Not a valid domain name" in plain(result.output)


def test_doctor_progress_view() -> None:
    progress = DoctorProgress()
    progress.update(Check.LOCAL, CheckState.DONE)
    progress.update(Check.LOOKUP, CheckState.RUNNING)
    progress.update(Check.EMAIL, CheckState.SKIPPED)
    progress.update(Check.REACH, CheckState.ERROR)
    console = Console(width=120, record=True)

    console.print(progress)
    text = console.export_text()

    assert "✓ This computer:" in text
    assert "Records (A, AAAA, MX, CNAME, NS, TXT)" in text and " s" in text
    assert "Email: MX, SPF, DMARC, DKIM (skipped)" in text
    assert "✗ Connection to the domain" in text
    assert "· DNSSEC chain of trust" in text


def test_doctor_shows_a_failed_check_even_when_another_issue_explains_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servfail = LookupResult("A", LookupStatus.SERVFAIL)
    issue = doctor_issue(Area.DOMAIN, Impact.CRITICAL, "DNSSEC is broken", Check.DNSSEC)
    report = dataclasses.replace(
        make_doctor(issue),
        lookup=LookupReport("example.com", "192.0.2.53", "auto", (servfail,), 9.0),
    )
    patch_doctor(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["doctor", "example.com"]).output)

    assert "Records (A, AAAA, MX, CNAME, NS, TXT) ✗ failed (explained below)" in output


def test_doctor_missing_domain_shows_skipped_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    runs = tuple(
        CheckRun(c, CheckState.SKIPPED, reason="domain doesn't exist")
        if c in (Check.COMPARE, Check.REACH, Check.EMAIL, Check.DNSSEC)
        else CheckRun(c, CheckState.DONE, 120.0)
        for c in Check
    )
    issue = doctor_issue(
        Area.DOMAIN, Impact.CRITICAL, "example.com: domain doesn't exist", Check.LOOKUP
    )
    report = DoctorReport("example.com", False, runs, (issue,), 300.0, name_missing=True)
    patch_doctor(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["doctor", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 1
    assert "Connection to the domain (port 443) skipped (domain doesn't exist)" in output
    assert "Health score: 0/100" in output
    assert "example.com doesn't exist" in output
    assert "Ran 2 checks in parallel" in output


def test_doctor_shows_dnssec_checked_via_a_public_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dnssec = SimpleNamespace(
        nameserver="8.8.8.8",
        signatures_stripped=False,
        stripped_by="192.0.2.53",
        status=DnssecStatus.SECURE,
    )
    report = dataclasses.replace(make_doctor(), dnssec=dnssec)
    patch_doctor(monkeypatch, report)

    output = plain(runner.invoke(cli_app.app, ["doctor", "example.com"]).output)

    assert "DNSSEC chain of trust ✓ OK (via 8.8.8.8)" in output


def test_dnssec_says_when_a_fallback_resolver_was_used(monkeypatch: pytest.MonkeyPatch) -> None:
    report = dataclasses.replace(
        make_dnssec(),
        nameserver="8.8.8.8",
        nameserver_source="this computer's DNS server 192.0.2.53 strips DNSSEC signatures",
        stripped_by="192.0.2.53",
    )
    patch_dnssec(monkeypatch, report)

    result = runner.invoke(cli_app.app, ["dnssec", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert (
        "This computer's DNS server (192.0.2.53) strips DNSSEC signatures, so this was "
        "checked through 8.8.8.8." in output
    )
    assert "Resolver: 8.8.8.8 (this computer's DNS server 192.0.2.53 strips" in output


# --- --json ---------------------------------------------------------------------------------

A_OK = LookupResult("A", LookupStatus.OK, (Record("192.0.2.10", 300),))
PTR_OK = LookupResult("PTR", LookupStatus.OK, (Record("dns.example.", 300),))


def json_out(result) -> dict:
    """The JSON object a command printed (stdout only: errors go to stderr otherwise)."""
    return json.loads(result.stdout)


def setup_for(command: str, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Patch `command`'s core function with a canned report; return the CLI arguments."""
    match command:
        case "lookup":
            patch_lookup(monkeypatch, make_report(A_OK))
            return ["lookup", "example.com", "-t", "A"]
        case "reverse":
            patch_reverse(monkeypatch, make_reverse("192.0.2.53", PTR_OK))
            return ["reverse", "192.0.2.53"]
        case "compare":
            patch_compare(
                monkeypatch,
                make_compare(ResolverAnswer("Google", "8.8.8.8", A_OK, Agreement.MAJORITY)),
            )
            return ["compare", "example.com"]
        case "email":
            patch_email(monkeypatch, make_email())
            return ["email", "example.com"]
        case "resolvers":
            patch_resolvers(monkeypatch, make_choice({"192.0.2.1": 9.0}))
            return ["resolvers"]
        case "local":
            patch_local(monkeypatch, make_local())
            return ["local"]
        case "reach":
            patch_reach(monkeypatch, make_reach())
            return ["reach", "example.com"]
        case "trace":
            patch_trace(monkeypatch, make_trace())
            return ["trace", "example.com"]
        case "dnssec":
            patch_dnssec(monkeypatch, make_dnssec())
            return ["dnssec", "example.com"]
        case "propagation":
            patch_propagation(monkeypatch, make_propagation(NEW_A, NEW_A))
            return ["propagation", "example.com"]
        case "doctor":
            patch_doctor(monkeypatch, make_doctor())
            return ["doctor", "example.com"]
    raise AssertionError(command)


JSON_SUMMARY_KEYS = {
    "lookup": {"exists"},
    "reverse": {"hostnames"},
    "compare": {"all_agree", "has_majority", "distinct_answers"},
    "email": {"status", "failed"},
    "resolvers": {"chosen"},
    "local": {"has_errors", "problems"},
    "reach": {"verdict"},
    "trace": {"succeeded", "mode"},
    "dnssec": {"status", "name_missing", "checked_through", "stripped_by"},
    "propagation": {"percent", "complete", "location_based", "blocked"},
    "doctor": {"score", "healthy", "name_missing", "issues", "notes"},
}


@pytest.mark.parametrize("command", sorted(JSON_SUMMARY_KEYS))
def test_every_command_prints_json(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    args = setup_for(command, monkeypatch)

    result = runner.invoke(cli_app.app, [*args, "--json"])
    data = json_out(result)

    assert data["command"] == command
    assert data["dnskit_version"] == __version__
    assert data["exit_code"] == result.exit_code
    assert set(data["summary"]) == JSON_SUMMARY_KEYS[command]
    assert isinstance(data["report"], dict)
    assert "─" not in result.stdout  # no table drawn alongside


def test_json_lookup_values_and_failure_diagnosis(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, make_report(LookupResult("A", LookupStatus.NXDOMAIN)))

    result = runner.invoke(cli_app.app, ["lookup", "example.com", "-t", "A", "--json"])
    data = json_out(result)

    assert result.exit_code == 1
    assert data["summary"] == {"exists": False}
    assert data["report"]["results"][0]["status"] == "nxdomain"
    assert data["diagnosis"]["title"] == "Domain doesn't exist"


def test_json_doctor_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    issue = doctor_issue(Area.DOMAIN, Impact.MAJOR, "Broken", Check.REACH)
    patch_doctor(monkeypatch, make_doctor(issue))

    data = json_out(runner.invoke(cli_app.app, ["doctor", "example.com", "--json"]))

    assert data["summary"] == {
        "score": 85,
        "healthy": False,
        "name_missing": False,
        "issues": 1,
        "notes": 0,
    }
    assert data["report"]["issues"][0]["impact"] == "major"
    assert data["diagnosis"]["title"] == "Mostly healthy, but some things need fixing"


def test_json_bad_input_is_json_too() -> None:
    result = runner.invoke(cli_app.app, ["reverse", "not-an-ip", "--json"])

    assert result.exit_code == 2
    data = json_out(result)
    assert data["exit_code"] == 2
    assert "is not a valid IP address" in data["error"]


# --- config file ----------------------------------------------------------------------------


def write_config(text: str) -> Path:
    path = Path(os.environ["DNSKIT_CONFIG"])
    path.write_text(text, encoding="utf-8")
    return path


def test_config_sets_option_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    write_config('[lookup]\ntype = "MX"\n')
    calls = patch_lookup(monkeypatch, make_report(A_OK))

    runner.invoke(cli_app.app, ["lookup", "example.com"])
    runner.invoke(cli_app.app, ["lookup", "example.com", "-t", "TXT"])

    assert calls == [["MX"], ["TXT"]]  # the command line wins


def test_config_defaults_section_applies_to_every_command(monkeypatch: pytest.MonkeyPatch) -> None:
    write_config("[defaults]\njson = true\n")
    patch_reach(monkeypatch, make_reach())

    result = runner.invoke(cli_app.app, ["reach", "example.com"])

    assert json_out(result)["command"] == "reach"


def test_config_resolver_lists_are_used(monkeypatch: pytest.MonkeyPatch) -> None:
    write_config(
        '[compare]\nresolvers = [{ name = "Office", address = "10.0.0.53" }]\n'
        '[propagation]\nresolvers = [{ name = "Google", address = "8.8.8.8", region = "global" }]\n'
    )
    seen: dict[str, object] = {}

    def fake_compare(name, rtype, **kwargs):
        seen["compare"] = kwargs["resolvers"]
        return make_compare(ResolverAnswer("Office", "10.0.0.53", A_OK, Agreement.MAJORITY))

    def fake_propagation(name, rtype, **kwargs):
        seen["propagation"] = kwargs["resolvers"]
        return make_propagation(NEW_A, NEW_A)

    monkeypatch.setattr(cli_app, "compare", fake_compare)
    monkeypatch.setattr(cli_app, "propagation", fake_propagation)
    runner.invoke(cli_app.app, ["compare", "example.com"])
    runner.invoke(cli_app.app, ["propagation", "example.com"])

    assert seen["compare"] == (("Office", "10.0.0.53"),)
    assert [(r.name, r.anycast) for r in seen["propagation"]] == [("Google", True)]


def test_a_broken_config_stops_every_command() -> None:
    write_config('[lookup]\ntimeout = "fast"\n')

    result = runner.invoke(cli_app.app, ["lookup", "example.com"])

    assert result.exit_code == 2
    assert "[lookup] timeout must be a number above 0, not 'fast'" in plain(result.output)


def test_config_command_without_a_file() -> None:
    result = runner.invoke(cli_app.app, ["config"])

    assert result.exit_code == 0
    assert "No config file at" in plain(result.output)
    assert "dnskit config --init" in plain(result.output)


def test_config_init_creates_a_template_once() -> None:
    first = runner.invoke(cli_app.app, ["config", "--init"])
    second = runner.invoke(cli_app.app, ["config", "--init"])

    path = Path(os.environ["DNSKIT_CONFIG"])
    assert first.exit_code == 0 and path.exists()
    assert "[defaults]" in path.read_text(encoding="utf-8")
    assert second.exit_code == 1
    assert "already exists" in plain(second.output)


def test_config_command_shows_settings_and_path() -> None:
    write_config(
        "[doctor]\nquick = true\n"
        '[compare]\nresolvers = [{ name = "Office", address = "10.0.0.53" }]\n'
    )

    output = plain(runner.invoke(cli_app.app, ["config"]).output)
    path = runner.invoke(cli_app.app, ["config", "--path"]).output.strip()
    data = json_out(runner.invoke(cli_app.app, ["config", "--json"]))

    assert "doctor quick True" in output
    assert "compare resolvers: Office (10.0.0.53)" in output
    assert path == os.environ["DNSKIT_CONFIG"]
    assert data["summary"]["exists"] is True
    assert data["report"]["settings"] == {"doctor": {"quick": True}}


def test_config_command_reports_a_broken_file() -> None:
    write_config("[nonsense]\n")

    result = runner.invoke(cli_app.app, ["config"])

    assert result.exit_code == 2
    assert "[nonsense] isn't a dnskit section" in plain(result.output)


# --- batch ----------------------------------------------------------------------------------


def make_batch(*items: BatchItem, invalid: tuple[BatchLine, ...] = ()) -> BatchReport:
    return BatchReport(BatchCheck.LOOKUP, items, invalid, (), 900.0)


def patch_batch(monkeypatch: pytest.MonkeyPatch, report: BatchReport) -> list[tuple]:
    calls: list[tuple] = []

    def fake_run_batch(lines, check, **kwargs):
        calls.append(([line.name for line in lines], check, kwargs))
        return report

    monkeypatch.setattr(cli_app, "run_batch", fake_run_batch)
    return calls


def domains_file(tmp_path: Path, text: str) -> str:
    path = tmp_path / "domains.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_batch_runs_the_check_and_shows_a_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = make_batch(
        BatchItem(1, "example.com", True, "A 1", 30.0),
        BatchItem(3, "missing.example", False, "Domain doesn't exist", 40.0),
        invalid=(BatchLine(4, "not a domain", None, "'not a domain' is not a valid domain name."),),
    )
    calls = patch_batch(monkeypatch, report)
    path = domains_file(tmp_path, "example.com\n# a comment\nmissing.example\nnot a domain\n")

    result = runner.invoke(cli_app.app, ["batch", path, "--check", "doctor", "--quick"])
    output = plain(result.output)

    assert result.exit_code == 1
    names, check, kwargs = calls[0]
    assert names == ["example.com", "missing.example", None]
    assert check is BatchCheck.DOCTOR
    assert kwargs["quick"] is True and kwargs["parallel"] == 4 and kwargs["server"] is None
    assert "1 example.com ✓ OK A 1 30 ms" in output
    assert "3 missing.example ✗ not OK Domain doesn't exist" in output
    assert "Skipped line 4: 'not a domain' is not a valid domain name." in output
    assert "1 OK · 1 not OK · 1 invalid line" in output


def test_batch_all_ok_exits_0_and_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_batch(monkeypatch, make_batch(BatchItem(1, "example.com", True, "A 1", 30.0)))

    result = runner.invoke(cli_app.app, ["batch", "-"], input="example.com\n")

    assert result.exit_code == 0
    assert calls[0][0] == ["example.com"]


def test_batch_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    patch_batch(monkeypatch, make_batch(BatchItem(1, "example.com", True, "A 1", 30.0)))

    result = runner.invoke(
        cli_app.app, ["batch", domains_file(tmp_path, "example.com\n"), "--json"]
    )
    data = json_out(result)

    assert data["summary"] == {
        "check": "lookup",
        "domains": 1,
        "ok": 1,
        "not_ok": 0,
        "invalid_lines": 0,
    }
    assert data["report"]["items"][0]["name"] == "example.com"


@pytest.mark.parametrize("text", ["", "# only comments\n\n", "not a domain\n"])
def test_batch_without_domains_exits_2(tmp_path: Path, text: str) -> None:
    result = runner.invoke(cli_app.app, ["batch", domains_file(tmp_path, text)])

    assert result.exit_code == 2
    assert "No domains found in" in plain(result.output)


def test_batch_missing_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(cli_app.app, ["batch", str(tmp_path / "nope.txt")])

    assert result.exit_code == 2
    assert "Can't read" in plain(result.output)


def test_batch_uses_config_selectors_and_resolvers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_config(
        '[email]\nselectors = ["s1"]\n'
        '[compare]\nresolvers = [{ name = "Office", address = "10.0.0.53" }]\n'
        '[batch]\ncheck = "email"\nparallel = 2\n'
    )
    calls = patch_batch(monkeypatch, make_batch(BatchItem(1, "example.com", True, "ok", 1.0)))

    runner.invoke(cli_app.app, ["batch", domains_file(tmp_path, "example.com\n")])

    _, check, kwargs = calls[0]
    assert check is BatchCheck.EMAIL
    assert kwargs["parallel"] == 2
    assert kwargs["selectors"] == ("s1",)
    assert kwargs["resolvers"] == (("Office", "10.0.0.53"),)


# --- watch ----------------------------------------------------------------------------------

AT = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
WATCH_OLD = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 300),))
WATCH_NEW = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 300),))


def sample(
    number: int,
    result: LookupResult,
    previous: LookupResult | None = None,
    new_values: tuple[str, ...] | None = None,
) -> WatchSample:
    """A watch sample; a change's values count as new unless `new_values` says otherwise."""
    if new_values is None:
        new_values = tuple(r.value for r in result.records) if previous else ()
    return WatchSample(number, AT, "example.com", "A", "192.0.2.53", result, previous, new_values)


def patch_watch(monkeypatch: pytest.MonkeyPatch, samples: list, then: BaseException | None = None):
    calls: list[tuple] = []

    def fake_watch(name, rtype, **kwargs):
        calls.append((name, rtype, kwargs))

        def gen():
            yield from samples
            if then is not None:
                raise then

        return gen()

    monkeypatch.setattr(cli_app, "watch", fake_watch)
    return calls


def test_watch_prints_each_check_and_highlights_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = [sample(1, WATCH_OLD), sample(2, WATCH_OLD), sample(3, WATCH_NEW, WATCH_OLD)]
    calls = patch_watch(monkeypatch, samples)

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--interval", "5", "--count", "3"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert calls == [("example.com", "A", {"nameserver": None, "interval": 5.0, "timeout": 5.0})]
    assert "Watching example.com A every 5 s (Ctrl+C to stop)" in output
    assert "192.0.2.1 (TTL 300) first answer, from 192.0.2.53" in output
    assert "192.0.2.1 (TTL 300) unchanged" in output
    assert "192.0.2.2 (TTL 300) CHANGED (was 192.0.2.1 (TTL 300))" in output
    assert "Stopped after 3 checks; the answer changed 1 time." in output


def test_watch_until_stops_when_the_new_value_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(
        monkeypatch, [sample(1, WATCH_OLD), sample(2, WATCH_NEW, WATCH_OLD), sample(3, WATCH_NEW)]
    )

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--until", "192.0.2.2"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert "✓ includes 192.0.2.2" in output
    assert "Done: the answer includes 192.0.2.2 after 2 checks" in output


def test_watch_until_not_reached_within_count_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, [sample(1, WATCH_OLD), sample(2, WATCH_OLD)])

    result = runner.invoke(
        cli_app.app, ["watch", "example.com", "--until", "192.0.2.2", "--count", "2"]
    )

    assert result.exit_code == 1


def test_watch_exit_on_change(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(
        monkeypatch, [sample(1, WATCH_OLD), sample(2, WATCH_NEW, WATCH_OLD), sample(3, WATCH_NEW)]
    )

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--exit-on-change"])

    assert result.exit_code == 0
    assert "Stopped at the first change after 2 checks" in plain(result.output)


def test_watch_failed_lookup_is_not_a_change(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(
        monkeypatch, [sample(1, WATCH_OLD), sample(2, LookupResult("A", LookupStatus.TIMEOUT))]
    )

    output = plain(runner.invoke(cli_app.app, ["watch", "example.com", "--count", "2"]).output)

    assert "timed out lookup failed (not counted as a change)" in output
    assert "the answer didn't change" in output


def test_watch_ctrl_c_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, [sample(1, WATCH_OLD)], then=KeyboardInterrupt())

    result = runner.invoke(cli_app.app, ["watch", "example.com"])

    assert result.exit_code == 130
    assert "Stopped after 1 check; the answer didn't change." in plain(result.output)


def test_watch_json_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, [sample(1, WATCH_OLD), sample(2, WATCH_NEW, WATCH_OLD)])

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--json", "--until", "192.0.2.2"])
    events = [json.loads(line) for line in result.stdout.splitlines()]

    assert [e["event"] for e in events] == ["check", "check", "end"]
    assert [e["changed"] for e in events[:2]] == [False, True]
    assert events[1]["includes_until"] is True
    assert events[1]["sample"]["result"]["records"][0]["value"] == "192.0.2.2"
    assert events[2] == {
        "command": "watch",
        "event": "end",
        "reason": "Done: the answer includes 192.0.2.2",
        "checks": 2,
        "changes": 1,
        "rotations": 0,
        "seen": [
            {"value": v, "times": 1, "first": AT.isoformat(), "last": AT.isoformat()}
            for v in ("192.0.2.1", "192.0.2.2")
        ],
        "exit_code": 0,
    }
    assert [e["alert"] for e in events[:2]] == [False, True]


def test_watch_bad_input_exits_2() -> None:
    result = runner.invoke(cli_app.app, ["watch", "example.com", "--interval", "0.1"])

    assert result.exit_code == 2
    assert "interval must be at least 1 second" in plain(result.output)


ROTATE_A = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 60), Record("192.0.2.3", 60)))
ROTATE_B = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 60), Record("192.0.2.3", 60)))


def rotation_samples() -> list[WatchSample]:
    """Two answers, then back and forth between them: everything after #2 is rotation."""
    return [
        sample(1, ROTATE_A),
        sample(2, ROTATE_B, ROTATE_A, ("192.0.2.2",)),
        sample(3, ROTATE_A, ROTATE_B, ()),
        sample(4, ROTATE_B, ROTATE_A, ()),
    ]


def test_watch_rotation_between_known_addresses_isnt_a_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_watch(monkeypatch, rotation_samples())

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--count", "4"])
    output = plain(result.output)

    assert result.exit_code == 0
    assert output.count("CHANGED") == 1  # only #2 brought something new
    assert output.count("rotating (CDN) (all seen before)") == 2
    assert "the answer changed 1 time and rotated 2 times between addresses already seen" in output
    assert "Everything seen" in output
    for value, times in (("192.0.2.1", 2), ("192.0.2.3", 4), ("192.0.2.2", 2)):
        assert re.search(rf"{re.escape(value)} +{times} ", output)


def test_watch_strict_counts_rotation_as_change(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, rotation_samples())

    output = plain(
        runner.invoke(cli_app.app, ["watch", "example.com", "--count", "4", "--strict"]).output
    )

    assert output.count("CHANGED") == 3
    assert "rotating" not in output
    assert "the answer changed 3 times." in output


def test_watch_exit_on_change_ignores_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    new = LookupResult("A", LookupStatus.OK, (Record("192.0.2.9", 60),))
    rotation = sample(2, ROTATE_B, ROTATE_A, ())  # a change, but nothing new
    patch_watch(monkeypatch, [sample(1, ROTATE_A), rotation, sample(3, new, ROTATE_B)])

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--exit-on-change"])

    assert result.exit_code == 0
    assert "Stopped at the first change after 3 checks" in plain(result.output)


def test_watch_ctrl_c_shows_everything_seen(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, rotation_samples()[:3], then=KeyboardInterrupt())

    result = runner.invoke(cli_app.app, ["watch", "example.com"])
    output = plain(result.output)

    assert result.exit_code == 130
    assert "Stopped after 3 checks; the answer changed 1 time and rotated 1 time" in output
    assert "Everything seen" in output and "First seen" in output
    assert "192.0.2.2" in output


def test_watch_json_marks_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_watch(monkeypatch, rotation_samples())

    result = runner.invoke(cli_app.app, ["watch", "example.com", "--count", "4", "--json"])
    events = [json.loads(line) for line in result.stdout.splitlines()]

    assert [e.get("rotating") for e in events[:4]] == [False, False, True, True]
    assert [e.get("alert") for e in events[:4]] == [False, True, False, False]
    assert (events[4]["changes"], events[4]["rotations"]) == (1, 2)
    assert [s["value"] for s in events[4]["seen"]] == ["192.0.2.1", "192.0.2.3", "192.0.2.2"]


def test_watch_strict_can_come_from_the_config(monkeypatch: pytest.MonkeyPatch) -> None:
    write_config("[watch]\nstrict = true\n")
    patch_watch(monkeypatch, rotation_samples())

    output = plain(runner.invoke(cli_app.app, ["watch", "example.com", "--count", "4"]).output)

    assert output.count("CHANGED") == 3


def test_python_dash_m_dnskit_runs_the_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["dnskit", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("dnskit", run_name="__main__")

    assert exit_info.value.code == 0
    assert f"dnskit {__version__}" in capsys.readouterr().out


@pytest.mark.parametrize("windows", [True, False])
def test_run_exits_quietly_when_help_cant_be_written(
    monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    # Typer's own console (--help, usage errors) isn't a PipeSafeConsole.
    def closed_pipe(**kwargs: object) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")

    quiet_exits = []

    def on_broken_pipe() -> None:
        quiet_exits.append(True)
        raise SystemExit(1)

    monkeypatch.setattr(cli_app, "app", closed_pipe)
    monkeypatch.setattr(cli_app, "_WINDOWS", windows)
    monkeypatch.setattr(cli_app.console, "on_broken_pipe", on_broken_pipe)

    expected = SystemExit if windows else OSError
    with pytest.raises(expected):
        cli_app.run()
    assert quiet_exits == ([True] if windows else [])


def test_closing_the_pipe_on_help_exits_quietly() -> None:
    src = str(Path(dnskit.__file__).parents[1])
    proc = subprocess.Popen(
        [sys.executable, "-m", "dnskit", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": src},
    )
    proc.stdout.close()
    stderr = proc.stderr.read().decode("utf-8", "replace")
    proc.stderr.close()

    assert proc.wait(timeout=30) in (0, 1)  # help may finish before the pipe closes
    assert "Traceback" not in stderr and "Exception ignored" not in stderr
