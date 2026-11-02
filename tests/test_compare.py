import importlib
import threading
from collections.abc import Sequence
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from dnskit.core import Agreement, CompareReport, LookupStatus, compare
from fakes import FakeAnswer, no_nameservers

lookup_mod = importlib.import_module("dnskit.core.lookup")
compare_mod = importlib.import_module("dnskit.core.compare")

PUBLIC = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
SYSTEM = ["192.0.2.1", "192.0.2.2"]
ALL = PUBLIC + SYSTEM

SAME = FakeAnswer(["192.0.2.10", "192.0.2.11"], 300)


class PerServerResolver:
    """Fake resolver that answers according to the one nameserver it was built for."""

    def __init__(self, state: SimpleNamespace, nameservers: Sequence[str]) -> None:
        self.state = state
        self.nameserver = nameservers[0]

    def resolve(self, name: str, rtype: str) -> FakeAnswer:
        self.state.queried.append((self.nameserver, name, rtype))
        if self.state.barrier is not None:
            self.state.barrier.wait()
        response = self.state.answers.get(self.nameserver, SAME)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def cmp_env(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Patch out the network for compare(); `answers` maps nameserver -> answer or error."""
    state = SimpleNamespace(answers={}, system=list(SYSTEM), queried=[], resolvers=[], barrier=None)

    def fake_make_resolver(nameservers: Sequence[str], timeout: float) -> PerServerResolver:
        state.resolvers.append((list(nameservers), timeout))
        return PerServerResolver(state, nameservers)

    monkeypatch.setattr(lookup_mod, "_make_resolver", fake_make_resolver)
    monkeypatch.setattr(compare_mod, "system_nameservers", lambda: list(state.system))
    return state


def agreements(report: CompareReport) -> dict[str, Agreement]:
    return {a.nameserver: a.agreement for a in report.answers}


# --- Which resolvers are queried, and how -------------------------------------------------


def test_queries_public_then_system_resolvers_each_on_its_own(cmp_env: SimpleNamespace) -> None:
    report = compare("example.com", timeout=1.5)

    assert [a.nameserver for a in report.answers] == ALL
    assert [a.label for a in report.answers] == [
        "Google",
        "Cloudflare",
        "Quad9",
        "System #1",
        "System #2",
    ]
    # One resolver per server with no fallbacks, so each answer is that server's own.
    assert sorted(cmp_env.resolvers) == sorted(([ns], 1.5) for ns in ALL)
    assert {(name, rtype) for _, name, rtype in cmp_env.queried} == {("example.com", "A")}


def test_queries_run_in_parallel(cmp_env: SimpleNamespace) -> None:
    # Every query waits until all of them have started; run one at a time, this would fail.
    cmp_env.barrier = threading.Barrier(len(ALL), timeout=5)

    report = compare("example.com")

    assert report.all_agree


def test_system_nameserver_that_is_also_public_is_queried_once(cmp_env: SimpleNamespace) -> None:
    cmp_env.system = ["192.0.2.1", "1.1.1.1", "1.1.1.1"]

    report = compare("example.com")

    assert [(a.label, a.nameserver) for a in report.answers] == [
        ("Google", "8.8.8.8"),
        ("Cloudflare / system #2", "1.1.1.1"),
        ("Quad9", "9.9.9.9"),
        ("System #1", "192.0.2.1"),
    ]


def test_no_system_nameservers_compares_public_only(cmp_env: SimpleNamespace) -> None:
    cmp_env.system = []

    assert [a.nameserver for a in compare("example.com").answers] == PUBLIC


def test_type_is_case_insensitive(cmp_env: SimpleNamespace) -> None:
    report = compare("example.com", "mx")

    assert report.rtype == "MX"
    assert {rtype for *_, rtype in cmp_env.queried} == {"MX"}


def test_unknown_type_raises_before_querying(cmp_env: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="Unknown record type: NOPE"):
        compare("example.com", "NOPE")

    assert cmp_env.queried == []


# --- Agreement ----------------------------------------------------------------------------


def test_all_agree_ignoring_order_ttl_and_name_case(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = {
        "1.1.1.1": FakeAnswer(["192.0.2.11", "192.0.2.10"], 42),  # different order and TTL
        "192.0.2.1": FakeAnswer(["192.0.2.10", "192.0.2.11"], 7),
    }

    report = compare("example.com")

    assert report.all_agree
    assert report.has_majority
    assert report.distinct_answers == 1
    assert set(agreements(report).values()) == {Agreement.MAJORITY}
    assert report.differing == () and report.failed == ()


def test_dns_names_compare_case_insensitively(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = dict.fromkeys(ALL, FakeAnswer(["Target.Example.COM."], 60))
    cmp_env.answers["9.9.9.9"] = FakeAnswer(["target.example.com."], 60)

    assert compare("www.example.com", "CNAME").all_agree


def test_txt_compares_case_sensitively(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = dict.fromkeys(ALL, FakeAnswer(['"token=ABC"'], 60))
    cmp_env.answers["9.9.9.9"] = FakeAnswer(['"token=abc"'], 60)

    report = compare("example.com", "TXT")

    assert agreements(report)["9.9.9.9"] is Agreement.DIFFERS


def test_one_resolver_differs_from_majority(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = {"9.9.9.9": FakeAnswer(["203.0.113.99"], 300)}

    report = compare("example.com")

    assert not report.all_agree
    assert report.has_majority
    assert report.distinct_answers == 2
    assert [a.nameserver for a in report.differing] == ["9.9.9.9"]
    assert len(report.majority) == 4


def test_nxdomain_from_one_resolver_is_a_different_answer(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = {"192.0.2.2": dns.resolver.NXDOMAIN()}

    report = compare("example.com")

    differing = report.differing
    assert [a.nameserver for a in differing] == ["192.0.2.2"]
    assert differing[0].result.status is LookupStatus.NXDOMAIN


def test_agreeing_on_nxdomain_counts_as_agreement(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = dict.fromkeys(ALL, dns.resolver.NXDOMAIN())

    assert compare("nope.invalid").all_agree


def test_tie_means_no_majority(cmp_env: SimpleNamespace) -> None:
    cmp_env.system = ["192.0.2.1"]
    other = FakeAnswer(["203.0.113.99"], 300)
    cmp_env.answers = {"9.9.9.9": other, "192.0.2.1": other}  # 2 vs 2

    report = compare("example.com")

    assert not report.has_majority
    assert not report.all_agree
    assert report.distinct_answers == 2
    assert set(agreements(report).values()) == {Agreement.DIFFERS}


# --- Failures -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (dns.exception.Timeout(), LookupStatus.TIMEOUT),
        (no_nameservers("SERVFAIL"), LookupStatus.SERVFAIL),
        (no_nameservers("REFUSED"), LookupStatus.NO_NAMESERVERS),
        (OSError(10051, "unreachable"), LookupStatus.NO_NETWORK),
    ],
)
def test_failed_resolver_is_marked_and_left_out_of_majority(
    cmp_env: SimpleNamespace, error: Exception, status: LookupStatus
) -> None:
    cmp_env.answers = {"192.0.2.1": error}

    report = compare("example.com")

    assert [(a.nameserver, a.result.status) for a in report.failed] == [("192.0.2.1", status)]
    assert report.all_agree  # the rest agree; a failure isn't a disagreement
    assert len(report.responded) == 4
    assert report.failed[0].ttl is None


def test_every_resolver_failing(cmp_env: SimpleNamespace) -> None:
    cmp_env.answers = dict.fromkeys(ALL, dns.exception.Timeout())

    report = compare("example.com")

    assert not report.all_agree
    assert not report.has_majority
    assert report.distinct_answers == 0
    assert len(report.failed) == len(ALL)
