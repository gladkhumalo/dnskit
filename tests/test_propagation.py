import importlib
from types import SimpleNamespace

import pytest

from dnskit.core import Agreement, DnsBlocking, LookupResult, LookupStatus, Record
from dnskit.core.propagation import (
    GLOBAL_REGION,
    PROPAGATION_RESOLVERS,
    PROPAGATION_TIMEOUT_S,
    explain_propagation,
    propagation,
)

prop_mod = importlib.import_module("dnskit.core.propagation")

ADDRESSES = [r.address for r in PROPAGATION_RESOLVERS]
NEW = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 300),))
OLD = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 1800),))
TIMEOUT = LookupResult("A", LookupStatus.TIMEOUT)


@pytest.fixture
def resolvers(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Every resolver answers NEW unless `results` says otherwise (address -> result)."""
    state = SimpleNamespace(
        results={},
        default=NEW,
        blocking=DnsBlocking(("192.0.2.53",), ("OfficeVPN",), local_firewall=False),
        blocking_calls=0,
        queried=[],
        retry_after=[],
    )

    def fake_query_one(
        name: str, rtype: str, nameservers: list[str], timeout: float, retry_after=None
    ):
        state.retry_after.append(retry_after)
        assert len(nameservers) == 1  # each resolver alone: no fallback hides its answer
        state.queried.append((name, rtype, nameservers[0]))
        return state.results.get(nameservers[0], state.default)

    def fake_check_blocking() -> DnsBlocking:
        state.blocking_calls += 1
        return state.blocking

    monkeypatch.setattr(prop_mod, "_query_one", fake_query_one)
    monkeypatch.setattr(prop_mod, "check_blocking", fake_check_blocking)
    return state


def test_anycast_resolvers_are_global_and_the_rest_have_regions() -> None:
    regions = [r.region for r in PROPAGATION_RESOLVERS]
    assert set(regions) == {GLOBAL_REGION, "Americas", "Europe", "Asia"}
    assert regions == sorted(regions, key=regions.index)  # each group in one block
    assert regions[0] == GLOBAL_REGION
    for resolver in PROPAGATION_RESOLVERS:
        assert resolver.anycast == (resolver.location == "nearest site")
    anycast = {r.name for r in PROPAGATION_RESOLVERS if r.anycast}
    assert {"Google", "Cloudflare", "OpenDNS", "Quad9"} <= anycast
    assert len(set(ADDRESSES)) == len(ADDRESSES)


def test_timeout_is_short_but_resends_lost_queries(resolvers: SimpleNamespace) -> None:
    propagation("example.com")

    assert PROPAGATION_TIMEOUT_S == 1.5
    assert set(resolvers.retry_after) == {0.5}


def test_everyone_agreeing_is_fully_propagated(resolvers: SimpleNamespace) -> None:
    report = propagation("example.com", "mx")

    assert report.rtype == "MX"
    assert {q[2] for q in resolvers.queried} == set(ADDRESSES)
    assert report.percent == 100
    assert report.complete
    assert resolvers.blocking_calls == 0
    diagnosis = explain_propagation(report)
    assert diagnosis.title == f"Fully propagated: all {len(ADDRESSES)} resolvers agree"


def test_some_still_serving_the_old_answer(resolvers: SimpleNamespace) -> None:
    resolvers.results = {ADDRESSES[0]: OLD, ADDRESSES[5]: OLD, ADDRESSES[-1]: TIMEOUT}

    report = propagation("example.com")

    total = len(ADDRESSES)
    assert len(report.responded) == total - 1
    assert len(report.differing) == 2
    assert report.percent == pytest.approx(100 * (total - 3) / (total - 1))
    assert not report.complete
    assert report.answers[0].agreement is Agreement.DIFFERS
    assert report.answers[-1].agreement is Agreement.FAILED
    diagnosis = explain_propagation(report)
    assert diagnosis.title.startswith("Still propagating: ")
    assert "within about 30 minutes" in diagnosis.explanation  # the old answer's 1800 s TTL
    assert "CDN" in diagnosis.explanation
    assert "lower the record's TTL" in diagnosis.suggestion


def test_a_tie_has_no_consensus(resolvers: SimpleNamespace) -> None:
    half = len(ADDRESSES) // 2
    resolvers.results = dict.fromkeys(ADDRESSES[:half], OLD)
    if len(ADDRESSES) % 2:
        resolvers.results[ADDRESSES[-1]] = TIMEOUT  # an even split of those that answer

    report = propagation("example.com")

    assert not report.has_majority
    assert report.percent == 0
    assert explain_propagation(report).title == "No consensus: 2 different answers"


def test_agreeing_that_a_name_doesnt_exist(resolvers: SimpleNamespace) -> None:
    resolvers.default = LookupResult("A", LookupStatus.NXDOMAIN)

    report = propagation("gone.example.com")

    assert report.complete
    assert "gone.example.com doesn't exist" in explain_propagation(report).explanation


def test_a_vpn_blocking_outside_resolvers_is_explained(resolvers: SimpleNamespace) -> None:
    resolvers.default = TIMEOUT
    resolvers.results = {"8.8.8.8": NEW}  # only the VPN's own DNS server gets through

    report = propagation("example.com")

    assert resolvers.blocking_calls == 1
    assert report.blocked
    assert not report.complete
    diagnosis = explain_propagation(report)
    assert diagnosis.title == "Direct DNS queries are blocked by the VPN"
    assert f"No reply from {len(ADDRESSES) - 1} of the {len(ADDRESSES)}" in diagnosis.explanation
    assert f"Only 1 of {len(ADDRESSES)} resolvers could be reached" in diagnosis.suggestion


def test_many_failures_with_enough_answers_still_measure(resolvers: SimpleNamespace) -> None:
    answering = ADDRESSES[:4]
    resolvers.default = TIMEOUT
    resolvers.results = dict.fromkeys(answering, NEW)

    report = propagation("example.com")

    assert report.blocking is not None
    assert not report.blocked
    assert report.complete
    assert report.percent == 100


def test_nobody_answering_while_offline(resolvers: SimpleNamespace) -> None:
    resolvers.default = TIMEOUT
    resolvers.blocking = DnsBlocking((), (), local_firewall=False)

    report = propagation("example.com")

    assert report.blocked
    assert "offline" in explain_propagation(report).title


@pytest.mark.parametrize(("target", "rtype"), [("not a domain!", "A"), ("example.com", "NOPE")])
def test_invalid_input_raises(resolvers: SimpleNamespace, target: str, rtype: str) -> None:
    with pytest.raises(ValueError, match=r"is not a valid domain name|Unknown record type"):
        propagation(target, rtype)
    assert resolvers.queried == []


def test_one_odd_answer_is_singular(resolvers: SimpleNamespace) -> None:
    resolvers.results = {ADDRESSES[0]: OLD}

    explanation = explain_propagation(propagation("example.com")).explanation

    assert "and 1 gives another." in explanation


def fixed(name: str) -> str:
    return next(r.address for r in PROPAGATION_RESOLVERS if r.name == name)


def test_differences_only_abroad_look_location_based(resolvers: SimpleNamespace) -> None:
    resolvers.results = {fixed("Yandex"): OLD, fixed("KT"): OLD}

    report = propagation("example.com")

    assert report.location_based
    assert not report.complete  # still reported as differing: it's only a likely cause
    diagnosis = explain_propagation(report)
    assert diagnosis.title == "Probably location-based DNS, not propagation"
    anycast = sum(1 for r in PROPAGATION_RESOLVERS if r.anycast)
    assert f"All {anycast} global resolvers agree" in diagnosis.explanation
    assert "(Yandex in Russia, KT in South Korea)" in diagnosis.explanation
    assert "the most common answer is the value you set" in diagnosis.suggestion


def test_one_difference_abroad_is_singular(resolvers: SimpleNamespace) -> None:
    resolvers.results = {fixed("Yandex"): OLD}

    explanation = explain_propagation(propagation("example.com")).explanation

    assert "the 1 resolver that differs is in another country (Yandex in Russia)" in explanation


@pytest.mark.parametrize(
    "case",
    ["anycast differs", "not an address", "nxdomain abroad", "too few anycast"],
)
def test_when_differences_are_not_location_based(resolvers: SimpleNamespace, case: str) -> None:
    rtype = "A"
    resolvers.results = {fixed("Yandex"): OLD}
    if case == "anycast differs":
        resolvers.results[ADDRESSES[0]] = OLD
    elif case == "not an address":
        rtype = "MX"
    elif case == "nxdomain abroad":
        resolvers.results = {fixed("Yandex"): LookupResult("A", LookupStatus.NXDOMAIN)}
    else:
        for resolver in PROPAGATION_RESOLVERS[1:]:
            if resolver.anycast:
                resolvers.results[resolver.address] = TIMEOUT

    report = propagation("example.com", rtype)

    assert report.differing
    assert not report.location_based
    assert not explain_propagation(report).title.startswith("Probably location-based")


def test_nobody_answering_without_a_block(resolvers: SimpleNamespace) -> None:
    resolvers.default = TIMEOUT
    resolvers.blocking = DnsBlocking(("192.0.2.53",), (), local_firewall=False)
    report = propagation("example.com")
    unblocked = prop_mod.PropagationReport(
        report.name, report.rtype, report.answers, False, 0, 10.0, blocking=None
    )

    diagnosis = explain_propagation(unblocked)

    assert diagnosis.title == "No resolver answered"


def test_agreeing_that_there_are_no_records(resolvers: SimpleNamespace) -> None:
    resolvers.default = LookupResult("A", LookupStatus.NO_ANSWER)

    diagnosis = explain_propagation(propagation("example.com"))

    assert "example.com has no A records" in diagnosis.explanation


@pytest.mark.parametrize(
    ("seconds", "words"),
    [(45, "45 seconds"), (1800, "30 minutes"), (86400, "24 hours")],
)
def test_durations_read_naturally(seconds: int, words: str) -> None:
    assert prop_mod._duration(seconds) == words
