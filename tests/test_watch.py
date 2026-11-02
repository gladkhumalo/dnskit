import importlib
import itertools
from datetime import UTC, datetime

import pytest

from dnskit.core import LookupReport, LookupResult, LookupStatus, Record
from dnskit.core.watch import watch, watch_summary

watch_mod = importlib.import_module("dnskit.core.watch")

OLD = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 300), Record("192.0.2.9", 300)))
SAME = LookupResult("A", LookupStatus.OK, (Record("192.0.2.9", 120), Record("192.0.2.1", 120)))
NEW = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 300),))
TIMEOUT = LookupResult("A", LookupStatus.TIMEOUT)
MISSING = LookupResult("A", LookupStatus.NXDOMAIN)
AT = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)


@pytest.fixture
def answers(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Each lookup returns the next of `state["results"]`; sleeps are recorded."""
    state: dict = {"results": [], "lookups": [], "sleeps": []}

    def fake_lookup(name, rtypes, **kwargs):
        state["lookups"].append((name, list(rtypes), kwargs))
        result = state["results"][len(state["lookups"]) - 1]
        return LookupReport(name, "192.0.2.53", "auto", (result,), 5.0)

    monkeypatch.setattr(watch_mod, "lookup", fake_lookup)
    return state


def run(state: dict, *results: LookupResult, **options: object) -> list:
    state["results"] = list(results)
    samples = watch(
        "https://Example.com/",
        sleep=state["sleeps"].append,
        now=lambda: AT,
        **options,
    )
    return list(itertools.islice(samples, len(results)))


def test_samples_and_changes(answers: dict) -> None:
    samples = run(answers, OLD, SAME, NEW, NEW, interval=10.0, rtype="aaaa")

    assert [s.number for s in samples] == [1, 2, 3, 4]
    assert [s.changed for s in samples] == [False, False, True, False]  # order and TTL ignored
    assert samples[2].previous is SAME  # the latest real answer
    assert answers["lookups"][0] == ("example.com", ["AAAA"], {"nameserver": None, "timeout": 5.0})
    assert answers["sleeps"] == [10.0, 10.0, 10.0]  # between checks, not after the last
    assert samples[0].at == AT and samples[0].nameserver == "192.0.2.53"


def test_failed_lookups_never_count_as_changes(answers: dict) -> None:
    samples = run(answers, OLD, TIMEOUT, OLD, TIMEOUT, NEW)

    assert [s.answered for s in samples] == [True, False, True, False, True]
    assert [s.changed for s in samples] == [False, False, False, False, True]
    assert samples[4].previous is OLD  # compared with the last real answer


def test_doesnt_exist_is_an_answer(answers: dict) -> None:
    samples = run(answers, MISSING, NEW)

    assert samples[0].answered
    assert samples[1].changed and samples[1].previous is MISSING


def test_matches_ignores_case_and_the_final_dot(answers: dict) -> None:
    cname = LookupResult("CNAME", LookupStatus.OK, (Record("New.Example.NET.", 300),))
    (sample,) = run(answers, cname)

    assert sample.matches("new.example.net")
    assert sample.matches("NEW.example.net.")
    assert not sample.matches("old.example.net")


def test_server_and_timeout_are_passed_on(answers: dict) -> None:
    run(answers, OLD, nameserver="1.1.1.1", timeout=2.0)

    assert answers["lookups"][0][2] == {"nameserver": "1.1.1.1", "timeout": 2.0}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target": "bad name!"}, "not a valid domain name"),
        ({"target": "example.com", "rtype": "BOGUS"}, "Unknown record type"),
        ({"target": "example.com", "interval": 0.5}, "at least 1 second"),
    ],
)
def test_bad_input_raises_before_any_lookup(answers: dict, kwargs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        watch(**kwargs)

    assert answers["lookups"] == []


ONE = LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 60), Record("192.0.2.3", 60)))
TWO = LookupResult("A", LookupStatus.OK, (Record("192.0.2.2", 60), Record("192.0.2.3", 60)))
THREE = LookupResult("A", LookupStatus.OK, (Record("192.0.2.4", 60),))


def test_rotation_between_values_already_seen(answers: dict) -> None:
    samples = run(answers, ONE, TWO, ONE, TWO, THREE)

    assert [s.changed for s in samples] == [False, True, True, True, True]
    assert [s.rotating for s in samples] == [False, False, True, True, False]
    assert [s.new_change for s in samples] == [False, True, False, False, True]
    assert [s.new_values for s in samples] == [(), ("192.0.2.2",), (), (), ("192.0.2.4",)]


def test_appearing_or_disappearing_is_never_rotation(answers: dict) -> None:
    samples = run(answers, ONE, MISSING, ONE)

    assert [s.rotating for s in samples] == [False, False, False]
    assert [s.new_change for s in samples] == [False, True, True]  # back again is news too


def test_values_compare_without_case_or_final_dot(answers: dict) -> None:
    upper = LookupResult("CNAME", LookupStatus.OK, (Record("CDN.Example.NET.", 60),))
    lower = LookupResult("CNAME", LookupStatus.OK, (Record("cdn.example.net.", 60),))
    other = LookupResult("CNAME", LookupStatus.OK, (Record("edge.example.net.", 60),))

    samples = run(answers, upper, other, lower)

    assert samples[2].rotating  # the same name as the first answer


def test_watch_summary_counts_everything_seen(answers: dict) -> None:
    times = iter(AT.replace(minute=m) for m in range(10))
    answers["results"] = [ONE, TWO, TIMEOUT, ONE, THREE]
    samples = list(
        itertools.islice(
            watch("example.com", sleep=answers["sleeps"].append, now=lambda: next(times)), 5
        )
    )

    summary = watch_summary(samples)

    assert (summary.checks, summary.new_changes, summary.rotations, summary.failures) == (
        5,
        2,
        1,
        1,
    )
    assert [(v.value, v.times, v.first.minute, v.last.minute) for v in summary.values] == [
        ("192.0.2.1", 2, 0, 3),
        ("192.0.2.3", 3, 0, 3),
        ("192.0.2.2", 1, 1, 1),
        ("192.0.2.4", 1, 4, 4),
    ]
    assert watch_summary([]).values == ()
