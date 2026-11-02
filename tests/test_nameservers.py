import json
import time
from pathlib import Path

import pytest

from dnskit.core import nameservers
from dnskit.core.nameservers import (
    CACHE_TTL_S,
    ProbeResult,
    ResolverChoice,
    cache_path,
    choose_nameserver,
    probe_all,
)

SYSTEM = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
# 192.0.2.1 is dead, 192.0.2.3 answers but slowly.
LATENCIES: dict[str, float | None] = {"192.0.2.1": None, "192.0.2.2": 20.0, "192.0.2.3": 400.0}


class FakeProbe:
    """Probe stub returning fixed latencies; counts calls so tests can see cache hits."""

    def __init__(self, latencies: dict[str, float | None]) -> None:
        self.latencies = dict(latencies)
        self.calls: list[str] = []

    def __call__(self, ns: str, timeout: float) -> float | None:
        self.calls.append(ns)
        return self.latencies[ns]


@pytest.fixture
def fake_probe(monkeypatch: pytest.MonkeyPatch) -> FakeProbe:
    stub = FakeProbe(LATENCIES)
    monkeypatch.setattr(nameservers, "probe", stub)
    return stub


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Controllable wall clock for cache-age tests: set clock[0] to move time."""
    now = [1_000_000.0]
    monkeypatch.setattr(nameservers, "_now", lambda: now[0])
    return now


# --- Probing ------------------------------------------------------------------------------


def test_probe_all_keeps_input_order(fake_probe: FakeProbe) -> None:
    assert probe_all(SYSTEM, timeout=0.1) == [ProbeResult(ns, LATENCIES[ns]) for ns in SYSTEM]


def test_probe_all_with_no_candidates() -> None:
    assert probe_all([]) == []


# --- Choosing and reporting failed/slow servers ------------------------------------------


def test_choose_picks_fastest_and_reports_failed_and_slow(fake_probe: FakeProbe) -> None:
    choice = choose_nameserver(SYSTEM)

    assert choice.nameserver == "192.0.2.2"
    assert choice.latency_ms == 20.0
    assert not choice.from_cache
    assert [p.nameserver for p in choice.probes] == SYSTEM
    assert [p.nameserver for p in choice.failed] == ["192.0.2.1"]
    assert [p.nameserver for p in choice.slow] == ["192.0.2.3"]
    assert choice.ordered() == ["192.0.2.2", "192.0.2.3", "192.0.2.1"]


def test_choose_with_no_responders(fake_probe: FakeProbe) -> None:
    fake_probe.latencies = dict.fromkeys(SYSTEM)

    choice = choose_nameserver(SYSTEM)

    assert choice.nameserver is None
    assert len(choice.failed) == 3
    assert choice.ordered() == SYSTEM


def test_healthy_servers_report_nothing(fake_probe: FakeProbe) -> None:
    fake_probe.latencies = {"192.0.2.1": 10.0, "192.0.2.2": 20.0, "192.0.2.3": 30.0}

    choice = choose_nameserver(SYSTEM)

    assert choice.failed == ()
    assert choice.slow == ()


# --- Caching ------------------------------------------------------------------------------


def test_second_call_reuses_cached_choice(fake_probe: FakeProbe, clock: list[float]) -> None:
    first = choose_nameserver(SYSTEM)
    fake_probe.calls.clear()
    # Even if latencies change, a cached choice keeps the result stable.
    fake_probe.latencies = {"192.0.2.1": 1.0, "192.0.2.2": 50.0, "192.0.2.3": 2.0}
    clock[0] += 60

    second = choose_nameserver(SYSTEM)

    assert fake_probe.calls == []
    assert second.from_cache
    assert second.nameserver == first.nameserver == "192.0.2.2"
    assert second.probes == first.probes
    assert second.probed_at == first.probed_at


def test_cache_expires_after_ttl(fake_probe: FakeProbe, clock: list[float]) -> None:
    choose_nameserver(SYSTEM)
    fake_probe.calls.clear()
    clock[0] += CACHE_TTL_S

    choice = choose_nameserver(SYSTEM)

    assert not choice.from_cache
    assert sorted(fake_probe.calls) == SYSTEM


def test_cache_from_the_future_is_ignored(fake_probe: FakeProbe, clock: list[float]) -> None:
    choose_nameserver(SYSTEM)
    clock[0] -= 10  # clock went backwards

    assert not choose_nameserver(SYSTEM).from_cache


def test_changed_nameserver_list_invalidates_cache(fake_probe: FakeProbe) -> None:
    choose_nameserver(SYSTEM)
    fake_probe.latencies["192.0.2.9"] = 5.0

    choice = choose_nameserver([*SYSTEM, "192.0.2.9"])

    assert not choice.from_cache
    assert choice.nameserver == "192.0.2.9"


def test_use_cache_false_probes_and_refreshes_cache(
    fake_probe: FakeProbe, clock: list[float]
) -> None:
    choose_nameserver(SYSTEM)
    fake_probe.latencies["192.0.2.3"] = 5.0
    clock[0] += 10

    refreshed = choose_nameserver(SYSTEM, use_cache=False)
    after = choose_nameserver(SYSTEM)

    assert not refreshed.from_cache
    assert refreshed.nameserver == "192.0.2.3"
    assert after.from_cache
    assert after.nameserver == "192.0.2.3"


def test_no_responder_is_not_cached(fake_probe: FakeProbe) -> None:
    fake_probe.latencies = dict.fromkeys(SYSTEM)
    choose_nameserver(SYSTEM)

    assert not cache_path().exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"version": 999}),
        json.dumps({"version": 1, "system": SYSTEM, "probed_at": "soon"}),
        json.dumps(
            {
                "version": 1,
                "system": SYSTEM,
                "nameserver": "203.0.113.1",  # not one of the system nameservers
                "probed_at": 1_000_000.0,
                "probes": [[ns, 10.0] for ns in SYSTEM],
            }
        ),
    ],
)
def test_bad_cache_file_is_a_miss(fake_probe: FakeProbe, clock: list[float], content: str) -> None:
    path = cache_path()
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")

    choice = choose_nameserver(SYSTEM)

    assert not choice.from_cache
    assert choice.nameserver == "192.0.2.2"


def test_unwritable_cache_is_not_an_error(
    fake_probe: FakeProbe, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setenv("DNSKIT_CACHE_DIR", str(blocker))

    assert choose_nameserver(SYSTEM).nameserver == "192.0.2.2"


def test_cache_path_honours_override(isolated_cache: Path) -> None:
    assert cache_path() == isolated_cache / "resolver.json"


def test_resolver_choice_ordering_ties_keep_system_order() -> None:
    probes = (ProbeResult("a", 10.0), ProbeResult("b", None), ProbeResult("c", 10.0))
    choice = ResolverChoice("a", probes, time.time(), from_cache=False)

    assert choice.ordered() == ["a", "c", "b"]


# --- Reading and probing the system's nameservers ----------------------------------------------


def test_configured_nameservers_reads_dnspython(monkeypatch: pytest.MonkeyPatch) -> None:
    class Configured:
        nameservers = ("192.0.2.1", "2001:db8::53")

    monkeypatch.setattr(nameservers.dns.resolver, "Resolver", Configured)

    assert nameservers.configured_nameservers() == ["192.0.2.1", "2001:db8::53"]


def test_no_resolver_configuration_is_no_nameservers(monkeypatch: pytest.MonkeyPatch) -> None:
    def unconfigured() -> None:
        raise nameservers.dns.resolver.NoResolverConfiguration

    monkeypatch.setattr(nameservers.dns.resolver, "Resolver", unconfigured)

    assert nameservers.configured_nameservers() == []


def test_system_nameservers_are_the_usable_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        nameservers,
        "classify_nameservers",
        lambda: nameservers.SystemNameservers(("a", "b"), ("b",), ("a",)),
    )

    assert nameservers.system_nameservers() == ["b"]


class Answer:
    def __init__(self, rcode: int) -> None:
        self._rcode = rcode

    def rcode(self) -> int:
        return self._rcode


def unreachable(*args: object, **kwargs: object) -> Answer:
    raise OSError("unreachable")


@pytest.mark.parametrize(
    ("udp", "answered"),
    [
        (lambda *a, **k: Answer(nameservers.dns.rcode.NOERROR), True),
        (lambda *a, **k: Answer(nameservers.dns.rcode.SERVFAIL), False),
        (unreachable, False),
    ],
)
def test_probe(monkeypatch: pytest.MonkeyPatch, udp: object, answered: bool) -> None:
    monkeypatch.setattr(nameservers.dns.query, "udp", udp)

    latency = nameservers.probe("192.0.2.1", 1.0)

    assert (latency is not None) is answered
    if latency is not None:
        assert latency >= 0


def test_cache_path_on_windows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DNSKIT_CACHE_DIR")
    monkeypatch.setattr(nameservers.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert cache_path() == tmp_path / "dnskit" / "resolver.json"


@pytest.mark.parametrize("xdg", [True, False])
def test_cache_path_elsewhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, xdg: bool) -> None:
    monkeypatch.delenv("DNSKIT_CACHE_DIR")
    monkeypatch.setattr(nameservers.sys, "platform", "linux")
    if xdg:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        expected = tmp_path / "dnskit" / "resolver.json"
    else:
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.setattr(nameservers.Path, "home", lambda: tmp_path)
        expected = tmp_path / ".cache" / "dnskit" / "resolver.json"

    assert cache_path() == expected
