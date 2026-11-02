import importlib
import time
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from dnskit.core import ProbeResult, ResolverChoice
from fakes import FakeResolver

# `dnskit.core.lookup` as an attribute is the re-exported function, so fetch the module itself.
lookup_mod = importlib.import_module("dnskit.core.lookup")

SYSTEM_NAMESERVERS = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the resolver cache at a temp dir so no test reads or writes the real one."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("DNSKIT_CACHE_DIR", str(cache_dir))
    # Nor the user's config file: tests that want one write it here.
    monkeypatch.setenv("DNSKIT_CONFIG", str(tmp_path / "config.toml"))
    return cache_dir


def make_choice(
    latencies: dict[str, float | None], from_cache: bool = False, probed_at: float | None = None
) -> ResolverChoice:
    """A ResolverChoice as choose_nameserver would build it from these probe latencies."""
    probes = tuple(ProbeResult(ns, latency) for ns, latency in latencies.items())
    responsive = [p for p in probes if p.latency_ms is not None]
    fastest = min(responsive, key=lambda p: p.latency_ms or 0.0) if responsive else None
    return ResolverChoice(
        nameserver=fastest.nameserver if fastest else None,
        probes=probes,
        probed_at=time.time() if probed_at is None else probed_at,
        from_cache=from_cache,
    )


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Patch out all network access for core lookups; returns knobs tests can adjust.

    - `responses`: rtype -> FakeAnswer or exception to raise
    - `choice`: what choosing a system nameserver returns
    - `system`: the system nameserver list
    Records `resolver_nameservers`, `queried` (name, rtype) pairs and `choose_calls`
    (the `use_cache` value of each call to choose_nameserver).
    """
    state = SimpleNamespace(
        responses={},
        choice=make_choice({"192.0.2.1": None, "192.0.2.2": 12.0, "192.0.2.3": 30.0}),
        system=list(SYSTEM_NAMESERVERS),
        resolver_nameservers=[],
        queried=[],
        choose_calls=[],
    )

    def fake_make_resolver(nameservers: Sequence[str], timeout: float) -> FakeResolver:
        state.resolver_nameservers.append(list(nameservers))
        return FakeResolver(state.responses, state.queried)

    def fake_choose(candidates: Sequence[str], *, use_cache: bool = True, **kwargs):
        state.choose_calls.append(use_cache)
        return state.choice

    monkeypatch.setattr(lookup_mod, "_make_resolver", fake_make_resolver)
    monkeypatch.setattr(lookup_mod, "system_nameservers", lambda: list(state.system))
    monkeypatch.setattr(lookup_mod, "choose_nameserver", fake_choose)
    return state
