"""Discovering, probing and choosing the system's nameservers."""

import json
import os
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.resolver

from dnskit.core.adapters import AdapterScan, is_loopback, normalize_ip, scan_adapters

# How long a probed choice is reused, so repeated commands use the same nameserver.
CACHE_TTL_S = 300.0
# Probe timeout: a nameserver that can't answer a trivial query within this is "failed".
PROBE_TIMEOUT_S = 1.0
# A nameserver that answers, but slower than this, is reported as slow.
SLOW_THRESHOLD_MS = 250.0

_CACHE_VERSION = 1


@dataclass(frozen=True)
class ProbeResult:
    nameserver: str
    latency_ms: float | None  # None means no usable answer within the timeout


@dataclass(frozen=True)
class ResolverChoice:
    """The outcome of probing the system nameservers, fresh or from the cache."""

    nameserver: str | None  # fastest responder, or None if none answered
    probes: tuple[ProbeResult, ...]  # in system order
    probed_at: float  # Unix time of the probe
    from_cache: bool

    @property
    def failed(self) -> tuple[ProbeResult, ...]:
        return tuple(p for p in self.probes if p.latency_ms is None)

    @property
    def slow(self) -> tuple[ProbeResult, ...]:
        return tuple(
            p for p in self.probes if p.latency_ms is not None and p.latency_ms > SLOW_THRESHOLD_MS
        )

    @property
    def latency_ms(self) -> float | None:
        return next((p.latency_ms for p in self.probes if p.nameserver == self.nameserver), None)

    def ordered(self) -> list[str]:
        """All probed nameservers, fastest first; non-responders last, in system order."""
        responsive = sorted(
            (p for p in self.probes if p.latency_ms is not None), key=lambda p: p.latency_ms or 0.0
        )
        return [p.nameserver for p in responsive] + [p.nameserver for p in self.failed]


@dataclass(frozen=True)
class SystemNameservers:
    """The OS's configured nameservers, split by whether a connected adapter uses them."""

    configured: tuple[str, ...]  # everything the OS configuration lists, in system order
    usable: tuple[str, ...]  # the ones to query, in system order
    ignored: tuple[str, ...]  # configured, but on no connected adapter ("ghosts")


def configured_nameservers() -> list[str]:
    """Every nameserver in the OS configuration, as dnspython reads it, in system order.

    On Windows this is every interface in the registry, including disconnected adapters and
    leftovers from adapters that no longer exist; `system_nameservers` filters those out.
    """
    try:
        resolver = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        return []
    return [str(ns) for ns in resolver.nameservers]


def classify_nameservers(
    configured: Sequence[str] | None = None, scan: AdapterScan | None = None
) -> SystemNameservers:
    """Split the configured nameservers into those on a connected adapter and the rest.

    Like the OS's own DNS client, only nameservers of connected adapters are usable; local
    stubs (127.0.0.53, ::1) always are. When adapters can't be matched to nameservers, or
    the filter would leave nothing (e.g. offline), every configured nameserver is usable.
    """
    configured = tuple(configured_nameservers() if configured is None else configured)
    scan = scan_adapters() if scan is None else scan
    if not scan.dns_per_adapter:
        return SystemNameservers(configured, configured, ())
    connected = scan.connected_dns()
    usable = tuple(ns for ns in configured if normalize_ip(ns) in connected or is_loopback(ns))
    if not usable:
        return SystemNameservers(configured, configured, ())
    return SystemNameservers(configured, usable, tuple(ns for ns in configured if ns not in usable))


def system_nameservers() -> list[str]:
    """The nameservers this computer actually uses: configured, on a connected adapter."""
    return list(classify_nameservers().usable)


def probe(nameserver: str, timeout: float) -> float | None:
    """Send one recursive query to `nameserver`; return latency in ms, or None if unusable."""
    query = dns.message.make_query(".", "NS")
    start = time.perf_counter()
    try:
        response = dns.query.udp(query, nameserver, timeout=timeout)
    except Exception:
        return None
    if response.rcode() != dns.rcode.NOERROR:
        return None
    return (time.perf_counter() - start) * 1000


def probe_all(candidates: Sequence[str], timeout: float = PROBE_TIMEOUT_S) -> list[ProbeResult]:
    """Probe every candidate in parallel and wait for all of them. Keeps input order."""
    if not candidates:
        return []
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        latencies = list(pool.map(lambda ns: probe(ns, timeout), candidates))
    return [ProbeResult(ns, latency) for ns, latency in zip(candidates, latencies, strict=True)]


def choose_nameserver(
    candidates: Sequence[str],
    *,
    use_cache: bool = True,
    ttl: float = CACHE_TTL_S,
    timeout: float = PROBE_TIMEOUT_S,
) -> ResolverChoice:
    """Pick the fastest of `candidates`, reusing a recent choice when one is cached.

    A cached choice is reused only if it is younger than `ttl` and was made for exactly the
    same nameserver list (a changed list means the network changed). A fresh probe waits
    for every candidate (up to `timeout`) so failed and slow servers can be reported; it is
    cached only if some nameserver answered. `use_cache=False` always probes, and still
    saves the result for later runs.
    """
    candidates = list(candidates)
    if use_cache:
        cached = _load_cached_choice(candidates, ttl)
        if cached is not None:
            return cached

    probes = tuple(probe_all(candidates, timeout))
    responsive = [p for p in probes if p.latency_ms is not None]
    fastest = min(responsive, key=lambda p: p.latency_ms or 0.0) if responsive else None
    choice = ResolverChoice(
        nameserver=fastest.nameserver if fastest else None,
        probes=probes,
        probed_at=_now(),
        from_cache=False,
    )
    if choice.nameserver is not None:
        _save_choice(candidates, choice)
    return choice


def cache_path() -> Path:
    """Where the resolver choice is cached. Override the directory with DNSKIT_CACHE_DIR."""
    if override := os.environ.get("DNSKIT_CACHE_DIR"):
        base = Path(override)
    elif sys.platform == "win32" and (local := os.environ.get("LOCALAPPDATA")):
        base = Path(local) / "dnskit"
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        base = (Path(xdg) if xdg else Path.home() / ".cache") / "dnskit"
    return base / "resolver.json"


def _now() -> float:
    return time.time()


def _load_cached_choice(candidates: list[str], ttl: float) -> ResolverChoice | None:
    """Return the cached choice if it is still valid for `candidates`; any problem is a miss."""
    try:
        data = json.loads(cache_path().read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("version") != _CACHE_VERSION or data.get("system") != candidates:
            return None
        probed_at = float(data["probed_at"])
        age = _now() - probed_at
        if not 0 <= age < ttl:
            return None
        probes = tuple(ProbeResult(str(ns), latency) for ns, latency in data["probes"])
        chosen = str(data["nameserver"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if [p.nameserver for p in probes] != candidates or chosen not in candidates:
        return None
    return ResolverChoice(chosen, probes, probed_at, from_cache=True)


def _save_choice(candidates: list[str], choice: ResolverChoice) -> None:
    """Write the choice atomically; failing to cache is not an error."""
    data = {
        "version": _CACHE_VERSION,
        "system": candidates,
        "nameserver": choice.nameserver,
        "probed_at": choice.probed_at,
        "probes": [[p.nameserver, p.latency_ms] for p in choice.probes],
    }
    path = cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass
