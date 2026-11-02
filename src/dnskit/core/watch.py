"""Look a record up again and again, and notice when the answer changes.

`watch()` yields one `WatchSample` per check, sleeping `interval` seconds in between, until
the caller stops iterating. Only real answers (records, "doesn't exist", "no records") are
compared: a failed lookup (timeout, SERVFAIL…) is reported but never counts as a change, so
a flaky network doesn't raise false alarms.

Every value of every real answer is remembered. A change whose values were all seen before
is `rotating`: a CDN or round-robin name handing out addresses from a pool. Only a change
that brings a value never seen before is `new_change`. `watch_summary` lists everything
seen.
"""

import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from dnskit.core.compare import answer_key
from dnskit.core.lookup import LookupResult, LookupStatus, _validate_rtype, lookup
from dnskit.core.reach import parse_target

WATCH_INTERVAL_S = 30.0
MIN_INTERVAL_S = 1.0


@dataclass(frozen=True)
class WatchSample:
    number: int  # 1 for the first check
    at: datetime  # when it was checked, UTC
    name: str
    rtype: str
    nameserver: str
    result: LookupResult
    # The last real answer before this one, when this one differs from it.
    previous: LookupResult | None = None
    # On a change: this answer's values that no earlier answer had (lower-case).
    new_values: tuple[str, ...] = ()

    @property
    def answered(self) -> bool:
        """A real answer, as opposed to a failed lookup."""
        return answer_key(self.result) is not None

    @property
    def changed(self) -> bool:
        """The answer differs from the last real one, in any way."""
        return self.previous is not None

    @property
    def rotating(self) -> bool:
        """A change between values already seen, as a CDN or round-robin pool does.

        Only between two answers with records: a name appearing or disappearing is never
        rotation.
        """
        return (
            self.changed
            and not self.new_values
            and self.result.status is LookupStatus.OK
            and self.previous is not None
            and self.previous.status is LookupStatus.OK
        )

    @property
    def new_change(self) -> bool:
        """A change that isn't just rotation: something not seen before."""
        return self.changed and not self.rotating

    def matches(self, expected: str) -> bool:
        """Whether one of the answer's records is `expected` (case and final dot ignored)."""
        wanted = expected.strip().rstrip(".").lower()
        return any(r.value.rstrip(".").lower() == wanted for r in self.result.records)


def watch(
    target: str,
    rtype: str = "A",
    nameserver: str | None = None,
    interval: float = WATCH_INTERVAL_S,
    timeout: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Iterator[WatchSample]:
    """Check `target`/`rtype` every `interval` seconds, forever; stop by not iterating.

    Validates the name, record type and interval before the first lookup (ValueError).
    Each sample's `previous` is set when its answer differs from the last real answer.
    """
    name = parse_target(target)
    rtype = _validate_rtype(rtype)
    if interval < MIN_INTERVAL_S:
        raise ValueError(f"The interval must be at least {MIN_INTERVAL_S:g} second.")
    return _samples(name, rtype, nameserver, interval, timeout, sleep, now)


def _samples(
    name: str,
    rtype: str,
    nameserver: str | None,
    interval: float,
    timeout: float,
    sleep: Callable[[float], None],
    now: Callable[[], datetime],
) -> Iterator[WatchSample]:
    last: LookupResult | None = None  # the last real answer
    seen: set[str] = set()  # every value of every real answer so far
    number = 0
    while True:
        number += 1
        report = lookup(name, [rtype], nameserver=nameserver, timeout=timeout)
        result = report.results[0]
        previous: LookupResult | None = None
        new_values: tuple[str, ...] = ()
        if answer_key(result) is not None:
            values = [_value(r.value) for r in result.records]
            if last is not None and answer_key(result) != answer_key(last):
                previous = last
                new_values = tuple(sorted({v for v in values if v not in seen}))
            seen.update(values)
            last = result
        yield WatchSample(
            number, now(), name, rtype, report.nameserver, result, previous, new_values
        )
        sleep(interval)


def _value(value: str) -> str:
    return value.rstrip(".").lower()


@dataclass(frozen=True)
class SeenValue:
    value: str
    times: int  # how many checks answered with it
    first: datetime
    last: datetime


@dataclass(frozen=True)
class WatchSummary:
    checks: int
    new_changes: int
    rotations: int
    failures: int  # lookups that failed
    values: tuple[SeenValue, ...]  # every value seen, in the order first seen


def watch_summary(samples: Sequence[WatchSample]) -> WatchSummary:
    """What a watch saw: counts, and every value with how often and when it was seen."""
    seen: dict[str, list[Any]] = {}  # value -> [times, first, last]
    for sample in samples:
        if not sample.answered:
            continue
        # Sorted, so values first seen in the same answer are listed in a stable order.
        for value in sorted({_value(r.value) for r in sample.result.records}):
            entry = seen.setdefault(value, [0, sample.at, sample.at])
            entry[0] += 1
            entry[2] = sample.at
    return WatchSummary(
        checks=len(samples),
        new_changes=sum(s.new_change for s in samples),
        rotations=sum(s.rotating for s in samples),
        failures=sum(not s.answered for s in samples),
        values=tuple(SeenValue(v, times, first, last) for v, (times, first, last) in seen.items()),
    )
