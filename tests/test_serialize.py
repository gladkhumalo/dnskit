import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace

from dnskit.core import (
    LookupReport,
    LookupResult,
    LookupStatus,
    ProbeResult,
    Record,
    ResolverChoice,
    to_data,
)
from dnskit.core.doctor import Area, Check, CheckRun, CheckState, DoctorReport, Impact, Issue


class Colour(StrEnum):
    RED = "red"


@dataclass(frozen=True)
class Inner:
    colour: Colour
    when: datetime


@dataclass(frozen=True)
class Outer:
    name: str
    inner: Inner
    items: tuple[int, ...]
    tags: frozenset[str]
    where: Path
    extra: dict[str, object]
    nothing: None = None


def test_nested_dataclasses_become_plain_data() -> None:
    value = Outer(
        "x",
        Inner(Colour.RED, datetime(2026, 11, 2, 10, 0, tzinfo=UTC)),
        (1, 2),
        frozenset({"b", "a"}),
        Path("dir") / "file.txt",
        {"k": Colour.RED, 3: (True, 1.5)},
    )

    assert to_data(value) == {
        "name": "x",
        "inner": {"colour": "red", "when": "2026-11-02T10:00:00+00:00"},
        "items": [1, 2],
        "tags": ["a", "b"],
        "where": str(Path("dir") / "file.txt"),
        "extra": {"k": "red", "3": [True, 1.5]},
        "nothing": None,
    }


def test_plain_objects_and_unknown_types() -> None:
    assert to_data(SimpleNamespace(a=1, _private=2)) == {"a": 1}
    assert to_data(object.__new__(type("Opaque", (), {"__slots__": ()}))).startswith("<")


def test_reports_survive_json() -> None:
    lookup = LookupReport(
        "example.com",
        "192.0.2.53",
        "auto",
        (LookupResult("A", LookupStatus.OK, (Record("192.0.2.1", 300),)),),
        12.0,
    )
    doctor = DoctorReport(
        "example.com",
        False,
        (CheckRun(Check.LOCAL, CheckState.DONE, 10.0),),
        (Issue(Area.MACHINE, Impact.NOTE, "Ghost", "Why.", "Nothing.", Check.LOCAL),),
        10.0,
        lookup=lookup,
    )

    data = json.loads(json.dumps(to_data(doctor)))

    assert data["runs"][0] == {
        "check": "local",
        "state": "done",
        "elapsed_ms": 10.0,
        "error": None,
        "reason": "",
    }
    assert data["issues"][0]["impact"] == "note"
    assert data["lookup"]["results"][0]["records"] == [{"value": "192.0.2.1", "ttl": 300}]


def test_timings_are_rounded_and_unix_times_become_iso() -> None:
    choice = ResolverChoice(
        "192.0.2.53",
        (ProbeResult("192.0.2.53", 12.345678), ProbeResult("192.0.2.54", None)),
        probed_at=1793604090.3573694,
        from_cache=True,
    )
    report = LookupReport("example.com", "192.0.2.53", "auto", (), 120.82139, choice)

    data = to_data(report)

    assert data["elapsed_ms"] == 120.8
    assert data["resolver_choice"]["probes"] == [
        {"nameserver": "192.0.2.53", "latency_ms": 12.3},
        {"nameserver": "192.0.2.54", "latency_ms": None},
    ]
    assert data["resolver_choice"]["probed_at"] == "2026-11-02T07:21:30.357369+00:00"


def test_only_numbers_follow_the_naming_conventions() -> None:
    @dataclass(frozen=True)
    class Odd:
        label_ms: str
        flag_ms: bool
        started_at: datetime

    when = datetime(2026, 11, 2, tzinfo=UTC)

    assert to_data(Odd("fast", True, when)) == {
        "label_ms": "fast",
        "flag_ms": True,
        "started_at": when.isoformat(),
    }


def test_txt_values_lose_their_quotes() -> None:
    txt = LookupResult(
        "TXT",
        LookupStatus.OK,
        (
            Record('"v=spf1 include:_spf.example.net" " -all"', 300),
            Record('"say \\"hi\\"" "semi\\059colon"', 300),
            Record('"google-site-verification=abc"', 300),
        ),
    )
    a = LookupResult("A", LookupStatus.OK, (Record('"not-txt"', 300),))

    values = [r["value"] for r in to_data(txt)["records"]]

    assert values == [
        "v=spf1 include:_spf.example.net -all",
        'say "hi"semi;colon',
        "google-site-verification=abc",
    ]
    assert to_data(a)["records"][0]["value"] == '"not-txt"'  # only TXT (and SPF)
    assert txt.records[0].value.startswith('"')  # the report itself is unchanged
