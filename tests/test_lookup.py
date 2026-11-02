import errno
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from conftest import SYSTEM_NAMESERVERS, lookup_mod, make_choice
from dnskit.core import DEFAULT_RTYPES, LookupStatus, Record, lookup
from fakes import FakeAnswer, FakeResolver, no_nameservers

NO_ROUTE = OSError(errno.ENETUNREACH, "Network is unreachable")
WINDOWS_NO_ROUTE = OSError(10051, "A socket operation was attempted to an unreachable network")


def test_default_queries_all_types_in_order(env: SimpleNamespace) -> None:
    env.responses = {"A": FakeAnswer(["192.0.2.10"], 300)}

    report = lookup("example.com")

    assert [r.rtype for r in report.results] == list(DEFAULT_RTYPES)
    assert report.results[0].status is LookupStatus.OK
    assert report.results[0].records == (Record("192.0.2.10", 300),)
    assert all(r.status is LookupStatus.NO_ANSWER for r in report.results[1:])


def test_single_type(env: SimpleNamespace) -> None:
    env.responses = {"MX": FakeAnswer(["10 mail.example.com."], 60)}

    report = lookup("example.com", ["mx"])

    assert [r.rtype for r in report.results] == ["MX"]
    assert report.results[0].status is LookupStatus.OK


def test_mixed_statuses(env: SimpleNamespace) -> None:
    env.responses = {
        "A": FakeAnswer(["192.0.2.10"], 300),
        "AAAA": dns.exception.Timeout(),
        "MX": no_nameservers("SERVFAIL"),
        "TXT": dns.resolver.NXDOMAIN(),
    }

    statuses = {r.rtype: r.status for r in lookup("example.com").results}

    assert statuses["A"] is LookupStatus.OK
    assert statuses["AAAA"] is LookupStatus.TIMEOUT
    assert statuses["MX"] is LookupStatus.SERVFAIL
    assert statuses["TXT"] is LookupStatus.NXDOMAIN
    assert statuses["NS"] is LookupStatus.NO_ANSWER


@pytest.mark.parametrize(
    ("error", "status"),
    [
        pytest.param(dns.resolver.NXDOMAIN(), LookupStatus.NXDOMAIN, id="nxdomain"),
        pytest.param(dns.resolver.NoAnswer(), LookupStatus.NO_ANSWER, id="no-answer"),
        pytest.param(dns.exception.Timeout(), LookupStatus.TIMEOUT, id="timeout"),
        pytest.param(no_nameservers("SERVFAIL"), LookupStatus.SERVFAIL, id="servfail"),
        pytest.param(
            no_nameservers("REFUSED", "SERVFAIL"), LookupStatus.SERVFAIL, id="servfail-mixed"
        ),
        pytest.param(no_nameservers(NO_ROUTE), LookupStatus.NO_NETWORK, id="no-network"),
        pytest.param(
            no_nameservers(WINDOWS_NO_ROUTE, NO_ROUTE),
            LookupStatus.NO_NETWORK,
            id="no-network-windows",
        ),
        pytest.param(
            OSError(errno.ENETUNREACH, "unreachable"),
            LookupStatus.NO_NETWORK,
            id="no-network-raised",
        ),
        pytest.param(no_nameservers("REFUSED"), LookupStatus.NO_NAMESERVERS, id="refused"),
        pytest.param(
            no_nameservers(ConnectionResetError(10054, "reset")),
            LookupStatus.NO_NAMESERVERS,
            id="port-closed-is-not-offline",
        ),
        pytest.param(
            no_nameservers(NO_ROUTE, "REFUSED"),
            LookupStatus.NO_NAMESERVERS,
            id="partly-offline-is-not-offline",
        ),
    ],
)
def test_errors_map_to_status(env: SimpleNamespace, error: Exception, status: LookupStatus) -> None:
    env.responses = {"A": error}

    result = lookup("example.com", ["A"]).results[0]

    assert result.status is status
    assert result.records == ()


@pytest.mark.parametrize("refresh", [False, True])
def test_explicit_server_overrides_choice_and_cache(env: SimpleNamespace, refresh: bool) -> None:
    report = lookup("example.com", ["A"], nameserver="198.51.100.53", refresh=refresh)

    assert env.choose_calls == []
    assert report.nameserver == "198.51.100.53"
    assert report.nameserver_source == "--server"
    assert report.resolver_choice is None
    assert env.resolver_nameservers == [["198.51.100.53"]]


def test_fastest_first_then_by_latency_then_failed(env: SimpleNamespace) -> None:
    report = lookup("example.com", ["A", "MX"])

    assert report.nameserver == "192.0.2.2"
    assert report.nameserver_source == "auto: fastest of 3 system nameservers, 12 ms"
    assert report.resolver_choice is env.choice
    # 192.0.2.1 didn't answer the probe, so it's tried last.
    assert env.resolver_nameservers == [["192.0.2.2", "192.0.2.3", "192.0.2.1"]] * 2


def test_uses_cache_unless_refresh(env: SimpleNamespace) -> None:
    lookup("example.com", ["A"])
    lookup("example.com", ["A"], refresh=True)

    assert env.choose_calls == [True, False]


def test_no_probe_answer_keeps_system_order(env: SimpleNamespace) -> None:
    env.choice = make_choice(dict.fromkeys(SYSTEM_NAMESERVERS))

    report = lookup("example.com", ["A"])

    assert report.nameserver == "192.0.2.1"
    assert report.nameserver_source.startswith("system order")
    assert env.resolver_nameservers == [SYSTEM_NAMESERVERS]


def test_no_system_nameservers_explains_offline(env: SimpleNamespace) -> None:
    env.system = []

    with pytest.raises(ValueError, match=r"may be offline.*--server"):
        lookup("example.com")


def test_unknown_type_raises_with_examples(env: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match=r"Unknown record type: NOTATYPE\. Common types are A, "):
        lookup("example.com", ["A", "NOTATYPE"])


def test_query_one_can_resend_sooner(monkeypatch: pytest.MonkeyPatch) -> None:
    resolvers: list[FakeResolver] = []

    def make(nameservers: list[str], timeout: float) -> FakeResolver:
        resolvers.append(FakeResolver({"A": FakeAnswer(["192.0.2.1"], 60)}, []))
        return resolvers[-1]

    monkeypatch.setattr(lookup_mod, "_make_resolver", make)

    lookup_mod._query_one("example.com", "A", ["192.0.2.53"], 1.5, retry_after=0.5)
    lookup_mod._query_one("example.com", "A", ["192.0.2.53"], 1.5)

    assert resolvers[0].timeout == 0.5
    assert not hasattr(resolvers[1], "timeout")  # dnspython's own default


def test_make_resolver_uses_only_the_given_servers() -> None:
    resolver = lookup_mod._make_resolver(["192.0.2.1", "192.0.2.2"], 3.0)

    assert resolver.nameservers == ["192.0.2.1", "192.0.2.2"]
    assert resolver.lifetime == 3.0


def test_txt_text_leaves_unquoted_text_alone() -> None:
    assert lookup_mod.txt_text("v=spf1 -all") == "v=spf1 -all"
