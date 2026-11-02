import importlib
from types import SimpleNamespace

import dns.resolver
import pytest

from dnskit.core import HostsEntry, HostsFile, HostsKind, ReachVerdict, explain_reach, reach
from dnskit.core.connectivity import ConnectAttempt, ConnectError
from dnskit.core.reach import parse_target
from fakes import FakeAnswer

reach_mod = importlib.import_module("dnskit.core.reach")

V4 = ["192.0.2.10", "192.0.2.11"]
V6 = ["2001:db8::10"]


@pytest.fixture
def reach_env(env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """`env` (fake DNS) plus fake TCP connections and hosts file. Everything works."""
    env.responses = {"A": FakeAnswer(V4, 300), "AAAA": FakeAnswer(V6, 300)}
    env.connect = {}  # address -> ConnectError; missing = connects
    env.connected = []
    env.hosts = HostsFile("/etc/hosts", ())

    def fake_connect(address: str, port: int, timeout: float) -> ConnectAttempt:
        env.connected.append((address, port, timeout))
        error = env.connect.get(address)
        if error is None:
            return ConnectAttempt(address, port, 20.0 if ":" not in address else 30.0)
        return ConnectAttempt(address, port, None, error, "boom")

    monkeypatch.setattr(reach_mod, "tcp_connect", fake_connect)
    monkeypatch.setattr(reach_mod, "read_hosts", lambda: env.hosts)
    return env


def test_reachable(reach_env: SimpleNamespace) -> None:
    report = reach("Example.com", timeout=3.0)

    assert report.name == "example.com"
    assert report.addresses == (*V4, *V6)
    # Connections run in parallel, so they're recorded in any order.
    assert sorted((a, p) for a, p, _ in reach_env.connected) == sorted(
        (ip, 443) for ip in (*V4, *V6)
    )
    assert report.verdict is ReachVerdict.REACHABLE
    assert report.nameserver == "192.0.2.2"  # the fastest system nameserver
    diagnosis = explain_reach(report)
    assert diagnosis.title == "Neither: DNS and the connection both work"
    assert "resolved to 3 addresses, and 192.0.2.10 accepted a connection on port 443 in 20 ms" in (
        diagnosis.explanation
    )


def test_custom_port_and_explicit_server(reach_env: SimpleNamespace) -> None:
    report = reach("example.com", port=8443, nameserver="9.9.9.9")

    assert {p for _, p, _ in reach_env.connected} == {8443}
    assert report.nameserver_source == "--server"
    assert reach_env.choose_calls == []


def test_parse_target_accepts_urls() -> None:
    assert parse_target("https://www.Example.com/login?x=1") == "www.example.com"
    assert parse_target(" example.com ") == "example.com"


@pytest.mark.parametrize("bad", ["not a domain", "http://", "user@example.com"])
def test_invalid_target_raises(bad: str) -> None:
    with pytest.raises(ValueError, match=r"is not a valid domain name|looks like an email"):
        parse_target(bad)


def test_invalid_port_raises(reach_env: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="out of range"):
        reach("example.com", port=70000)


# --- DNS problems -------------------------------------------------------------------------


def test_nxdomain_is_a_dns_problem(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {"A": dns.resolver.NXDOMAIN(), "AAAA": dns.resolver.NXDOMAIN()}

    report = reach("nope.example")
    diagnosis = explain_reach(report)

    assert report.verdict is ReachVerdict.DNS
    assert reach_env.connected == []
    assert diagnosis.title == "The problem is DNS: domain doesn't exist"


def test_no_addresses_is_a_dns_problem(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {}  # NoAnswer for both

    diagnosis = explain_reach(reach("example.com"))

    assert diagnosis.title == "The problem is DNS: no addresses"
    assert "no A (IPv4) or AAAA (IPv6) records" in diagnosis.explanation


def test_timeout_is_a_dns_problem(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {"A": dns.exception.Timeout(), "AAAA": dns.exception.Timeout()}

    diagnosis = explain_reach(reach("example.com"), timeout=5.0)

    assert diagnosis.title == "The problem is DNS: query timed out"
    assert "within 5 seconds" in diagnosis.explanation


def test_sinkholed_name_is_blocked_by_dns(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {"A": FakeAnswer(["0.0.0.0"], 10), "AAAA": FakeAnswer(["::"], 10)}

    report = reach("ads.example")
    diagnosis = explain_reach(report)

    assert report.blocked_by_dns
    assert report.verdict is ReachVerdict.DNS
    assert reach_env.connected == []  # nothing worth connecting to
    assert diagnosis.title == "The problem is DNS: the name is blocked"
    assert "Pi-hole" in diagnosis.explanation


def test_ipv6_only_name_still_counts_as_resolved(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {"AAAA": FakeAnswer(V6, 300)}

    assert reach("example.com").verdict is ReachVerdict.REACHABLE


# --- Connection problems ------------------------------------------------------------------


def test_all_refused(reach_env: SimpleNamespace) -> None:
    reach_env.connect = dict.fromkeys((*V4, *V6), ConnectError.REFUSED)

    report = reach("example.com")
    diagnosis = explain_reach(report)

    assert report.verdict is ReachVerdict.CONNECTION
    assert diagnosis.title == "The problem is the connection: port 443 isn't reachable"
    assert "refused the connection on port 443" in diagnosis.explanation
    assert "does the site support HTTPS?" in diagnosis.suggestion


def test_all_timed_out(reach_env: SimpleNamespace) -> None:
    reach_env.connect = dict.fromkeys((*V4, *V6), ConnectError.TIMEOUT)

    diagnosis = explain_reach(reach("example.com"))

    assert "no connection to port 443 got a reply" in diagnosis.explanation
    assert "phone hotspot" in diagnosis.suggestion


def test_ipv6_only_site_without_ipv6(reach_env: SimpleNamespace) -> None:
    reach_env.responses = {"AAAA": FakeAnswer(V6, 300)}
    reach_env.connect = {V6[0]: ConnectError.UNREACHABLE}

    diagnosis = explain_reach(reach("example.com"))

    assert "no network route" in diagnosis.explanation
    assert "only has IPv6 addresses" in diagnosis.suggestion


def test_failed_ipv6_with_working_ipv4_is_noted(reach_env: SimpleNamespace) -> None:
    reach_env.connect = {V6[0]: ConnectError.TIMEOUT}

    report = reach("example.com")

    assert report.verdict is ReachVerdict.REACHABLE
    assert "IPv6 connections failed" in explain_reach(report).explanation


def test_no_ipv6_route_is_not_a_slow_ipv6_warning(reach_env: SimpleNamespace) -> None:
    reach_env.connect = {V6[0]: ConnectError.UNREACHABLE}

    assert "IPv6" not in explain_reach(reach("example.com")).explanation


def test_refused_ipv4_without_ipv6_is_still_refused(reach_env: SimpleNamespace) -> None:
    reach_env.connect = {**dict.fromkeys(V4, ConnectError.REFUSED), V6[0]: ConnectError.UNREACHABLE}

    diagnosis = explain_reach(reach("example.com"))

    assert "refused the connection on port 443" in diagnosis.explanation
    assert V6[0] not in diagnosis.explanation


def test_addresses_are_capped_per_family(reach_env: SimpleNamespace) -> None:
    many = [f"192.0.2.{i}" for i in range(1, 10)]
    reach_env.responses = {"A": FakeAnswer(many, 60)}

    reach("example.com")

    assert sorted(a for a, _, _ in reach_env.connected) == many[:4]


def test_hosts_file_entry_is_mentioned(reach_env: SimpleNamespace) -> None:
    entry = HostsEntry(12, "203.0.113.7", ("Example.com",), HostsKind.REDIRECT)
    reach_env.hosts = HostsFile("/etc/hosts", (entry,))

    report = reach("example.com")

    assert report.hosts_entries == (entry,)
    assert "hosts file points example.com at 203.0.113.7 (line 12)" in (
        explain_reach(report).explanation
    )


def test_only_ip_addresses_can_be_a_dns_filters_block() -> None:
    assert reach_mod._is_sinkhole("0.0.0.0")
    assert reach_mod._is_sinkhole("::1")
    assert not reach_mod._is_sinkhole("192.0.2.80")
    assert not reach_mod._is_sinkhole("example.com.")
