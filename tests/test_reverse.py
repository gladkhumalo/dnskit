from types import SimpleNamespace

import dns.resolver
import pytest

from dnskit.core import LookupStatus, Record, parse_ip, reverse_lookup
from fakes import FakeAnswer, no_nameservers


@pytest.mark.parametrize(
    ("text", "canonical", "version"),
    [
        ("8.8.8.8", "8.8.8.8", 4),
        ("  1.1.1.1 ", "1.1.1.1", 4),
        ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888", 6),
        ("::1", "::1", 6),
        ("fe80::1%eth0", "fe80::1", 6),
    ],
)
def test_parse_ip_accepts_ipv4_and_ipv6(text: str, canonical: str, version: int) -> None:
    addr = parse_ip(text)

    assert str(addr) == canonical
    assert addr.version == version


@pytest.mark.parametrize(
    "text", ["", "example.com", "256.1.1.1", "1.2.3", "2001:db8::g", "1.2.3.4/24"]
)
def test_parse_ip_rejects_invalid(text: str) -> None:
    with pytest.raises(ValueError, match="not a valid IP address"):
        parse_ip(text)


def test_invalid_ip_never_queries(env: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="is not a valid IP address"):
        reverse_lookup("not-an-ip")

    assert env.queried == []
    assert env.choose_calls == []


def test_reverse_ipv4(env: SimpleNamespace) -> None:
    env.responses = {"PTR": FakeAnswer(["dns.google."], 3600)}

    report = reverse_lookup("8.8.8.8")

    assert env.queried == [("8.8.8.8.in-addr.arpa.", "PTR")]
    assert report.ip == "8.8.8.8"
    assert report.version == 4
    assert report.ptr_name == "8.8.8.8.in-addr.arpa."
    assert report.result.status is LookupStatus.OK
    assert report.result.records == (Record("dns.google.", 3600),)


def test_reverse_ipv6(env: SimpleNamespace) -> None:
    env.responses = {"PTR": FakeAnswer(["dns.google."], 3600)}

    report = reverse_lookup("2001:4860:4860::8888")

    expected = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa."
    assert env.queried == [(expected, "PTR")]
    assert report.version == 6
    assert report.result.status is LookupStatus.OK


def test_reverse_explicit_server_overrides_choice(env: SimpleNamespace) -> None:
    report = reverse_lookup("8.8.8.8", nameserver="198.51.100.53", refresh=True)

    assert env.choose_calls == []
    assert report.nameserver == "198.51.100.53"
    assert report.resolver_choice is None
    assert env.resolver_nameservers == [["198.51.100.53"]]


def test_reverse_uses_cached_choice_unless_refresh(env: SimpleNamespace) -> None:
    report = reverse_lookup("8.8.8.8")
    reverse_lookup("8.8.8.8", refresh=True)

    assert env.choose_calls == [True, False]
    assert report.nameserver == "192.0.2.2"
    assert report.resolver_choice is env.choice


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (dns.resolver.NXDOMAIN(), LookupStatus.NXDOMAIN),
        (dns.resolver.NoAnswer(), LookupStatus.NO_ANSWER),
        (no_nameservers("SERVFAIL"), LookupStatus.SERVFAIL),
    ],
)
def test_reverse_failures(env: SimpleNamespace, error: Exception, status: LookupStatus) -> None:
    env.responses = {"PTR": error}

    assert reverse_lookup("203.0.113.7").result.status is status
