import importlib

import dns.exception
import dns.message
import dns.rcode
import dns.rrset
import pytest

from dnskit.core.integrity import (
    RawAnswer,
    Verdict,
    ask,
    classify_cloudflare,
    classify_google,
    classify_nxdomain,
    probe_name,
)

integrity_mod = importlib.import_module("dnskit.core.integrity")


# --- ask ----------------------------------------------------------------------------------


def make_response(
    name: str, rdtype: str, rcode: int = dns.rcode.NOERROR, *texts: str, rdclass: str = "IN"
) -> dns.message.Message:
    response = dns.message.make_response(dns.message.make_query(name, rdtype, rdclass))
    response.set_rcode(rcode)
    if texts:
        response.answer.append(dns.rrset.from_text(name, 60, rdclass, rdtype, *texts))
    return response


def test_ask_returns_rcode_and_unquoted_txt(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = []

    def fake_udp(query: dns.message.Message, where: str, timeout: float) -> dns.message.Message:
        sent.append((query.question[0].to_text(), where, timeout))
        return make_response(
            "whoami.cloudflare.", "TXT", dns.rcode.NOERROR, '"203.0.113.5"', rdclass="CH"
        )

    monkeypatch.setattr(integrity_mod.dns.query, "udp", fake_udp)

    answer = ask("1.1.1.1", "whoami.cloudflare", "TXT", 1.0, "CH")

    assert answer == RawAnswer("NOERROR", ("203.0.113.5",))
    assert sent == [("whoami.cloudflare. CH TXT", "1.1.1.1", 1.0)]


def test_ask_keeps_only_the_asked_type(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response("x.com.", "A", dns.rcode.NOERROR, "198.51.100.80")
    response.answer.insert(0, dns.rrset.from_text("x.com.", 60, "IN", "CNAME", "ads.example."))
    monkeypatch.setattr(integrity_mod.dns.query, "udp", lambda *a, **k: response)

    assert ask("192.0.2.1", "x.com", "A", 1.0) == RawAnswer("NOERROR", ("198.51.100.80",))


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (dns.exception.Timeout(), "no response"),
        (OSError(10051, "unreachable network"), "[Errno 10051] unreachable network"),
    ],
)
def test_ask_never_raises(monkeypatch: pytest.MonkeyPatch, error: Exception, expected: str) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(integrity_mod.dns.query, "udp", fail)

    assert ask("192.0.2.1", "x.com", "A", 1.0) == RawAnswer(None, error=expected)


# --- NXDOMAIN hijacking -------------------------------------------------------------------


def test_probe_name_is_random_and_under_com() -> None:
    first, second = probe_name(), probe_name()

    assert first != second
    assert first.startswith("dnskit-nx-") and first.endswith(".com")


def test_nxdomain_is_honest() -> None:
    check = classify_nxdomain("192.0.2.1", "nx.com", RawAnswer("NXDOMAIN"))

    assert check.verdict is Verdict.OK
    assert check.summary == 'answers "doesn\'t exist" honestly'


def test_an_address_for_a_made_up_name_is_hijacking() -> None:
    answer = RawAnswer("NOERROR", ("198.51.100.80", "198.51.100.81"))

    check = classify_nxdomain("192.0.2.1", "nx.com", answer)

    assert check.verdict is Verdict.SUSPECT
    assert check.addresses == ("198.51.100.80", "198.51.100.81")
    assert check.summary == "hijacked: a made-up name got 198.51.100.80, 198.51.100.81"


@pytest.mark.parametrize(
    ("answer", "summary"),
    [
        (RawAnswer(None, error="no response"), "couldn't tell (no response)"),
        (RawAnswer("SERVFAIL"), "couldn't tell (answered SERVFAIL without an address)"),
        (RawAnswer("NOERROR"), "couldn't tell (answered NOERROR without an address)"),
    ],
)
def test_other_answers_are_unknown(answer: RawAnswer, summary: str) -> None:
    check = classify_nxdomain("192.0.2.1", "nx.com", answer)

    assert check.verdict is Verdict.UNKNOWN
    assert check.summary == summary


# --- Interception -------------------------------------------------------------------------


def test_google_answered_from_google() -> None:
    # Google also returns the client's subnet; only the resolver address matters.
    answer = RawAnswer("NOERROR", ("172.253.249.215", "edns0-client-subnet 203.0.113.0/24"))

    check = classify_google(answer)

    assert check.verdict is Verdict.OK
    assert check.answered_by == "172.253.249.215"
    assert check.summary == "answered by Google (172.253.249.215)"


def test_google_ipv6_resolver_counts_as_google() -> None:
    assert classify_google(RawAnswer("NOERROR", ("2404:6800:4003::1",))).verdict is Verdict.OK


@pytest.mark.parametrize(
    "address", ["34.153.64.87", "74.114.29.10", "2404:f340:10:1400::1", "2600:1900:4260:40e::5"]
)
def test_google_resolvers_in_its_newer_ranges_count_as_google(address: str) -> None:
    # Real egress addresses from Google's published Public DNS list, once flagged as
    # interception.
    assert classify_google(RawAnswer("NOERROR", (address,))).verdict is Verdict.OK


def test_google_answered_from_elsewhere_is_intercepted() -> None:
    check = classify_google(RawAnswer("NOERROR", ("198.51.100.53",)))

    assert check.verdict is Verdict.SUSPECT
    assert check.answered_by == "198.51.100.53"
    assert check.summary == "intercepted: answered from 198.51.100.53, which isn't Google"


@pytest.mark.parametrize(
    ("answer", "response"),
    [(RawAnswer("NXDOMAIN"), "NXDOMAIN"), (RawAnswer("NOERROR"), "an empty answer")],
)
def test_google_without_an_address_is_intercepted(answer: RawAnswer, response: str) -> None:
    check = classify_google(answer)

    assert check.verdict is Verdict.SUSPECT
    assert check.answered_by is None
    assert check.response == response


def test_cloudflare_answers_with_your_address() -> None:
    check = classify_cloudflare(RawAnswer("NOERROR", ("203.0.113.5",)))

    assert check.verdict is Verdict.OK
    assert check.summary == "answered by Cloudflare"  # your address stays out of the output


@pytest.mark.parametrize(
    ("answer", "response"),
    [
        (RawAnswer("SERVFAIL"), "SERVFAIL"),
        (RawAnswer("REFUSED"), "REFUSED"),
        (RawAnswer("NOERROR", ("resolver.isp.example",)), "resolver.isp.example"),
    ],
)
def test_cloudflare_other_answers_are_intercepted(answer: RawAnswer, response: str) -> None:
    check = classify_cloudflare(answer)

    assert check.verdict is Verdict.SUSPECT
    assert check.summary == f"intercepted: got {response}"


def test_no_response_is_unknown_not_intercepted() -> None:
    for check in (
        classify_google(RawAnswer(None, error="no response")),
        classify_cloudflare(RawAnswer(None, error="no response")),
    ):
        assert check.verdict is Verdict.UNKNOWN
        assert check.summary == "couldn't tell (no response)"


def test_the_checks_ask_the_right_server_for_the_right_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = []

    def fake_ask(nameserver, name, rdtype, timeout, rdclass="IN"):
        asked.append((nameserver, name, rdtype, rdclass))
        return RawAnswer(None, (), "timed out")

    monkeypatch.setattr(integrity_mod, "ask", fake_ask)

    integrity_mod.check_nxdomain("192.0.2.53", 1.0, name="dnskit-nx-test.com")
    integrity_mod.check_google(1.0)
    integrity_mod.check_cloudflare(1.0)

    assert asked == [
        ("192.0.2.53", "dnskit-nx-test.com", "A", "IN"),
        ("8.8.8.8", "o-o.myaddr.l.google.com", "TXT", "IN"),
        ("1.1.1.1", "whoami.cloudflare", "TXT", "CH"),
    ]


def test_a_made_up_name_is_random_and_under_com() -> None:
    first, second = integrity_mod.probe_name(), integrity_mod.probe_name()

    assert first != second
    assert first.startswith("dnskit-nx-") and first.endswith(".com")
