import importlib
import time
from types import SimpleNamespace

import dns.exception
import dns.message
import pytest

from dnskit.core import DnsBlocking, LookupResult, LookupStatus, Record
from dnskit.core.trace import (
    ROOT_SERVERS,
    FailReason,
    StepStatus,
    TraceMode,
    explain_trace,
    level_name,
    trace,
    trace_blocked_diagnosis,
)
from fakes import FakeNetwork, question, reply, rrset

trace_mod = importlib.import_module("dnskit.core.trace")

ROOT_ADDRESSES = [address for _, address in ROOT_SERVERS]
TLD = {"a.gtld-servers.net.": "192.0.2.10", "b.gtld-servers.net.": "192.0.2.11"}
AUTH = {"ns1.example.com.": "192.0.2.20", "ns2.example.com.": "192.0.2.21"}
VPN_BLOCKING = DnsBlocking(("192.0.2.53",), ("OfficeVPN",), local_firewall=False)
OFFLINE = DnsBlocking((), (), local_firewall=False)


def referral(zone: str, servers: dict[str, str], glue: bool = True):
    def handler(query: dns.message.Message) -> dns.message.Message:
        return reply(
            query,
            authority=[rrset(zone, "NS", *servers)],
            additional=[rrset(ns, "A", ip) for ns, ip in servers.items()] if glue else [],
        )

    return handler


def authoritative(query: dns.message.Message) -> dns.message.Message:
    name, rtype = question(query)
    if name == "www.example.com." and rtype == "A":
        return reply(query, answer=[rrset(name, "CNAME", "example.com.")], aa=True)
    if name == "example.com." and rtype == "A":
        return reply(query, answer=[rrset(name, "A", "192.0.2.80")], aa=True)
    soa = rrset("example.com.", "SOA", "ns1.example.com. admin.example.com. 1 2 3 4 5")
    if name in ("example.com.", "www.example.com."):
        return reply(query, authority=[soa], aa=True)  # exists, but no records of this type
    return reply(query, authority=[soa], rcode="NXDOMAIN", aa=True)


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """A working delegation: root -> com. -> example.com., all with glue.

    Knobs: `network.handlers` (per address), `blocking` (what check_blocking returns),
    `addresses` (name -> A record for nameservers without glue). Records `blocking_calls`.
    """
    network = FakeNetwork()
    for address in ROOT_ADDRESSES:
        network.handlers[address] = referral("com.", TLD)
    for address in TLD.values():
        network.handlers[address] = referral("example.com.", AUTH)
    for address in AUTH.values():
        network.handlers[address] = authoritative
    state = SimpleNamespace(network=network, blocking=VPN_BLOCKING, blocking_calls=0, addresses={})

    def fake_check_blocking() -> DnsBlocking:
        state.blocking_calls += 1
        return state.blocking

    def fake_query_one(name: str, rtype: str, nameservers: list[str], timeout: float):
        address = state.addresses.get(name)
        if address is None:
            return LookupResult(rtype, LookupStatus.NXDOMAIN)
        return LookupResult(rtype, LookupStatus.OK, (Record(address, 300),))

    monkeypatch.setattr(trace_mod, "_send", network)
    monkeypatch.setattr(trace_mod, "check_blocking", fake_check_blocking)
    monkeypatch.setattr(trace_mod, "_query_one", fake_query_one)
    monkeypatch.setattr(trace_mod, "system_nameservers", lambda: ["192.0.2.53"])
    return state


def test_follows_the_delegation_from_the_root(net: SimpleNamespace) -> None:
    report = trace("example.com")

    assert report.mode is TraceMode.DIRECT
    assert report.name == "example.com."
    assert [s.zone for s in report.steps] == [".", "com.", "example.com."]
    assert [s.status for s in report.steps] == [
        StepStatus.REFERRAL,
        StepStatus.REFERRAL,
        StepStatus.ANSWER,
    ]
    root, tld, auth = report.steps
    assert root.server is not None and root.server.address in ROOT_ADDRESSES[:3]  # first wins
    assert root.referral_zone == "com."
    assert root.referral_servers == ("a.gtld-servers.net.", "b.gtld-servers.net.")
    assert tld.server is not None and tld.server.address in TLD.values()
    assert auth.records == ("192.0.2.80",)
    assert report.succeeded
    assert explain_trace(report) is None
    assert net.blocking_calls == 0
    # Iterative: every query went straight to that level's servers, without recursion.
    assert {address for address, _, _ in net.network.sent} <= {
        *ROOT_ADDRESSES,
        *TLD.values(),
        *AUTH.values(),
    }


def test_shows_cnames_in_the_answer(net: SimpleNamespace) -> None:
    report = trace("www.example.com")

    assert report.final.status is StepStatus.ANSWER
    assert report.final.records == ("CNAME example.com.",)


def test_a_dead_server_is_noted_when_another_answers(net: SimpleNamespace) -> None:
    del net.network.handlers["192.0.2.10"]  # a.gtld-servers.net times out
    # The fake timeout is instant; delay b's reply so the failure is in before b wins the level
    # (otherwise the parallel race decides whether it's noted).
    answer = net.network.handlers["192.0.2.11"]
    net.network.handlers["192.0.2.11"] = lambda query: (time.sleep(0.2), answer(query))[1]

    report = trace("example.com")

    tld = report.steps[1]
    assert tld.status is StepStatus.REFERRAL
    assert tld.server is not None and tld.server.address == "192.0.2.11"
    assert [(f.server.name, f.error) for f in tld.failures] == [
        ("a.gtld-servers.net.", "timed out")
    ]


def test_nxdomain_from_the_authoritative_servers(net: SimpleNamespace) -> None:
    report = trace("missing.example.com")

    assert report.final.status is StepStatus.NXDOMAIN
    assert report.final.zone == "example.com."
    assert not report.succeeded
    diagnosis = explain_trace(report)
    assert diagnosis is not None and diagnosis.title == "The name doesn't exist"
    assert "final word" in diagnosis.explanation
    assert "DNS host for example.com" in diagnosis.suggestion


def test_nxdomain_from_the_tld_means_the_domain_isnt_registered(net: SimpleNamespace) -> None:
    def tld(query: dns.message.Message) -> dns.message.Message:
        soa = rrset("com.", "SOA", "a.gtld-servers.net. nstld.verisign-grs.com. 1 2 3 4 5")
        return reply(query, authority=[soa], rcode="NXDOMAIN", aa=True)

    for address in TLD.values():
        net.network.handlers[address] = tld

    report = trace("unregistered.com")

    assert report.final.status is StepStatus.NXDOMAIN
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "isn't registered" in diagnosis.suggestion
    assert "WHOIS" in diagnosis.suggestion


def test_no_records_of_the_type(net: SimpleNamespace) -> None:
    report = trace("example.com", "MX")

    assert report.final.status is StepStatus.NO_ANSWER
    diagnosis = explain_trace(report)
    assert diagnosis is not None and diagnosis.title == "No MX records"


def test_refusing_nameservers_are_a_lame_delegation(net: SimpleNamespace) -> None:
    for address in AUTH.values():
        net.network.handlers[address] = lambda q: reply(q, rcode="REFUSED")

    report = trace("example.com")

    step = report.final
    assert step.status is StepStatus.FAILED
    assert step.zone == "example.com."
    assert step.reason is FailReason.REFUSED
    assert {f.error for f in step.failures} == {"REFUSED"}
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "lame delegation" in diagnosis.title
    assert "registrar" in diagnosis.suggestion
    assert net.blocking_calls == 0  # the root answered: nothing is blocked


def test_a_reply_without_records_or_referral_is_lame(net: SimpleNamespace) -> None:
    for address in AUTH.values():
        net.network.handlers[address] = lambda q: reply(q)  # not authoritative, no referral

    report = trace("example.com")

    assert report.final.status is StepStatus.FAILED
    assert report.final.reason is FailReason.LAME


def test_an_upward_referral_is_not_followed(net: SimpleNamespace) -> None:
    for address in AUTH.values():
        net.network.handlers[address] = referral("com.", TLD)  # back up the tree

    report = trace("example.com")

    assert report.final.status is StepStatus.FAILED
    assert report.final.reason is FailReason.LAME
    assert len(report.steps) == 3


def test_silent_domain_nameservers_are_the_domains_problem(net: SimpleNamespace) -> None:
    for address in AUTH.values():
        del net.network.handlers[address]

    report = trace("example.com", timeout=1.5)

    step = report.final
    assert step.status is StepStatus.FAILED
    assert step.reason is FailReason.NO_RESPONSE
    diagnosis = explain_trace(report)
    assert diagnosis is not None
    assert diagnosis.title == "example.com's nameservers didn't respond"
    assert "within 1.5 s" in diagnosis.explanation
    assert "your connection is fine" in diagnosis.explanation
    assert net.blocking_calls == 0


def test_servfail_from_the_domains_nameservers(net: SimpleNamespace) -> None:
    for address in AUTH.values():
        net.network.handlers[address] = lambda q: reply(q, rcode="SERVFAIL")

    report = trace("example.com")

    assert report.final.reason is FailReason.SERVFAIL
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "server failure" in diagnosis.title


def test_nameservers_without_glue_are_looked_up(net: SimpleNamespace) -> None:
    outside = {"ns1.dnshost.net.": "192.0.2.30", "ns2.dnshost.net.": "192.0.2.31"}
    for address in TLD.values():
        net.network.handlers[address] = referral("example.com.", outside, glue=False)
    for address in outside.values():
        net.network.handlers[address] = authoritative
    net.addresses = dict(outside)

    report = trace("example.com")

    assert report.succeeded
    assert report.steps[1].note.startswith("no glue")
    assert report.final.server is not None and report.final.server.address in outside.values()


def test_nameservers_with_no_address_fail_the_level(net: SimpleNamespace) -> None:
    outside = {"ns1.gone.net.": "", "ns2.gone.net.": ""}
    for address in TLD.values():
        net.network.handlers[address] = referral("example.com.", outside, glue=False)

    report = trace("example.com")

    step = report.final
    assert step.status is StepStatus.FAILED
    assert step.zone == "example.com."
    assert step.reason is FailReason.NO_ADDRESS
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "have no address" in diagnosis.title
    assert "ns1.gone.net" in diagnosis.explanation


def test_blocked_root_servers_trace_through_the_resolver(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        del net.network.handlers[address]

    def resolver(query: dns.message.Message) -> dns.message.Message:
        name, rtype = question(query)
        if rtype == "NS" and name == "com.":
            return reply(query, answer=[rrset(name, "NS", *TLD)])
        if rtype == "NS" and name == "example.com.":
            return reply(query, answer=[rrset(name, "NS", *AUTH)])
        if name == "example.com." and rtype == "A":
            return reply(query, answer=[rrset(name, "A", "192.0.2.80")])
        return reply(query)

    net.network.handlers["192.0.2.53"] = resolver

    report = trace("example.com")

    assert net.blocking_calls == 1
    assert report.mode is TraceMode.VIA_RESOLVER
    assert report.resolver == "192.0.2.53"
    assert [(s.zone, s.status) for s in report.steps] == [
        (".", StepStatus.REFERRAL),
        ("com.", StepStatus.REFERRAL),
        ("example.com.", StepStatus.ANSWER),
    ]
    assert report.steps[1].referral_servers == tuple(AUTH)
    assert report.succeeded
    assert explain_trace(report) is None
    blocked = trace_blocked_diagnosis(report)
    assert blocked is not None and blocked.title == "Direct DNS queries are blocked by the VPN"
    assert "OfficeVPN" in blocked.explanation and "the root servers" in blocked.explanation
    assert "through 192.0.2.53" in blocked.suggestion


def test_via_resolver_nxdomain(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        del net.network.handlers[address]

    def resolver(query: dns.message.Message) -> dns.message.Message:
        name, rtype = question(query)
        if rtype == "NS" and name == "com.":
            return reply(query, answer=[rrset(name, "NS", *TLD)])
        return reply(query, rcode="NXDOMAIN")

    net.network.handlers["192.0.2.53"] = resolver

    report = trace("unregistered.com")

    assert report.mode is TraceMode.VIA_RESOLVER
    assert report.final.status is StepStatus.NXDOMAIN
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "192.0.2.53" in diagnosis.explanation


def test_unreachable_root_servers_while_offline(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        net.network.handlers[address] = lambda q: OSError(10051, "unreachable")
    net.blocking = OFFLINE

    report = trace("example.com")

    assert report.mode is TraceMode.DIRECT
    step = report.final
    assert step.status is StepStatus.FAILED and step.zone == "."
    assert {f.error for f in step.failures} == {"no route to it"}
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "offline" in diagnosis.title


def test_firewall_refusal_is_named(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        net.network.handlers[address] = lambda q: PermissionError(13, "denied")
    net.blocking = OFFLINE

    report = trace("example.com")

    assert {f.error for f in report.final.failures} == {"blocked by a firewall on this computer"}


def test_at_most_a_few_servers_per_level_are_asked(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        del net.network.handlers[address]
    net.blocking = OFFLINE

    trace("example.com")

    roots_asked = {a for a, _, _ in net.network.sent if a in ROOT_ADDRESSES}
    assert len(roots_asked) == trace_mod.SERVERS_PER_LEVEL


@pytest.mark.parametrize(("target", "rtype"), [("not a domain!", "A"), ("example.com", "NOTATYPE")])
def test_invalid_input_raises(net: SimpleNamespace, target: str, rtype: str) -> None:
    with pytest.raises(ValueError, match=r"is not a valid domain name|Unknown record type"):
        trace(target, rtype)
    assert net.network.sent == []


def test_level_names() -> None:
    assert level_name(".") == "the root"
    assert level_name("com.") == "the .com top-level domain"
    assert level_name("example.com.") == "example.com"


def test_timeout_errors_count_as_no_response() -> None:
    server = trace_mod.Server("x.", "192.0.2.1")

    def boom(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
        raise dns.exception.Timeout

    original = trace_mod._send
    trace_mod._send = boom
    try:
        result = trace_mod._ask(server, "example.com.", "A", 1.0, recursive=False)
    finally:
        trace_mod._send = original
    assert result.failure is not None and result.failure.reason is FailReason.NO_RESPONSE


# --- Edge cases --------------------------------------------------------------------------------


def blocked_roots(net: SimpleNamespace, resolver) -> None:
    """Root servers silent; this computer's resolver (192.0.2.53) answers with `resolver`."""
    for address in ROOT_ADDRESSES:
        del net.network.handlers[address]
    net.network.handlers["192.0.2.53"] = resolver


def test_via_resolver_silent_is_explained(net: SimpleNamespace) -> None:
    blocked_roots(net, lambda q: dns.exception.Timeout())

    report = trace("example.com")

    assert report.mode is TraceMode.VIA_RESOLVER
    assert (report.final.zone, report.final.status) == (".", StepStatus.FAILED)
    assert report.final.reason is FailReason.NO_RESPONSE
    diagnosis = explain_trace(report)
    assert diagnosis is not None
    assert diagnosis.title.startswith("The resolver couldn't follow")
    assert "192.0.2.53 failed" in diagnosis.explanation


@pytest.mark.parametrize(("rcode", "reason"), [("SERVFAIL", "servfail"), ("REFUSED", "refused")])
def test_via_resolver_error_at_a_level(net: SimpleNamespace, rcode: str, reason: str) -> None:
    def resolver(query: dns.message.Message) -> dns.message.Message:
        name, rtype = question(query)
        if rtype == "NS" and name == "com.":
            return reply(query, answer=[rrset(name, "NS", *TLD)])
        return reply(query, rcode=rcode)

    blocked_roots(net, resolver)

    report = trace("example.com")

    assert [s.status for s in report.steps] == [StepStatus.REFERRAL, StepStatus.FAILED]
    assert report.final.zone == "com."
    assert report.final.reason.value == reason


def via_resolver_final(answer):
    """A resolver that delegates normally and answers the final A query with `answer`."""

    def resolver(query: dns.message.Message) -> dns.message.Message:
        name, rtype = question(query)
        if rtype == "NS" and name == "com.":
            return reply(query, answer=[rrset(name, "NS", *TLD)])
        if rtype == "NS" and name == "example.com.":
            return reply(query, answer=[rrset(name, "NS", *AUTH)])
        return answer(query)

    return resolver


@pytest.mark.parametrize(
    ("final", "status", "reason"),
    [
        (lambda q: dns.exception.Timeout(), StepStatus.FAILED, FailReason.NO_RESPONSE),
        (lambda q: reply(q, rcode="SERVFAIL"), StepStatus.FAILED, FailReason.SERVFAIL),
        (lambda q: reply(q, rcode="REFUSED"), StepStatus.FAILED, FailReason.REFUSED),
        (lambda q: reply(q, rcode="NXDOMAIN"), StepStatus.NXDOMAIN, None),
        (lambda q: reply(q), StepStatus.NO_ANSWER, None),
    ],
)
def test_via_resolver_final_query(net: SimpleNamespace, final, status, reason) -> None:
    blocked_roots(net, via_resolver_final(final))

    report = trace("example.com")

    assert (report.final.zone, report.final.status) == ("example.com.", status)
    assert report.final.reason is reason


def test_via_resolver_stops_delegating_at_an_alias(net: SimpleNamespace) -> None:
    def resolver(query: dns.message.Message) -> dns.message.Message:
        name, rtype = question(query)
        if rtype == "NS" and name == "com.":
            return reply(query, answer=[rrset(name, "NS", *TLD)])
        if name == "alias.com.":
            target = [rrset(name, "CNAME", "example.com.")]
            if rtype == "A":
                target.append(rrset("example.com.", "A", "192.0.2.80"))
            return reply(query, answer=target)
        return reply(query)

    blocked_roots(net, resolver)

    report = trace("alias.com")

    assert [s.zone for s in report.steps] == [".", "com."]
    assert report.final.records == ("CNAME example.com.", "192.0.2.80")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (ConnectionResetError(104, "reset by peer"), "reset by peer"),
        (dns.exception.FormError("bad reply"), "bad reply"),
    ],
)
def test_other_failures_are_described(net: SimpleNamespace, error: Exception, message: str) -> None:
    for address in TLD.values():
        net.network.handlers[address] = lambda q, error=error: error

    report = trace("example.com")

    assert report.final.status is StepStatus.FAILED
    assert any(message in f.error for f in report.final.failures)


def test_too_many_referrals_stop(net: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trace_mod, "MAX_STEPS", 2)

    report = trace("example.com")

    assert [s.status for s in report.steps] == [
        StepStatus.REFERRAL,
        StepStatus.REFERRAL,
        StepStatus.FAILED,
    ]
    assert report.final.reason is FailReason.TOO_DEEP
    diagnosis = explain_trace(report)
    assert diagnosis is not None and "After 2 levels" in diagnosis.explanation


def test_glueless_nameservers_without_system_dns(
    net: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    for address in TLD.values():
        net.network.handlers[address] = referral("example.com.", AUTH, glue=False)
    monkeypatch.setattr(trace_mod, "system_nameservers", list)

    report = trace("example.com")

    assert report.final.reason is FailReason.NO_ADDRESS


def test_a_top_level_domain_that_doesnt_exist(net: SimpleNamespace) -> None:
    for address in ROOT_ADDRESSES:
        net.network.handlers[address] = lambda q: reply(q, rcode="NXDOMAIN")

    report = trace("example.notatld")

    assert (report.final.zone, report.final.status) == (".", StepStatus.NXDOMAIN)
    diagnosis = explain_trace(report)
    assert diagnosis is not None
    assert (
        diagnosis.suggestion == "Check the spelling: .notatld isn't a top-level domain that exists."
    )


@pytest.mark.parametrize("module", ["dnskit.core.trace", "dnskit.core.dnssec"])
def test_send_uses_udp_with_tcp_fallback(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    mod = importlib.import_module(module)
    sent = []
    answer = dns.message.make_response(dns.message.make_query("example.com.", "A"))

    def fake(query, address, timeout):
        sent.append((address, timeout))
        return answer, True

    monkeypatch.setattr(mod.dns.query, "udp_with_fallback", fake)

    assert mod._send(dns.message.make_query("example.com.", "A"), "192.0.2.53", 2.0) is answer
    assert sent == [("192.0.2.53", 2.0)]
