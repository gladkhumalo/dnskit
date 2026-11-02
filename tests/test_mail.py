import base64
import importlib
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from dnskit.core import (
    DKIM_SELECTORS,
    CheckStatus,
    EmailReport,
    EmailSection,
    Finding,
    LookupStatus,
    email_check,
    normalize_domain,
)
from fakes import FakeAnswer, no_nameservers

mail_mod = importlib.import_module("dnskit.core.mail")

DOMAIN = "example.com"
RSA_OID = bytes.fromhex("2a864886f70d010101")


def txt(*values: str) -> FakeAnswer:
    """A TXT answer as dnspython prints it: each record a quoted string."""
    return FakeAnswer([f'"{v}"' for v in values], 300)


def der(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    size = (len(content).bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + len(content).to_bytes(size) + content


def rsa_key(bits: int, spki: bool = True) -> str:
    """A base64 RSA public key with a `bits`-bit modulus, as published in DKIM records."""
    modulus = ((1 << (bits - 1)) | 1).to_bytes(bits // 8)
    rsa = der(0x30, der(0x02, b"\x00" + modulus) + der(0x02, b"\x01\x00\x01"))
    if spki:
        algorithm = der(0x30, der(0x06, RSA_OID) + der(0x05, b""))
        rsa = der(0x30, algorithm + der(0x03, b"\x00" + rsa))
    return base64.b64encode(rsa).decode()


def dkim(bits: int = 2048) -> FakeAnswer:
    return txt(f"v=DKIM1; k=rsa; p={rsa_key(bits)}")


def healthy(env: SimpleNamespace) -> None:
    """A domain where every check passes."""
    env.responses = {
        (DOMAIN, "MX"): FakeAnswer(["10 mx1.example.com.", "20 mx2.example.com."], 300),
        ("mx1.example.com", "A"): FakeAnswer(["192.0.2.10"], 300),
        ("mx2.example.com", "A"): FakeAnswer(["192.0.2.20"], 300),
        ("mx2.example.com", "AAAA"): FakeAnswer(["2001:db8::20"], 300),
        (DOMAIN, "TXT"): txt("google-site-verification=abc", "v=spf1 include:_spf.mail.test ~all"),
        ("_spf.mail.test", "TXT"): txt("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"),
        (f"_dmarc.{DOMAIN}", "TXT"): txt("v=DMARC1; p=reject; rua=mailto:d@example.com"),
        (f"google._domainkey.{DOMAIN}", "TXT"): dkim(),
    }


def set_spf(env: SimpleNamespace, *records: str) -> None:
    env.responses[(DOMAIN, "TXT")] = txt(*records)


def set_dmarc(env: SimpleNamespace, *records: str) -> None:
    env.responses[(f"_dmarc.{DOMAIN}", "TXT")] = txt(*records)


def titles(section: EmailSection | None) -> list[tuple[CheckStatus, str]]:
    assert section is not None
    return [(f.status, f.title) for f in section.findings]


def finding(section: EmailSection | None, status: CheckStatus) -> Finding:
    assert section is not None
    return next(f for f in section.findings if f.status is status)


def check(**kwargs: object) -> EmailReport:
    return email_check(DOMAIN, **kwargs)  # type: ignore[arg-type]


# --- Input validation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("mail.example.co.za", "mail.example.co.za"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_normalize_domain(text: str, expected: str) -> None:
    assert normalize_domain(text) == expected


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "not a valid domain"),
        ("localhost", "not a valid domain"),
        ("exa mple.com", "not a valid domain"),
        ("-bad.example.com", "not a valid domain"),
        ("a..b.com", "not a valid domain"),
        ("user@example.com", "looks like an email address"),
        ("https://example.com/", "without http://"),
    ],
)
def test_normalize_domain_rejects_invalid(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_domain(text)


def test_invalid_input_never_queries(env: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="is not a valid domain name"):
        email_check("not a domain")
    with pytest.raises(ValueError, match="not a valid DKIM selector"):
        email_check(DOMAIN, selectors=["bad selector"])
    with pytest.raises(ValueError, match="just the DKIM selector"):
        email_check(DOMAIN, selectors=["s1._domainkey.example.com"])

    assert env.queried == []
    assert env.choose_calls == []


# --- Overall -------------------------------------------------------------------------------


def test_healthy_domain_passes(env: SimpleNamespace) -> None:
    healthy(env)

    report = check()

    assert report.domain_status is LookupStatus.OK
    assert [(label, s.status) for label, s in report.checks] == [
        ("MX", CheckStatus.PASS),
        ("SPF", CheckStatus.PASS),
        ("DMARC", CheckStatus.PASS),
        ("DKIM", CheckStatus.PASS),
    ]
    assert report.status is CheckStatus.PASS
    assert not report.failed
    assert report.nameserver == "192.0.2.2"  # the fastest in the env fixture's choice
    expected = {
        (DOMAIN, "MX"),
        (DOMAIN, "TXT"),
        (f"_dmarc.{DOMAIN}", "TXT"),
        ("mx1.example.com", "A"),
        ("mx1.example.com", "AAAA"),
        ("_spf.mail.test", "TXT"),
        *((f"{s}._domainkey.{DOMAIN}", "TXT") for s in DKIM_SELECTORS),
    }
    assert expected <= set(env.queried)


def test_explicit_server_and_refresh(env: SimpleNamespace) -> None:
    healthy(env)

    report = check(nameserver="198.51.100.53")
    check(refresh=True)

    assert report.nameserver == "198.51.100.53"
    assert report.nameserver_source == "--server"
    assert report.resolver_choice is None
    assert env.choose_calls == [False]  # only the second call chose, and it re-probed


def test_domain_that_does_not_exist(env: SimpleNamespace) -> None:
    env.responses = {"MX": dns.resolver.NXDOMAIN(), "TXT": dns.resolver.NXDOMAIN()}

    report = check()

    assert report.domain_status is LookupStatus.NXDOMAIN
    assert report.checks == ()
    assert report.failed
    assert ("mx1.example.com", "A") not in env.queried


def test_every_query_timing_out_is_one_failure(env: SimpleNamespace) -> None:
    env.responses = {"MX": dns.exception.Timeout(), "TXT": dns.exception.Timeout()}

    report = check()

    assert report.domain_status is LookupStatus.TIMEOUT
    assert report.checks == ()
    assert report.failed


# --- MX ------------------------------------------------------------------------------------


def test_mx_lists_hosts_by_priority_with_addresses(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["20 mx2.example.com.", "10 MX1.example.com."], 1)

    mx = check().mx

    assert mx is not None
    assert [(h.preference, h.host, h.addresses) for h in mx.hosts] == [
        (10, "mx1.example.com", ("192.0.2.10",)),
        (20, "mx2.example.com", ("192.0.2.20", "2001:db8::20")),
    ]
    assert titles(mx) == [(CheckStatus.PASS, "2 mail servers, all with IP addresses")]
    assert "goes to mx1.example.com first" in mx.findings[0].explanation


def test_no_mx_records_fails(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[(DOMAIN, "MX")]

    mx = check().mx

    assert titles(mx) == [(CheckStatus.FAIL, "No MX records")]
    assert "null MX" in mx.findings[0].fix  # type: ignore[union-attr]


def test_null_mx_passes_without_resolving_hosts(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["0 ."], 300)

    mx = check().mx

    assert mx is not None and mx.null_mx
    assert titles(mx) == [(CheckStatus.PASS, "Doesn't accept email (null MX)")]
    assert not any(rtype in ("A", "AAAA") for _, rtype in env.queried)


def test_null_mx_with_real_mx_fails(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["0 .", "10 mx1.example.com."], 300)

    assert titles(check().mx) == [(CheckStatus.FAIL, "Null MX mixed with real mail servers")]


def test_some_mail_servers_without_address_warns(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[("mx2.example.com", "A")] = dns.resolver.NXDOMAIN()
    env.responses[("mx2.example.com", "AAAA")] = dns.resolver.NXDOMAIN()

    mx = check().mx

    assert mx is not None
    assert mx.hosts[1].lookup_status is LookupStatus.NXDOMAIN
    assert titles(mx) == [(CheckStatus.WARN, "1 mail server of 2 has no IP address")]
    assert "mx2.example.com: the name doesn't exist" in mx.findings[0].explanation


def test_no_mail_server_with_address_fails(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[("mx1.example.com", "A")]
    env.responses[("mx2.example.com", "A")] = dns.exception.Timeout()
    env.responses[("mx2.example.com", "AAAA")] = dns.exception.Timeout()

    mx = check().mx

    assert titles(mx) == [(CheckStatus.FAIL, "No mail server has an IP address")]
    explanation = mx.findings[0].explanation  # type: ignore[union-attr]
    assert "mx1.example.com: no A or AAAA record" in explanation
    assert "mx2.example.com: lookup failed (timeout)" in explanation


def test_mx_pointing_at_ip_address_fails(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["10 192.0.2.25."], 300)

    mx = check().mx

    assert titles(mx) == [(CheckStatus.FAIL, "MX record points at an IP address")]
    assert ("192.0.2.25", "A") not in env.queried


def test_mx_lookup_failure_fails_only_mx(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "MX")] = no_nameservers("SERVFAIL")

    report = check()

    assert report.domain_status is LookupStatus.OK
    assert titles(report.mx) == [
        (CheckStatus.FAIL, "Couldn't check MX: nameserver failure (SERVFAIL)")
    ]
    assert report.spf is not None and report.spf.status is CheckStatus.PASS


# --- SPF -----------------------------------------------------------------------------------


def test_spf_counts_lookups_through_includes(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 a mx include:_spf.mail.test include:other.test ~all")
    env.responses[("other.test", "TXT")] = txt("v=spf1 include:deep.other.test exists:x.test -all")
    env.responses[("deep.other.test", "TXT")] = txt("v=spf1 ptr:host.test ip4:192.0.2.1 -all")

    spf = check().spf

    assert spf is not None
    assert [(lk.term, lk.source, lk.depth) for lk in spf.lookups] == [
        ("a", DOMAIN, 0),
        ("mx", DOMAIN, 0),
        ("include:_spf.mail.test", DOMAIN, 0),
        ("include:other.test", DOMAIN, 0),
        ("include:deep.other.test", "other.test", 1),
        ("ptr:host.test", "deep.other.test", 2),
        ("exists:x.test", "other.test", 1),
    ]
    assert spf.lookup_count == 7
    assert spf.complete
    assert finding(spf, CheckStatus.PASS).explanation.startswith(
        "7 of 10 DNS lookups. Ends with ~all"
    )


def test_spf_over_ten_lookups_fails(env: SimpleNamespace) -> None:
    healthy(env)
    includes = " ".join(f"include:s{i}.mail.test" for i in range(6))
    set_spf(env, f"v=spf1 {includes} ~all")
    for i in range(6):
        env.responses[(f"s{i}.mail.test", "TXT")] = txt("v=spf1 a -all")

    spf = check().spf

    assert spf is not None and spf.lookup_count == 12
    assert titles(spf) == [(CheckStatus.FAIL, "Too many DNS lookups (12 of 10)")]


def test_spf_include_counted_each_time_and_loops_stop(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 include:a.test include:b.test -all")
    env.responses[("a.test", "TXT")] = txt("v=spf1 include:b.test -all")
    env.responses[("b.test", "TXT")] = txt("v=spf1 mx include:a.test -all")

    spf = check().spf

    assert spf is not None
    # a.test -> b.test -> (a.test again: a loop, not expanded), then b.test -> a.test -> ...
    assert [lk.term for lk in spf.lookups] == [
        "include:a.test",
        "include:b.test",
        "mx",
        "include:a.test",
        "include:b.test",
        "mx",
        "include:a.test",
        "include:b.test",
    ]
    assert sorted(q for q in env.queried if q[0] in ("a.test", "b.test")) == [
        ("a.test", "TXT"),
        ("b.test", "TXT"),
    ]


def test_spf_redirect_is_followed_and_counted(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 redirect=_spf.mail.test")

    spf = check().spf

    assert spf is not None
    assert [lk.term for lk in spf.lookups] == ["redirect=_spf.mail.test"]
    assert titles(spf) == [(CheckStatus.PASS, "SPF record is valid")]
    assert "Uses _spf.mail.test's SPF policy (redirect)" in spf.findings[0].explanation


def test_spf_record_split_into_strings_is_joined(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "TXT")] = FakeAnswer(['"v=spf1 include:_spf.mail.test " "-all"'], 1)

    spf = check().spf

    assert spf is not None
    assert spf.records == ("v=spf1 include:_spf.mail.test -all",)
    assert spf.status is CheckStatus.PASS


def test_missing_spf_suggests_provider_include(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "some-verification=1")
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["1 smtp.google.com."], 300)
    env.responses[("smtp.google.com", "A")] = FakeAnswer(["192.0.2.30"], 300)

    spf = check().spf

    assert titles(spf) == [(CheckStatus.FAIL, "No SPF record")]
    assert "v=spf1 include:_spf.google.com ~all" in spf.findings[0].fix  # type: ignore[union-attr]


def test_missing_spf_on_null_mx_domain_suggests_dash_all(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[(DOMAIN, "TXT")]
    env.responses[(DOMAIN, "MX")] = FakeAnswer(["0 ."], 300)

    spf = check().spf

    assert "v=spf1 -all" in finding(spf, CheckStatus.FAIL).fix


def test_multiple_spf_records_fail(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 include:_spf.mail.test ~all", "v=spf1 ip4:192.0.2.1 -all")

    spf = check().spf

    assert titles(spf) == [(CheckStatus.FAIL, "2 SPF records (only one is allowed)")]
    assert ("_spf.mail.test", "TXT") not in env.queried


@pytest.mark.parametrize(
    ("record", "error"),
    [
        ("v=spf1 inclde:_spf.mail.test ~all", "Unknown term 'inclde:_spf.mail.test'"),
        ("v=spf1 ipv4:192.0.2.1 ~all", "(did you mean ip4?)"),
        ("v=spf1 ip4:192.0.2.300 ~all", "isn't a valid IPv4 address or range"),
        ("v=spf1 ip4:2001:db8::1 ~all", "isn't a valid IPv4 address or range"),
        ("v=spf1 ip6:192.0.2.1 ~all", "isn't a valid IPv6 address or range"),
        ("v=spf1 include ~all", "'include' needs a domain"),
        ("v=spf1 include:nodot ~all", "'include:nodot' needs a domain"),
        ("v=spf1 a/33 ~all", "isn't a valid a mechanism"),
        ("v=spf1 mx:example.com/24//129 ~all", "isn't a valid mx mechanism"),
        ("v=spf1 -all:foo", "all takes no value"),
        ("v=spf1 redirect=a.test redirect=b.test", "'redirect=' appears more than once"),
    ],
)
def test_spf_syntax_errors_fail(env: SimpleNamespace, record: str, error: str) -> None:
    healthy(env)
    set_spf(env, record)

    spf = check().spf

    failure = finding(spf, CheckStatus.FAIL)
    assert failure.title == "SPF record has syntax errors"
    assert error in failure.explanation


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 a:mail.example.com/24 mx//64 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
        "v=spf1 ?include:_spf.mail.test exists:%{i}._spf.example.com ~all",
        "V=SPF1 +MX -ALL",
        "v=spf1 -all exp=explain.example.com",
    ],
)
def test_valid_spf_syntax_passes(env: SimpleNamespace, record: str) -> None:
    healthy(env)
    set_spf(env, record)

    assert check().spf.status is CheckStatus.PASS  # type: ignore[union-attr]


def test_spf_macro_include_is_not_followed(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 include:%{d}.spf.example.com -all")

    spf = check().spf

    assert spf is not None and spf.lookup_count == 1
    assert not any("%" in name for name, _ in env.queried)


@pytest.mark.parametrize(
    ("record", "status", "title"),
    [
        ("v=spf1 ip4:192.0.2.1 +all", CheckStatus.FAIL, "SPF allows anyone to send (+all)"),
        ("v=spf1 ip4:192.0.2.1 all", CheckStatus.FAIL, "SPF allows anyone to send (all)"),
        ("v=spf1 ip4:192.0.2.1 ?all", CheckStatus.WARN, "SPF ends with a neutral ?all"),
        ("v=spf1 ip4:192.0.2.1", CheckStatus.WARN, "SPF record doesn't end with all"),
        ("v=spf1 -all ip4:192.0.2.1", CheckStatus.WARN, "SPF terms after all are ignored"),
        ("v=spf1 ptr -all", CheckStatus.WARN, "SPF uses the deprecated ptr mechanism"),
        ("v=spf1 ip4:192.0.2.1 foo=bar -all", CheckStatus.WARN, "Unknown SPF modifier"),
    ],
)
def test_spf_policy_problems(
    env: SimpleNamespace, record: str, status: CheckStatus, title: str
) -> None:
    healthy(env)
    set_spf(env, record)

    spf = check().spf

    assert (status, title) in titles(spf)
    assert spf is not None and spf.status is status


@pytest.mark.parametrize(
    ("response", "title"),
    [
        (txt("not spf"), "include:_spf.mail.test has no SPF record"),
        (dns.resolver.NXDOMAIN(), "include:_spf.mail.test has no SPF record"),
        (txt("v=spf1 -all", "v=spf1 ~all"), "include:_spf.mail.test has 2 SPF records"),
        (txt("v=spf1 bogus -all"), "include:_spf.mail.test's SPF record is invalid"),
    ],
)
def test_broken_include_fails(env: SimpleNamespace, response: object, title: str) -> None:
    healthy(env)
    env.responses[("_spf.mail.test", "TXT")] = response  # type: ignore[assignment]

    spf = check().spf

    assert titles(spf) == [(CheckStatus.FAIL, title)]


def test_include_lookup_failure_warns_and_marks_count_incomplete(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[("_spf.mail.test", "TXT")] = dns.exception.Timeout()

    spf = check().spf

    assert spf is not None and not spf.complete
    assert titles(spf) == [
        (CheckStatus.PASS, "SPF record is valid"),
        (CheckStatus.WARN, "Couldn't check include:_spf.mail.test"),
    ]
    assert spf.findings[0].explanation.startswith("At least 1 of 10 DNS lookups")


def test_spf_lookup_failure_fails(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(DOMAIN, "TXT")] = dns.exception.Timeout()

    spf = check(timeout=3.0).spf

    failure = finding(spf, CheckStatus.FAIL)
    assert failure.title == "Couldn't check SPF: query timed out"
    assert "within 3 seconds" in failure.explanation


# --- DMARC ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "status", "title", "meaning"),
    [
        ("none", CheckStatus.WARN, "DMARC policy is monitoring only (p=none)", "monitoring only"),
        ("quarantine", CheckStatus.PASS, "DMARC policy: quarantine", "spam or junk folder"),
        ("reject", CheckStatus.PASS, "DMARC policy: reject", "refused outright"),
    ],
)
def test_dmarc_policy_is_explained(
    env: SimpleNamespace, policy: str, status: CheckStatus, title: str, meaning: str
) -> None:
    healthy(env)
    set_dmarc(env, f"v=DMARC1; p={policy}; rua=mailto:d@example.com")

    dmarc = check().dmarc

    assert dmarc is not None and dmarc.policy == policy
    assert titles(dmarc) == [(status, title)]
    assert meaning in dmarc.findings[0].explanation


def test_dmarc_subdomain_policy_is_mentioned(env: SimpleNamespace) -> None:
    healthy(env)
    set_dmarc(env, "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com")

    explanation = check().dmarc.findings[0].explanation  # type: ignore[union-attr]

    assert "Subdomains (sp=quarantine): mail that fails DMARC is put in the spam" in explanation


def test_missing_dmarc_fails(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(f"_dmarc.{DOMAIN}", "TXT")] = dns.resolver.NXDOMAIN()

    dmarc = check().dmarc

    assert titles(dmarc) == [(CheckStatus.FAIL, "No DMARC record")]
    assert "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com" in dmarc.findings[0].fix  # type: ignore[union-attr]


def test_multiple_dmarc_records_fail(env: SimpleNamespace) -> None:
    healthy(env)
    set_dmarc(env, "v=DMARC1; p=none", "v=DMARC1; p=reject")

    assert titles(check().dmarc) == [(CheckStatus.FAIL, "2 DMARC records (only one is allowed)")]


@pytest.mark.parametrize(
    ("record", "error"),
    [
        ("v=DMARC1; rua=mailto:d@example.com", "There's no policy (p=)"),
        ("v=DMARC1; p=block", "P=block isn't a policy"),
        ("v=DMARC1; p=reject; sp=maybe", "Sp=maybe isn't a policy"),
        ("v=DMARC1; p=reject; pct=150", "Pct=150 isn't a number from 0 to 100"),
        ("v=DMARC1; p=reject; oops", "'oops' isn't tag=value"),
    ],
)
def test_invalid_dmarc_fails(env: SimpleNamespace, record: str, error: str) -> None:
    healthy(env)
    set_dmarc(env, record)

    failure = finding(check().dmarc, CheckStatus.FAIL)

    assert failure.title == "DMARC record is invalid"
    assert error in failure.explanation


@pytest.mark.parametrize(
    ("record", "title"),
    [
        ("v=DMARC1; p=reject", "No DMARC report address (rua)"),
        (
            "v=DMARC1; p=reject; pct=25; rua=mailto:d@example.com",
            "DMARC policy applies to only 25% of mail",
        ),
        ("v=DMARC1; p=reject; rua=mailto:d@example.com; colour=blue", "Unknown DMARC tags"),
    ],
)
def test_dmarc_warnings(env: SimpleNamespace, record: str, title: str) -> None:
    healthy(env)
    set_dmarc(env, record)

    dmarc = check().dmarc

    assert titles(dmarc) == [(CheckStatus.PASS, "DMARC policy: reject"), (CheckStatus.WARN, title)]


# --- DKIM ----------------------------------------------------------------------------------


def test_dkim_key_found(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(f"selector1._domainkey.{DOMAIN}", "TXT")] = txt(f"p={rsa_key(2048, spki=False)}")

    dkim_check = check().dkim

    assert dkim_check is not None
    found = {s.selector: s.key_bits for s in dkim_check.selectors if s.found}
    assert found == {"google": 2048, "selector1": 2048}
    assert titles(dkim_check) == [(CheckStatus.PASS, "DKIM keys found")]
    assert "google (RSA 2048-bit), selector1 (RSA 2048-bit)" in dkim_check.findings[0].explanation


@pytest.mark.parametrize(
    ("bits", "status", "title"),
    [
        (1024, CheckStatus.WARN, "DKIM key at google is 1024-bit"),
        (512, CheckStatus.FAIL, "DKIM key at google is too short (512-bit)"),
    ],
)
def test_short_dkim_keys(env: SimpleNamespace, bits: int, status: CheckStatus, title: str) -> None:
    healthy(env)
    env.responses[(f"google._domainkey.{DOMAIN}", "TXT")] = dkim(bits)

    dkim_check = check().dkim

    assert (status, title) in titles(dkim_check)
    assert dkim_check is not None and dkim_check.status is status


def test_ed25519_dkim_key(env: SimpleNamespace) -> None:
    healthy(env)
    key = base64.b64encode(bytes(32)).decode()
    env.responses[(f"google._domainkey.{DOMAIN}", "TXT")] = txt(f"v=DKIM1; k=ed25519; p={key}")

    dkim_check = check().dkim

    assert titles(dkim_check) == [(CheckStatus.PASS, "DKIM key found")]
    assert "google (Ed25519)" in dkim_check.findings[0].explanation  # type: ignore[union-attr]


@pytest.mark.parametrize("key", ["not base64!", base64.b64encode(b"garbage").decode()])
def test_malformed_dkim_key_fails(env: SimpleNamespace, key: str) -> None:
    healthy(env)
    env.responses[(f"google._domainkey.{DOMAIN}", "TXT")] = txt(f"v=DKIM1; p={key}")

    assert titles(check().dkim) == [(CheckStatus.FAIL, "DKIM key at google is malformed")]


def test_revoked_dkim_key_warns(env: SimpleNamespace) -> None:
    healthy(env)
    env.responses[(f"google._domainkey.{DOMAIN}", "TXT")] = txt("v=DKIM1; p=")

    dkim_check = check().dkim

    assert dkim_check is not None and dkim_check.selectors[0].revoked
    assert titles(dkim_check) == [(CheckStatus.WARN, "DKIM key revoked")]


def test_no_dkim_at_common_selectors_warns(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[(f"google._domainkey.{DOMAIN}", "TXT")]
    # A wildcard SPF or DMARC record isn't a DKIM key.
    env.responses[(f"k1._domainkey.{DOMAIN}", "TXT")] = txt("v=DMARC1; p=reject")

    dkim_check = check().dkim

    assert titles(dkim_check) == [(CheckStatus.WARN, "No DKIM key at the common selectors")]
    assert "--selector" in dkim_check.findings[0].fix  # type: ignore[union-attr]


def test_domain_that_sends_no_mail_needs_no_dkim(env: SimpleNamespace) -> None:
    healthy(env)
    set_spf(env, "v=spf1 -all")
    env.responses[(f"google._domainkey.{DOMAIN}", "TXT")] = txt("v=DKIM1; p=")

    dkim_check = check().dkim

    assert titles(dkim_check) == [(CheckStatus.PASS, "No DKIM key needed")]


def test_custom_selector_is_checked(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[(f"google._domainkey.{DOMAIN}", "TXT")]
    env.responses[(f"s2024._domainkey.{DOMAIN}", "TXT")] = dkim()

    dkim_check = check(selectors=["s2024"]).dkim

    assert dkim_check is not None
    assert [s.selector for s in dkim_check.selectors] == [*DKIM_SELECTORS, "s2024"]
    assert dkim_check.selectors[-1].custom
    assert titles(dkim_check) == [(CheckStatus.PASS, "DKIM key found")]


def test_missing_custom_selector_fails(env: SimpleNamespace) -> None:
    healthy(env)

    dkim_check = check(selectors=["mine"]).dkim

    assert titles(dkim_check) == [
        (CheckStatus.PASS, "DKIM key found"),
        (CheckStatus.FAIL, "No DKIM key at selector mine"),
    ]


def test_dkim_lookup_failure_fails(env: SimpleNamespace) -> None:
    healthy(env)
    del env.responses[(f"google._domainkey.{DOMAIN}", "TXT")]
    env.responses[(f"selector1._domainkey.{DOMAIN}", "TXT")] = dns.exception.Timeout()

    dkim_check = check().dkim

    assert dkim_check is not None
    assert dkim_check.selectors[1].lookup_status is LookupStatus.TIMEOUT
    assert titles(dkim_check) == [(CheckStatus.FAIL, "Couldn't check DKIM: query timed out")]


def test_rsa_key_bits_rejects_garbage() -> None:
    assert mail_mod._rsa_key_bits(b"") is None
    assert mail_mod._rsa_key_bits(b"\x30\x05\x02") is None
    assert mail_mod._rsa_key_bits(base64.b64decode(rsa_key(3072))) == 3072
