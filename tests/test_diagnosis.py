import pytest

from dnskit.core import LookupStatus, explain, explain_reverse


def test_ok_has_no_diagnosis() -> None:
    assert explain(LookupStatus.OK, "example.com", "A") is None
    assert explain_reverse(LookupStatus.OK, "8.8.8.8") is None


@pytest.mark.parametrize(
    ("status", "in_explanation", "in_suggestion"),
    [
        (LookupStatus.NXDOMAIN, "isn't registered", "typos"),
        (LookupStatus.NO_ANSWER, "has no MX records", "dnskit lookup example.com"),
        (LookupStatus.SERVFAIL, "DNSSEC", "different public resolver"),
        (LookupStatus.TIMEOUT, "No nameserver replied", "internet connection"),
        (LookupStatus.NO_NETWORK, "offline", "Wi-Fi"),
        (LookupStatus.NO_NAMESERVERS, "rejected the query", "dnskit resolvers"),
    ],
)
def test_every_failure_has_explanation_and_next_step(
    status: LookupStatus, in_explanation: str, in_suggestion: str
) -> None:
    diagnosis = explain(status, "example.com", "MX")

    assert diagnosis is not None
    assert diagnosis.title
    assert in_explanation in diagnosis.explanation
    assert in_suggestion in diagnosis.suggestion


def test_every_non_ok_status_is_covered() -> None:
    for status in LookupStatus:
        if status is not LookupStatus.OK:
            assert explain(status, "example.com", "A") is not None, status


def test_nxdomain_mentions_expiry() -> None:
    diagnosis = explain(LookupStatus.NXDOMAIN, "example.com", "A")

    assert diagnosis is not None
    assert "expired" in diagnosis.suggestion


def test_timeout_includes_duration_when_known() -> None:
    diagnosis = explain(LookupStatus.TIMEOUT, "example.com", "A", timeout=2.5)

    assert diagnosis is not None
    assert "within 2.5 seconds" in diagnosis.explanation


@pytest.mark.parametrize("status", [LookupStatus.NXDOMAIN, LookupStatus.NO_ANSWER])
def test_reverse_missing_ptr_public_ip(status: LookupStatus) -> None:
    diagnosis = explain_reverse(status, "8.8.4.4")

    assert diagnosis is not None
    assert "no PTR record" in diagnosis.explanation
    assert "ISP or hosting provider" in diagnosis.suggestion


@pytest.mark.parametrize("ip", ["192.168.1.10", "10.0.0.1", "fd00::1", "203.0.113.7"])
def test_reverse_missing_ptr_private_ip(ip: str) -> None:
    diagnosis = explain_reverse(LookupStatus.NXDOMAIN, ip)

    assert diagnosis is not None
    assert "private or reserved address" in diagnosis.suggestion


def test_reverse_other_failures_use_general_explanation() -> None:
    diagnosis = explain_reverse(LookupStatus.SERVFAIL, "8.8.8.8")

    assert diagnosis is not None
    assert diagnosis.title == "Nameserver failure (SERVFAIL)"
