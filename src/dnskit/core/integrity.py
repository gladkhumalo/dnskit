"""Is this computer getting honest DNS answers? NXDOMAIN hijacking and DNS interception.

- NXDOMAIN hijacking: a resolver answers a name that can't exist with an address (usually
  a search or advertising page) instead of "doesn't exist".
- Interception: something on the path (router, network, ISP, VPN) answers queries meant
  for a public resolver such as 8.8.8.8 itself. Google and Cloudflare each have a name that
  only they answer in a recognisable way, which shows who really answered.
"""

import ipaddress
import secrets
from dataclasses import dataclass
from enum import StrEnum

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdata
import dns.rdatatype

GOOGLE_DNS = "8.8.8.8"
CLOUDFLARE_DNS = "1.1.1.1"
# Google answers this TXT with the address of its resolver that asked (one of Google's).
GOOGLE_WHOAMI = "o-o.myaddr.l.google.com"
# Cloudflare answers this CHAOS-class TXT with your public address; other resolvers can't.
CLOUDFLARE_WHOAMI = "whoami.cloudflare"

# Google's address blocks (AS15169), which its public DNS resolvers ask from. They cover
# every prefix in https://www.gstatic.com/ipranges/publicdns.json (checked 2026-10-31).
_GOOGLE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "8.8.4.0/24",
        "8.8.8.0/24",
        "8.34.208.0/20",
        "8.35.192.0/20",
        "34.64.0.0/10",
        "34.128.0.0/10",
        "35.184.0.0/13",
        "64.233.160.0/19",
        "66.102.0.0/20",
        "66.249.64.0/19",
        "72.14.192.0/18",
        "74.114.28.0/22",
        "74.125.0.0/16",
        "108.170.192.0/18",
        "108.177.0.0/17",
        "142.250.0.0/15",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "173.194.0.0/16",
        "192.178.0.0/15",
        "209.85.128.0/17",
        "216.58.192.0/19",
        "216.239.32.0/19",
        "2001:4860::/32",
        "2404:6800::/32",
        "2404:f340::/32",
        "2600:1900::/28",
        "2607:f8b0::/32",
        "2800:3f0::/32",
        "2a00:1450::/32",
        "2c0f:fb50::/32",
    )
)


class Verdict(StrEnum):
    OK = "ok"
    SUSPECT = "suspect"  # hijacked or intercepted
    UNKNOWN = "unknown"  # no usable answer, so it can't be told


@dataclass(frozen=True)
class RawAnswer:
    """One query's outcome, before any interpretation."""

    rcode: str | None  # "NOERROR", "NXDOMAIN", ...; None when nothing came back
    values: tuple[str, ...] = ()  # the answer's records of the asked type (TXT unquoted)
    error: str | None = None  # why nothing came back


@dataclass(frozen=True)
class HijackCheck:
    nameserver: str
    probe_name: str  # the made-up name that was asked for
    verdict: Verdict
    addresses: tuple[str, ...]  # what came back instead of "doesn't exist"
    summary: str


@dataclass(frozen=True)
class InterceptionCheck:
    provider: str  # "Google" or "Cloudflare"
    nameserver: str  # the address the query was sent to
    verdict: Verdict
    answered_by: str | None  # the address the answer reveals, when it reveals one
    summary: str
    response: str = ""  # what came back, in words (e.g. "SERVFAIL", "no response")


def ask(nameserver: str, name: str, rdtype: str, timeout: float, rdclass: str = "IN") -> RawAnswer:
    """Send one query straight to `nameserver` (no fallback, no retries). Never raises."""
    query = dns.message.make_query(name, rdtype, rdclass)
    try:
        response = dns.query.udp(query, nameserver, timeout=timeout)
    except dns.exception.Timeout:
        return RawAnswer(None, error="no response")
    except (OSError, dns.exception.DNSException) as exc:
        return RawAnswer(None, error=str(exc) or type(exc).__name__)
    wanted = dns.rdatatype.from_text(rdtype)
    values = tuple(
        _rdata_text(rdata) for rrset in response.answer if rrset.rdtype == wanted for rdata in rrset
    )
    return RawAnswer(dns.rcode.to_text(response.rcode()), values)


def _rdata_text(rdata: dns.rdata.Rdata) -> str:
    strings = getattr(rdata, "strings", None)  # TXT: join the strings, without quotes
    if strings is not None:
        return b"".join(strings).decode("utf-8", "replace")
    return rdata.to_text()


# --- NXDOMAIN hijacking -------------------------------------------------------------------


def probe_name() -> str:
    """A random name that can't exist, under a real top-level domain."""
    return f"dnskit-nx-{secrets.token_hex(8)}.com"


def check_nxdomain(nameserver: str, timeout: float, name: str | None = None) -> HijackCheck:
    """Ask `nameserver` for a made-up name; an honest resolver says it doesn't exist."""
    name = probe_name() if name is None else name
    return classify_nxdomain(nameserver, name, ask(nameserver, name, "A", timeout))


def classify_nxdomain(nameserver: str, name: str, answer: RawAnswer) -> HijackCheck:
    if answer.rcode == "NXDOMAIN":
        return HijackCheck(nameserver, name, Verdict.OK, (), 'answers "doesn\'t exist" honestly')
    if answer.rcode == "NOERROR" and answer.values:
        shown = ", ".join(answer.values)
        return HijackCheck(
            nameserver,
            name,
            Verdict.SUSPECT,
            answer.values,
            f"hijacked: a made-up name got {shown}",
        )
    reason = answer.error or f"answered {answer.rcode} without an address"
    return HijackCheck(nameserver, name, Verdict.UNKNOWN, (), f"couldn't tell ({reason})")


# --- Interception -------------------------------------------------------------------------


def check_google(timeout: float) -> InterceptionCheck:
    return classify_google(ask(GOOGLE_DNS, GOOGLE_WHOAMI, "TXT", timeout))


def check_cloudflare(timeout: float) -> InterceptionCheck:
    return classify_cloudflare(ask(CLOUDFLARE_DNS, CLOUDFLARE_WHOAMI, "TXT", timeout, "CH"))


def classify_google(answer: RawAnswer) -> InterceptionCheck:
    """Google answers with one of its own resolvers' addresses; anyone else gives theirs."""
    if answer.rcode is None:
        return _unknown("Google", GOOGLE_DNS, answer)
    got = _describe(answer)
    addresses = [ip for ip in map(_parse_ip, answer.values) if ip is not None]
    if not addresses:
        return InterceptionCheck(
            "Google", GOOGLE_DNS, Verdict.SUSPECT, None, f"intercepted: got {got}", got
        )
    google = next((ip for ip in addresses if _is_google(ip)), None)
    if google is not None:
        return InterceptionCheck(
            "Google", GOOGLE_DNS, Verdict.OK, str(google), f"answered by Google ({google})", got
        )
    other = str(addresses[0])
    return InterceptionCheck(
        "Google",
        GOOGLE_DNS,
        Verdict.SUSPECT,
        other,
        f"intercepted: answered from {other}, which isn't Google",
        got,
    )


def classify_cloudflare(answer: RawAnswer) -> InterceptionCheck:
    """Cloudflare answers with your public address; other resolvers refuse or fail."""
    if answer.rcode is None:
        return _unknown("Cloudflare", CLOUDFLARE_DNS, answer)
    got = _describe(answer)
    address = next((ip for ip in map(_parse_ip, answer.values) if ip is not None), None)
    if answer.rcode == "NOERROR" and address is not None:
        return InterceptionCheck(
            "Cloudflare", CLOUDFLARE_DNS, Verdict.OK, str(address), "answered by Cloudflare", got
        )
    return InterceptionCheck(
        "Cloudflare", CLOUDFLARE_DNS, Verdict.SUSPECT, None, f"intercepted: got {got}", got
    )


def _unknown(provider: str, nameserver: str, answer: RawAnswer) -> InterceptionCheck:
    reason = answer.error or "no response"
    return InterceptionCheck(
        provider, nameserver, Verdict.UNKNOWN, None, f"couldn't tell ({reason})", reason
    )


def _describe(answer: RawAnswer) -> str:
    if answer.rcode != "NOERROR":
        return answer.rcode or "nothing"
    if not answer.values:
        return "an empty answer"
    shown = [v for v in answer.values if _parse_ip(v) is not None] or list(answer.values[:1])
    return ", ".join(shown)  # addresses only: Google also returns the client's subnet


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def _is_google(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip.version == net.version and ip in net for net in _GOOGLE_NETWORKS)
