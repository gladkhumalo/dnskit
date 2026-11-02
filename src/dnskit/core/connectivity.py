"""TCP connection tests and IPv6 health: can this computer reach what DNS points it at?"""

import ipaddress
import socket
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from dnskit.core.lookup import LookupStatus, _is_no_route, _query_one

# A dual-stack name whose AAAA lookup and IPv6 web servers are reliably up.
IPV6_TEST_HOST = "www.google.com"
IPV6_TEST_PORT = 443
# Any global IPv6 address works for finding the outgoing route; no packet is sent to it.
_IPV6_ROUTE_PROBE = ("2001:4860:4860::8888", 53)


class ConnectError(StrEnum):
    REFUSED = "refused"  # the host answered, but nothing accepts connections on that port
    TIMEOUT = "timed out"  # no reply: a firewall drops it, or the host is down
    UNREACHABLE = "unreachable"  # no route to the address from this computer
    FAILED = "failed"  # any other socket error


@dataclass(frozen=True)
class ConnectAttempt:
    address: str
    port: int
    latency_ms: float | None  # None when it failed
    error: ConnectError | None = None
    message: str = ""  # the OS's error text, for failures

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version


def tcp_connect(address: str, port: int, timeout: float) -> ConnectAttempt:
    """Open (and close) a TCP connection to `address`:`port`. Never raises."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((address, port))
    except TimeoutError:
        return ConnectAttempt(address, port, None, ConnectError.TIMEOUT, "no reply")
    except ConnectionRefusedError as exc:
        return ConnectAttempt(address, port, None, ConnectError.REFUSED, _message(exc))
    except OSError as exc:
        error = ConnectError.UNREACHABLE if _is_no_route(exc) else ConnectError.FAILED
        return ConnectAttempt(address, port, None, error, _message(exc))
    return ConnectAttempt(address, port, (time.perf_counter() - start) * 1000)


def _message(exc: OSError) -> str:
    return exc.strerror or str(exc) or type(exc).__name__


# --- IPv6 health --------------------------------------------------------------------------


class IPv6State(StrEnum):
    WORKING = "working"
    NOT_AVAILABLE = "not available"  # no IPv6 address/route: fine, IPv4 is used
    BROKEN = "broken"  # IPv6 route and AAAA answers, but connections fail
    UNKNOWN = "unknown"  # couldn't test: the AAAA lookup failed


@dataclass(frozen=True)
class IPv6Check:
    state: IPv6State
    local_address: str | None  # this computer's IPv6 address used for the internet
    host: str  # the name tested
    attempt: ConnectAttempt | None  # the IPv6 connection test, when one was made
    summary: str


def ipv6_source_address() -> str | None:
    """This computer's global IPv6 address towards the internet, or None without one.

    Connecting a UDP socket only picks a route and a source address; nothing is sent.
    """
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(_IPV6_ROUTE_PROBE)
            address = sock.getsockname()[0].split("%", 1)[0]
    except OSError:
        return None
    try:
        return address if ipaddress.ip_address(address).is_global else None
    except ValueError:
        return None


def check_ipv6(nameservers: Sequence[str], timeout: float) -> IPv6Check:
    """Test IPv6: an IPv6 route, an AAAA lookup through `nameservers`, then a connection."""
    host = IPV6_TEST_HOST
    local = ipv6_source_address()
    if local is None:
        return IPv6Check(
            IPv6State.NOT_AVAILABLE,
            None,
            host,
            None,
            "not available (no IPv6 address); IPv4 is used, which is fine",
        )
    if not nameservers:
        return IPv6Check(IPv6State.UNKNOWN, local, host, None, "couldn't test (no DNS server)")
    result = _query_one(host, "AAAA", nameservers, timeout)
    if result.status is not LookupStatus.OK or not result.records:
        return IPv6Check(
            IPv6State.UNKNOWN,
            local,
            host,
            None,
            f"couldn't test (the AAAA lookup for {host} failed: {result.status})",
        )
    attempt = tcp_connect(result.records[0].value, IPV6_TEST_PORT, timeout)
    if attempt.ok:
        return IPv6Check(
            IPv6State.WORKING,
            local,
            host,
            attempt,
            f"working ({host} over IPv6 in {attempt.latency_ms:.0f} ms)",
        )
    return IPv6Check(
        IPv6State.BROKEN,
        local,
        host,
        attempt,
        f"broken: {host} has IPv6 addresses, but connecting to {attempt.address} {attempt.error}",
    )
