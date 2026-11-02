import importlib
import socket
from collections.abc import Iterator
from types import SimpleNamespace

import pytest

from dnskit.core import LookupResult, LookupStatus, Record
from dnskit.core.connectivity import (
    ConnectAttempt,
    ConnectError,
    IPv6State,
    check_ipv6,
    tcp_connect,
)

conn_mod = importlib.import_module("dnskit.core.connectivity")


# --- tcp_connect (loopback only) ----------------------------------------------------------


@pytest.fixture
def listening_port() -> Iterator[int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        yield server.getsockname()[1]


@pytest.fixture
def closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]  # nothing listens once it's closed


def test_tcp_connect_succeeds(listening_port: int) -> None:
    attempt = tcp_connect("127.0.0.1", listening_port, 2.0)

    assert attempt.ok
    assert attempt.latency_ms is not None
    assert attempt.version == 4


def test_tcp_connect_refused(closed_port: int) -> None:
    attempt = tcp_connect("127.0.0.1", closed_port, 5.0)

    assert attempt.error is ConnectError.REFUSED
    assert not attempt.ok and attempt.latency_ms is None


class FakeSocket:
    """A socket whose connect raises `error`."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def settimeout(self, timeout: float) -> None:
        pass

    def connect(self, address: tuple) -> None:
        raise self.error


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError("timed out"), ConnectError.TIMEOUT),
        (OSError(10051, "unreachable network"), ConnectError.UNREACHABLE),
        (OSError(10013, "access denied"), ConnectError.FAILED),
    ],
)
def test_tcp_connect_classifies_errors(
    monkeypatch: pytest.MonkeyPatch, error: BaseException, expected: ConnectError
) -> None:
    monkeypatch.setattr(conn_mod.socket, "socket", lambda *args: FakeSocket(error))

    assert tcp_connect("2001:db8::1", 443, 1.0).error is expected


# --- IPv6 health --------------------------------------------------------------------------

V6 = "2001:db8::80"


@pytest.fixture
def v6_env(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = SimpleNamespace(
        local="2001:db8::2",
        aaaa=LookupResult("AAAA", LookupStatus.OK, (Record(V6, 60),)),
        attempt=ConnectAttempt(V6, 443, 25.0),
        queried=[],
        connected=[],
    )

    def fake_query(name: str, rtype: str, nameservers: list[str], timeout: float) -> LookupResult:
        state.queried.append((name, rtype, list(nameservers)))
        return state.aaaa

    def fake_connect(address: str, port: int, timeout: float) -> ConnectAttempt:
        state.connected.append((address, port))
        return state.attempt

    monkeypatch.setattr(conn_mod, "ipv6_source_address", lambda: state.local)
    monkeypatch.setattr(conn_mod, "_query_one", fake_query)
    monkeypatch.setattr(conn_mod, "tcp_connect", fake_connect)
    return state


def test_ipv6_working(v6_env: SimpleNamespace) -> None:
    check = check_ipv6(["192.0.2.1"], 1.0)

    assert check.state is IPv6State.WORKING
    assert v6_env.queried == [("www.google.com", "AAAA", ["192.0.2.1"])]
    assert v6_env.connected == [(V6, 443)]
    assert check.summary == "working (www.google.com over IPv6 in 25 ms)"


def test_no_ipv6_address_is_not_a_problem(v6_env: SimpleNamespace) -> None:
    v6_env.local = None

    check = check_ipv6(["192.0.2.1"], 1.0)

    assert check.state is IPv6State.NOT_AVAILABLE
    assert v6_env.queried == [] and v6_env.connected == []


def test_ipv6_broken_when_connections_fail(v6_env: SimpleNamespace) -> None:
    v6_env.attempt = ConnectAttempt(V6, 443, None, ConnectError.TIMEOUT, "no reply")

    check = check_ipv6(["192.0.2.1"], 1.0)

    assert check.state is IPv6State.BROKEN
    assert check.local_address == "2001:db8::2"
    assert check.summary == (
        f"broken: www.google.com has IPv6 addresses, but connecting to {V6} timed out"
    )


def test_ipv6_unknown_when_aaaa_fails(v6_env: SimpleNamespace) -> None:
    v6_env.aaaa = LookupResult("AAAA", LookupStatus.TIMEOUT)

    check = check_ipv6(["192.0.2.1"], 1.0)

    assert check.state is IPv6State.UNKNOWN
    assert v6_env.connected == []
    assert "timeout" in check.summary


def test_ipv6_unknown_without_nameservers(v6_env: SimpleNamespace) -> None:
    assert check_ipv6([], 1.0).state is IPv6State.UNKNOWN


def test_ipv6_source_address_needs_a_global_address(monkeypatch: pytest.MonkeyPatch) -> None:
    class RouteSocket(FakeSocket):
        def __init__(self, local: str) -> None:
            self.local = local

        def connect(self, address: tuple) -> None:
            pass

        def getsockname(self) -> tuple:
            return (self.local, 50000, 0, 0)

    for local, expected in (
        ("2a00:1450::99", "2a00:1450::99"),
        ("fe80::1%12", None),  # link-local only: no internet route
        ("fd00::5", None),  # unique local (private)
    ):
        monkeypatch.setattr(conn_mod.socket, "socket", lambda *a, local=local: RouteSocket(local))
        assert conn_mod.ipv6_source_address() == expected

    monkeypatch.setattr(conn_mod.socket, "socket", lambda *a: FakeSocket(OSError(10051, "x")))
    assert conn_mod.ipv6_source_address() is None
