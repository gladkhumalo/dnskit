import errno
import importlib
import socket

import pytest

from dnskit.core import Adapter, AdapterScan, DnsBlocking, ProbeResult, SystemNameservers
from dnskit.core.outside import blocked_diagnosis, check_blocking, firewall_blocks

outside_mod = importlib.import_module("dnskit.core.outside")

VPN = Adapter("{v}", "OfficeVPN", "WireGuard Tunnel", True, ("10.8.0.1",))
WIFI = Adapter("{w}", "Wi-Fi", "Intel Wireless", True, ("192.168.1.1",))


def test_check_blocking_probes_own_servers_and_finds_vpns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = AdapterScan((WIFI, VPN), dns_per_adapter=True)
    probed: list[tuple[str, ...]] = []

    def fake_probe_all(candidates, timeout):
        probed.append(tuple(candidates))
        return [ProbeResult("10.8.0.1", 12.0), ProbeResult("192.168.1.1", None)]

    monkeypatch.setattr(outside_mod, "scan_adapters", lambda: scan)
    monkeypatch.setattr(
        outside_mod,
        "classify_nameservers",
        lambda scan: SystemNameservers(
            ("10.8.0.1", "192.168.1.1"), ("10.8.0.1", "192.168.1.1"), ()
        ),
    )
    monkeypatch.setattr(outside_mod, "probe_all", fake_probe_all)
    monkeypatch.setattr(outside_mod, "firewall_blocks", lambda address, timeout: True)

    blocking = check_blocking()

    assert probed == [("10.8.0.1", "192.168.1.1")]
    assert blocking == DnsBlocking(("10.8.0.1",), ("OfficeVPN",), local_firewall=True)
    assert blocking.system_works


class RefusingSocket:
    def __init__(self, error: OSError | None) -> None:
        self.error = error

    def __enter__(self) -> "RefusingSocket":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def settimeout(self, timeout: float) -> None:
        pass

    def connect(self, address: tuple[str, int]) -> None:
        if self.error is not None:
            raise self.error


@pytest.mark.parametrize(
    ("error", "blocked"),
    [
        (PermissionError(errno.EACCES, "denied"), True),
        (OSError(10013, "forbidden"), True),
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), False),
        (TimeoutError("timed out"), False),
        (None, False),
    ],
)
def test_firewall_blocks_only_on_access_denied(
    monkeypatch: pytest.MonkeyPatch, error: OSError | None, blocked: bool
) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args: RefusingSocket(error))

    assert firewall_blocks("9.9.9.9", 1.0) is blocked


def test_vpn_blocking_is_explained() -> None:
    blocking = DnsBlocking(("10.8.0.1",), ("OfficeVPN",), local_firewall=False)

    diagnosis = blocked_diagnosis(blocking, "the root servers", "Meanwhile, X.")

    assert diagnosis.title == "Direct DNS queries are blocked by the VPN"
    assert "No reply from the root servers" in diagnosis.explanation
    assert "own DNS server (10.8.0.1) works" in diagnosis.explanation
    assert "OfficeVPN (VPN) is connected" in diagnosis.explanation
    assert "DNS leak protection" in diagnosis.explanation
    assert "The root servers are almost certainly fine" in diagnosis.explanation
    assert "kill switch" not in diagnosis.explanation
    assert diagnosis.suggestion.startswith("Disconnect OfficeVPN")
    assert diagnosis.suggestion.endswith("Meanwhile, X.")


def test_a_local_firewall_under_a_vpn_is_its_kill_switch() -> None:
    blocking = DnsBlocking(("10.8.0.1",), ("OfficeVPN",), local_firewall=True)

    diagnosis = blocked_diagnosis(blocking, "the root servers")

    assert "a firewall on this computer (the VPN's kill switch)" in diagnosis.explanation


def test_firewall_blocking_without_a_vpn() -> None:
    blocking = DnsBlocking(("192.168.1.1",), (), local_firewall=False)

    diagnosis = blocked_diagnosis(blocking, "1.1.1.1")

    assert diagnosis.title == "Direct DNS queries are blocked by a firewall"
    assert "port 53" in diagnosis.explanation
    assert "1.1.1.1 are almost certainly fine" in diagnosis.explanation
    assert "hotspot" in diagnosis.suggestion


def test_nothing_answering_means_offline() -> None:
    diagnosis = blocked_diagnosis(DnsBlocking((), ("OfficeVPN",), False), "the root servers")

    assert "offline" in diagnosis.title
    assert "dnskit local" in diagnosis.suggestion
