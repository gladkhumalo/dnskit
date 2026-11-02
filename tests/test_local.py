import importlib
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from dnskit.core import (
    Adapter,
    AdapterScan,
    FlushCommand,
    HostsEntry,
    HostsFile,
    HostsKind,
    LocalReport,
    ProbeResult,
    RegistryEntry,
    Severity,
    local_check,
)
from dnskit.core.connectivity import ConnectAttempt, ConnectError, IPv6Check, IPv6State
from dnskit.core.integrity import (
    HijackCheck,
    RawAnswer,
    Verdict,
    classify_cloudflare,
    classify_google,
    classify_nxdomain,
)
from dnskit.core.local import flush_command, hosts_path, parse_hosts, read_hosts

local_mod = importlib.import_module("dnskit.core.local")

# The setup that prompted `dnskit local`: a connected adapter, a disconnected one whose dead
# router is still in the system configuration, and a leftover with no adapter at all.
CONNECTED = Adapter("{c}", "Ethernet 2", "Multiplexor", True, ("192.0.2.1", "1.1.1.1"))
UNPLUGGED = Adapter("{u}", "Ethernet", "Realtek", False, ("192.0.2.88", "1.1.1.1"))
LEFTOVER = RegistryEntry("{gone}", "DhcpNameServer", ("192.0.2.55",))
CONFIGURED = ["192.0.2.88", "1.1.1.1", "192.0.2.55", "192.0.2.1"]


@pytest.fixture
def local_env(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Mock every system source local_check reads; returns knobs tests can adjust."""
    state = SimpleNamespace(
        scan=AdapterScan((CONNECTED, UNPLUGGED), dns_per_adapter=True, registry=(LEFTOVER,)),
        configured=list(CONFIGURED),
        latencies={"192.0.2.1": 12.0, "1.1.1.1": 15.0},  # missing = no response
        hosts=HostsFile("/etc/hosts", ()),
        platform="Windows",
        probed=[],
        # The integrity and IPv6 checks: honest and working unless a test says otherwise.
        hijacked={},  # nameserver -> addresses it returns for a made-up name
        google=classify_google(RawAnswer("NOERROR", ("172.253.1.2",))),
        cloudflare=classify_cloudflare(RawAnswer("NOERROR", ("203.0.113.5",))),
        ipv6=IPv6Check(IPv6State.NOT_AVAILABLE, None, "www.google.com", None, "not available"),
        hijack_checked=[],
        ipv6_nameservers=[],
    )

    def fake_probe_all(candidates: Sequence[str], timeout: float) -> list[ProbeResult]:
        state.probed.append((list(candidates), timeout))
        return [ProbeResult(ns, state.latencies.get(ns)) for ns in candidates]

    def fake_check_nxdomain(nameserver: str, timeout: float) -> HijackCheck:
        state.hijack_checked.append(nameserver)
        addresses = state.hijacked.get(nameserver, ())
        answer = RawAnswer("NOERROR", addresses) if addresses else RawAnswer("NXDOMAIN")
        return classify_nxdomain(nameserver, "dnskit-nx-test.com", answer)

    def fake_check_ipv6(nameservers: Sequence[str], timeout: float) -> IPv6Check:
        state.ipv6_nameservers.append(list(nameservers))
        return state.ipv6

    monkeypatch.setattr(local_mod, "check_nxdomain", fake_check_nxdomain)
    monkeypatch.setattr(local_mod, "check_google", lambda timeout: state.google)
    monkeypatch.setattr(local_mod, "check_cloudflare", lambda timeout: state.cloudflare)
    monkeypatch.setattr(local_mod, "check_ipv6", fake_check_ipv6)
    monkeypatch.setattr(local_mod, "scan_adapters", lambda: state.scan)
    monkeypatch.setattr(local_mod, "configured_nameservers", lambda: list(state.configured))
    monkeypatch.setattr(local_mod, "probe_all", fake_probe_all)
    monkeypatch.setattr(local_mod, "read_hosts", lambda: state.hosts)
    monkeypatch.setattr(local_mod, "platform_name", lambda: state.platform)
    monkeypatch.setattr(local_mod, "flush_command", lambda: FlushCommand("flush", "note"))
    return state


def titles(report: LocalReport) -> list[str]:
    return [p.title for p in report.problems]


def by_server(report: LocalReport) -> dict[str, object]:
    return {s.nameserver: s for s in report.servers}


# --- Servers and ghosts -------------------------------------------------------------------


def test_tests_every_server_once_connected_adapters_first(local_env: SimpleNamespace) -> None:
    report = local_check(timeout=0.5)

    assert local_env.probed == [(["192.0.2.1", "1.1.1.1", "192.0.2.88", "192.0.2.55"], 0.5)]
    assert [s.nameserver for s in report.servers] == [
        "192.0.2.1",
        "1.1.1.1",
        "192.0.2.88",
        "192.0.2.55",
    ]
    assert report.probe_timeout == 0.5


def test_servers_show_their_adapters(local_env: SimpleNamespace) -> None:
    servers = by_server(local_check())

    assert servers["192.0.2.1"].adapter_names == "Ethernet 2"
    assert servers["1.1.1.1"].adapter_names == "Ethernet 2, Ethernet"
    assert servers["192.0.2.88"].adapter_names == "Ethernet"
    assert servers["192.0.2.55"].adapters == ()
    assert servers["192.0.2.55"].registry == (LEFTOVER,)


def test_detects_ghost_servers(local_env: SimpleNamespace) -> None:
    report = local_check()
    servers = by_server(report)

    assert [s.nameserver for s in report.servers if s.ghost] == ["192.0.2.88", "192.0.2.55"]
    assert [s.nameserver for s in report.servers if s.used] == ["192.0.2.1", "1.1.1.1"]
    assert report.nameservers.ignored == ("192.0.2.88", "192.0.2.55")
    assert servers["192.0.2.88"].failed


def test_ghosts_can_be_left_unprobed(local_env: SimpleNamespace) -> None:
    report = local_check(probe_ghosts=False)
    servers = by_server(report)

    probed = local_env.probed[0][0]
    assert "192.0.2.88" not in probed and "192.0.2.55" not in probed
    assert "192.0.2.1" in probed
    ghost = servers["192.0.2.88"]
    assert (ghost.ghost, ghost.probed, ghost.failed) == (True, False, False)
    problem = next(p for p in report.problems if "192.0.2.88" in p.title)
    assert "It wasn't tested, since it isn't used." in problem.detail
    assert "time out" not in problem.detail


def test_ghost_on_disconnected_adapter_explained(local_env: SimpleNamespace) -> None:
    problem = local_check().problems[0]

    assert problem.title == "Ghost DNS server 192.0.2.88 (on disconnected Ethernet)"
    assert problem.severity is Severity.WARNING
    assert "Windows ignores it until that adapter reconnects" in problem.detail
    assert "wait for it to time out" in problem.detail


def test_leftover_ghost_points_at_registry_on_windows(local_env: SimpleNamespace) -> None:
    problem = local_check().problems[1]

    assert problem.title == "Ghost DNS server 192.0.2.55"
    assert "on no network adapter" in problem.detail
    assert "{gone} (DhcpNameServer)" in problem.fix


def test_leftover_ghost_on_linux_points_at_resolv_conf(local_env: SimpleNamespace) -> None:
    local_env.platform = "Linux"
    local_env.latencies["192.0.2.55"] = 30.0

    problem = local_check().problems[1]

    assert "/etc/resolv.conf" in problem.fix
    assert "It does respond (30 ms)" in problem.detail


def test_healthy_setup_has_no_problems(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]

    report = local_check()

    assert report.problems == ()
    assert not report.has_errors


def test_without_per_adapter_dns_servers_come_from_config(local_env: SimpleNamespace) -> None:
    local_env.scan = AdapterScan((Adapter("eth0", "eth0", "", True, ()),), dns_per_adapter=False)
    local_env.configured = ["127.0.0.53"]
    local_env.latencies = {"127.0.0.53": 1.0}

    report = local_check()

    assert [(s.nameserver, s.used, s.ghost) for s in report.servers] == [
        ("127.0.0.53", True, False)
    ]
    assert report.problems == ()


# --- Failing and slow servers -------------------------------------------------------------


def test_failing_server_in_use_is_flagged_with_its_adapter(local_env: SimpleNamespace) -> None:
    del local_env.latencies["192.0.2.1"]

    report = local_check()

    assert "DNS server 192.0.2.1 (Ethernet 2) isn't responding" in titles(report)
    assert not report.has_errors  # 1.1.1.1 still answers


def test_slow_server_is_flagged(local_env: SimpleNamespace) -> None:
    local_env.latencies["1.1.1.1"] = 900.0

    report = local_check()

    assert by_server(report)["1.1.1.1"].slow
    assert "DNS server 1.1.1.1 (Ethernet 2, Ethernet) is slow" in titles(report)


def test_every_server_failing_is_one_error(local_env: SimpleNamespace) -> None:
    local_env.latencies = {}

    report = local_check()

    assert report.has_errors
    assert report.problems[0].title == "No DNS server is responding"
    assert report.problems[0].severity is Severity.ERROR
    assert not any("isn't responding" in t for t in titles(report))


def test_failing_public_resolver_is_probably_blocked(local_env: SimpleNamespace) -> None:
    del local_env.latencies["1.1.1.1"]

    report = local_check()
    servers = by_server(report)
    problem = next(p for p in report.problems if "1.1.1.1" in p.title)

    assert servers["1.1.1.1"].public == "Cloudflare"
    assert servers["192.0.2.1"].public is None
    assert "almost never down" in problem.detail
    assert "firewall or VPN is blocking it" in problem.detail
    assert "firewall, antivirus or VPN" in problem.fix
    assert "often the router" not in problem.fix


def test_public_resolver_matches_any_spelling() -> None:
    assert local_mod.public_resolver("2001:4860:4860:0:0:0:0:8888") == "Google"
    assert local_mod.public_resolver("9.9.9.9") == "Quad9"
    assert local_mod.public_resolver("192.0.2.1") is None


def test_failing_public_ghost_mentions_blocking(local_env: SimpleNamespace) -> None:
    local_env.scan = AdapterScan(
        (Adapter("{c}", "Ethernet 2", "", True, ("192.0.2.1",)),), dns_per_adapter=True
    )
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    del local_env.latencies["1.1.1.1"]

    problem = next(p for p in local_check().problems if p.title == "Ghost DNS server 1.1.1.1")

    assert "1.1.1.1 (Cloudflare) is a well-known public DNS service" in problem.detail


# --- VPN ----------------------------------------------------------------------------------

VPN = Adapter("{v}", "OfficeVPN", "WireGuard Tunnel", True, ("10.8.0.1",))


def with_vpn(local_env: SimpleNamespace, **latencies: float) -> None:
    """Connect a VPN; the other adapters' servers don't answer unless given a latency."""
    local_env.scan = AdapterScan((VPN, CONNECTED, UNPLUGGED), dns_per_adapter=True)
    local_env.configured = ["10.8.0.1", "192.0.2.1", "1.1.1.1"]
    local_env.latencies = {"10.8.0.1": 20.0, **latencies}


def test_servers_outside_a_vpn_are_probably_blocked_not_broken(
    local_env: SimpleNamespace,
) -> None:
    with_vpn(local_env)

    report = local_check()
    servers = by_server(report)

    assert report.vpns == (VPN,)
    assert [s.nameserver for s in report.servers if s.vpn_blocked] == ["192.0.2.1", "1.1.1.1"]
    assert not servers["10.8.0.1"].vpn_blocked
    assert titles(report) == ["DNS servers outside the VPN aren't responding"]
    problem = report.problems[0]
    assert "while OfficeVPN (VPN) is connected" in problem.detail
    assert "DNS leak protection" in problem.detail
    assert "They are probably fine." in problem.detail
    assert problem.fix.startswith("Don't remove them. To test them, disconnect OfficeVPN")
    assert not report.has_errors


def test_one_server_outside_a_vpn_reads_singular(local_env: SimpleNamespace) -> None:
    with_vpn(local_env, **{"1.1.1.1": 15.0})

    problem = local_check().problems[0]

    assert problem.title == "A DNS server outside the VPN isn't responding"
    assert "It is probably fine." in problem.detail
    assert problem.fix.startswith("Don't remove it.")


def test_failing_vpn_server_points_at_the_vpn(local_env: SimpleNamespace) -> None:
    with_vpn(local_env, **{"192.0.2.1": 12.0, "1.1.1.1": 15.0})
    del local_env.latencies["10.8.0.1"]

    report = local_check()

    assert titles(report) == ["DNS server 10.8.0.1 (OfficeVPN) isn't responding"]
    assert "It's set by the VPN (OfficeVPN)" in report.problems[0].fix
    assert not any(s.vpn_blocked for s in report.servers)


def test_nothing_answering_with_a_vpn_suggests_reconnecting(local_env: SimpleNamespace) -> None:
    with_vpn(local_env)
    local_env.latencies = {}

    report = local_check()
    problem = report.problems[0]

    assert problem.title == "No DNS server is responding"
    assert report.has_errors
    assert "OfficeVPN (VPN) is connected." in problem.detail
    assert problem.fix.startswith("Reconnect OfficeVPN, or disconnect it")
    assert "If they still fail: check that you're online" in problem.fix
    assert "1.1.1.1 (Cloudflare) is a well-known public DNS service" in problem.detail


def test_without_a_vpn_failures_are_not_blamed_on_one(local_env: SimpleNamespace) -> None:
    del local_env.latencies["192.0.2.1"]

    report = local_check()

    assert report.vpns == ()
    assert not any(s.vpn_blocked for s in report.servers)


def test_no_connected_adapter_is_an_error(local_env: SimpleNamespace) -> None:
    local_env.scan = AdapterScan((UNPLUGGED,), dns_per_adapter=True)

    report = local_check()

    assert report.problems[0].title == "No network adapter is connected"
    assert report.has_errors


def test_connected_adapter_without_dns_is_an_error(local_env: SimpleNamespace) -> None:
    local_env.scan = AdapterScan((Adapter("x", "Wi-Fi", "", True, ()),), dns_per_adapter=True)

    assert "No DNS servers on the connected adapters" in titles(local_check())


def test_unreadable_adapters_is_a_warning(local_env: SimpleNamespace) -> None:
    local_env.scan = AdapterScan((), dns_per_adapter=False, error="OSError: denied")
    local_env.configured = ["192.0.2.1"]

    report = local_check()

    assert titles(report) == ["Couldn't read the network adapters"]
    assert by_server(report)["192.0.2.1"].used


# --- Hosts file ---------------------------------------------------------------------------

HOSTS = """\
\ufeff# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
127.0.1.1       mypc.example mypc
# 203.0.113.9   commented.example
0.0.0.0         ads.example tracker.example   # blocked
127.0.0.1       myapp.test localhost
203.0.113.7     intranet.example
not-an-ip       broken.example
192.0.2.1
"""


def test_parse_hosts_keeps_only_overrides() -> None:
    assert parse_hosts(HOSTS, "mypc.example") == [
        HostsEntry(6, "0.0.0.0", ("ads.example", "tracker.example"), HostsKind.BLOCKED),
        HostsEntry(7, "127.0.0.1", ("myapp.test",), HostsKind.LOCAL),
        HostsEntry(8, "203.0.113.7", ("intranet.example",), HostsKind.REDIRECT),
    ]


def test_read_hosts(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_text("203.0.113.7 intranet.example\n", encoding="utf-8")

    hosts = read_hosts(path)

    assert hosts.path == str(path)
    assert [e.names for e in hosts.entries] == [("intranet.example",)]


def test_missing_hosts_file_is_not_an_error(tmp_path: Path) -> None:
    hosts = read_hosts(tmp_path / "nope")

    assert hosts.entries == () and hosts.error is None


def test_unreadable_hosts_file_reports_error(tmp_path: Path) -> None:
    hosts = read_hosts(tmp_path)  # a directory can't be read as a file

    assert hosts.error is not None


def test_hosts_overrides_are_a_problem(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1"]
    entries = tuple(
        HostsEntry(i, "203.0.113.7", (f"site{i}.example",), HostsKind.REDIRECT) for i in range(7)
    )
    local_env.hosts = HostsFile("/etc/hosts", entries)

    problem = local_check().problems[0]

    assert problem.title == "The hosts file overrides DNS for 7 names"
    assert "site0.example → 203.0.113.7" in problem.detail
    assert "and 2 more" in problem.detail
    assert "/etc/hosts" in problem.fix


def test_hosts_path_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"D:\Win")  # Windows reads it case-insensitively

    assert hosts_path("win32") == Path(r"D:\Win") / "System32" / "drivers" / "etc" / "hosts"
    assert hosts_path("linux") == Path("/etc/hosts")
    assert hosts_path("darwin") == Path("/etc/hosts")


# --- Flushing the DNS cache ---------------------------------------------------------------


def test_flush_command_per_platform() -> None:
    def none(_: str) -> None:
        return None

    assert flush_command("win32", none).command == "ipconfig /flushdns"
    assert "mDNSResponder" in (flush_command("darwin", none).command or "")
    assert (
        flush_command(
            "linux", lambda cmd: "/usr/bin/resolvectl" if cmd == "resolvectl" else None
        ).command
        == "sudo resolvectl flush-caches"
    )
    assert (
        flush_command("linux", lambda cmd: "/usr/sbin/nscd" if cmd == "nscd" else None).command
        == "sudo nscd --invalidate=hosts"
    )
    no_cache = flush_command("linux", none)
    assert no_cache.command is None
    assert "doesn't cache" in no_cache.note


# --- Hijacking, interception and IPv6 -----------------------------------------------------


def test_honest_setup_reports_checks_without_problems(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]

    report = local_check()

    assert [(h.nameserver, h.verdict) for h in report.hijack] == [
        ("192.0.2.1", Verdict.OK),  # fastest first
        ("1.1.1.1", Verdict.OK),
    ]
    assert [c.provider for c in report.interception] == ["Google", "Cloudflare"]
    assert all(c.verdict is Verdict.OK for c in report.interception)
    assert report.ipv6 is local_env.ipv6
    assert report.problems == ()


def test_only_answering_servers_in_use_are_checked(local_env: SimpleNamespace) -> None:
    del local_env.latencies["192.0.2.1"]

    local_check()

    assert local_env.hijack_checked == ["1.1.1.1"]  # not the dead one, nor ghosts
    assert local_env.ipv6_nameservers == [["1.1.1.1"]]


def test_nxdomain_hijacking_is_a_warning(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    local_env.hijacked = {"192.0.2.1": ("198.51.100.80",)}

    report = local_check()
    problem = report.problems[0]

    assert report.hijack[0].verdict is Verdict.SUSPECT
    assert problem.title == (
        "DNS server 192.0.2.1 answers for names that don't exist (NXDOMAIN hijacking)"
    )
    assert "it answered 198.51.100.80 instead of saying the name doesn't exist" in problem.detail
    assert '"DNS assist"' in problem.fix
    assert not report.has_errors


def test_intercepted_google_names_the_impostor(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    local_env.google = classify_google(RawAnswer("NOERROR", ("198.51.100.53",)))

    problem = local_check().problems[0]

    assert problem.title == "Queries to 8.8.8.8 (Google) appear to be intercepted"
    assert "the answer named 198.51.100.53, which isn't Google's" in problem.detail
    assert "Routers, firewalls, ISPs" in problem.detail
    assert "DNS over HTTPS" in problem.fix


def test_intercepted_cloudflare_with_a_vpn_blames_the_vpn(local_env: SimpleNamespace) -> None:
    with_vpn(local_env, **{"192.0.2.1": 12.0, "1.1.1.1": 15.0})
    local_env.cloudflare = classify_cloudflare(RawAnswer("SERVFAIL"))

    problem = local_check().problems[0]

    assert problem.title == "Queries to 1.1.1.1 (Cloudflare) appear to be intercepted"
    assert "but got SERVFAIL" in problem.detail
    assert "OfficeVPN (VPN) is connected: VPNs often redirect all DNS" in problem.detail
    assert problem.fix.startswith("If it's the VPN, that's expected: disconnect OfficeVPN")


def test_unreachable_check_resolvers_are_not_problems(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    local_env.google = classify_google(RawAnswer(None, error="no response"))
    local_env.cloudflare = classify_cloudflare(RawAnswer(None, error="no response"))

    report = local_check()

    assert [c.verdict for c in report.interception] == [Verdict.UNKNOWN, Verdict.UNKNOWN]
    assert report.problems == ()


def test_broken_ipv6_is_a_warning(local_env: SimpleNamespace) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    attempt = ConnectAttempt("2001:db8::80", 443, None, ConnectError.TIMEOUT, "no reply")
    local_env.ipv6 = IPv6Check(IPv6State.BROKEN, "2001:db8::2", "www.google.com", attempt, "x")

    problem = local_check().problems[0]

    assert problem.title.startswith("IPv6 is broken")
    assert "has an IPv6 address (2001:db8::2) and AAAA lookups work" in problem.detail
    assert "at 2001:db8::80 timed out (no reply)" in problem.detail
    assert "try IPv6 first" in problem.detail
    assert "turn IPv6 off" in problem.fix


@pytest.mark.parametrize("state", [IPv6State.NOT_AVAILABLE, IPv6State.UNKNOWN, IPv6State.WORKING])
def test_other_ipv6_states_are_not_problems(local_env: SimpleNamespace, state: IPv6State) -> None:
    local_env.configured = ["192.0.2.1", "1.1.1.1"]
    local_env.ipv6 = IPv6Check(state, None, "www.google.com", None, "x")

    assert local_check().problems == ()
