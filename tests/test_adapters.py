import importlib
import sys
from pathlib import Path

import pytest

from dnskit.core import Adapter, AdapterScan, RegistryEntry, classify_nameservers
from dnskit.core.adapters import (
    _sockaddr_ip,
    bridge_members,
    is_loopback,
    normalize_ip,
    parse_bridge_members,
    parse_ifconfig,
    parse_registry_nameservers,
    parse_resolvectl_dns,
    parse_scutil_dns,
    scan_adapters,
)

adapters_mod = importlib.import_module("dnskit.core.adapters")

WIFI = Adapter("wifi", "Wi-Fi", "Intel", True, ("192.0.2.1", "1.1.1.1"))
ETHERNET = Adapter("eth", "Ethernet", "Realtek", False, ("192.0.2.88", "1.1.1.1"))


def scan(*adapters: Adapter, per_adapter: bool = True) -> AdapterScan:
    return AdapterScan(adapters, dns_per_adapter=per_adapter)


# --- Addresses ----------------------------------------------------------------------------


def test_normalize_ip_drops_zone_and_compresses() -> None:
    assert normalize_ip("fe80:0:0:0:0:0:0:1%12") == "fe80::1"
    assert normalize_ip("192.0.2.1") == "192.0.2.1"
    assert normalize_ip("not-an-ip") == "not-an-ip"


def test_is_loopback() -> None:
    assert is_loopback("127.0.0.53")
    assert is_loopback("::1")
    assert not is_loopback("192.0.2.1")
    assert not is_loopback("nonsense")


def test_sockaddr_ip_reads_ipv4_and_ipv6() -> None:
    ipv4 = (2).to_bytes(2, "little") + b"\x00\x35" + bytes([192, 0, 2, 1]) + bytes(8)
    ipv6 = (23).to_bytes(2, "little") + bytes(6) + bytes.fromhex("20010db8" + "0" * 22 + "53")
    ipv6 += bytes(4)

    assert _sockaddr_ip(ipv4) == "192.0.2.1"
    assert _sockaddr_ip(ipv6) == "2001:db8::53"
    assert _sockaddr_ip((99).to_bytes(2, "little") + bytes(14)) is None


# --- AdapterScan --------------------------------------------------------------------------


def test_scan_helpers() -> None:
    s = scan(ETHERNET, WIFI)

    assert s.connected == (WIFI,)
    assert s.connected_dns() == {"192.0.2.1", "1.1.1.1"}
    assert s.adapters_listing("1.1.1.1") == (WIFI, ETHERNET)  # connected first
    assert s.adapters_listing("192.0.2.99") == ()


@pytest.mark.parametrize(
    ("name", "description", "dns", "expected"),
    [
        ("OfficeVPN", "WireGuard Tunnel", ("8.8.8.8",), True),
        ("Local Area Connection", "TAP-Windows Adapter V9 for OpenVPN Connect", (), True),
        ("tailscale0", "", (), True),
        ("Ethernet 3", "PANGP Virtual Ethernet Adapter", (), True),
        ("utun3", "", ("10.8.0.1",), True),  # a tunnel that sets DNS
        ("utun0", "", (), False),  # macOS's own tunnels set no DNS
        ("Wi-Fi", "Intel(R) Wireless-AC 9560", ("192.0.2.1",), False),
        ("Desktop Adapter", "Realtek", (), False),  # "tap" only as a whole word
    ],
)
def test_is_vpn(name: str, description: str, dns: tuple[str, ...], expected: bool) -> None:
    assert Adapter("x", name, description, True, dns).vpn is expected


def test_connected_vpns() -> None:
    vpn = Adapter("v", "WireGuard", "", True, ("10.0.0.1",))
    off = Adapter("o", "OpenVPN", "", False, ())

    assert scan(WIFI, vpn, off).connected_vpns == (vpn,)


def test_bridge_members_are_not_connected_adapters() -> None:
    member = Adapter("m", "WiFi", "", True, (), bridged_into="Wi-Fi")

    assert scan(WIFI, member).connected == (WIFI,)


def test_registry_listing() -> None:
    entry = RegistryEntry("{guid}", "DhcpNameServer", ("192.0.2.55",))
    s = AdapterScan((), dns_per_adapter=True, registry=(entry,))

    assert s.registry_listing("192.0.2.55") == (entry,)
    assert s.registry_listing("192.0.2.1") == ()


def test_scan_adapters_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> AdapterScan:
        raise RuntimeError("no access")

    for reader in ("_windows_scan", "_macos_scan", "_linux_scan"):
        monkeypatch.setattr(adapters_mod, reader, boom)

    result = scan_adapters()

    assert result.adapters == ()
    assert not result.dns_per_adapter
    assert result.error == "RuntimeError: no access"


# --- Choosing usable nameservers ----------------------------------------------------------


def test_only_nameservers_on_connected_adapters_are_usable() -> None:
    configured = ["192.0.2.88", "1.1.1.1", "192.0.2.55", "192.0.2.1"]

    result = classify_nameservers(configured, scan(ETHERNET, WIFI))

    assert result.usable == ("1.1.1.1", "192.0.2.1")  # system order kept
    assert result.ignored == ("192.0.2.88", "192.0.2.55")
    assert result.configured == tuple(configured)


def test_local_stub_is_always_usable() -> None:
    result = classify_nameservers(["127.0.0.53"], scan(WIFI))

    assert result.usable == ("127.0.0.53",)


def test_without_per_adapter_dns_everything_is_usable() -> None:
    result = classify_nameservers(["192.0.2.55"], scan(WIFI, per_adapter=False))

    assert result.usable == ("192.0.2.55",)
    assert result.ignored == ()


def test_nothing_on_a_connected_adapter_falls_back_to_all() -> None:
    # Offline, or adapters that don't match: better to try them than to have nothing.
    result = classify_nameservers(["192.0.2.88"], scan(ETHERNET))

    assert result.usable == ("192.0.2.88",)
    assert result.ignored == ()


def test_matching_ignores_ipv6_formatting() -> None:
    wifi = Adapter("wifi", "Wi-Fi", "", True, ("2001:db8:0:0::53",))

    assert classify_nameservers(["2001:db8::53"], scan(wifi)).usable == ("2001:db8::53",)


# --- Windows ------------------------------------------------------------------------------


def test_parse_registry_nameservers_accepts_commas_and_spaces() -> None:
    assert parse_registry_nameservers("192.0.2.1,1.1.1.1") == ("192.0.2.1", "1.1.1.1")
    assert parse_registry_nameservers("172.16.0.1 1.1.1.1 8.8.8.8") == (
        "172.16.0.1",
        "1.1.1.1",
        "8.8.8.8",
    )
    assert parse_registry_nameservers("") == ()


def test_bridge_members_walks_through_filter_layers() -> None:
    # As on Windows: Ethernet 2 (14) sits on filter layers 38..34, then WiFi (8). Filters
    # (39) also sit above it, and an unrelated adapter (4) has nothing below.
    stack = [(39, 14), (14, 38), (38, 37), (37, 36), (36, 35), (35, 34), (34, 8), (8, 0)]
    stack += [(30, 4), (0, 39)]

    assert bridge_members(stack, [14, 4], interfaces={14, 8, 4}) == {8: 14}


def test_bridge_members_finds_every_member_once() -> None:
    stack = [(1, 2), (1, 3), (2, 4), (3, 4), (4, 1)]  # 4 reached twice; a loop back to 1

    assert bridge_members(stack, [1], interfaces={1, 4, 5}) == {4: 1}
    assert bridge_members([(1, 5), (1, 6)], [1], interfaces={5, 6}) == {5: 1, 6: 1}
    assert bridge_members(stack, [9], interfaces={4}) == {}


def test_clean_dns_drops_windows_placeholders() -> None:
    assert adapters_mod._clean_dns(["fec0:0:0:ffff::1", "192.0.2.1", "192.0.2.1"]) == ("192.0.2.1",)


# --- macOS --------------------------------------------------------------------------------

IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:00:01
\tstatus: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tstatus: inactive
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tConfiguration:
\t\tid 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
\tmember: en1 flags=3<LEARNING,DISCOVER>
\t        ifmaxaddr 0 port 5 priority 0 path cost 0
\tstatus: inactive
"""

SCUTIL = """\
DNS configuration

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 6 (en0)
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.0.2.1
  nameserver[1] : 2001:db8::1
  if_index : 6 (en0)
  flags    : Scoped, Request A records, Request AAAA records

resolver #2
  nameserver[0] : 10.8.0.1
  if_index : 14 (utun3)
  flags    : Scoped, Request A records
"""


def test_parse_ifconfig() -> None:
    assert parse_ifconfig(IFCONFIG) == [
        ("en0", True),
        ("en1", False),
        ("utun3", True),  # no status line: UP and RUNNING
        ("gif0", False),
        ("bridge0", False),
    ]


def test_parse_bridge_members() -> None:
    assert parse_bridge_members(IFCONFIG) == {"en1": "bridge0"}
    assert parse_bridge_members("en0: flags=8863<UP> mtu 1500\n") == {}


def test_parse_scutil_uses_scoped_section() -> None:
    assert parse_scutil_dns(SCUTIL) == {
        "en0": ("192.0.2.1", "2001:db8::1"),
        "utun3": ("10.8.0.1",),
    }
    assert parse_scutil_dns("DNS configuration\n\nresolver #1\n") == {}


def test_macos_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = {"ifconfig": IFCONFIG, "scutil": SCUTIL}
    monkeypatch.setattr(adapters_mod, "_run", lambda args: outputs[args[0]])

    result = adapters_mod._macos_scan()

    assert result.dns_per_adapter
    assert [(a.name, a.connected, a.dns_servers, a.bridged_into) for a in result.adapters] == [
        ("en0", True, ("192.0.2.1", "2001:db8::1"), None),
        ("en1", False, (), "bridge0"),
        ("utun3", True, ("10.8.0.1",), None),
        ("gif0", False, (), None),
        ("bridge0", False, (), None),
    ]


def test_macos_scan_without_ifconfig(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters_mod, "_run", lambda args: None)

    result = adapters_mod._macos_scan()

    assert result.error == "couldn't run ifconfig"


# --- Linux --------------------------------------------------------------------------------

RESOLVECTL = """\
Global:
Link 2 (eth0): 192.0.2.1 2001:db8::1
Link 3 (wlan0):
Link 4 (tun0): 10.8.0.1
"""


def test_parse_resolvectl_dns() -> None:
    assert parse_resolvectl_dns(RESOLVECTL) == {
        "eth0": ("192.0.2.1", "2001:db8::1"),
        "wlan0": (),
        "tun0": ("10.8.0.1",),
    }


def make_sys_net(root: Path, links: dict[str, dict[str, str]]) -> Path:
    for name, files in links.items():
        (root / name).mkdir(parents=True)
        for file, content in files.items():
            (root / name / file).write_text(content + "\n", encoding="utf-8")
    return root


def test_linux_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sys_net = make_sys_net(
        tmp_path,
        {
            "lo": {"operstate": "unknown", "carrier": "1"},
            "eth0": {"operstate": "up"},
            "wlan0": {"operstate": "down"},
            "tun0": {"operstate": "unknown", "carrier": "1"},
        },
    )
    monkeypatch.setattr(adapters_mod, "_run", lambda args: RESOLVECTL)

    result = adapters_mod._linux_scan(sys_net)

    assert result.dns_per_adapter
    assert [(a.name, a.connected, a.dns_servers) for a in result.adapters] == [
        ("eth0", True, ("192.0.2.1", "2001:db8::1")),
        ("tun0", True, ("10.8.0.1",)),
        ("wlan0", False, ()),
    ]


def test_linux_scan_finds_bridge_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sys_net = make_sys_net(
        tmp_path, {"br0": {"operstate": "up"}, "eth0": {"operstate": "up"}, "wlan0": {}}
    )
    (sys_net / "br0" / "brif" / "eth0").mkdir(parents=True)  # a symlink in real sysfs
    monkeypatch.setattr(adapters_mod, "_run", lambda args: "Link 3 (br0): 192.0.2.1\n")

    result = adapters_mod._linux_scan(sys_net)

    assert [(a.name, a.connected, a.bridged_into) for a in result.adapters] == [
        ("br0", True, None),
        ("eth0", True, "br0"),
        ("wlan0", False, None),
    ]
    assert [a.name for a in result.connected] == ["br0"]


def test_linux_scan_without_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sys_net = make_sys_net(tmp_path, {"eth0": {"operstate": "up"}})
    monkeypatch.setattr(adapters_mod, "_run", lambda args: None)

    result = adapters_mod._linux_scan(sys_net)

    assert not result.dns_per_adapter
    assert result.adapters[0].connected


# --- Choosing the reader, and running commands -------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "reader"),
    [("win32", "_windows_scan"), ("darwin", "_macos_scan"), ("linux", "_linux_scan")],
)
def test_scan_adapters_picks_the_reader_for_the_os(
    monkeypatch: pytest.MonkeyPatch, platform: str, reader: str
) -> None:
    expected = AdapterScan((), dns_per_adapter=True)
    monkeypatch.setattr(adapters_mod.sys, "platform", platform)
    monkeypatch.setattr(adapters_mod, reader, lambda: expected)

    assert scan_adapters() is expected


def test_scan_adapters_on_an_unknown_os(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters_mod.sys, "platform", "plan9")

    assert scan_adapters().error == "not supported on plan9"


class Completed:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode, self.stdout = returncode, stdout


def missing_command(*args: object, **kwargs: object) -> Completed:
    raise FileNotFoundError("ifconfig")


def too_slow(*args: object, **kwargs: object) -> Completed:
    raise adapters_mod.subprocess.TimeoutExpired("ifconfig", 1)


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        (lambda *a, **k: Completed(0, "output"), "output"),
        (lambda *a, **k: Completed(1, "partial"), None),
        (missing_command, None),
        (too_slow, None),
    ],
)
def test_run_returns_output_or_none(
    monkeypatch: pytest.MonkeyPatch, run: object, expected: str | None
) -> None:
    monkeypatch.setattr(adapters_mod.subprocess, "run", run)

    assert adapters_mod._run(["ifconfig", "-a"]) == expected


def test_windows_scan_adds_bridge_members_and_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    wifi = Adapter("{w}", "Wi-Fi", "", True, ("192.0.2.1",))
    member = Adapter("{m}", "Ethernet", "", True, (), bridged_into="Network Bridge")
    entry = RegistryEntry("{w}", "NameServer", ("192.0.2.1",))
    monkeypatch.setattr(adapters_mod, "_windows_adapters", lambda: {7: wifi})
    monkeypatch.setattr(adapters_mod, "_windows_bridge_members", lambda adapters: [member])
    monkeypatch.setattr(adapters_mod, "_windows_registry", lambda: [entry])

    scan = adapters_mod._windows_scan()

    assert scan.adapters == (wifi, member)
    assert scan.registry == (entry,)
    assert scan.dns_per_adapter


def test_windows_scan_keeps_adapters_when_bridges_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    wifi = Adapter("{w}", "Wi-Fi", "", True, ("192.0.2.1",))

    def broken(adapters: object) -> list[Adapter]:
        raise OSError("GetIfStackTable failed")

    monkeypatch.setattr(adapters_mod, "_windows_adapters", lambda: {7: wifi})
    monkeypatch.setattr(adapters_mod, "_windows_bridge_members", broken)
    monkeypatch.setattr(adapters_mod, "_windows_registry", list)

    assert adapters_mod._windows_scan().adapters == (wifi,)


class FakeKey:
    def __init__(
        self, children: dict[str, "FakeKey"] | None = None, values: dict[str, str] | None = None
    ) -> None:
        self.children = children or {}
        self.values = values or {}

    def __enter__(self) -> "FakeKey":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeWinreg:
    """Stands in for the `winreg` module, serving a fixed Interfaces key."""

    HKEY_LOCAL_MACHINE = object()

    def __init__(self, interfaces: dict[str, FakeKey] | None) -> None:
        self.interfaces = interfaces

    def OpenKey(self, parent: object, name: str) -> FakeKey:  # winreg's own names
        if parent is self.HKEY_LOCAL_MACHINE:
            if self.interfaces is None:
                raise OSError("no such key")
            return FakeKey(self.interfaces)
        assert isinstance(parent, FakeKey)
        child = parent.children.get(name)
        if child is None:
            raise OSError("access denied")
        return child

    def EnumKey(self, key: FakeKey, index: int) -> str:
        names = [*key.children, "{locked}"]  # one more that can't be opened
        if index >= len(names):
            raise OSError("no more items")
        return names[index]

    def QueryValueEx(self, key: FakeKey, name: str) -> tuple[str, int]:
        if name not in key.values:
            raise OSError("not found")
        return key.values[name], 1


def test_windows_registry_reads_every_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    interfaces = {
        "{AAA}": FakeKey(values={"NameServer": "192.0.2.1,192.0.2.2"}),
        "{BBB}": FakeKey(values={"DhcpNameServer": "192.0.2.53 192.0.2.54", "NameServer": ""}),
        "{CCC}": FakeKey(),  # no DNS servers
    }
    monkeypatch.setattr(adapters_mod.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg(interfaces))

    entries = adapters_mod._windows_registry()

    assert entries == [
        RegistryEntry("{aaa}", "NameServer", ("192.0.2.1", "192.0.2.2")),
        RegistryEntry("{bbb}", "DhcpNameServer", ("192.0.2.53", "192.0.2.54")),
    ]


def test_windows_registry_without_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters_mod.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg(None))

    assert adapters_mod._windows_registry() == []


def test_windows_registry_elsewhere_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters_mod.sys, "platform", "linux")

    assert adapters_mod._windows_registry() == []
