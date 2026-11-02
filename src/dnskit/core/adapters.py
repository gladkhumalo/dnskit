"""Network adapters and the DNS servers configured on each, read from the operating system.

Each OS has its own reader; they all return an `AdapterScan`. The parsing of command output
(macOS, Linux) is split into pure functions so it can be tested with sample text.
"""

import dataclasses
import ipaddress
import re
import subprocess
import sys
from collections.abc import Callable, Container, Iterable
from dataclasses import dataclass
from pathlib import Path

# Windows lists these deprecated site-local addresses on IPv6 interfaces that have no DNS
# server configured. They are placeholders, never real servers, so they are dropped.
PLACEHOLDER_DNS = frozenset({"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"})

_COMMAND_TIMEOUT_S = 5.0

# Words in an adapter's name or description that mark it as a VPN.
_VPN_WORDS = re.compile(
    r"vpn|\btap\b|tap-windows|wireguard|wintun|tailscale|zerotier|nordlynx|anyconnect"
    r"|globalprotect|pangp|fortinet|forticlient|juniper|pulse secure|cisco.*secure client",
    re.IGNORECASE,
)
_TUNNEL_NAMES = re.compile(r"^(u?tun|wg|ppp|ipsec)\d+$")


@dataclass(frozen=True)
class Adapter:
    id: str  # OS identifier: the interface GUID on Windows, the interface name elsewhere
    name: str  # friendly name, e.g. "Wi-Fi", "Ethernet 2", "en0"
    description: str  # driver or hardware description; "" when the OS doesn't give one
    connected: bool
    dns_servers: tuple[str, ...]  # in the adapter's order
    # A bridge member (e.g. Wi-Fi in a network bridge) carries traffic for another adapter
    # and has no IP or DNS settings of its own: this is that adapter's name.
    bridged_into: str | None = None

    @property
    def vpn(self) -> bool:
        return is_vpn(self)


@dataclass(frozen=True)
class RegistryEntry:
    """Windows only: a registry value that lists a nameserver."""

    interface_id: str  # the interface GUID, as in Adapter.id
    value: str  # "NameServer" (set by hand) or "DhcpNameServer" (from DHCP)
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class AdapterScan:
    adapters: tuple[Adapter, ...]
    # Whether the OS reported each adapter's DNS servers. Without that (Linux without
    # systemd-resolved), nameservers can't be matched to adapters.
    dns_per_adapter: bool
    registry: tuple[RegistryEntry, ...] = ()  # Windows only
    error: str | None = None  # why adapters couldn't be read, if they couldn't

    @property
    def connected(self) -> tuple[Adapter, ...]:
        """Connected adapters with their own network settings (not bridge members)."""
        return tuple(a for a in self.adapters if a.connected and a.bridged_into is None)

    @property
    def connected_vpns(self) -> tuple[Adapter, ...]:
        return tuple(a for a in self.connected if a.vpn)

    def connected_dns(self) -> set[str]:
        return {normalize_ip(ns) for a in self.connected for ns in a.dns_servers}

    def adapters_listing(self, nameserver: str) -> tuple[Adapter, ...]:
        """Adapters that list `nameserver`, connected ones first."""
        key = normalize_ip(nameserver)
        owners = [a for a in self.adapters if key in {normalize_ip(ns) for ns in a.dns_servers}]
        return tuple(sorted(owners, key=lambda a: not a.connected))

    def registry_listing(self, nameserver: str) -> tuple[RegistryEntry, ...]:
        key = normalize_ip(nameserver)
        return tuple(e for e in self.registry if key in {normalize_ip(ns) for ns in e.nameservers})


def normalize_ip(address: str) -> str:
    """Canonical text for an IP address (zone id dropped), so equal addresses compare equal."""
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).compressed
    except ValueError:
        return address


def is_vpn(adapter: Adapter) -> bool:
    """Whether the adapter looks like a VPN, judging by its name and description.

    Generic tunnel interfaces (tun0, utun3, wg0, ppp0) only count when they have DNS
    servers: macOS always has a few utun interfaces for its own services.
    """
    text = f"{adapter.name} {adapter.description}"
    if _VPN_WORDS.search(text):
        return True
    return bool(adapter.dns_servers) and bool(_TUNNEL_NAMES.match(adapter.name))


def is_loopback(address: str) -> bool:
    """True for a local DNS stub such as 127.0.0.53 (systemd-resolved) or ::1."""
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def scan_adapters() -> AdapterScan:
    """Read this computer's network adapters and their DNS servers. Never raises."""
    try:
        if sys.platform == "win32":
            return _windows_scan()
        if sys.platform == "darwin":
            return _macos_scan()
        if sys.platform.startswith("linux"):
            return _linux_scan()
    except Exception as exc:  # an OS quirk must not break lookups
        return AdapterScan((), dns_per_adapter=False, error=f"{type(exc).__name__}: {exc}")
    return AdapterScan((), dns_per_adapter=False, error=f"not supported on {sys.platform}")


def _clean_dns(servers: list[str]) -> tuple[str, ...]:
    """Drop placeholders and duplicates, keeping order."""
    seen: dict[str, None] = {}
    for server in servers:
        if normalize_ip(server) not in PLACEHOLDER_DNS:
            seen.setdefault(server, None)
    return tuple(seen)


def _run(args: list[str]) -> str | None:
    """Run a command and return its stdout, or None if it's missing or fails."""
    try:
        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=_COMMAND_TIMEOUT_S, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


# --- Windows ------------------------------------------------------------------------------

_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_OPER_STATUS_UP = 1
_INTERFACES_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"


def _windows_scan() -> AdapterScan:
    adapters = _windows_adapters()
    try:
        members = _windows_bridge_members(adapters)
    except Exception:  # bridge members are extra detail; never lose the adapter list over them
        members = []
    return AdapterScan(
        tuple(adapters.values()) + tuple(members),
        dns_per_adapter=True,
        registry=tuple(_windows_registry()),
    )


def _windows_adapters() -> dict[int, Adapter]:  # pragma: no cover (Windows API; checked live)
    """Adapters from GetAdaptersAddresses: the same data as Get-DnsClientServerAddress.

    Keyed by interface index. Only adapters with TCP/IP bound are listed, so bridge members
    (which have none) come from `_windows_bridge_members`.
    """
    import ctypes

    class _Adapter(ctypes.Structure):  # IP_ADAPTER_ADDRESSES_LH, up to OperStatus
        pass

    class _SocketAddress(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class _DnsServer(ctypes.Structure):  # IP_ADAPTER_DNS_SERVER_ADDRESS_XP
        pass

    _DnsServer._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
        ("Next", ctypes.POINTER(_DnsServer)),
        ("Address", _SocketAddress),
    ]
    _Adapter._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", ctypes.c_ulong),
        ("Next", ctypes.POINTER(_Adapter)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(_DnsServer)),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("Mtu", ctypes.c_ulong),
        ("IfType", ctypes.c_ulong),
        ("OperStatus", ctypes.c_int),
    ]

    get_adapters = ctypes.windll.iphlpapi.GetAdaptersAddresses  # type: ignore[attr-defined,unused-ignore]
    af_unspec, skip_unicast_anycast_multicast = 0, 0x7
    error_buffer_overflow = 111
    size = ctypes.c_ulong(16 * 1024)
    for _ in range(3):  # the adapter list can grow between calls
        buffer = ctypes.create_string_buffer(size.value)
        status = get_adapters(
            af_unspec, skip_unicast_anycast_multicast, None, buffer, ctypes.byref(size)
        )
        if status != error_buffer_overflow:
            break
    if status != 0:
        raise OSError(status, "GetAdaptersAddresses failed")

    adapters = {}
    node = ctypes.cast(buffer, ctypes.POINTER(_Adapter))
    while node:
        entry = node.contents
        if entry.IfType != _IF_TYPE_SOFTWARE_LOOPBACK:
            servers = []
            dns = entry.FirstDnsServerAddress
            while dns:
                address = dns.contents.Address
                raw = ctypes.string_at(address.lpSockaddr, address.iSockaddrLength)
                if (ip := _sockaddr_ip(raw)) is not None:
                    servers.append(ip)
                dns = dns.contents.Next
            adapters[entry.IfIndex] = Adapter(
                id=(entry.AdapterName or b"").decode("ascii", "replace").lower(),
                name=entry.FriendlyName or "",
                description=entry.Description or "",
                connected=entry.OperStatus == _IF_OPER_STATUS_UP,
                dns_servers=_clean_dns(servers),
            )
        node = entry.Next
    return adapters


def _windows_bridge_members(
    adapters: dict[int, Adapter],
) -> list[Adapter]:  # pragma: no cover (Windows API; checked live)
    """Adapters bridged into one of `adapters`, from the interface stack (GetIfStackTable).

    Between an adapter and its members the stack holds filter drivers (e.g. the WFP filter),
    which GetIfTable2 flags, and unnamed internal layers; both are skipped to reach the
    member itself.
    """
    import ctypes
    import uuid

    class _Row(ctypes.Structure):  # MIB_IF_ROW2
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_ulong),
            ("InterfaceGuid", ctypes.c_ubyte * 16),
            ("Alias", ctypes.c_wchar * 257),
            ("Description", ctypes.c_wchar * 257),
            ("PhysicalAddressLength", ctypes.c_ulong),
            ("PhysicalAddress", ctypes.c_ubyte * 32),
            ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
            ("Mtu", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
            ("TunnelType", ctypes.c_int),
            ("MediaType", ctypes.c_int),
            ("PhysicalMediumType", ctypes.c_int),
            ("AccessType", ctypes.c_int),
            ("DirectionType", ctypes.c_int),
            ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
            ("OperStatus", ctypes.c_int),
            ("AdminStatus", ctypes.c_int),
            ("MediaConnectState", ctypes.c_int),
            ("NetworkGuid", ctypes.c_ubyte * 16),
            ("ConnectionType", ctypes.c_int),
            ("Counters", ctypes.c_uint64 * 20),  # link speeds and traffic counters
        ]

    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined,unused-ignore]
    filter_interface = 0x2  # bit 1 of InterfaceAndOperStatusFlags

    table = ctypes.c_void_p()
    if iphlpapi.GetIfTable2(ctypes.byref(table)) != 0 or table.value is None:
        return []
    base = table.value
    try:
        count = ctypes.c_ulong.from_address(base).value
        rows = (_Row * count).from_address(base + ctypes.alignment(_Row))
        interfaces = {
            row.InterfaceIndex: Adapter(
                id=f"{{{uuid.UUID(bytes_le=bytes(row.InterfaceGuid))}}}",
                name=row.Alias,
                description=row.Description,
                connected=row.OperStatus == _IF_OPER_STATUS_UP,
                dns_servers=(),
            )
            for row in rows
            if row.Alias and not row.InterfaceAndOperStatusFlags & filter_interface
        }
    finally:
        iphlpapi.FreeMibTable(table)

    if iphlpapi.GetIfStackTable(ctypes.byref(table)) != 0 or table.value is None:
        return []
    base = table.value
    try:
        count = ctypes.c_ulong.from_address(base).value
        pairs = (ctypes.c_ulong * (2 * count)).from_address(base + ctypes.sizeof(ctypes.c_ulong))
        stack = list(zip(pairs[0::2], pairs[1::2], strict=True))  # (higher, lower) per row
    finally:
        iphlpapi.FreeMibTable(table)

    return [
        dataclasses.replace(interfaces[member], bridged_into=adapters[parent].name)
        for member, parent in bridge_members(stack, adapters, interfaces).items()
        if member not in adapters
    ]


def bridge_members(
    stack: Iterable[tuple[int, int]], parents: Iterable[int], interfaces: Container[int]
) -> dict[int, int]:
    """Member interface -> the parent it's bridged into, from (higher, lower) stack rows.

    Walks down from each parent; an index not in `interfaces` (a filter driver layer) is
    passed through, and the first real interface found on each path is a member.
    """
    lowers: dict[int, list[int]] = {}
    for higher, lower in stack:
        if higher and lower:  # 0 marks the top or bottom of a stack
            lowers.setdefault(higher, []).append(lower)
    members: dict[int, int] = {}
    for parent in parents:
        pending, seen = list(lowers.get(parent, ())), {parent}
        while pending:
            index = pending.pop(0)
            if index in seen:
                continue
            seen.add(index)
            if index in interfaces:
                members.setdefault(index, parent)
            else:
                pending.extend(lowers.get(index, ()))
    return members


def _sockaddr_ip(raw: bytes) -> str | None:
    """The IP address in a raw Windows SOCKADDR (sockaddr_in or sockaddr_in6)."""
    family = int.from_bytes(raw[:2], "little")
    if family == 2 and len(raw) >= 8:  # AF_INET: family, port, 4-byte address
        return str(ipaddress.IPv4Address(raw[4:8]))
    if family == 23 and len(raw) >= 24:  # AF_INET6: family, port, flowinfo, 16-byte address
        return str(ipaddress.IPv6Address(raw[8:24]))
    return None


def _windows_registry() -> list[RegistryEntry]:
    """Every interface's NameServer/DhcpNameServer value: what dnspython reads."""
    if sys.platform != "win32":  # also tells type checkers on other systems to skip the rest
        return []
    import winreg

    entries = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _INTERFACES_KEY)
    except OSError:
        return []
    with root:
        index = 0
        while True:
            try:
                interface_id = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            try:
                key = winreg.OpenKey(root, interface_id)
            except OSError:
                continue
            with key:
                for value in ("NameServer", "DhcpNameServer"):
                    try:
                        text = winreg.QueryValueEx(key, value)[0]
                    except OSError:
                        continue
                    servers = parse_registry_nameservers(str(text))
                    if servers:
                        entries.append(RegistryEntry(interface_id.lower(), value, servers))
    return entries


def parse_registry_nameservers(text: str) -> tuple[str, ...]:
    """Registry nameserver lists are separated by commas or spaces."""
    return tuple(part for part in re.split(r"[,\s]+", text) if part)


# --- macOS --------------------------------------------------------------------------------


def _macos_scan() -> AdapterScan:
    ifconfig = _run(["ifconfig", "-a"])
    if ifconfig is None:
        return AdapterScan((), dns_per_adapter=False, error="couldn't run ifconfig")
    scoped = parse_scutil_dns(_run(["scutil", "--dns"]) or "")
    bridges = parse_bridge_members(ifconfig)
    adapters = tuple(
        Adapter(name, name, "", connected, scoped.get(name, ()), bridges.get(name))
        for name, connected in parse_ifconfig(ifconfig)
    )
    return AdapterScan(adapters, dns_per_adapter=bool(scoped))


def parse_ifconfig(text: str) -> list[tuple[str, bool]]:
    """(interface, connected) for each non-loopback interface in `ifconfig -a` output.

    An interface with a `status:` line is connected when it says `active`; one without
    (e.g. a VPN tunnel) is connected when its flags include both UP and RUNNING.
    """
    interfaces: list[tuple[str, bool]] = []
    name, flags, status = None, set[str](), None

    def flush() -> None:
        if name is not None and "LOOPBACK" not in flags:
            connected = status == "active" if status else {"UP", "RUNNING"} <= flags
            interfaces.append((name, connected))

    for line in text.splitlines():
        if header := re.match(r"^(\S+?): flags=\w+<([^>]*)>", line):
            flush()
            name, flags, status = header[1], set(header[2].split(",")), None
        elif match := re.match(r"^\s+status: (\S+)", line):
            status = match[1]
    flush()
    return interfaces


def parse_bridge_members(text: str) -> dict[str, str]:
    """Member interface -> bridge, from the `member:` lines of bridges in `ifconfig -a`."""
    members: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        if header := re.match(r"^(\S+?): flags=", line):
            name = header[1]
        elif (match := re.match(r"^\s+member: (\S+)", line)) and name is not None:
            members[match[1]] = name
    return members


def parse_scutil_dns(text: str) -> dict[str, tuple[str, ...]]:
    """Interface name -> nameservers, from the scoped section of `scutil --dns`."""
    _, found, scoped = text.partition("DNS configuration (for scoped queries)")
    if not found:
        return {}
    result: dict[str, list[str]] = {}
    for block in re.split(r"\n(?=resolver #\d+)", scoped):
        interface = re.search(r"if_index\s*:\s*\d+\s*\((\S+)\)", block)
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block)
        if interface and servers:
            result.setdefault(interface[1], []).extend(servers)
    return {name: _clean_dns(servers) for name, servers in result.items()}


# --- Linux --------------------------------------------------------------------------------


def _linux_scan(sys_net: Path = Path("/sys/class/net")) -> AdapterScan:
    per_link = parse_resolvectl_dns(_run(["resolvectl", "dns"]) or "")
    links = sorted(path for path in sys_net.iterdir() if path.name != "lo")
    # A bridge lists its members as entries of its brif/ directory.
    bridges = {
        member.name: path.name
        for path in links
        if (path / "brif").is_dir()
        for member in (path / "brif").iterdir()
    }
    adapters = tuple(
        Adapter(
            path.name,
            path.name,
            "",
            _linux_connected(path, _read_text),
            per_link.get(path.name, ()),
            bridges.get(path.name),
        )
        for path in links
    )
    return AdapterScan(adapters, dns_per_adapter=bool(per_link))


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _linux_connected(path: Path, read: Callable[[Path], str | None]) -> bool:
    """Up with a carrier. `operstate` is "unknown" for some virtual links (e.g. tun)."""
    state = read(path / "operstate")
    if state == "up":
        return True
    return state == "unknown" and read(path / "carrier") == "1"


def parse_resolvectl_dns(text: str) -> dict[str, tuple[str, ...]]:
    """Link name -> nameservers, from `resolvectl dns` (lines like `Link 2 (eth0): 1.1.1.1`)."""
    result = {}
    for line in text.splitlines():
        if match := re.match(r"^Link \d+ \(([^)]+)\):\s*(.*)$", line.strip()):
            result[match[1]] = _clean_dns(match[2].split())
    return result
