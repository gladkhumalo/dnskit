"""Inspect this computer's DNS setup: adapters, their nameservers, ghosts and the hosts file.

Problems are returned with plain-English explanations and fixes, so every front end can
present them its own way.
"""

import dataclasses
import ipaddress
import os
import shutil
import socket
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from dnskit.core.adapters import (
    Adapter,
    AdapterScan,
    RegistryEntry,
    normalize_ip,
    scan_adapters,
)
from dnskit.core.connectivity import IPv6Check, IPv6State, check_ipv6
from dnskit.core.integrity import (
    CLOUDFLARE_WHOAMI,
    GOOGLE_WHOAMI,
    HijackCheck,
    InterceptionCheck,
    Verdict,
    check_cloudflare,
    check_google,
    check_nxdomain,
)
from dnskit.core.nameservers import (
    PROBE_TIMEOUT_S,
    SLOW_THRESHOLD_MS,
    SystemNameservers,
    classify_nameservers,
    configured_nameservers,
    probe_all,
)

_INTERFACES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

# Hosts file names that every OS ships with; entries for these don't override real DNS.
_STANDARD_HOST_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localhost4",
        "localhost4.localdomain4",
        "localhost6",
        "localhost6.localdomain6",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
    }
)

# Public resolvers that are practically never down: when one doesn't answer, something
# between this computer and it (a firewall, a VPN, the network) is blocking it.
WELL_KNOWN_RESOLVERS: dict[str, str] = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
}


class Severity(StrEnum):
    ERROR = "error"  # DNS doesn't work
    WARNING = "warning"  # DNS works, but something is misconfigured or slow


class ProblemKind(StrEnum):
    """What a problem is about, so other reports (`doctor`) can weigh it."""

    NO_ADAPTER = "no_adapter"
    NO_DNS_SERVERS = "no_dns_servers"
    NO_RESPONSE = "no_response"  # every DNS server in use is silent
    ADAPTERS_UNREADABLE = "adapters_unreadable"
    SERVER_FAILED = "server_failed"
    VPN_BLOCKED = "vpn_blocked"
    SLOW = "slow"
    GHOST = "ghost"
    HOSTS = "hosts"
    HOSTS_UNREADABLE = "hosts_unreadable"
    HIJACK = "hijack"
    INTERCEPTION = "interception"
    IPV6_BROKEN = "ipv6_broken"


@dataclass(frozen=True)
class Problem:
    severity: Severity
    title: str
    detail: str
    fix: str
    kind: ProblemKind


@dataclass(frozen=True)
class ServerCheck:
    nameserver: str
    adapters: tuple[Adapter, ...]  # adapters that list it, connected first
    used: bool  # lookups use it: it's on a connected adapter (or adapters are unknown)
    ghost: bool  # in the OS configuration, but on no connected adapter
    latency_ms: float | None  # None: no response within the probe timeout
    registry: tuple[RegistryEntry, ...] = ()  # Windows: registry values that list it
    public: str | None = None  # provider, for a well-known public resolver like 1.1.1.1
    probed: bool = True  # False: not tested (a ghost, with probe_ghosts=False)
    # In use and not answering while a VPN is connected, and not on the VPN: most likely
    # the VPN blocks DNS outside its tunnel, rather than the server being down.
    vpn_blocked: bool = False

    @property
    def failed(self) -> bool:
        return self.probed and self.latency_ms is None

    @property
    def slow(self) -> bool:
        return self.latency_ms is not None and self.latency_ms > SLOW_THRESHOLD_MS

    @property
    def adapter_names(self) -> str:
        return ", ".join(a.name for a in self.adapters)


class HostsKind(StrEnum):
    BLOCKED = "blocked"  # points at 0.0.0.0 or ::, so the name can't be reached
    LOCAL = "this computer"  # points at a loopback address
    REDIRECT = "redirect"  # points at some other address


@dataclass(frozen=True)
class HostsEntry:
    line: int
    ip: str
    names: tuple[str, ...]  # non-standard names on the line
    kind: HostsKind


@dataclass(frozen=True)
class HostsFile:
    path: str
    entries: tuple[HostsEntry, ...]  # only lines that could override DNS
    error: str | None = None  # why the file couldn't be read (a missing file is no error)


@dataclass(frozen=True)
class FlushCommand:
    command: str | None  # None when there is no system DNS cache to flush
    note: str


@dataclass(frozen=True)
class LocalReport:
    platform: str  # "Windows", "macOS" or "Linux"
    scan: AdapterScan
    nameservers: SystemNameservers
    servers: tuple[ServerCheck, ...]  # connected adapters' servers first, then the rest
    hosts: HostsFile
    flush: FlushCommand
    problems: tuple[Problem, ...]  # errors first
    probe_timeout: float
    elapsed_ms: float
    hijack: tuple[HijackCheck, ...] = ()  # one per responding DNS server in use
    interception: tuple[InterceptionCheck, ...] = ()  # Google, then Cloudflare
    ipv6: IPv6Check | None = None

    @property
    def has_errors(self) -> bool:
        return any(p.severity is Severity.ERROR for p in self.problems)

    @property
    def vpns(self) -> tuple[Adapter, ...]:
        """Connected VPN adapters."""
        return self.scan.connected_vpns


def local_check(timeout: float = PROBE_TIMEOUT_S, probe_ghosts: bool = True) -> LocalReport:
    """Inspect the local DNS setup and test every nameserver it mentions, in parallel.

    First every server is probed while the interception checks run; then the servers in use
    that answered are checked for NXDOMAIN hijacking, and IPv6 is tested through the fastest.
    Without `probe_ghosts`, ghost servers (which nothing uses) aren't tested, which saves
    waiting for the dead ones to time out.
    """
    start = time.perf_counter()
    scan = scan_adapters()
    nameservers = classify_nameservers(configured_nameservers(), scan)

    candidates = list(dict.fromkeys(_candidates(scan, nameservers)))
    with ThreadPoolExecutor(max_workers=8) as pool:
        to_probe = [ns for ns in candidates if probe_ghosts or ns not in nameservers.ignored]
        probes = pool.submit(probe_all, to_probe, timeout)
        google = pool.submit(check_google, timeout)
        cloudflare = pool.submit(check_cloudflare, timeout)
        latencies = {p.nameserver: p.latency_ms for p in probes.result()}
        servers = tuple(
            _vpn_aware(
                ServerCheck(
                    nameserver=ns,
                    adapters=scan.adapters_listing(ns),
                    used=ns in nameservers.usable or _on_connected_adapter(scan, ns),
                    ghost=ns in nameservers.ignored,
                    latency_ms=latencies.get(ns),
                    registry=scan.registry_listing(ns),
                    public=public_resolver(ns),
                    probed=ns in to_probe,
                ),
                vpn_connected=bool(scan.connected_vpns),
            )
            for ns in candidates
        )

        # Servers in use that answered, fastest first.
        answering = [
            s.nameserver
            for s in sorted(servers, key=lambda s: s.latency_ms or 0.0)
            if s.used and not s.failed
        ]
        hijacks = [pool.submit(check_nxdomain, ns, timeout) for ns in answering]
        ipv6 = pool.submit(check_ipv6, answering, timeout)
        hijack = tuple(f.result() for f in hijacks)
        interception = (google.result(), cloudflare.result())
        ipv6_check = ipv6.result()

    hosts = read_hosts()
    platform = platform_name()
    problems = _problems(scan, servers, hosts, platform, timeout)
    problems += _check_problems(hijack, interception, ipv6_check, scan.connected_vpns)
    problems = tuple(sorted(problems, key=lambda p: p.severity is not Severity.ERROR))
    return LocalReport(
        platform=platform,
        scan=scan,
        nameservers=nameservers,
        servers=servers,
        hosts=hosts,
        flush=flush_command(),
        problems=problems,
        probe_timeout=timeout,
        elapsed_ms=(time.perf_counter() - start) * 1000,
        hijack=hijack,
        interception=interception,
        ipv6=ipv6_check,
    )


def platform_name(platform: str | None = None) -> str:
    platform = sys.platform if platform is None else platform
    if platform == "win32":
        return "Windows"
    if platform == "darwin":
        return "macOS"
    return "Linux"


def _candidates(scan: AdapterScan, nameservers: SystemNameservers) -> list[str]:
    """Connected adapters' servers in adapter order, then the configured ones not yet seen."""
    return [ns for a in scan.connected for ns in a.dns_servers] + list(nameservers.configured)


def _on_connected_adapter(scan: AdapterScan, nameserver: str) -> bool:
    return any(a.connected for a in scan.adapters_listing(nameserver))


def public_resolver(nameserver: str) -> str | None:
    """The provider of a well-known public resolver (e.g. "Cloudflare"), else None."""
    return WELL_KNOWN_RESOLVERS.get(normalize_ip(nameserver))


def _vpn_aware(server: ServerCheck, vpn_connected: bool) -> ServerCheck:
    """Mark a failing server outside a connected VPN as probably blocked by that VPN."""
    blocked = (
        vpn_connected
        and server.used
        and server.failed
        and bool(server.adapters)
        and not any(a.vpn for a in server.adapters)
    )
    return dataclasses.replace(server, vpn_blocked=blocked) if blocked else server


# --- Hosts file ---------------------------------------------------------------------------


def hosts_path(platform: str | None = None) -> Path:
    """Where the OS keeps its hosts file."""
    if platform_name(platform) == "Windows":
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        return Path(root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def read_hosts(path: Path | None = None) -> HostsFile:
    """The hosts file's entries that could override DNS. Never raises."""
    path = hosts_path() if path is None else path
    try:
        text = path.read_bytes().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return HostsFile(str(path), ())
    except OSError as exc:
        return HostsFile(str(path), (), error=exc.strerror or str(exc))
    return HostsFile(str(path), tuple(parse_hosts(text, socket.gethostname())))


def parse_hosts(text: str, hostname: str = "") -> list[HostsEntry]:
    """Entries naming anything beyond the OS defaults (localhost, this computer's name)."""
    standard = set(_STANDARD_HOST_NAMES)
    if hostname:
        standard |= {hostname.lower(), hostname.split(".", 1)[0].lower()}

    entries = []
    for number, line in enumerate(text.lstrip("\ufeff").splitlines(), start=1):
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        ip, names = fields[0], tuple(n for n in fields[1:] if n.lower() not in standard)
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            continue  # not a valid line; the OS ignores it too
        if not names:
            continue
        if address.is_unspecified:
            kind = HostsKind.BLOCKED
        elif address.is_loopback:
            kind = HostsKind.LOCAL
        else:
            kind = HostsKind.REDIRECT
        entries.append(HostsEntry(number, ip, names, kind))
    return entries


# --- Flushing the DNS cache ---------------------------------------------------------------


def flush_command(
    platform: str | None = None, which: Callable[[str], str | None] = shutil.which
) -> FlushCommand:
    """The command that clears the OS's DNS cache."""
    match platform_name(platform):
        case "Windows":
            return FlushCommand(
                "ipconfig /flushdns",
                "Browsers keep their own DNS cache too; restart the browser if a site still "
                "goes to the old address.",
            )
        case "macOS":
            return FlushCommand(
                "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
                "It asks for your password. Restart the browser too; it keeps its own cache.",
            )
    if which("resolvectl"):
        return FlushCommand("sudo resolvectl flush-caches", "Clears systemd-resolved's cache.")
    if which("nscd"):
        return FlushCommand("sudo nscd --invalidate=hosts", "Clears nscd's hosts cache.")
    return FlushCommand(
        None,
        "No DNS cache service (systemd-resolved or nscd) was found, so the system doesn't "
        "cache DNS answers. Restart the browser or app to clear its own cache.",
    )


# --- Problems -----------------------------------------------------------------------------


def _problems(
    scan: AdapterScan,
    servers: tuple[ServerCheck, ...],
    hosts: HostsFile,
    platform: str,
    timeout: float,
) -> tuple[Problem, ...]:
    problems: list[Problem] = []
    used = [s for s in servers if s.used]

    if scan.error:
        problems.append(
            Problem(
                Severity.WARNING,
                "Couldn't read the network adapters",
                f"{scan.error}. Without them, nameservers can't be matched to adapters, so "
                "every configured nameserver is treated as in use.",
                "Run dnskit local again; if it keeps happening, please report it.",
                ProblemKind.ADAPTERS_UNREADABLE,
            )
        )
    elif not scan.connected:
        problems.append(
            Problem(
                Severity.ERROR,
                "No network adapter is connected",
                "Every network adapter is disconnected, so this computer can't reach any DNS "
                "server.",
                "Connect to Wi-Fi or plug in a network cable, then run dnskit local again.",
                ProblemKind.NO_ADAPTER,
            )
        )
    elif scan.dns_per_adapter and not any(a.dns_servers for a in scan.connected):
        problems.append(
            Problem(
                Severity.ERROR,
                "No DNS servers on the connected adapters",
                f"{_names(scan.connected)} {_is_are(scan.connected)} connected, but no DNS "
                "server is set, so names can't be looked up.",
                "Set the adapter to get DNS servers automatically (DHCP), or enter servers "
                "by hand, such as 1.1.1.1 and 8.8.8.8, in its network settings.",
                ProblemKind.NO_DNS_SERVERS,
            )
        )

    vpns = scan.connected_vpns
    if used and all(s.failed for s in used):
        listed = ", ".join(_server_label(s) for s in used)
        detail = f"None of the DNS servers in use answered within {timeout:g} s: {listed}."
        fix = (
            "Check that you're online (try a web page by IP address), restart the router, "
            "or temporarily set the adapter's DNS servers to 1.1.1.1 and 8.8.8.8."
        )
        if vpns:
            detail += f" {_names(vpns)} (VPN) {_is_are(vpns)} connected."
            fix = (
                f"Reconnect {_names(vpns)}, or disconnect it and run dnskit local again to "
                "test the other servers without it. If they still fail: " + fix[0].lower()
            ) + fix[1:]
        problems.append(
            Problem(
                Severity.ERROR,
                "No DNS server is responding",
                detail + _public_note(used),
                fix,
                ProblemKind.NO_RESPONSE,
            )
        )
    else:
        blocked = tuple(s for s in used if s.vpn_blocked)
        if blocked:
            problems.append(_vpn_blocked_problem(blocked, vpns, timeout))
        for server in used:
            if server.failed and not server.vpn_blocked:
                problems.append(_failed_problem(server, timeout))
            elif server.slow:
                problems.append(_slow_problem(server))

    problems.extend(_ghost_problem(s, platform) for s in servers if s.ghost)

    if hosts.error:
        problems.append(
            Problem(
                Severity.WARNING,
                "Couldn't read the hosts file",
                f"{hosts.path}: {hosts.error}.",
                "Open it as an administrator to check for entries that override DNS.",
                ProblemKind.HOSTS_UNREADABLE,
            )
        )
    elif hosts.entries:
        problems.append(_hosts_problem(hosts))

    return tuple(sorted(problems, key=lambda p: p.severity is not Severity.ERROR))


def _failed_problem(server: ServerCheck, timeout: float) -> Problem:
    where = f"{server.adapter_names}'s" if server.adapters else "the adapter's"
    detail = (
        f"It didn't answer a test query within {timeout:g} s. Lookups that try it first wait "
        "for it to time out before moving on to the next server."
    )
    if server.public:
        fix = (
            "Check whether a firewall, antivirus or VPN on this computer blocks DNS, or "
            "whether this network only allows its own DNS server (common at work, schools "
            f"and hotels). If it does, remove {server.nameserver} from {where} DNS settings "
            "and use the network's DNS server instead."
        )
    elif any(a.vpn for a in server.adapters):
        fix = (
            f"It's set by the VPN ({server.adapter_names}). Reconnect the VPN; if it keeps "
            "failing, ask whoever runs the VPN to check its DNS server."
        )
    else:
        fix = (
            f"If it keeps failing, remove it from {where} DNS settings, or check the device "
            f"at {server.nameserver} (often the router)."
        )
    return Problem(
        Severity.WARNING,
        f"DNS server {_server_label(server)} isn't responding",
        detail + _public_note((server,)),
        fix,
        ProblemKind.SERVER_FAILED,
    )


def _vpn_blocked_problem(
    servers: tuple[ServerCheck, ...], vpns: tuple[Adapter, ...], timeout: float
) -> Problem:
    one = len(servers) == 1
    vpn = _names(vpns)
    listed = ", ".join(_server_label(s) for s in servers)
    return Problem(
        Severity.WARNING,
        f"{'A DNS server' if one else 'DNS servers'} outside the VPN "
        f"{'isn' if one else 'aren'}'t responding",
        f"{listed} didn't answer within {timeout:g} s while {vpn} (VPN) {_is_are(vpns)} "
        "connected. Many VPNs send all traffic through the tunnel, or block DNS queries that "
        "go around it (DNS leak protection), so DNS servers on other adapters can't be "
        f"reached while the VPN is on. {'It is' if one else 'They are'} probably fine.",
        f"Don't remove {'it' if one else 'them'}. To test {'it' if one else 'them'}, "
        f"disconnect {vpn} and run dnskit local again. Meanwhile, lookups use the DNS "
        "servers that do answer.",
        ProblemKind.VPN_BLOCKED,
    )


def _public_note(servers: tuple[ServerCheck, ...] | list[ServerCheck]) -> str:
    """A sentence noting that silent well-known public resolvers are blocked, not down."""
    public = [s for s in servers if s.public and s.failed]
    if not public:
        return ""
    names = ", ".join(f"{s.nameserver} ({s.public})" for s in public)
    if len(public) == 1:
        return (
            f" {names} is a well-known public DNS service that's almost never down, so no "
            "response usually means a firewall or VPN is blocking it."
        )
    return (
        f" {names} are well-known public DNS services that are almost never down, so no "
        "response usually means a firewall or VPN is blocking them."
    )


def _slow_problem(server: ServerCheck) -> Problem:
    return Problem(
        Severity.WARNING,
        f"DNS server {_server_label(server)} is slow",
        f"It answered in {server.latency_ms:.0f} ms; a healthy DNS server usually answers in "
        f"under {SLOW_THRESHOLD_MS:.0f} ms.",
        "Run dnskit local again to see whether it's consistently slow. If it is, consider a "
        "faster DNS server such as 1.1.1.1 or 8.8.8.8 in the adapter's settings.",
        ProblemKind.SLOW,
    )


def _ghost_problem(server: ServerCheck, platform: str) -> Problem:
    ns = server.nameserver
    if not server.probed:
        responds = "It wasn't tested, since it isn't used."
    elif server.failed:
        responds = "It doesn't respond, so they wait for it to time out." + _public_note((server,))
    else:
        responds = f"It does respond ({server.latency_ms:.0f} ms)."
    readers = "programs that read the system configuration directly (such as dnspython)"
    if server.adapters:
        adapters = server.adapters
        detail = (
            f"It's set on {_names(adapters)}, which {_is_are(adapters)} disconnected. "
            f"{platform} ignores it until that adapter reconnects, but {readers} still try "
            "it. " + responds
        )
        fix = (
            "Nothing to do. dnskit ignores it too. If it doesn't answer once "
            f"{_names(adapters)} reconnects, change that adapter's DNS settings."
        )
    else:
        detail = (
            f"It's in the system configuration but on no network adapter, probably left "
            f"behind by a removed adapter, a VPN or an old DHCP lease. {readers.capitalize()} "
            "still try it. " + responds
        )
        if platform == "Windows" and server.registry:
            values = ", ".join(f"{e.interface_id} ({e.value})" for e in server.registry)
            fix = (
                f"dnskit ignores it. To remove it, delete {ns} from these values under "
                f"{_INTERFACES_KEY} in the registry (needs administrator rights): {values}."
            )
        elif platform == "Windows":
            fix = "dnskit ignores it, and so does Windows; no change is needed."
        else:
            fix = f"dnskit ignores it. To remove it, delete {ns} from /etc/resolv.conf or "
            fix += "your network settings."
    title = f"Ghost DNS server {ns}"
    if server.adapters:
        title += f" (on disconnected {_names(server.adapters)})"
    return Problem(Severity.WARNING, title, detail, fix, ProblemKind.GHOST)


def _hosts_problem(hosts: HostsFile) -> Problem:
    pairs = [f"{name} → {e.ip}" for e in hosts.entries for name in e.names]
    shown = ", ".join(pairs[:5])
    more = f" and {len(pairs) - 5} more" if len(pairs) > 5 else ""
    count = f"{len(pairs)} name" + ("" if len(pairs) == 1 else "s")
    return Problem(
        Severity.WARNING,
        f"The hosts file overrides DNS for {count}",
        f"{shown}{more}. Browsers and most apps use these addresses without asking DNS, so "
        "dnskit lookups (which ask DNS directly) won't show them.",
        f"If one of these names goes to the wrong place, remove or comment out its line in "
        f"{hosts.path} (needs administrator rights), then flush the DNS cache.",
        ProblemKind.HOSTS,
    )


def _check_problems(
    hijack: tuple[HijackCheck, ...],
    interception: tuple[InterceptionCheck, ...],
    ipv6: IPv6Check,
    vpns: tuple[Adapter, ...],
) -> tuple[Problem, ...]:
    """Problems from the hijacking, interception and IPv6 checks (all warnings)."""
    problems = [_hijack_problem(h) for h in hijack if h.verdict is Verdict.SUSPECT]
    problems += [
        _interception_problem(c, vpns) for c in interception if c.verdict is Verdict.SUSPECT
    ]
    if ipv6.state is IPv6State.BROKEN:
        problems.append(_ipv6_problem(ipv6))
    return tuple(problems)


def _hijack_problem(check: HijackCheck) -> Problem:
    return Problem(
        Severity.WARNING,
        f"DNS server {check.nameserver} answers for names that don't exist (NXDOMAIN hijacking)",
        f"Asked for {check.probe_name}, a made-up name, it answered {', '.join(check.addresses)} "
        "instead of saying the name doesn't exist. ISPs and some routers do this to send "
        "mistyped addresses to a search or advertising page. It also breaks programs that rely "
        'on "doesn\'t exist" (a typo in a server name looks like it works), and can confuse '
        "VPNs and company networks.",
        'Turn off "DNS assist", "error redirect" or "search assist" in your router or ISP '
        "account, or use a resolver that doesn't do this, such as 1.1.1.1, 8.8.8.8 or 9.9.9.9.",
        ProblemKind.HIJACK,
    )


def _interception_problem(check: InterceptionCheck, vpns: tuple[Adapter, ...]) -> Problem:
    if check.provider == "Google" and check.answered_by:
        how = (
            f"Google answers this test ({GOOGLE_WHOAMI}) with the address of its own DNS "
            f"server that asked, but the answer named {check.answered_by}, which isn't "
            f"Google's. So a query sent to {check.nameserver} was answered by another DNS server."
        )
    elif check.provider == "Google":
        how = (
            f"Google always answers this test ({GOOGLE_WHOAMI}) with an address, but got "
            f"{check.response}. Another DNS server most likely answered in Google's place."
        )
    else:
        how = (
            f"Cloudflare always answers this test ({CLOUDFLARE_WHOAMI}, class CH) with your "
            f"address, but got {check.response}. Another DNS server most likely answered in "
            "Cloudflare's place."
        )
    why = (
        f" {_names(vpns)} (VPN) {_is_are(vpns)} connected: VPNs often redirect all DNS to "
        "their own servers on purpose, to stop DNS leaks."
        if vpns
        else " Routers, firewalls, ISPs and work, school or hotel networks do this to filter "
        "or log DNS."
    )
    fix = (
        f"If it's the VPN, that's expected: disconnect {_names(vpns)} and run dnskit local again "
        "to check the network itself."
        if vpns
        else "On a work, school or hotel network this is usually deliberate filtering. At home, "
        'look for "DNS redirect", "DNS proxy" or parental-control options in the router, or '
        "ask your ISP. Encrypted DNS (DNS over HTTPS in the browser or OS) gets around it."
    )
    return Problem(
        Severity.WARNING,
        f"Queries to {check.nameserver} ({check.provider}) appear to be intercepted",
        how + why + " Answers can be filtered or changed without you knowing.",
        fix,
        ProblemKind.INTERCEPTION,
    )


def _ipv6_problem(check: IPv6Check) -> Problem:
    attempt = check.attempt
    failure = f"{attempt.error} ({attempt.message})" if attempt and attempt.message else "failed"
    target = attempt.address if attempt else check.host
    return Problem(
        Severity.WARNING,
        "IPv6 is broken: names resolve to IPv6 addresses, but connecting to them fails",
        f"This computer has an IPv6 address ({check.local_address}) and AAAA lookups work, but "
        f"connecting to {check.host} at {target} {failure}. Browsers and apps try IPv6 first "
        "and only fall back to IPv4 after it fails, so sites can load slowly or time out.",
        "Restart the router. If it keeps happening, the router or ISP has a half-working "
        "IPv6 setup: turn IPv6 off in the router (or on this adapter) until the ISP fixes it.",
        ProblemKind.IPV6_BROKEN,
    )


def _server_label(server: ServerCheck) -> str:
    if server.adapters:
        return f"{server.nameserver} ({server.adapter_names})"
    return server.nameserver


def _names(adapters: tuple[Adapter, ...]) -> str:
    return ", ".join(a.name for a in adapters)


def _is_are(items: tuple[Adapter, ...]) -> str:
    return "is" if len(items) == 1 else "are"
