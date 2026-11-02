"""Rich renderers for core results."""

import re
import threading
import time
from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.tree import Tree

from dnskit.core import (
    ANYCAST_NOTE,
    CACHE_TTL_S,
    CHECK_LABELS,
    SLOW_THRESHOLD_MS,
    SPF_LOOKUP_LIMIT,
    Adapter,
    Agreement,
    BatchCheck,
    BatchItem,
    BatchReport,
    Check,
    CheckState,
    CheckStatus,
    ClockState,
    CompareReport,
    Config,
    ConnectError,
    Diagnosis,
    DnssecReport,
    DnssecStatus,
    DoctorReport,
    EmailReport,
    EmailSection,
    FailReason,
    Impact,
    IPv6State,
    KeyInfo,
    LocalReport,
    LookupReport,
    LookupResult,
    LookupStatus,
    PropagationReport,
    ReachReport,
    ReachVerdict,
    ResolverChoice,
    ReverseReport,
    Severity,
    StepStatus,
    TraceMode,
    TraceReport,
    TraceStep,
    Verdict,
    WatchSample,
    WatchSummary,
    ZoneStatus,
    blocked_diagnosis,
    clock_diagnosis,
    describe_key,
    doctor_verdict,
    explain,
    explain_dnssec,
    explain_propagation,
    explain_reach,
    explain_reverse,
    explain_trace,
    trace_blocked_diagnosis,
)

# Short reasons shown inside result tables; the full explanation goes in a panel below.
_STATUS_LABELS: dict[LookupStatus, str] = {
    LookupStatus.NXDOMAIN: "domain does not exist (NXDOMAIN)",
    LookupStatus.NO_ANSWER: "no records",
    LookupStatus.SERVFAIL: "server failure (SERVFAIL)",
    LookupStatus.TIMEOUT: "timed out",
    LookupStatus.NO_NETWORK: "no network",
    LookupStatus.NO_NAMESERVERS: "refused by all nameservers",
}

# Problems that warrant a red panel; the rest (no records, NXDOMAIN) are answers, not faults.
_FAULTS = {
    LookupStatus.SERVFAIL,
    LookupStatus.TIMEOUT,
    LookupStatus.NO_NETWORK,
    LookupStatus.NO_NAMESERVERS,
}

# Hosts files used as ad blockers can have thousands of lines; show only the first few.
_MAX_HOSTS_ROWS = 15


def _age(probed_at: float) -> str:
    seconds = max(0.0, time.time() - probed_at)
    if seconds < 60:
        return f"{seconds:.0f}s ago"
    return f"{seconds / 60:.0f} min ago"


def _print_footer(
    console: Console,
    nameserver: str,
    source: str,
    elapsed_ms: float,
    choice: ResolverChoice | None,
) -> None:
    """The resolver line, plus any system nameservers that failed or were slow to answer."""
    if choice is not None and choice.from_cache:
        source += f"; cached, probed {_age(choice.probed_at)}"
    console.print(
        f"[dim]Resolver: {escape(nameserver)} ({escape(source)}) · {elapsed_ms:.0f} ms total[/dim]"
    )
    if choice is None:
        return

    problems = []
    if choice.failed:
        names = ", ".join(escape(p.nameserver) for p in choice.failed)
        problems.append(f"no response from {names}")
    if choice.slow:
        names = ", ".join(f"{escape(p.nameserver)} ({p.latency_ms:.0f} ms)" for p in choice.slow)
        problems.append(f"slow: {names}")
    if problems:
        console.print(
            f"[yellow]Nameserver problems[/yellow] [dim](probed {_age(choice.probed_at)}; "
            f"run `dnskit resolvers` for details):[/dim] {'; '.join(problems)}"
        )


def render_diagnosis(
    diagnosis: Diagnosis, status: LookupStatus, console: Console, affected: str = ""
) -> None:
    title = f"[bold]{escape(diagnosis.title)}[/bold]"
    if affected:
        title += f" [dim]({escape(affected)})[/dim]"
    body = (
        f"{escape(diagnosis.explanation)}\n\n[bold]Next step:[/bold] {escape(diagnosis.suggestion)}"
    )
    style = "red" if status in _FAULTS else "yellow"
    console.print(Panel(body, title=title, title_align="left", border_style=style))


def _diagnosed_statuses(results: Sequence[LookupResult]) -> dict[LookupStatus, list[str]]:
    """Group non-OK results by status, for the explanation panels.

    In a multi-type lookup, a few types having no records is normal (most domains have no
    CNAME at the apex, for example), so NO_ANSWER is only explained when it's the whole story.
    """
    groups: dict[LookupStatus, list[str]] = {}
    for result in results:
        if result.status is not LookupStatus.OK:
            groups.setdefault(result.status, []).append(result.rtype)
    no_answer = groups.get(LookupStatus.NO_ANSWER, [])
    if len(results) > 1 and 0 < len(no_answer) < len(results):
        del groups[LookupStatus.NO_ANSWER]
    return groups


def render_report(report: LookupReport, console: Console, timeout: float | None = None) -> None:
    groups = _diagnosed_statuses(report.results)

    if not all(r.status is LookupStatus.NXDOMAIN for r in report.results):
        table = Table(title=escape(report.name), title_justify="left")
        table.add_column("Type", style="bold")
        table.add_column("Value", style="cyan", overflow="fold")
        table.add_column("TTL", justify="right")
        for i, result in enumerate(report.results):
            if i:
                table.add_section()
            if result.status is LookupStatus.OK:
                for j, record in enumerate(result.records):
                    rtype = result.rtype if j == 0 else ""
                    table.add_row(rtype, escape(record.value), str(record.ttl))
            else:
                table.add_row(result.rtype, f"[dim]{_STATUS_LABELS[result.status]}[/dim]", "")
        console.print(table)

    multi_type = len(report.results) > 1
    for status, rtypes in groups.items():
        diagnosis = explain(status, report.name, rtypes[0], timeout)
        if diagnosis is not None:
            affected = (
                ", ".join(rtypes) if multi_type and status is not LookupStatus.NXDOMAIN else ""
            )
            render_diagnosis(diagnosis, status, console, affected)

    _print_footer(
        console,
        report.nameserver,
        report.nameserver_source,
        report.elapsed_ms,
        report.resolver_choice,
    )


def render_reverse(report: ReverseReport, console: Console, timeout: float | None = None) -> None:
    result = report.result
    if result.status is LookupStatus.OK:
        # A heading line rather than a table title: titles wrap to the (narrow) table width.
        console.print(f"[bold]{escape(report.ip)}[/bold] [dim](IPv{report.version})[/dim]")
        table = Table()
        table.add_column("Hostname", style="cyan", overflow="fold")
        table.add_column("TTL", justify="right")
        for record in result.records:
            table.add_row(escape(record.value), str(record.ttl))
        console.print(table)
    else:
        diagnosis = explain_reverse(result.status, report.ip, timeout)
        if diagnosis is not None:
            render_diagnosis(diagnosis, result.status, console, f"{report.ip}, IPv{report.version}")

    console.print(f"[dim]PTR name: {escape(report.ptr_name)}[/dim]")
    _print_footer(
        console,
        report.nameserver,
        report.nameserver_source,
        report.elapsed_ms,
        report.resolver_choice,
    )


def render_compare(report: CompareReport, console: Console) -> None:
    table = Table(
        title=f"{escape(report.name)} {report.rtype} across {len(report.answers)} resolvers",
        title_justify="left",
    )
    table.add_column("Resolver", style="bold")
    table.add_column("IP")
    table.add_column("Answer", overflow="fold")
    table.add_column("TTL", justify="right")
    table.add_column("Time", justify="right")
    table.add_column("")
    split = not report.all_agree  # only mark the majority when someone disagrees

    for i, answer in enumerate(report.answers):
        if i:
            table.add_section()
        result = answer.result
        value, marker = _agreement_cells(result, answer.agreement, report.has_majority, split)
        ttl = "" if answer.ttl is None else str(answer.ttl)
        table.add_row(
            escape(answer.label),
            escape(answer.nameserver),
            value,
            ttl,
            f"{result.elapsed_ms:.0f} ms",
            marker,
        )
    console.print(table)
    console.print(_compare_summary(report))
    console.print(
        f"[dim]Queried {len(report.answers)} resolvers in parallel · "
        f"{report.elapsed_ms:.0f} ms total[/dim]"
    )


def _agreement_cells(
    result: LookupResult, agreement: Agreement, has_majority: bool, split: bool
) -> tuple[str, str]:
    """The answer and marker cells for one resolver in compare or propagation."""
    if agreement is Agreement.FAILED:
        return f"[red]{_STATUS_LABELS[result.status]}[/red]", "[bold red]✗ failed[/bold red]"
    # With no majority nobody is the odd one out, so the answers aren't highlighted.
    odd_one_out = agreement is Agreement.DIFFERS and has_majority
    style = "yellow" if odd_one_out else "cyan"
    if result.status is LookupStatus.OK:
        # Sorted, because resolvers return records in varying order.
        values = sorted((r.value for r in result.records), key=_natural_key)
        value = "\n".join(f"[{style}]{escape(v)}[/{style}]" for v in values)
    else:
        value = f"[{style}]{_STATUS_LABELS[result.status]}[/{style}]"
    if odd_one_out:
        marker = "[bold yellow]≠ differs[/bold yellow]"
    elif agreement is Agreement.DIFFERS:
        marker = "[dim]varies[/dim]"
    else:
        marker = "[green]majority[/green]" if split else ""
    return value, marker


def _compare_summary(report: CompareReport) -> str:
    responded = len(report.responded)
    failed = ""
    if report.failed:
        names = ", ".join(
            f"{escape(a.label)} ({_STATUS_LABELS[a.result.status]})" for a in report.failed
        )
        failed = f" [red]{len(report.failed)} failed:[/red] {names}."

    if not responded:
        return f"[bold red]No resolver answered.[/bold red]{failed} Check your network connection."
    if report.all_agree:
        if report.failed:
            return (
                f"[bold green]✓ All {responded} resolvers that answered agree.[/bold green]{failed}"
            )
        return f"[bold green]✓ All {responded} resolvers agree.[/bold green]"

    if report.has_majority:
        names = ", ".join(escape(a.label) for a in report.differing)
        verdict = (
            f"[bold yellow]≠ {len(report.differing)} of {responded} resolvers disagree with the "
            f"majority answer[/bold yellow] (given by {len(report.majority)}): {names}."
        )
    else:
        verdict = (
            f"[bold yellow]≠ Resolvers disagree, with no majority:[/bold yellow] {responded} "
            f"resolvers gave {report.distinct_answers} different answers."
        )
    if report.rtype in ("A", "AAAA"):
        verdict += (
            " [dim]Different addresses can be normal for sites on a CDN, which give each "
            "resolver a nearby server.[/dim]"
        )
    return verdict + failed


def _natural_key(value: str) -> list[int | str]:
    """Sort key that orders numbers numerically, so "5 mx." comes before "10 mx."."""
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]


def _adapter_order(adapters: tuple[Adapter, ...]) -> list[Adapter]:
    """Connected adapters first, each bridge member right after the adapter it's bridged into."""
    ordered = sorted(adapters, key=lambda a: not a.connected)
    names = {a.name for a in adapters}
    result = []
    for adapter in ordered:
        if adapter.bridged_into in names:
            continue  # listed under its bridge
        result.append(adapter)
        result.extend(m for m in ordered if m.bridged_into == adapter.name)
    return result


def render_local(report: LocalReport, console: Console) -> None:
    scan = report.scan
    table = Table(title=f"Network adapters ({report.platform})", title_justify="left")
    table.add_column("Adapter", style="bold")
    table.add_column("Status")
    table.add_column("DNS servers", overflow="fold")
    for adapter in _adapter_order(scan.adapters):
        status = "[green]connected[/green]" if adapter.connected else "[dim]disconnected[/dim]"
        if adapter.vpn:
            status += ", [cyan]VPN[/cyan]" if adapter.connected else "[dim], VPN[/dim]"
        if adapter.bridged_into:
            status += f", bridged into {escape(adapter.bridged_into)}"
            dns = f"[dim]uses {escape(adapter.bridged_into)}'s[/dim]"
        elif scan.dns_per_adapter:
            dns = ", ".join(escape(ns) for ns in adapter.dns_servers) or "[dim]none[/dim]"
        else:
            dns = "[dim]not reported[/dim]"
        table.add_row(
            escape(adapter.name), status, dns if adapter.connected else f"[dim]{dns}[/dim]"
        )
    if scan.adapters:
        console.print(table)
    else:
        console.print("[yellow]No network adapters found.[/yellow]")
    if not scan.dns_per_adapter and not scan.error:
        console.print(
            "[dim]This system doesn't report DNS servers per adapter (no systemd-resolved or "
            "scutil), so the servers below come from the system configuration.[/dim]"
        )

    servers = Table(
        title=f"DNS servers (test query, {report.probe_timeout:g} s timeout)", title_justify="left"
    )
    servers.add_column("Server")
    servers.add_column("Adapter")
    servers.add_column("Response", justify="right")
    servers.add_column("")
    for server in report.servers:
        if server.adapters:
            listed = ", ".join(
                escape(a.name) if a.connected else f"[dim]{escape(a.name)} (disconnected)[/dim]"
                for a in server.adapters
            )
        else:
            listed = "[dim]none[/dim]" if scan.dns_per_adapter else "[dim]system config[/dim]"
        if server.vpn_blocked:
            response = "[yellow]no response[/yellow]"
        elif server.failed:
            response = "[red]no response[/red]"
        elif server.slow:
            response = f"[yellow]{server.latency_ms:.0f} ms[/yellow]"
        else:
            response = f"[green]{server.latency_ms:.0f} ms[/green]"
        if server.ghost:
            marker = "[magenta]ghost (ignored)[/magenta]"
        elif server.vpn_blocked:
            marker = "[yellow]blocked by VPN?[/yellow]"
        elif server.failed:
            marker = "[bold red]✗ failing[/bold red]"
        elif server.slow:
            marker = "[yellow]slow[/yellow]"
        else:
            marker = ""
        name = escape(server.nameserver)
        if server.public:
            name += f" [dim]({escape(server.public)})[/dim]"
        servers.add_row(name, listed, response, marker)
    if report.servers:
        console.print(servers)
    else:
        console.print("[red]No DNS servers are configured.[/red]")
    _local_checks(report, console)

    hosts = report.hosts
    if hosts.entries:
        entries = Table(
            title=f"Hosts file entries that override DNS ({escape(hosts.path)})",
            title_justify="left",
        )
        entries.add_column("Line", justify="right")
        entries.add_column("Address")
        entries.add_column("Names", overflow="fold")
        entries.add_column("Effect")
        for entry in hosts.entries[:_MAX_HOSTS_ROWS]:
            entries.add_row(
                str(entry.line), escape(entry.ip), escape(" ".join(entry.names)), entry.kind
            )
        console.print(entries)
        if len(hosts.entries) > _MAX_HOSTS_ROWS:
            console.print(f"[dim]… and {len(hosts.entries) - _MAX_HOSTS_ROWS} more lines[/dim]")
    elif not hosts.error:
        console.print(f"Hosts file: no entries override DNS [dim]({escape(hosts.path)})[/dim]")

    if report.flush.command:
        console.print(
            f"Flush the DNS cache: [bold cyan]{escape(report.flush.command)}[/bold cyan]\n"
            f"[dim]{escape(report.flush.note)}[/dim]"
        )
    else:
        console.print(f"Flush the DNS cache: [dim]{escape(report.flush.note)}[/dim]")

    console.print()
    for problem in report.problems:
        error = problem.severity is Severity.ERROR
        icon = "✗" if error else "!"
        body = f"{escape(problem.detail)}\n\n[bold]Fix:[/bold] {escape(problem.fix)}"
        console.print(
            Panel(
                body,
                title=f"[bold]{icon} {escape(problem.title)}[/bold]",
                title_align="left",
                border_style="red" if error else "yellow",
            )
        )
    console.print(_local_summary(report))
    console.print(
        f"[dim]Tested {len(report.servers)} DNS servers in parallel · "
        f"{report.elapsed_ms:.0f} ms total[/dim]"
    )


_VERDICT_MARKS = {
    Verdict.OK: "[green]✓[/green]",
    Verdict.SUSPECT: "[bold yellow]![/bold yellow]",
    Verdict.UNKNOWN: "[dim]?[/dim]",
}
_IPV6_MARKS = {
    IPv6State.WORKING: "[green]✓[/green]",
    IPv6State.NOT_AVAILABLE: "[dim]–[/dim]",
    IPv6State.BROKEN: "[bold yellow]![/bold yellow]",
    IPv6State.UNKNOWN: "[dim]?[/dim]",
}


def _local_checks(report: LocalReport, console: Console) -> None:
    """Hijacking, interception and IPv6: one row each, details in the problem panels."""
    rows = [
        (f"NXDOMAIN hijacking: {escape(h.nameserver)}", _VERDICT_MARKS[h.verdict], h.summary)
        for h in report.hijack
    ]
    rows += [
        (
            f"Interception: {escape(c.nameserver)} ({escape(c.provider)})",
            _VERDICT_MARKS[c.verdict],
            c.summary,
        )
        for c in report.interception
    ]
    if report.ipv6 is not None:
        rows.append(("IPv6", _IPV6_MARKS[report.ipv6.state], report.ipv6.summary))
    if not rows:
        return
    table = Table(title="Network checks", title_justify="left")
    table.add_column("Check")
    table.add_column("Result", overflow="fold")
    for check, mark, summary in rows:
        table.add_row(check, f"{mark} {escape(summary)}")
    console.print(table)


def render_reach(report: ReachReport, console: Console, timeout: float | None = None) -> None:
    table = Table(title=f"{escape(report.name)} on port {report.port}", title_justify="left")
    table.add_column("Address")
    table.add_column("Type")
    table.add_column("Connection", justify="right")
    tried = {a.address: a for a in report.attempts}
    skipped = 0
    for record_set, family in ((report.a, "IPv4"), (report.aaaa, "IPv6")):
        for record in record_set.records:
            attempt = tried.get(record.value)
            if report.blocked_by_dns:
                result = "[red]✗ blocked by DNS[/red]"
            elif attempt is None:
                skipped += 1  # beyond the per-family limit
                continue
            elif attempt.ok:
                result = f"[green]✓ {attempt.latency_ms:.0f} ms[/green]"
            elif attempt.version == 6 and attempt.error is ConnectError.UNREACHABLE:
                result = "[dim]– no IPv6 route[/dim]"
            else:
                result = f"[red]✗ {attempt.error}[/red]"
            table.add_row(escape(record.value), family, result)
    if report.addresses:
        console.print(table)
        if skipped:
            console.print(f"[dim]… and {skipped} more addresses, not tried[/dim]")
    else:
        statuses = f"A: {_STATUS_LABELS[report.a.status]}"
        statuses += f", AAAA: {_STATUS_LABELS[report.aaaa.status]}"
        console.print(f"[red]No addresses for {escape(report.name)}[/red] [dim]({statuses})[/dim]")

    diagnosis = explain_reach(report, timeout)
    ok = report.verdict is ReachVerdict.REACHABLE
    console.print(
        Panel(
            f"{escape(diagnosis.explanation)}\n\n[bold]Next step:[/bold] "
            f"{escape(diagnosis.suggestion)}",
            title=f"[bold]{'✓' if ok else '✗'} {escape(diagnosis.title)}[/bold]",
            title_align="left",
            border_style="green" if ok else "red",
        )
    )
    _print_footer(
        console,
        report.nameserver,
        report.nameserver_source,
        report.elapsed_ms,
        report.resolver_choice,
    )


def _local_summary(report: LocalReport) -> str:
    in_use = [s for s in report.servers if s.used]
    if not report.problems:
        return (
            f"[bold green]✓ No problems found.[/bold green] {len(in_use)} DNS servers in use, "
            "all responding."
        )
    errors = sum(p.severity is Severity.ERROR for p in report.problems)
    warnings = len(report.problems) - errors
    counts = ", ".join(
        f"{n} {word}{'' if n == 1 else 's'}"
        for n, word in ((errors, "error"), (warnings, "warning"))
        if n
    )
    if errors:
        return f"[bold red]✗ DNS isn't working properly:[/bold red] {counts} (see above)."
    working = sum(not s.failed for s in in_use)
    return (
        f"[bold yellow]DNS is working[/bold yellow] ({working} of {len(in_use)} servers in use "
        f"responding), with {counts} (see above)."
    )


def render_probes(
    choice: ResolverChoice, console: Console, cache_location: str, ignored: Sequence[str] = ()
) -> None:
    table = Table(title="System nameservers (in system order)", title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("Nameserver")
    table.add_column("Latency", justify="right")
    table.add_column("")
    slow = set(choice.slow)
    for i, probe in enumerate(choice.probes, start=1):
        if probe.latency_ms is None:
            latency = "[red]no response[/red]"
        elif probe in slow:
            latency = f"[yellow]{probe.latency_ms:.0f} ms (slow)[/yellow]"
        else:
            latency = f"[green]{probe.latency_ms:.0f} ms[/green]"
        marker = "[bold]← used by lookup[/bold]" if probe.nameserver == choice.nameserver else ""
        table.add_row(str(i), escape(probe.nameserver), latency, marker)
    console.print(table)
    if ignored:
        console.print(
            f"[dim]Ignored (not on a connected adapter): {escape(', '.join(ignored))}. "
            "Run `dnskit local` for details.[/dim]"
        )

    if choice.nameserver is None:
        console.print(
            "[red]No nameserver answered.[/red] Lookups will try them in system order; "
            "check your network connection."
        )
        return
    console.print(
        f"[dim]Slow means slower than {SLOW_THRESHOLD_MS:.0f} ms. {escape(choice.nameserver)} "
        f"is cached as the lookup choice for {CACHE_TTL_S / 60:.0f} min "
        f"({escape(cache_location)}).[/dim]"
    )


_CHECK_ICONS: dict[CheckStatus, str] = {
    CheckStatus.PASS: "[bold green]✓[/bold green]",
    CheckStatus.WARN: "[bold yellow]![/bold yellow]",
    CheckStatus.FAIL: "[bold red]✗[/bold red]",
}
_CHECK_LABELS: dict[CheckStatus, str] = {
    CheckStatus.PASS: "[green]pass[/green]",
    CheckStatus.WARN: "[yellow]warn[/yellow]",
    CheckStatus.FAIL: "[bold red]fail[/bold red]",
}
_CHECK_HEADINGS = {
    "MX": "MX · where mail for the domain is delivered",
    "SPF": "SPF · which servers may send its mail",
    "DMARC": "DMARC · what receivers do with mail that fails SPF and DKIM",
    "DKIM": "DKIM · keys that sign its mail",
}


def render_email(report: EmailReport, console: Console, timeout: float | None = None) -> None:
    console.print(f"[bold]Email DNS check for {escape(report.domain)}[/bold]")
    if report.domain_status is not LookupStatus.OK:
        diagnosis = explain(report.domain_status, report.domain, "MX", timeout)
        if diagnosis is not None:
            render_diagnosis(diagnosis, report.domain_status, console)
    else:
        details = {"MX": _email_mx, "SPF": _email_spf, "DMARC": _email_dmarc, "DKIM": _email_dkim}
        for label, section in report.checks:
            console.print()
            console.rule(f"[bold]{escape(_CHECK_HEADINGS[label])}[/bold]", align="left")
            details[label](report, console)
            _print_findings(section, console)
        console.print()
        _print_email_summary(report, console)

    _print_footer(
        console,
        report.nameserver,
        report.nameserver_source,
        report.elapsed_ms,
        report.resolver_choice,
    )


def _print_findings(section: EmailSection, console: Console) -> None:
    for finding in section.findings:
        icon = _CHECK_ICONS[finding.status]
        if finding.status is CheckStatus.PASS:
            console.print(
                f"{icon} [bold]{escape(finding.title)}[/bold] "
                f"[dim]— {escape(finding.explanation)}[/dim]"
            )
            continue
        body = escape(finding.explanation)
        if finding.fix:
            body += f"\n\n[bold]Fix:[/bold] {escape(finding.fix)}"
        console.print(
            Panel(
                body,
                title=f"{icon} [bold]{escape(finding.title)}[/bold]",
                title_align="left",
                border_style="red" if finding.status is CheckStatus.FAIL else "yellow",
            )
        )


def _email_mx(report: EmailReport, console: Console) -> None:
    mx = report.mx
    if mx is None or not mx.hosts or (mx.null_mx and len(mx.hosts) == 1):
        return
    table = Table()
    table.add_column("Priority", justify="right")
    table.add_column("Mail server", style="bold")
    table.add_column("Addresses", style="cyan", overflow="fold")
    for host in mx.hosts:
        if host.addresses:
            addresses = "\n".join(escape(a) for a in host.addresses)
        elif not host.host:
            addresses = "[dim]null MX: accepts no mail[/dim]"
        else:
            addresses = f"[red]{_STATUS_LABELS[host.lookup_status]}[/red]"
        table.add_row(str(host.preference), escape(host.host or "."), addresses)
    console.print(table)


def _email_spf(report: EmailReport, console: Console) -> None:
    spf = report.spf
    if spf is None:
        return
    for record in spf.records:
        console.print(f"Record: [cyan]{escape(record)}[/cyan]")
    if spf.lookups:
        at_least = "" if spf.complete else "at least "
        too_many = spf.lookup_count > SPF_LOOKUP_LIMIT
        console.print(
            f"DNS lookups: {at_least}{spf.lookup_count} of {SPF_LOOKUP_LIMIT}"
            + (" [bold red](too many)[/bold red]" if too_many else "")
        )
        for lookup in spf.lookups:
            where = f" [dim](in {escape(lookup.source)})[/dim]" if lookup.depth else ""
            console.print(f"  {'  ' * lookup.depth}{escape(lookup.term)}{where}")


def _email_dmarc(report: EmailReport, console: Console) -> None:
    dmarc = report.dmarc
    if dmarc is None:
        return
    for record in dmarc.records:
        console.print(f"Record at {escape(dmarc.name)}: [cyan]{escape(record)}[/cyan]")


def _email_dkim(report: EmailReport, console: Console) -> None:
    dkim = report.dkim
    if dkim is None:
        return
    table = Table()
    table.add_column("Selector", style="bold")
    table.add_column("Key")
    for selector in dkim.selectors:
        if selector.malformed:
            key = "[red]malformed key[/red]"
        elif selector.revoked:
            key = "[yellow]revoked (empty p=)[/yellow]"
        elif selector.found:
            key = f"[green]{escape(describe_key(selector))}[/green]"
        elif selector.lookup_status in _FAULTS:
            key = f"[red]{_STATUS_LABELS[selector.lookup_status]}[/red]"
        else:
            key = "[dim]not found[/dim]"
        name = escape(selector.selector) + (" [dim](--selector)[/dim]" if selector.custom else "")
        table.add_row(name, key)
    console.print(table)
    console.print(f"[dim]Looked up <selector>._domainkey.{escape(report.domain)}[/dim]")


def _print_email_summary(report: EmailReport, console: Console) -> None:
    table = Table(title="Summary", title_justify="left")
    table.add_column("Check", style="bold")
    table.add_column("Result")
    table.add_column("", overflow="fold")
    for label, section in report.checks:
        headline = section.headline
        table.add_row(
            label,
            f"{_CHECK_ICONS[section.status]} {_CHECK_LABELS[section.status]}",
            escape(headline.title) if headline else "",
        )
    console.print(table)

    statuses = [section.status for _, section in report.checks]
    failed = statuses.count(CheckStatus.FAIL)
    warned = statuses.count(CheckStatus.WARN)
    passed = statuses.count(CheckStatus.PASS)
    if failed:
        console.print(
            f"[bold red]✗ {failed} of {len(statuses)} checks failed[/bold red]"
            + (f", {warned} with warnings" if warned else "")
            + ". Fix the problems marked ✗ above."
        )
    elif warned:
        console.print(
            f"[bold yellow]! No check failed, but {warned} of {len(statuses)} "
            f"{'has warnings' if warned == 1 else 'have warnings'}.[/bold yellow] "
            f"{passed} passed. See the suggestions marked ! above."
        )
    else:
        console.print(f"[bold green]✓ All {len(statuses)} checks passed.[/bold green]")


def _diagnosis_panel(diagnosis: Diagnosis, style: str, mark: str = "") -> Panel:
    title = f"[bold]{mark + ' ' if mark else ''}{escape(diagnosis.title)}[/bold]"
    body = (
        f"{escape(diagnosis.explanation)}\n\n[bold]Next step:[/bold] {escape(diagnosis.suggestion)}"
    )
    return Panel(body, title=title, title_align="left", border_style=style)


# --- trace --------------------------------------------------------------------------------

_FAIL_REASONS = {
    FailReason.NO_RESPONSE: "no response",
    FailReason.REFUSED: "refused",
    FailReason.SERVFAIL: "server failure (SERVFAIL)",
    FailReason.LAME: "not serving the zone (lame delegation)",
    FailReason.NO_ADDRESS: "its nameservers have no address",
    FailReason.TOO_DEEP: "too many referrals",
}


def _short_list(names: Sequence[str], limit: int = 3) -> str:
    shown = ", ".join(escape(n) for n in names[:limit])
    return f"{shown} and {len(names) - limit} more" if len(names) > limit else shown


def _trace_label(step: TraceStep, report: TraceReport) -> str:
    zone = ". (root)" if step.zone == "." else step.zone
    lines = [f"[bold]{escape(zone)}[/bold]"]
    if step.server is not None:
        who = escape(step.server.address)
        if step.server.name != step.server.address:
            who = f"{escape(step.server.name)} ({who})"
        lines[0] += f"  [dim]asked {who} · {step.latency_ms:.0f} ms[/dim]"
    match step.status:
        case StepStatus.REFERRAL:
            servers = step.referral_servers
            count = f" [dim]({len(servers)} servers)[/dim]" if len(servers) > 3 else ""
            lines.append(
                f"[cyan]→ referral to {escape(step.referral_zone or '')}[/cyan] "
                f"{_short_list(servers)}{count}"
            )
        case StepStatus.ANSWER:
            values = ", ".join(escape(v) for v in step.records)
            lines.append(f"[green]✓ answer:[/green] {values}")
        case StepStatus.NXDOMAIN:
            lines.append("[yellow]✗ the name doesn't exist (NXDOMAIN)[/yellow]")
        case StepStatus.NO_ANSWER:
            lines.append(f"[yellow]no {report.rtype} records[/yellow]")
        case StepStatus.FAILED:
            reason = _FAIL_REASONS[step.reason or FailReason.NO_RESPONSE]
            lines.append(f"[bold red]✗ failed at this level: {reason}[/bold red]")
            if step.note:
                lines.append(f"[red]{escape(step.note)}[/red]")
            lines.extend(
                f"[red]  ✗ {escape(failure.server.name)} ({escape(failure.server.address)})"
                f": {escape(failure.error)}[/red]"
                for failure in step.failures
            )
            return "\n".join(lines)
    if step.note:
        lines.append(f"[dim]{escape(step.note)}[/dim]")
    lines.extend(
        f"[dim]{escape(failure.server.name)} {escape(failure.error)}; another server answered[/dim]"
        for failure in step.failures
    )
    return "\n".join(lines)


def render_trace(report: TraceReport, console: Console) -> None:
    if report.mode is TraceMode.DIRECT:
        how = "from the root servers down"
    else:
        how = f"through {report.resolver}: direct queries are blocked"
    tree = Tree(f"[bold]{escape(report.name)} {report.rtype}[/bold] [dim]({escape(how)})[/dim]")
    node = tree
    for step in report.steps:
        node = node.add(_trace_label(step, report))
    console.print(tree)

    diagnosis = explain_trace(report)
    blocked = trace_blocked_diagnosis(report)
    if blocked is not None and blocked != diagnosis:
        console.print(_diagnosis_panel(blocked, "yellow"))
    if diagnosis is not None:
        failed = report.final.status is StepStatus.FAILED
        console.print(_diagnosis_panel(diagnosis, "red" if failed else "yellow"))
    steps = f"{len(report.steps)} step{'s' if len(report.steps) != 1 else ''}"
    console.print(f"[dim]{steps} · {report.elapsed_ms:.0f} ms total[/dim]")


# --- dnssec -------------------------------------------------------------------------------

_ZONE_MARKS = {
    ZoneStatus.SECURE: "[green]✓[/green]",
    ZoneStatus.UNSIGNED: "[yellow]–[/yellow]",
    ZoneStatus.BOGUS: "[bold red]✗[/bold red]",
    ZoneStatus.UNKNOWN: "[dim]?[/dim]",
}
_DNSSEC_STYLES = {
    DnssecStatus.SECURE: ("green", "✓"),
    DnssecStatus.INSECURE: ("yellow", "–"),
    DnssecStatus.BOGUS: ("red", "✗"),
    DnssecStatus.UNKNOWN: ("red", "?"),
}


def _keys_cell(keys: Sequence[KeyInfo]) -> str:
    if not keys:
        return "[dim]none[/dim]"
    ksk = sum(1 for k in keys if k.ksk)
    parts = [f"{ksk} KSK"] if ksk else []
    if len(keys) - ksk:
        parts.append(f"{len(keys) - ksk} ZSK")
    algorithms = sorted({k.algorithm for k in keys})
    return f"{' + '.join(parts)} [dim]({escape(', '.join(algorithms))})[/dim]"


def render_dnssec(report: DnssecReport, console: Console) -> None:
    if report.stripped_by and not report.signatures_stripped:
        console.print(
            f"[yellow]This computer's DNS server ({escape(report.stripped_by)}) strips DNSSEC "
            f"signatures, so this was checked through {escape(report.nameserver)}.[/yellow]"
        )
    if report.zones:
        table = Table(
            title=f"DNSSEC chain of trust for {escape(report.name)}", title_justify="left"
        )
        table.add_column("Zone", style="bold")
        table.add_column("DS (at parent)")
        table.add_column("Keys")
        table.add_column("Result", overflow="fold")
        for zone in report.zones:
            if zone.zone == ".":
                ds = "trust anchors " + ", ".join(str(d.key_tag) for d in zone.ds)
            else:
                ds = ", ".join(str(d.key_tag) for d in zone.ds) or "[dim]none[/dim]"
            table.add_row(
                ". (root)" if zone.zone == "." else escape(zone.zone),
                ds,
                _keys_cell(zone.keys),
                f"{_ZONE_MARKS[zone.status]} {escape(zone.summary)}",
            )
        for record in report.records:
            table.add_row(
                f"{escape(record.name)} {record.rtype}",
                "",
                "",
                f"{_ZONE_MARKS[record.status]} {escape(record.summary)}",
            )
        console.print(table)

    clock_warning = clock_diagnosis(report.clock)
    if clock_warning is not None:
        console.print(_diagnosis_panel(clock_warning, "yellow", "!"))
    elif report.clock.state is ClockState.OK or report.zones:
        mark = "[green]✓[/green]" if report.clock.state is ClockState.OK else "[dim]?[/dim]"
        console.print(f"Clock: {mark} {escape(report.clock.summary)}")

    diagnosis = explain_dnssec(report)
    style, mark = _DNSSEC_STYLES[report.status]
    if report.name_missing:
        style, mark = "yellow", "✗"
    console.print(_diagnosis_panel(diagnosis, style, mark))
    _print_footer(
        console,
        report.nameserver,
        report.nameserver_source,
        report.elapsed_ms,
        report.resolver_choice,
    )


# --- propagation --------------------------------------------------------------------------


def render_propagation(report: PropagationReport, console: Console) -> None:
    table = Table(
        title=f"{escape(report.name)} {report.rtype} across {len(report.answers)} public resolvers",
        title_justify="left",
    )
    table.add_column("Region", style="bold")
    table.add_column("Resolver")
    table.add_column("Location", style="dim")
    table.add_column("Answer", overflow="fold")
    table.add_column("TTL", justify="right")
    table.add_column("")
    split = bool(report.differing)
    region = None
    for answer in report.answers:
        resolver = answer.resolver
        if region is not None and resolver.region != region:
            table.add_section()
        value, marker = _agreement_cells(
            answer.result, answer.agreement, report.has_majority, split
        )
        table.add_row(
            escape(resolver.region) if resolver.region != region else "",
            f"{escape(resolver.name)} [dim]{escape(resolver.address)}[/dim]",
            escape(resolver.location),
            value,
            "" if answer.ttl is None else str(answer.ttl),
            marker,
        )
        region = resolver.region
    console.print(table)
    if any(a.resolver.anycast for a in report.answers):
        console.print(f"[dim]{escape(ANYCAST_NOTE)}[/dim]")

    if not report.blocked and report.responded:
        failed = f" · {len(report.failed)} didn't respond" if report.failed else ""
        style = "green" if report.complete else "yellow"
        console.print(
            f"[bold {style}]{report.percent:.0f}%[/bold {style}] of the resolvers that answered "
            f"({len(report.majority)} of {len(report.responded)}) give the most common "
            f"answer{failed}"
        )
    diagnosis = explain_propagation(report)
    if report.complete:
        style, mark = "green", "✓"
    elif report.blocked or not report.responded:
        style, mark = "red", "✗"
    else:
        style, mark = "yellow", "…"
    console.print(_diagnosis_panel(diagnosis, style, mark))
    if report.blocking is not None and not report.blocked:
        blocked = blocked_diagnosis(
            report.blocking, f"{len(report.failed)} of the {len(report.answers)} resolvers"
        )
        console.print(_diagnosis_panel(blocked, "yellow"))
    console.print(
        f"[dim]Queried {len(report.answers)} resolvers in parallel · "
        f"{report.elapsed_ms:.0f} ms total[/dim]"
    )


# --- doctor -------------------------------------------------------------------------------

_IMPACT_STYLES = {
    Impact.CRITICAL: "red",
    Impact.MAJOR: "yellow",
    Impact.MINOR: "cyan",
    Impact.NOTE: "dim",
}


class DoctorProgress:
    """Live view of the doctor checks; `update` is safe to call from worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[Check, CheckState] = dict.fromkeys(Check, CheckState.PENDING)
        self._started: dict[Check, float] = {}
        self._spinner = Spinner("dots", style="cyan")

    def update(self, check: Check, state: CheckState) -> None:
        with self._lock:
            self._states[check] = state
            if state is CheckState.RUNNING:
                self._started[check] = time.perf_counter()

    def __rich__(self) -> Table:
        table = Table.grid(padding=(0, 1))
        with self._lock:
            states = dict(self._states)
            started = dict(self._started)
        for check, state in states.items():
            if state is CheckState.RUNNING:
                seconds = time.perf_counter() - started.get(check, time.perf_counter())
                table.add_row(self._spinner, CHECK_LABELS[check], f"[dim]{seconds:.1f} s[/dim]")
            elif state is CheckState.PENDING:
                table.add_row("[dim]·[/dim]", f"[dim]{CHECK_LABELS[check]}[/dim]", "")
            elif state is CheckState.SKIPPED:
                table.add_row("[dim]-[/dim]", f"[dim]{CHECK_LABELS[check]} (skipped)[/dim]", "")
            elif state is CheckState.ERROR:
                table.add_row("[red]✗[/red]", CHECK_LABELS[check], "")
            else:
                table.add_row("[green]✓[/green]", CHECK_LABELS[check], "")
        return table


def render_doctor(report: DoctorReport, console: Console) -> None:
    console.print(f"[bold]Health check for {escape(report.name)}[/bold]")
    checks = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    checks.add_column("Check")
    checks.add_column("Result")
    checks.add_column("Time", justify="right", style="dim")
    for run in report.runs:
        found = [i for i in report.issues if i.check is run.check]
        problems = [i for i in found if i.impact is not Impact.NOTE]
        notes = len(found) - len(problems)
        noted = f" [dim]({notes} note{'' if notes == 1 else 's'})[/dim]" if notes else ""
        if run.state is CheckState.SKIPPED:
            result = f"[dim]skipped ({escape(run.reason or '--quick')})[/dim]"
        elif run.state is CheckState.ERROR:
            result = f"[red]✗ couldn't run[/red] [dim]{escape(run.error or '')}[/dim]"
        elif not problems and report.failed(run.check):
            result = "[red]✗ failed[/red] [dim](explained below)[/dim]"
        elif not problems:
            result = "[green]✓ OK[/green]" + noted
        else:
            worst = min(problems, key=lambda i: list(Impact).index(i.impact)).impact
            style = _IMPACT_STYLES[worst]
            count = f"{len(problems)} issue" + ("" if len(problems) == 1 else "s")
            mark = "✗" if worst is Impact.CRITICAL else "!"
            result = f"[{style}]{mark} {count}[/{style}]{noted}"
        if run.check is Check.DNSSEC and report.dnssec_via:
            # This computer's DNS server strips signatures, so a public resolver stood in.
            result += f" [dim](via {report.dnssec_via})[/dim]"
        time_text = "" if run.state is CheckState.SKIPPED else f"{run.elapsed_ms:.0f} ms"
        checks.add_row(escape(CHECK_LABELS[run.check]), result, time_text)
    console.print(checks)
    console.print()

    score = report.score
    style = "green" if score >= 90 else "yellow" if score >= 60 else "red"
    if any(i.impact is Impact.CRITICAL for i in report.issues):
        style = "red"
    verdict = doctor_verdict(report)
    console.print(f"Health score: [bold {style}]{score}/100[/bold {style}]")
    console.print(_diagnosis_panel(verdict, style))

    sections = [
        ("This computer", report.machine_issues),
        (report.name, report.domain_issues),
    ]
    # The section with the most important issue first (this computer on a tie).
    sections.sort(key=lambda s: report.issues.index(s[1][0]) if s[1] else len(report.issues))
    number = 0
    for heading, issues in sections:
        if not issues:
            continue
        console.print()
        console.print(f"[bold underline]{escape(heading)}[/bold underline]")
        section_notes = [i for i in issues if i.impact is Impact.NOTE]
        for issue in issues:
            if issue.impact is Impact.NOTE:
                continue
            number += 1
            style = _IMPACT_STYLES[issue.impact]
            console.print(
                f"[bold]{number}.[/bold] [{style}]{issue.impact.value.upper()}[/{style}] "
                f"[bold]{escape(issue.title)}[/bold]"
            )
            body = f"[dim]{escape(issue.detail)}[/dim]\n[bold]Fix:[/bold] {escape(issue.fix)}"
            console.print(Padding(body, (0, 0, 0, 3)), highlight=False)
        if section_notes:
            console.print("[dim]Notes, nothing to fix:[/dim]")
            for note in section_notes:
                # Check values are the command names: `dnskit local` has the details.
                where = f"dnskit {note.check.value}"
                console.print(Padding(f"[dim]· {escape(note.title)} — {where}[/dim]", (0, 0, 0, 2)))

    console.print()
    ran = sum(r.state is not CheckState.SKIPPED for r in report.runs)
    console.print(f"[dim]Ran {ran} checks in parallel · {report.elapsed_ms:.0f} ms total[/dim]")


# --- batch --------------------------------------------------------------------------------


class BatchProgress:
    """Live count of checked domains; `done` is safe to call from worker threads."""

    def __init__(self, total: int, check: BatchCheck) -> None:
        self._lock = threading.Lock()
        self._total = total
        self._done = 0
        self._spinner = Spinner("dots", style="cyan")
        self._check = check

    def done(self, item: BatchItem) -> None:
        with self._lock:
            self._done += 1
            self._spinner.update(text=self._text(item.name))

    def _text(self, last: str = "") -> str:
        latest = f" [dim]· last: {escape(last)}[/dim]" if last else ""
        return f"Running {self._check.value} on {self._done}/{self._total} domains{latest}"

    def __rich__(self) -> Spinner:
        with self._lock:
            if not self._done:
                self._spinner.update(text=self._text())
            return self._spinner


def render_batch(report: BatchReport, console: Console) -> None:
    if report.local is not None:
        problems = [p for p in report.local.problems if p.severity is Severity.ERROR]
        state = (
            f"[red]{len(problems)} error{'s' if len(problems) > 1 else ''}[/red]"
            if problems
            else "[green]OK[/green]"
        )
        console.print(
            f"This computer: {state} [dim](checked once for every domain; details: "
            "dnskit local)[/dim]"
        )
    if report.items:
        table = Table(
            title=f"dnskit {report.check.value} for {len(report.items)} "
            f"domain{'s' if len(report.items) > 1 else ''}",
            title_justify="left",
        )
        table.add_column("Line", justify="right", style="dim")
        table.add_column("Domain", style="bold")
        table.add_column("Result")
        table.add_column("Summary", overflow="fold")
        table.add_column("Time", justify="right", style="dim")
        for item in report.items:
            result = "[green]✓ OK[/green]" if item.ok else "[red]✗ not OK[/red]"
            summary = escape(item.summary)
            if item.error:
                summary += f" [dim]({escape(item.error)})[/dim]"
            table.add_row(
                str(item.line), escape(item.name), result, summary, f"{item.elapsed_ms:.0f} ms"
            )
        console.print(table)
    for line in report.invalid:
        console.print(
            f"[yellow]Skipped line {line.line}:[/yellow] {escape(line.error or line.text)}"
        )
    for line in report.duplicates:
        console.print(
            f"[dim]Line {line.line}: {escape(line.name or line.text)} is listed again "
            "(checked once).[/dim]"
        )

    parts = [f"[green]{len(report.passed)} OK[/green]"]
    if report.failed:
        parts.append(f"[red]{len(report.failed)} not OK[/red]")
    if report.invalid:
        count = len(report.invalid)
        parts.append(f"[yellow]{count} invalid line{'s' if count > 1 else ''}[/yellow]")
    console.print(
        " · ".join(parts) + f" [dim]· {report.elapsed_ms / 1000:.1f} s total[/dim]",
        highlight=False,
    )


# --- watch --------------------------------------------------------------------------------


def render_watch_start(
    name: str, rtype: str, interval: float, until: str | None, console: Console
) -> None:
    goal = f", until it includes {escape(until)}" if until else ""
    console.print(
        f"Watching [bold]{escape(name)} {rtype}[/bold] every {interval:g} s{goal} "
        "[dim](Ctrl+C to stop)[/dim]"
    )


def watch_answer(result: LookupResult) -> str:
    """The answer in one line: the records sorted, or what went wrong."""
    if result.records:
        values = ", ".join(sorted(r.value for r in result.records))
        return f"{values} [dim](TTL {result.records[0].ttl})[/dim]"
    return _STATUS_LABELS.get(result.status, result.status.value)


def render_watch_sample(
    sample: WatchSample, console: Console, until: str | None = None, strict: bool = False
) -> None:
    at = sample.at.astimezone().strftime("%H:%M:%S")
    answer = watch_answer(sample.result)
    if not sample.answered:
        note = "[red]lookup failed[/red] [dim](not counted as a change)[/dim]"
        answer = f"[red]{escape(answer)}[/red]"
    elif sample.rotating and not strict:
        note = "[blue]rotating (CDN)[/blue] [dim](all seen before)[/dim]"
    elif sample.changed:
        assert sample.previous is not None
        note = (
            f"[bold yellow]CHANGED[/bold yellow] [dim](was {watch_answer(sample.previous)})[/dim]"
        )
        answer = f"[bold]{answer}[/bold]"
    elif sample.number == 1:
        note = f"[dim]first answer, from {escape(sample.nameserver)}[/dim]"
    else:
        note = "[dim]unchanged[/dim]"
    if until and sample.matches(until):
        note += f" [green]✓ includes {escape(until)}[/green]"
    console.print(f"[dim]{at}[/dim]  {answer}  {note}", highlight=False)


def _times(n: int) -> str:
    return f"{n} time{'s' if n != 1 else ''}"


def render_watch_end(summary: WatchSummary, reason: str, strict: bool, console: Console) -> None:
    checks = summary.checks
    changes = summary.new_changes + (summary.rotations if strict else 0)
    parts = [f"the answer changed {_times(changes)}"] if changes else []
    if summary.rotations and not strict:
        parts.append(f"rotated {_times(summary.rotations)} between addresses already seen")
    what = " and ".join(parts) if parts else "the answer didn't change"
    console.print(f"{reason} after {checks} check{'s' if checks != 1 else ''}; {what}.")
    if summary.failures:
        console.print(
            f"[dim]{summary.failures} lookup{'s' if summary.failures > 1 else ''} "
            "failed and weren't counted.[/dim]"
        )
    if not summary.values:
        return
    table = Table(title="Everything seen", title_justify="left")
    table.add_column("Answer")
    table.add_column("Checks", justify="right")
    table.add_column("First seen", style="dim")
    table.add_column("Last seen", style="dim")
    for value in summary.values:
        table.add_row(
            escape(value.value),
            str(value.times),
            value.first.astimezone().strftime("%H:%M:%S"),
            value.last.astimezone().strftime("%H:%M:%S"),
        )
    console.print(table)


# --- config -------------------------------------------------------------------------------


def render_config(config: Config, console: Console) -> None:
    if not config.exists:
        console.print(f"No config file at [bold]{escape(str(config.path))}[/bold].")
        console.print(
            "[dim]dnskit uses its built-in defaults. Run `dnskit config --init` to create a "
            "commented starter file there.[/dim]"
        )
        return
    console.print(f"Config file: [bold]{escape(str(config.path))}[/bold]")
    if config.settings:
        table = Table(title="Settings", title_justify="left")
        table.add_column("Command", style="bold")
        table.add_column("Setting")
        table.add_column("Value")
        for command, settings in config.settings.items():
            for n, (name, value) in enumerate(settings.items()):
                table.add_row(command if n == 0 else "", name, escape(repr(value)))
        console.print(table)
    for label, resolvers in (
        ("compare", config.compare_resolvers),
        (
            "propagation",
            tuple((r.name, r.address) for r in config.propagation_resolvers)
            if config.propagation_resolvers
            else None,
        ),
    ):
        if resolvers:
            listed = ", ".join(f"{escape(name)} ({address})" for name, address in resolvers)
            console.print(f"[bold]{label}[/bold] resolvers: {listed}")
    if not config.settings and not config.compare_resolvers and not config.propagation_resolvers:
        console.print("[dim]It sets nothing: everything uses the built-in defaults.[/dim]")
