"""Typer application: argument parsing and wiring between core and render."""

import codecs
import errno
import io
import json
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape

from dnskit import __version__
from dnskit.cli.render import (
    BatchProgress,
    DoctorProgress,
    render_batch,
    render_compare,
    render_config,
    render_dnssec,
    render_doctor,
    render_email,
    render_local,
    render_probes,
    render_propagation,
    render_reach,
    render_report,
    render_reverse,
    render_trace,
    render_watch_end,
    render_watch_sample,
    render_watch_start,
)
from dnskit.core import (
    COMPARE_TIMEOUT_S,
    DEFAULT_PARALLEL,
    DEFAULT_PORT,
    DEFAULT_RTYPES,
    DKIM_SELECTORS,
    DOCTOR_TIMEOUT_S,
    MAX_PARALLEL,
    PROBE_TIMEOUT_S,
    PROPAGATION_RESOLVERS,
    PROPAGATION_TIMEOUT_S,
    PUBLIC_RESOLVERS,
    TRACE_TIMEOUT_S,
    WATCH_INTERVAL_S,
    BatchCheck,
    Config,
    ConfigError,
    Diagnosis,
    DnssecStatus,
    LookupStatus,
    ReachVerdict,
    WatchSample,
    cache_path,
    choose_nameserver,
    classify_nameservers,
    compare,
    config_path,
    dnssec_check,
    doctor,
    doctor_verdict,
    email_check,
    explain,
    explain_dnssec,
    explain_propagation,
    explain_reach,
    explain_reverse,
    explain_trace,
    load_config,
    local_check,
    lookup,
    parse_target,
    propagation,
    reach,
    read_domains,
    reverse_lookup,
    run_batch,
    to_data,
    trace,
    watch,
    watch_summary,
    write_template,
)

_WINDOWS = sys.platform == "win32"


class PipeSafeConsole(Console):
    """A Console that exits quietly when the reader closes the pipe on Windows too.

    Rich handles `BrokenPipeError` (e.g. `dnskit compare example.com | head -3` on Linux or
    macOS) by sending the rest of stdout to devnull and exiting with code 1. On Windows a
    closed pipe raises `OSError(EINVAL)` instead, which Rich doesn't catch, so it printed a
    traceback and "Exception ignored on flushing sys.stdout". Treat it as a broken pipe.
    """

    def _check_buffer(self) -> None:
        try:
            super()._check_buffer()
        except OSError as exc:
            if _WINDOWS and exc.errno == errno.EINVAL:
                self.on_broken_pipe()
            raise


GUIDE_URL = "https://github.com/gladkhumalo/dnskit/blob/main/docs/USER_GUIDE.md"

app = typer.Typer(
    help="DNS troubleshooting toolkit: why a name doesn't resolve, a site won't load or email "
    "doesn't arrive, and whether the problem is this computer, its network or the domain.\n\n"
    "Not sure where to start? Run [bold]dnskit doctor example.com[/bold]. Every command "
    "explains what it finds in plain English, takes --json for scripts, and reads its defaults "
    "from a config file (see [bold]dnskit config[/bold]). Each command's --help has examples.",
    epilog=f"Full guide: {GUIDE_URL}",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = PipeSafeConsole()
err_console = PipeSafeConsole(stderr=True)

ServerOption = Annotated[
    str | None,
    typer.Option(
        "--server",
        "-s",
        help="IP address of the DNS server to ask, instead of the fastest of this computer's.",
    ),
]
TimeoutOption = Annotated[float, typer.Option(help="Seconds to wait for each answer.")]
RefreshOption = Annotated[
    bool,
    typer.Option(
        "--refresh", help="Re-probe the system nameservers instead of using the cached choice."
    ),
]
JsonOption = Annotated[
    bool, typer.Option("--json", help="Print the result as JSON (for scripts) instead.")
]

# The config file, read once per run by `main` (an empty one when there's no file).
_config: Config | None = None

# Setting names in the config file -> the commands' parameter names, where they differ.
_PARAMETER_NAMES = {"type": "rtype", "selectors": "selector", "json": "as_json"}


def _epilog(examples: list[str], exit_codes: str) -> str:
    """The examples and exit codes shown at the end of a command's --help."""
    shown = "\n\n".join(f"  {example}" for example in examples)
    return f"[bold]Examples[/bold]\n\n{shown}\n\n[bold]Exit codes:[/bold] {exit_codes}"


def current_config() -> Config:
    return _config if _config is not None else Config(config_path(), exists=False)


def run() -> None:
    """The `dnskit` program: the Typer app, plus a quiet exit when the reader goes away.

    PipeSafeConsole covers dnskit's own output, but --help and Typer's error messages are
    printed by Typer's console, so `dnskit --help | head -3` on Windows still raised
    OSError(EINVAL) with a traceback. Catch it here, where every way in passes.
    """
    try:
        app(prog_name="dnskit")
    except OSError as exc:
        if _WINDOWS and exc.errno == errno.EINVAL:
            console.on_broken_pipe()  # stdout to devnull, exit 1, as Rich does elsewhere
        raise


def _use_utf8_output() -> None:
    """Make stdout/stderr UTF-8 when they aren't already.

    On Windows, redirected or piped output falls back to the ANSI code page (cp1252), which
    can't encode ✓, ≠ or box-drawing characters, so Rich crashed with UnicodeEncodeError and
    the exit code became 1. A real console is already UTF-8 and is left alone.
    """
    for stream in (sys.stdout, sys.stderr):
        if not isinstance(stream, io.TextIOWrapper):
            continue
        try:
            if codecs.lookup(stream.encoding).name != "utf-8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (LookupError, OSError, ValueError):
            pass


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"dnskit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """DNS troubleshooting toolkit.

    Default options can be set in a config file: run `dnskit config` to see where it is.
    """
    global _config
    _use_utf8_output()
    if ctx.invoked_subcommand == "config":
        return  # `dnskit config` reports problems in the file itself
    try:
        _config = load_config()
    except ConfigError as exc:
        err_console.print(
            f"[red]Error in the config file:[/red] {escape(str(exc))}", highlight=False
        )
        raise typer.Exit(2) from exc
    # Click hands each command its section as option defaults; the command line still wins.
    ctx.default_map = {
        command: {_PARAMETER_NAMES.get(name, name): value for name, value in settings.items()}
        for command, settings in _config.settings.items()
    }


def _print_json(payload: dict[str, Any]) -> None:
    typer.echo(json.dumps(to_data(payload), indent=2, ensure_ascii=False))


def _print_json_line(payload: dict[str, Any]) -> None:
    """One compact object per line (JSON Lines), for output read as it arrives."""
    typer.echo(json.dumps(to_data(payload), ensure_ascii=False))


def _emit_json(
    command: str,
    report: Any,
    exit_code: int,
    summary: dict[str, Any] | None = None,
    diagnosis: Diagnosis | None = None,
) -> None:
    """The `--json` output: what was checked, the short answer, the explanation, everything."""
    _print_json(
        {
            "command": command,
            "dnskit_version": __version__,
            "exit_code": exit_code,
            "summary": summary or {},
            "diagnosis": diagnosis,
            "report": report,
        }
    )


def _fail(command: str, message: str, as_json: bool, code: int = 2) -> NoReturn:
    """Invalid input or an unusable setup: say so (as JSON with --json) and exit."""
    if as_json:
        _print_json(
            {
                "command": command,
                "dnskit_version": __version__,
                "exit_code": code,
                "error": message,
            }
        )
    else:
        err_console.print(f"[red]Error:[/red] {escape(message)}", highlight=False)
    raise typer.Exit(code)


def _exit(code: int) -> None:
    if code:
        raise typer.Exit(code)


@app.command(
    "lookup",
    epilog=_epilog(
        [
            "dnskit lookup example.com",
            "dnskit lookup example.com -t MX",
            "dnskit lookup example.com -s 1.1.1.1 --json",
        ],
        "0 the name exists (even with some types empty), 1 the lookup failed or the name doesn't "
        "exist, 2 invalid input.",
    ),
)
def lookup_command(
    name: Annotated[str, typer.Argument(help="Domain name to query.")],
    rtype: Annotated[
        str | None,
        typer.Option(
            "--type",
            "-t",
            help=f"Single record type to query. Default: {', '.join(DEFAULT_RTYPES)}.",
        ),
    ] = None,
    server: ServerOption = None,
    timeout: TimeoutOption = 5.0,
    refresh: RefreshOption = False,
    as_json: JsonOption = False,
) -> None:
    """Look up DNS records for a name.

    Queries A, AAAA, MX, CNAME, NS and TXT at once (or one --type) through the fastest of this
    computer's DNS servers, and explains in plain English when a lookup fails.
    """
    rtypes = [rtype] if rtype else list(DEFAULT_RTYPES)
    try:
        report = lookup(name, rtypes, nameserver=server, timeout=timeout, refresh=refresh)
    except ValueError as exc:
        _fail("lookup", str(exc), as_json)

    exists = {LookupStatus.OK, LookupStatus.NO_ANSWER}
    code = 0 if any(r.status in exists for r in report.results) else 1
    if as_json:
        failed = report.results[0] if code else None
        diagnosis = explain(failed.status, name, failed.rtype, timeout) if failed else None
        _emit_json("lookup", report, code, {"exists": code == 0}, diagnosis)
    else:
        render_report(report, console, timeout=timeout)
    _exit(code)


@app.command(
    "reverse",
    epilog=_epilog(
        ["dnskit reverse 8.8.8.8", "dnskit reverse 2001:4860:4860::8888"],
        "0 a name was found, 1 none (or the lookup failed), 2 not an IP address.",
    ),
)
def reverse_command(
    ip: Annotated[str, typer.Argument(help="IPv4 or IPv6 address to look up.")],
    server: ServerOption = None,
    timeout: TimeoutOption = 5.0,
    refresh: RefreshOption = False,
    as_json: JsonOption = False,
) -> None:
    """Find the hostname for an IP address (reverse DNS / PTR lookup).

    Useful for an unknown address in a log, or to check a mail server's reverse name.
    """
    try:
        report = reverse_lookup(ip, nameserver=server, timeout=timeout, refresh=refresh)
    except ValueError as exc:
        _fail("reverse", str(exc), as_json)

    code = 0 if report.result.status is LookupStatus.OK else 1
    if as_json:
        hostnames = [r.value for r in report.result.records]
        diagnosis = explain_reverse(report.result.status, report.ip, timeout)
        _emit_json("reverse", report, code, {"hostnames": hostnames}, diagnosis)
    else:
        render_reverse(report, console, timeout=timeout)
    _exit(code)


_PUBLIC_NAMES = ", ".join(f"{label} ({ip})" for label, ip in PUBLIC_RESOLVERS)


@app.command(
    "compare",
    epilog=_epilog(
        ["dnskit compare example.com", "dnskit compare example.com -t MX"],
        "0 every resolver that answered agrees, 1 they disagree or none answered, 2 invalid input.",
    ),
    help="Compare a record's answer across public and system resolvers.\n\n"
    f"Queries {_PUBLIC_NAMES} (or the resolvers in the config file) and each of this "
    "computer's nameservers in parallel, and highlights any resolver whose answer differs "
    "from the majority.",
)
def compare_command(
    name: Annotated[str, typer.Argument(help="Domain name to query.")],
    rtype: Annotated[str, typer.Option("--type", "-t", help="Record type to compare.")] = "A",
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for each resolver.")
    ] = COMPARE_TIMEOUT_S,
    as_json: JsonOption = False,
) -> None:
    try:
        report = compare(name, rtype, timeout=timeout, resolvers=current_config().compare_resolvers)
    except ValueError as exc:
        _fail("compare", str(exc), as_json)

    code = 0 if report.all_agree else 1
    if as_json:
        summary = {
            "all_agree": report.all_agree,
            "has_majority": report.has_majority,
            "distinct_answers": report.distinct_answers,
        }
        _emit_json("compare", report, code, summary)
    else:
        render_compare(report, console)
    _exit(code)


@app.command(
    "email",
    epilog=_epilog(
        ["dnskit email example.com", "dnskit email example.com --selector s2024"],
        "0 no check fails (warnings are fine), 1 a check fails or the domain doesn't exist, 2 "
        "invalid input.",
    ),
    help="Check a domain's email DNS setup: MX, SPF, DMARC and DKIM.\n\n"
    "Each check is shown as pass, warn or fail with an explanation and a suggested fix. "
    f"DKIM keys are looked up at the common selectors ({', '.join(DKIM_SELECTORS)}) and at "
    "any given with --selector. ",
)
def email_command(
    domain: Annotated[str, typer.Argument(help="Domain to check, such as example.com.")],
    selector: Annotated[
        list[str] | None,
        typer.Option(
            "--selector",
            help="Extra DKIM selector to check (the s= value in an email's DKIM-Signature "
            "header). Repeat it to check several.",
        ),
    ] = None,
    server: ServerOption = None,
    timeout: TimeoutOption = 5.0,
    refresh: RefreshOption = False,
    as_json: JsonOption = False,
) -> None:
    try:
        report = email_check(
            domain, selector or (), nameserver=server, timeout=timeout, refresh=refresh
        )
    except ValueError as exc:
        _fail("email", str(exc), as_json)

    code = 1 if report.failed else 0
    if as_json:
        _emit_json("email", report, code, {"status": report.status, "failed": report.failed})
    else:
        render_email(report, console, timeout=timeout)
    _exit(code)


@app.command(
    "resolvers",
    epilog=_epilog(
        ["dnskit resolvers", "dnskit resolvers --json"],
        "0 at least one DNS server answered, 1 none did.",
    ),
)
def resolvers_command(
    timeout: Annotated[float, typer.Option(help="Probe timeout in seconds.")] = 1.0,
    as_json: JsonOption = False,
) -> None:
    """Probe the system's nameservers, show which respond, and refresh the cached choice.

    Tests every DNS server this computer uses, shows how fast each answers, and marks the
    one dnskit will use (the fastest). The choice is remembered for 5 minutes.
    """
    nameservers = classify_nameservers()
    if not nameservers.usable:
        _fail("resolvers", "No system nameservers configured.", as_json, code=1)
    choice = choose_nameserver(nameservers.usable, use_cache=False, timeout=timeout)
    code = 1 if choice.nameserver is None else 0
    if as_json:
        report = {"choice": choice, "ignored": nameservers.ignored, "cache_path": cache_path()}
        _emit_json("resolvers", report, code, {"chosen": choice.nameserver})
    else:
        render_probes(choice, console, str(cache_path()), nameservers.ignored)
    _exit(code)


@app.command(
    "local",
    epilog=_epilog(
        ["dnskit local", "dnskit local --timeout 2"],
        "0 DNS works here (warnings are fine), 1 an error: no adapter, no DNS server, or none "
        "answering.",
    ),
)
def local_command(
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for each DNS server's test query.")
    ] = PROBE_TIMEOUT_S,
    as_json: JsonOption = False,
) -> None:
    """Check this computer's DNS setup: adapters, DNS servers, ghosts and the hosts file.

    Lists every network adapter and its DNS servers, tests each server, flags ghost servers
    (in the system configuration but on no connected adapter) and hosts file entries that
    override DNS, checks for NXDOMAIN hijacking, DNS interception and broken IPv6, and ends
    with the problems found and how to fix them.
    """
    report = local_check(timeout=timeout)
    code = 1 if report.has_errors else 0
    if as_json:
        summary = {"has_errors": report.has_errors, "problems": len(report.problems)}
        _emit_json("local", report, code, summary)
    else:
        render_local(report, console)
    _exit(code)


# Exit code for `reach` when DNS works but the connection doesn't (1 is a DNS problem).
EXIT_CONNECTION_FAILED = 3


@app.command(
    "reach",
    epilog=_epilog(
        [
            "dnskit reach example.com",
            "dnskit reach https://example.com/page",
            "dnskit reach mail.example.com -p 25",
        ],
        "0 reachable, 1 a DNS problem, 3 a connection problem, 2 invalid input.",
    ),
)
def reach_command(
    target: Annotated[str, typer.Argument(help="Domain name (or URL) to test, e.g. example.com.")],
    port: Annotated[
        int, typer.Option("--port", "-p", min=1, max=65535, help="TCP port to connect to.")
    ] = DEFAULT_PORT,
    server: ServerOption = None,
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for the lookups and each connection.")
    ] = 5.0,
    refresh: RefreshOption = False,
    as_json: JsonOption = False,
) -> None:
    """Can this computer reach a site? Resolve it, then connect to it.

    Looks up the name's IPv4 and IPv6 addresses, tries a TCP connection to the port (443,
    HTTPS, by default) on each, and says whether the problem is DNS, the connection, or
    neither.
    """
    try:
        report = reach(target, port=port, nameserver=server, timeout=timeout, refresh=refresh)
    except ValueError as exc:
        _fail("reach", str(exc), as_json)

    code = {ReachVerdict.DNS: 1, ReachVerdict.CONNECTION: EXIT_CONNECTION_FAILED}.get(
        report.verdict, 0
    )
    if as_json:
        diagnosis = explain_reach(report, timeout)
        _emit_json("reach", report, code, {"verdict": report.verdict}, diagnosis)
    else:
        render_reach(report, console, timeout=timeout)
    _exit(code)


@app.command(
    "trace",
    epilog=_epilog(
        ["dnskit trace example.com", "dnskit trace example.com -t MX"],
        "0 the records were found, 1 anything else, 2 invalid input.",
    ),
)
def trace_command(
    name: Annotated[str, typer.Argument(help="Domain name to trace.")],
    rtype: Annotated[str, typer.Option("--type", "-t", help="Record type to ask for.")] = "A",
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for each level's nameservers.")
    ] = TRACE_TIMEOUT_S,
    as_json: JsonOption = False,
) -> None:
    """Follow a name's delegation from the root servers down, like `dig +trace`.

    Asks the root servers, then each level's nameservers in turn, and shows who referred
    the query where and how long each took. If a level fails, says which one and why. If a
    VPN or firewall blocks direct queries, explains that and follows the delegation through
    this computer's own DNS server instead.
    """
    try:
        report = trace(name, rtype, timeout=timeout)
    except ValueError as exc:
        _fail("trace", str(exc), as_json)

    code = 0 if report.succeeded else 1
    if as_json:
        summary = {"succeeded": report.succeeded, "mode": report.mode}
        _emit_json("trace", report, code, summary, explain_trace(report))
    else:
        render_trace(report, console)
    _exit(code)


@app.command(
    "dnssec",
    epilog=_epilog(
        ["dnskit dnssec example.com", "dnskit dnssec example.com -s 8.8.8.8"],
        "0 it validates, or DNSSEC isn't enabled; 1 it's broken, couldn't be checked, or the name "
        "doesn't exist; 2 invalid input.",
    ),
)
def dnssec_command(
    name: Annotated[str, typer.Argument(help="Domain name to check.")],
    server: ServerOption = None,
    timeout: TimeoutOption = 5.0,
    refresh: RefreshOption = False,
    as_json: JsonOption = False,
) -> None:
    """Check whether DNSSEC is enabled and its chain of trust validates from the root down.

    Checks the DS and DNSKEY records of every zone from the root to the domain, verifies
    each signature, and explains the result. Also warns when this computer's clock looks
    wrong, since that breaks validation. When this computer's DNS server strips the
    signatures, the check is done through 8.8.8.8 or 1.1.1.1 instead.
    """
    try:
        report = dnssec_check(name, nameserver=server, timeout=timeout, refresh=refresh)
    except ValueError as exc:
        _fail("dnssec", str(exc), as_json)

    ok = report.status in (DnssecStatus.SECURE, DnssecStatus.INSECURE)
    code = 0 if ok and not report.name_missing else 1
    if as_json:
        summary = {
            "status": report.status,
            "name_missing": report.name_missing,
            "checked_through": report.nameserver,
            "stripped_by": report.stripped_by,
        }
        _emit_json("dnssec", report, code, summary, explain_dnssec(report))
    else:
        render_dnssec(report, console)
    _exit(code)


@app.command(
    "propagation",
    epilog=_epilog(
        ["dnskit propagation example.com", "dnskit propagation example.com -t MX"],
        "0 every resolver that answered agrees, 1 they differ or too few could be reached, 2 "
        "invalid input.",
    ),
    help="Has a DNS change reached resolvers around the world?\n\n"
    f"Asks {len(PROPAGATION_RESOLVERS)} public resolvers (or the ones in the config file) for "
    "the record: global anycast ones, which answer from the site nearest you, and ones in "
    "fixed countries in the Americas, Europe and Asia. Shows what share give the same "
    "answer.",
)
def propagation_command(
    name: Annotated[str, typer.Argument(help="Domain name to check.")],
    rtype: Annotated[str, typer.Option("--type", "-t", help="Record type to check.")] = "A",
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for each resolver.")
    ] = PROPAGATION_TIMEOUT_S,
    as_json: JsonOption = False,
) -> None:
    try:
        report = propagation(
            name, rtype, timeout=timeout, resolvers=current_config().propagation_resolvers
        )
    except ValueError as exc:
        _fail("propagation", str(exc), as_json)

    code = 0 if report.complete else 1
    if as_json:
        summary = {
            "percent": round(report.percent, 1),
            "complete": report.complete,
            "location_based": report.location_based,
            "blocked": report.blocked,
        }
        _emit_json("propagation", report, code, summary, explain_propagation(report))
    else:
        render_propagation(report, console)
    _exit(code)


@app.command(
    "doctor",
    epilog=_epilog(
        [
            "dnskit doctor example.com",
            "dnskit doctor example.com --quick",
            "dnskit doctor example.com --json",
        ],
        "0 no critical or major issue (minor issues and notes are fine), 1 otherwise, 2 invalid "
        "input.",
    ),
    help="Full health check: this computer's DNS setup, then the domain (records, resolvers, "
    "connection, email, DNSSEC), with a score out of 100 and a ranked list of fixes.\n\n"
    "Separates problems with this computer from problems with the domain, and explains each "
    "with a fix. A domain that doesn't exist scores 0. --quick skips the slower checks.",
)
def doctor_command(
    name: Annotated[str, typer.Argument(help="Domain name (or URL) to check.")],
    quick: Annotated[
        bool,
        typer.Option(
            "--quick", help="Skip the slower checks: resolver comparison, email and DNSSEC."
        ),
    ] = False,
    timeout: Annotated[
        float, typer.Option(help="Timeout in seconds for each query of the domain checks.")
    ] = DOCTOR_TIMEOUT_S,
    as_json: JsonOption = False,
) -> None:
    resolvers = current_config().compare_resolvers
    progress = DoctorProgress()
    try:
        if console.is_terminal and not as_json:
            with Live(progress, console=console, transient=True, refresh_per_second=12):
                report = doctor(
                    name,
                    quick=quick,
                    timeout=timeout,
                    on_progress=progress.update,
                    resolvers=resolvers,
                )
        else:
            report = doctor(name, quick=quick, timeout=timeout, resolvers=resolvers)
    except ValueError as exc:
        _fail("doctor", str(exc), as_json)

    code = 0 if report.healthy else 1
    if as_json:
        summary = {
            "score": report.score,
            "healthy": report.healthy,
            "name_missing": report.name_missing,
            "issues": len(report.problems),
            "notes": len(report.issues) - len(report.problems),
        }
        _emit_json("doctor", report, code, summary, doctor_verdict(report))
    else:
        render_doctor(report, console)
    _exit(code)


@app.command(
    "batch",
    epilog=_epilog(
        [
            "dnskit batch domains.txt",
            "dnskit batch domains.txt --check doctor --quick",
            "dnskit batch - --check email < domains.txt",
        ],
        "0 every domain is OK, 1 one isn't or a line isn't a domain, 2 the file can't be read or "
        "has no domains.",
    ),
    help="Run lookup, doctor or email on every domain in a text file, then show a summary.\n\n"
    "The file has one domain (or URL) per line; blank lines and # comments are skipped. Use "
    "'-' to read the list from standard input. For doctor, this computer is checked once.",
)
def batch_command(
    file: Annotated[str, typer.Argument(help="File with one domain per line, or '-'.")],
    check: Annotated[
        BatchCheck, typer.Option("--check", "-c", help="What to run on each domain.")
    ] = BatchCheck.LOOKUP,
    parallel: Annotated[
        int,
        typer.Option(min=1, max=MAX_PARALLEL, help="How many domains to check at the same time."),
    ] = DEFAULT_PARALLEL,
    quick: Annotated[
        bool, typer.Option("--quick", help="With --check doctor: skip the slower checks.")
    ] = False,
    server: ServerOption = None,
    timeout: Annotated[
        float | None,
        typer.Option(help="Timeout in seconds, as for the command run. Default: its own."),
    ] = None,
    as_json: JsonOption = False,
) -> None:
    try:
        text = sys.stdin.read() if file == "-" else Path(file).read_text(encoding="utf-8-sig")
    except OSError as exc:
        _fail("batch", f"Can't read {file}: {exc.strerror or exc}.", as_json)
    lines = read_domains(text)
    if not any(line.name for line in lines):
        where = "standard input" if file == "-" else file
        _fail("batch", f"No domains found in {where}: put one domain on each line.", as_json)

    config = current_config()
    options: dict[str, Any] = {
        "timeout": timeout,
        "parallel": parallel,
        "quick": quick,
        "server": server if check is not BatchCheck.DOCTOR else None,
        "selectors": tuple(config.for_command("email").get("selectors", ())),
        "resolvers": config.compare_resolvers,
    }
    total = len({line.name for line in lines if line.name})
    if console.is_terminal and not as_json:
        progress = BatchProgress(total, check)
        with Live(progress, console=console, transient=True, refresh_per_second=12):
            report = run_batch(lines, check, on_done=progress.done, **options)
    else:
        report = run_batch(lines, check, **options)

    code = 0 if report.all_ok else 1
    if as_json:
        summary = {
            "check": check,
            "domains": len(report.items),
            "ok": len(report.passed),
            "not_ok": len(report.failed),
            "invalid_lines": len(report.invalid),
        }
        _emit_json("batch", report, code, summary)
    else:
        render_batch(report, console)
    _exit(code)


@app.command(
    "watch",
    epilog=_epilog(
        [
            "dnskit watch example.com",
            "dnskit watch example.com --until 203.0.113.80 --interval 60",
            "dnskit watch www.example.com -t CNAME --exit-on-change",
        ],
        "0 stopped as asked, 1 --count ran out before --until was reached, 130 Ctrl+C, 2 invalid "
        "input.",
    ),
    help="Re-check a record every few seconds and say when the answer changes.\n\n"
    "Useful while waiting for a DNS change to spread. Each check prints the answer; a change "
    "is highlighted with a beep. A failed lookup is shown but never counts as a change. "
    "Stops with Ctrl+C, after --count checks, at the first change with --exit-on-change, or "
    "once the answer includes --until. Answers that only rotate between addresses already "
    "seen (a CDN) aren't changes unless --strict.",
)
def watch_command(
    name: Annotated[str, typer.Argument(help="Domain name (or URL) to watch.")],
    rtype: Annotated[str, typer.Option("--type", "-t", help="Record type to watch.")] = "A",
    server: ServerOption = None,
    interval: Annotated[
        float, typer.Option(help="Seconds between checks (at least 1).")
    ] = WATCH_INTERVAL_S,
    until: Annotated[
        str | None,
        typer.Option(help="Stop once the answer includes this value, e.g. the new IP address."),
    ] = None,
    count: Annotated[int | None, typer.Option(min=1, help="Stop after this many checks.")] = None,
    exit_on_change: Annotated[
        bool, typer.Option("--exit-on-change", help="Stop at the first change.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Count every change, including rotation between addresses already seen.",
        ),
    ] = False,
    timeout: TimeoutOption = 5.0,
    as_json: JsonOption = False,
) -> None:
    try:
        samples = watch(name, rtype, nameserver=server, interval=interval, timeout=timeout)
    except ValueError as exc:
        _fail("watch", str(exc), as_json)
    if not as_json:
        render_watch_start(parse_target(name), rtype.upper(), interval, until, console)

    seen: list[WatchSample] = []
    changes = 0  # changes worth an alert: any change with --strict, else new answers only

    def stop(reason: str, code: int) -> NoReturn:
        summary = watch_summary(seen)
        if as_json:
            _print_json_line(
                {
                    "command": "watch",
                    "event": "end",
                    "reason": reason,
                    "checks": len(seen),
                    "changes": changes,
                    "rotations": 0 if strict else summary.rotations,
                    "seen": summary.values,
                    "exit_code": code,
                }
            )
        else:
            render_watch_end(summary, reason, strict, console)
        raise typer.Exit(code)

    try:
        for sample in samples:
            seen.append(sample)
            # Rotation between addresses already seen is a CDN at work, not news.
            alert = sample.changed if strict else sample.new_change
            changes += alert
            if as_json:
                event = {
                    "command": "watch",
                    "event": "check",
                    "changed": sample.changed,
                    "rotating": sample.rotating and not strict,
                    "alert": alert,
                    "answered": sample.answered,
                    "sample": sample,
                }
                if until:
                    event["includes_until"] = sample.matches(until)
                _print_json_line(event)
            else:
                render_watch_sample(sample, console, until, strict)
                if alert:
                    console.bell()
            if until and sample.matches(until):
                stop(f"Done: the answer includes {until}", 0)
            if exit_on_change and alert:
                stop("Stopped at the first change", 0)
            if count and len(seen) >= count:
                stop("Stopped", 1 if until else 0)
    except KeyboardInterrupt:
        stop("Stopped", 130)


@app.command(
    "config",
    epilog=_epilog(
        ["dnskit config", "dnskit config --init", "dnskit config --path"],
        "0 done, 1 --init found a file already there, 2 the file has a mistake.",
    ),
)
def config_command(
    init: Annotated[
        bool, typer.Option("--init", help="Create a commented starter config file.")
    ] = False,
    show_path: Annotated[
        bool, typer.Option("--path", help="Only print where the config file is.")
    ] = False,
    as_json: JsonOption = False,
) -> None:
    """Show the config file's location and settings, or create one with --init.

    The file (TOML) sets default options for each command and can replace the resolvers
    that `compare` and `propagation` ask. Set DNSKIT_CONFIG to use another file.
    """
    path = config_path()
    if show_path:
        typer.echo(str(path))
        return
    if init:
        try:
            write_template(path)
        except ConfigError as exc:
            _fail("config", str(exc), as_json, code=1)
        console.print(f"Created [bold]{escape(str(path))}[/bold]. Uncomment the settings you want.")
        return
    try:
        config = load_config(path)
    except ConfigError as exc:
        _fail("config", str(exc), as_json)
    if as_json:
        _emit_json("config", config, 0, {"exists": config.exists, "path": path})
    else:
        render_config(config, console)
