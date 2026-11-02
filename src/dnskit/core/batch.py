"""Run `lookup`, `doctor` or `email` on every domain in a list, a few at a time.

`read_domains` turns a text file into `BatchLine`s (one domain per line; blank lines and
`#` comments skipped; a URL counts as its domain), `run_batch` checks each valid one and
returns a `BatchReport` whose items each say OK or not, with a one-line summary.
"""

import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from dnskit.core.diagnosis import explain
from dnskit.core.doctor import DOCTOR_TIMEOUT_S, DoctorReport, doctor
from dnskit.core.local import LocalReport, local_check
from dnskit.core.lookup import DEFAULT_RTYPES, LookupReport, LookupStatus, lookup
from dnskit.core.mail import CheckStatus, EmailReport, email_check
from dnskit.core.reach import parse_target

DEFAULT_PARALLEL = 4
MAX_PARALLEL = 16


class BatchCheck(StrEnum):
    LOOKUP = "lookup"
    DOCTOR = "doctor"
    EMAIL = "email"


@dataclass(frozen=True)
class BatchLine:
    line: int  # 1-based, in the file
    text: str  # as written, without the comment
    name: str | None  # the domain, or None when the line isn't one
    error: str | None = None  # why it isn't


@dataclass(frozen=True)
class BatchItem:
    line: int
    name: str
    ok: bool
    summary: str  # one line: what was found
    elapsed_ms: float
    report: LookupReport | DoctorReport | EmailReport | None = None
    error: str | None = None  # the check itself failed (crashed); report is None


@dataclass(frozen=True)
class BatchReport:
    check: BatchCheck
    items: tuple[BatchItem, ...]  # in file order
    invalid: tuple[BatchLine, ...]  # lines that aren't domains
    duplicates: tuple[BatchLine, ...]  # domains listed again (checked once)
    elapsed_ms: float
    local: LocalReport | None = None  # doctor: this computer, checked once for all domains

    @property
    def passed(self) -> tuple[BatchItem, ...]:
        return tuple(i for i in self.items if i.ok)

    @property
    def failed(self) -> tuple[BatchItem, ...]:
        return tuple(i for i in self.items if not i.ok)

    @property
    def all_ok(self) -> bool:
        return not self.failed and not self.invalid


def read_domains(text: str) -> list[BatchLine]:
    """One `BatchLine` per non-blank, non-comment line. Invalid domains get an `error`."""
    lines = []
    for number, raw in enumerate(text.splitlines(), start=1):
        content = raw.split("#", 1)[0].strip()
        if not content:
            continue
        try:
            lines.append(BatchLine(number, content, parse_target(content)))
        except ValueError as exc:
            lines.append(BatchLine(number, content, None, str(exc)))
    return lines


def run_batch(
    lines: Sequence[BatchLine],
    check: BatchCheck,
    *,
    timeout: float | None = None,
    parallel: int = DEFAULT_PARALLEL,
    quick: bool = False,
    server: str | None = None,
    selectors: Sequence[str] = (),
    resolvers: Sequence[tuple[str, str]] | None = None,
    on_done: Callable[[BatchItem], None] | None = None,
) -> BatchReport:
    """Check every valid line's domain with `check`, up to `parallel` at a time.

    A domain listed twice is checked once. `on_done` is called from worker threads as each
    finishes. For `doctor`, this computer is checked once and shared by every domain.
    `server`/`selectors` apply to lookup and email; `quick`/`resolvers` to doctor.
    """
    start = time.perf_counter()
    seen: set[str] = set()
    todo: list[BatchLine] = []
    duplicates: list[BatchLine] = []
    for line in lines:
        if line.name is None:
            continue
        (duplicates if line.name in seen else todo).append(line)
        seen.add(line.name)

    local = local_check(probe_ghosts=False) if check is BatchCheck.DOCTOR and todo else None

    def run(line: BatchLine) -> BatchItem:
        assert line.name is not None
        begun = time.perf_counter()
        try:
            report, ok, summary = _check(
                line.name, check, timeout, quick, server, selectors, resolvers, local
            )
            error = None
        except Exception as exc:  # one domain mustn't stop the rest
            report, ok, summary, error = (
                None,
                False,
                "couldn't be checked",
                str(exc) or type(exc).__name__,
            )
        item = BatchItem(
            line.line, line.name, ok, summary, (time.perf_counter() - begun) * 1000, report, error
        )
        if on_done:
            on_done(item)
        return item

    workers = max(1, min(parallel, MAX_PARALLEL, len(todo) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        items = tuple(pool.map(run, todo))
    return BatchReport(
        check=check,
        items=items,
        invalid=tuple(line for line in lines if line.name is None),
        duplicates=tuple(duplicates),
        elapsed_ms=(time.perf_counter() - start) * 1000,
        local=local,
    )


def _check(
    name: str,
    check: BatchCheck,
    timeout: float | None,
    quick: bool,
    server: str | None,
    selectors: Sequence[str],
    resolvers: Sequence[tuple[str, str]] | None,
    local: LocalReport | None,
) -> tuple[Any, bool, str]:
    match check:
        case BatchCheck.LOOKUP:
            found = lookup(name, DEFAULT_RTYPES, nameserver=server, timeout=timeout or 5.0)
            return found, *summarize_lookup(found)
        case BatchCheck.DOCTOR:
            health = doctor(
                name,
                quick=quick,
                timeout=timeout or DOCTOR_TIMEOUT_S,
                resolvers=resolvers,
                local=local,
            )
            return health, *summarize_doctor(health)
        case BatchCheck.EMAIL:
            mail = email_check(name, selectors, nameserver=server, timeout=timeout or 5.0)
            return mail, *summarize_email(mail)


def summarize_lookup(report: LookupReport) -> tuple[bool, str]:
    """OK when the name exists; the summary lists how many records of each type it has."""
    found = [r for r in report.results if r.records]
    if found:
        return True, ", ".join(f"{r.rtype} {len(r.records)}" for r in found)
    statuses = [r.status for r in report.results]
    if LookupStatus.NO_ANSWER in statuses:
        return True, "exists, but has none of these records"
    diagnosis = explain(statuses[0], report.name, "A")
    return False, diagnosis.title if diagnosis else statuses[0].value


def summarize_doctor(report: DoctorReport) -> tuple[bool, str]:
    """OK when healthy (no critical or major issue). The summary is the score and the most
    important issue (notes aside), or "no issues"."""
    top = report.problems[0].title if report.problems else "no issues"
    return report.healthy, f"{report.score}/100 · {top}"


def summarize_email(report: EmailReport) -> tuple[bool, str]:
    """OK unless a check fails; the summary is the most important finding."""
    if report.domain_status is not LookupStatus.OK:
        diagnosis = explain(report.domain_status, report.domain, "MX")
        return False, diagnosis.title if diagnosis else report.domain_status.value
    worst = report.status
    headline = next(
        (s.headline for _, s in report.checks if s.status is worst and s.headline), None
    )
    if worst is CheckStatus.PASS or headline is None:
        return True, "all checks pass"
    label = next(label for label, s in report.checks if s.headline is headline)
    return worst is not CheckStatus.FAIL, f"{worst.value}: {label}: {headline.title}"
