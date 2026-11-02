"""Check a domain's email DNS setup: MX, SPF, DMARC and DKIM.

Each check returns findings (pass / warn / fail) with plain-English explanations and fixes,
so every front end can present them its own way. Named `mail` to avoid shadowing the
standard library's `email` package.
"""

import base64
import binascii
import ipaddress
import re
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum

from dnskit.core.diagnosis import explain
from dnskit.core.lookup import LookupResult, LookupStatus, _choose_nameservers, _query_one, txt_text
from dnskit.core.nameservers import ResolverChoice

# Selectors tried when no --selector is given: Google Workspace, Microsoft 365 (two), and
# the defaults of common hosting panels and providers (cPanel, Mailchimp/Mandrill).
DKIM_SELECTORS: tuple[str, ...] = ("google", "selector1", "selector2", "default", "k1")

# RFC 7208 §4.6.4: evaluating an SPF record may cause at most 10 DNS lookups.
SPF_LOOKUP_LIMIT = 10

# What each DMARC policy asks receivers to do with mail that fails DMARC.
DMARC_POLICIES: dict[str, str] = {
    "none": "monitoring only: mail that fails DMARC is delivered as normal, and receivers "
    "only send reports",
    "quarantine": "mail that fails DMARC is put in the spam or junk folder",
    "reject": "mail that fails DMARC is refused outright",
}

# What an SPF record's final `all` means for mail from servers it doesn't list.
SPF_ALL_MEANINGS: dict[str, str] = {
    "-": "mail from servers not listed should be rejected (hard fail)",
    "~": "mail from servers not listed is treated as suspicious, usually sent to spam (soft fail)",
    "?": "mail from servers not listed gets no verdict at all (neutral), as if there were no "
    "SPF record",
    "+": "every server on the internet may send mail as this domain",
}

_FAULTS = {
    LookupStatus.SERVFAIL,
    LookupStatus.TIMEOUT,
    LookupStatus.NO_NETWORK,
    LookupStatus.NO_NAMESERVERS,
}

# SPF terms that cost a DNS lookup; `redirect` is a modifier and counted separately.
_SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
_SPF_MECHANISMS = _SPF_LOOKUP_MECHANISMS | {"all", "ip4", "ip6"}
_SPF_TYPOS = {"ipv4": "ip4", "ipv6": "ip6", "includes": "include", "inc": "include"}
_DMARC_TAGS = {"v", "p", "sp", "np", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri"}
_DMARC_TAGS |= {"psd", "t"}  # DMARCbis

# Bounds on following SPF includes, so a loop or a huge tree can't run away.
_MAX_SPF_DEPTH = 10
_MAX_SPF_FETCHES = 40

_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_SELECTOR = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")

# Providers whose MX hosts identify them, and the SPF include they document.
_PROVIDER_SPF: tuple[tuple[str, str], ...] = (
    (".google.com", "_spf.google.com"),
    (".googlemail.com", "_spf.google.com"),
    (".mail.protection.outlook.com", "spf.protection.outlook.com"),
)


class CheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"  # works, but is weak, risky or unusual
    FAIL = "fail"  # broken or missing, or couldn't be checked


_RANK = {CheckStatus.PASS: 0, CheckStatus.WARN: 1, CheckStatus.FAIL: 2}


def worst(statuses: Iterable[CheckStatus]) -> CheckStatus:
    """The most severe of `statuses` (PASS when there are none)."""
    return max(statuses, key=_RANK.__getitem__, default=CheckStatus.PASS)


@dataclass(frozen=True)
class Finding:
    status: CheckStatus
    title: str
    explanation: str
    fix: str = ""  # empty when there's nothing to do


class EmailSection:
    """Shared by the four checks: an overall status from their findings."""

    findings: tuple[Finding, ...]

    @property
    def status(self) -> CheckStatus:
        return worst(f.status for f in self.findings)

    @property
    def headline(self) -> Finding | None:
        """The first of the most severe findings: the one-line summary of this check."""
        status = self.status
        return next((f for f in self.findings if f.status is status), None)


@dataclass(frozen=True)
class MxHost:
    preference: int
    host: str  # without the trailing dot; empty for a null MX
    addresses: tuple[str, ...]  # A then AAAA
    lookup_status: LookupStatus  # OK when it has any address, else why not


@dataclass(frozen=True)
class MxCheck(EmailSection):
    lookup_status: LookupStatus
    hosts: tuple[MxHost, ...]  # by preference
    findings: tuple[Finding, ...]

    @property
    def null_mx(self) -> bool:
        return any(h.host == "" for h in self.hosts)


@dataclass(frozen=True)
class SpfLookup:
    term: str  # e.g. "include:_spf.google.com" or "redirect=_spf.example.com"
    source: str  # the domain whose SPF record contains it
    depth: int  # 0 for the checked domain's own record


@dataclass(frozen=True)
class SpfCheck(EmailSection):
    lookup_status: LookupStatus
    records: tuple[str, ...]  # every SPF (v=spf1) record at the domain; should be one
    lookups: tuple[SpfLookup, ...]  # every term that costs a DNS lookup, includes expanded
    complete: bool  # False when an include couldn't be fetched, so lookups is a lower bound
    findings: tuple[Finding, ...]

    @property
    def lookup_count(self) -> int:
        return len(self.lookups)

    @property
    def no_mail(self) -> bool:
        """The record is exactly v=spf1 -all: the domain says it sends no mail at all."""
        return len(self.records) == 1 and self.records[0].lower().split() == ["v=spf1", "-all"]


@dataclass(frozen=True)
class DmarcCheck(EmailSection):
    name: str  # _dmarc.<domain>
    lookup_status: LookupStatus
    records: tuple[str, ...]  # every v=DMARC1 record; should be one
    tags: tuple[tuple[str, str], ...]  # of the record, when there is exactly one
    findings: tuple[Finding, ...]

    @property
    def policy(self) -> str | None:
        return dict(self.tags).get("p")


@dataclass(frozen=True)
class DkimSelector:
    selector: str
    name: str  # <selector>._domainkey.<domain>
    lookup_status: LookupStatus
    record: str | None  # the DKIM key record, if one was found
    custom: bool = False  # given with --selector rather than one of DKIM_SELECTORS
    key_type: str | None = None  # "rsa" or "ed25519"
    key_bits: int | None = None  # RSA key size
    revoked: bool = False  # empty p=: the key has been withdrawn
    malformed: bool = False  # p= isn't a usable key

    @property
    def found(self) -> bool:
        return self.record is not None


@dataclass(frozen=True)
class DkimCheck(EmailSection):
    selectors: tuple[DkimSelector, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class EmailReport:
    domain: str
    # OK when the checks ran. NXDOMAIN when the domain doesn't exist, or the fault (e.g.
    # TIMEOUT) when every query failed the same way; the checks are then None.
    domain_status: LookupStatus
    nameserver: str
    nameserver_source: str
    elapsed_ms: float
    mx: MxCheck | None = None
    spf: SpfCheck | None = None
    dmarc: DmarcCheck | None = None
    dkim: DkimCheck | None = None
    resolver_choice: ResolverChoice | None = None  # None with an explicit nameserver

    @property
    def checks(self) -> tuple[tuple[str, EmailSection], ...]:
        sections: tuple[tuple[str, EmailSection | None], ...] = (
            ("MX", self.mx),
            ("SPF", self.spf),
            ("DMARC", self.dmarc),
            ("DKIM", self.dkim),
        )
        return tuple((label, s) for label, s in sections if s is not None)

    @property
    def status(self) -> CheckStatus:
        if self.domain_status is not LookupStatus.OK:
            return CheckStatus.FAIL
        return worst(section.status for _, section in self.checks)

    @property
    def failed(self) -> bool:
        return self.status is CheckStatus.FAIL


Query = Callable[[str, str], LookupResult]


def email_check(
    domain: str,
    selectors: Sequence[str] = (),
    nameserver: str | None = None,
    timeout: float = 5.0,
    refresh: bool = False,
) -> EmailReport:
    """Check `domain`'s MX, SPF, DMARC and DKIM records.

    DKIM is looked up at each of DKIM_SELECTORS plus any extra `selectors`. Nameserver
    selection works as in `lookup()`. An invalid domain or selector raises ValueError.
    """
    domain = normalize_domain(domain)
    custom = [_validate_selector(s) for s in selectors]
    all_selectors = list(dict.fromkeys([*DKIM_SELECTORS, *custom]))

    start = time.perf_counter()
    selection = _choose_nameservers(nameserver, refresh)

    def query(name: str, rtype: str) -> LookupResult:
        return _query_one(name, rtype, selection.nameservers, timeout)

    def report(
        status: LookupStatus,
        mx: MxCheck | None = None,
        spf: SpfCheck | None = None,
        dmarc: DmarcCheck | None = None,
        dkim: DkimCheck | None = None,
    ) -> EmailReport:
        return EmailReport(
            domain=domain,
            domain_status=status,
            nameserver=selection.nameservers[0],
            nameserver_source=selection.source,
            elapsed_ms=(time.perf_counter() - start) * 1000,
            mx=mx,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            resolver_choice=selection.choice,
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        mx_future = pool.submit(query, domain, "MX")
        txt_future = pool.submit(query, domain, "TXT")
        dmarc_future = pool.submit(query, f"_dmarc.{domain}", "TXT")
        dkim_futures = [
            pool.submit(query, f"{s}._domainkey.{domain}", "TXT") for s in all_selectors
        ]
        mx_result = mx_future.result()
        txt_result = txt_future.result()
        dmarc_result = dmarc_future.result()
        dkim_results = [f.result() for f in dkim_futures]

        status = _domain_status([mx_result, txt_result, dmarc_result, *dkim_results])
        if status is not LookupStatus.OK:
            return report(status)

        # Resolve the mail servers while following the SPF includes.
        hosts = _mx_hosts(mx_result)
        address_futures = {
            host: (pool.submit(query, host, "A"), pool.submit(query, host, "AAAA"))
            for _, host in hosts
            if host and not _is_ip(host)
        }
        spf = _check_spf(domain, txt_result, pool, query, timeout, hosts)
        addresses = {
            host: (a.result(), aaaa.result()) for host, (a, aaaa) in address_futures.items()
        }

    mx = _check_mx(domain, mx_result, hosts, addresses, timeout)
    dmarc = _check_dmarc(domain, dmarc_result, timeout)
    dkim = _check_dkim(
        domain, all_selectors, set(custom), dkim_results, timeout, sends_mail=not spf.no_mail
    )
    return report(LookupStatus.OK, mx=mx, spf=spf, dmarc=dmarc, dkim=dkim)


def normalize_domain(text: str) -> str:
    """Lower-case `text` and convert it to its ASCII (IDNA) form, or raise ValueError."""
    name = text.strip().rstrip(".").lower()
    if "@" in name:
        raise ValueError(
            f"'{text}' looks like an email address. Pass just the domain, such as "
            f"{name.rsplit('@', 1)[-1] or 'example.com'}."
        )
    if "/" in name or ":" in name:
        raise ValueError(
            f"'{text}' is not a domain name. Pass just the domain, such as example.com, "
            "without http:// or a path."
        )
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        name = ""
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253 or not all(_LABEL.fullmatch(lb) for lb in labels):
        raise ValueError(f"'{text}' is not a valid domain name. Use a name like example.com.")
    return name


def _validate_selector(text: str) -> str:
    selector = text.strip().rstrip(".")
    if "._domainkey" in selector.lower():
        raise ValueError(
            f"Pass just the DKIM selector, not the full name: '{selector.split('.')[0]}' "
            f"rather than '{text}'."
        )
    if not _SELECTOR.fullmatch(selector):
        raise ValueError(
            f"'{text}' is not a valid DKIM selector. It's the s= value in an email's "
            "DKIM-Signature header, such as google or selector1."
        )
    return selector


def _domain_status(results: Sequence[LookupResult]) -> LookupStatus:
    """NXDOMAIN if the domain doesn't exist; a fault if every query failed that way."""
    if results[0].status is LookupStatus.NXDOMAIN:
        return LookupStatus.NXDOMAIN
    statuses = {r.status for r in results}
    if len(statuses) == 1 and (status := statuses.pop()) in _FAULTS:
        return status
    return LookupStatus.OK


def _couldnt_check(what: str, result: LookupResult, name: str, timeout: float) -> Finding:
    diagnosis = explain(result.status, name, result.rtype, timeout)
    assert diagnosis is not None
    return Finding(
        CheckStatus.FAIL,
        f"Couldn't check {what}: {diagnosis.title[0].lower()}{diagnosis.title[1:]}",
        diagnosis.explanation,
        diagnosis.suggestion,
    )


def _sentence(text: str) -> str:
    """`text` with its first letter capitalised (unlike str.capitalize, the rest is kept)."""
    return text[:1].upper() + text[1:]


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _txt_records(result: LookupResult) -> list[str]:
    return [txt_text(r.value) for r in result.records]


# --- MX ------------------------------------------------------------------------------------


def _mx_hosts(result: LookupResult) -> list[tuple[int, str]]:
    """(preference, host) pairs, lowest preference first. A null MX has host ""."""
    hosts = []
    for record in result.records:
        preference, _, host = record.value.partition(" ")
        hosts.append((int(preference), host.strip().rstrip(".").lower()))
    return sorted(hosts)


def _host_status(a: LookupResult, aaaa: LookupResult) -> LookupStatus:
    if a.status is LookupStatus.OK or aaaa.status is LookupStatus.OK:
        return LookupStatus.OK
    for status in (a.status, aaaa.status):
        if status in _FAULTS:
            return status
    return a.status  # NXDOMAIN or NO_ANSWER


_HOST_PROBLEMS = {
    LookupStatus.NXDOMAIN: "the name doesn't exist",
    LookupStatus.NO_ANSWER: "no A or AAAA record",
}


def _check_mx(
    domain: str,
    result: LookupResult,
    hosts: list[tuple[int, str]],
    addresses: dict[str, tuple[LookupResult, LookupResult]],
    timeout: float,
) -> MxCheck:
    mx_hosts = []
    for preference, host in hosts:
        if host in addresses:
            a, aaaa = addresses[host]
            values = tuple(r.value for r in (*a.records, *aaaa.records))
            mx_hosts.append(MxHost(preference, host, values, _host_status(a, aaaa)))
        else:  # null MX or an IP address: nothing to resolve
            status = LookupStatus.OK if _is_ip(host) else LookupStatus.NO_ANSWER
            mx_hosts.append(MxHost(preference, host, (host,) if _is_ip(host) else (), status))

    def check(findings: list[Finding]) -> MxCheck:
        return MxCheck(result.status, tuple(mx_hosts), tuple(findings))

    if result.status in _FAULTS:
        return check([_couldnt_check("MX", result, domain, timeout)])
    if not mx_hosts:
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    "No MX records",
                    f"{domain} has no MX records, so other mail servers don't know where to "
                    "deliver email for it. Some will try the domain's own address instead, "
                    "which rarely works.",
                    "If this domain should receive email, add the MX records your email "
                    "provider gives you. If it never receives email, publish a null MX (one MX "
                    'record with priority 0 and host ".") so senders give up straight away.',
                )
            ]
        )

    real = [h for h in mx_hosts if h.host]
    if len(real) < len(mx_hosts):
        if not real:
            return check(
                [
                    Finding(
                        CheckStatus.PASS,
                        "Doesn't accept email (null MX)",
                        f"{domain} publishes a null MX record, which tells senders it never "
                        "receives email.",
                    )
                ]
            )
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    "Null MX mixed with real mail servers",
                    f"{domain} has a null MX record (meaning it accepts no email) alongside "
                    "real MX records. A null MX must be the only MX record, so senders may "
                    "treat the domain as not accepting mail.",
                    'Remove the null MX record (priority 0, host ".") if the domain receives '
                    "email, or remove the other MX records if it doesn't.",
                )
            ]
        )

    findings = []
    ip_hosts = [h for h in real if _is_ip(h.host)]
    if ip_hosts:
        listed = ", ".join(h.host for h in ip_hosts)
        findings.append(
            Finding(
                CheckStatus.FAIL,
                "MX record points at an IP address",
                f"MX records must name a mail server, not an IP address ({listed}). Many "
                "senders won't deliver to it.",
                f"Give the server a name with an A record (for example mail.{domain}) and "
                "point the MX record at that name.",
            )
        )

    named = [h for h in real if not _is_ip(h.host)]
    unresolved = [h for h in named if h.lookup_status is not LookupStatus.OK]
    if unresolved:
        reasons = "; ".join(
            f"{h.host}: "
            + _HOST_PROBLEMS.get(h.lookup_status, f"lookup failed ({h.lookup_status})")
            for h in unresolved
        )
        working = len(real) - len(unresolved)
        faults_only = all(h.lookup_status in _FAULTS for h in unresolved)
        fix = (
            "These lookups failed rather than coming back empty; run the check again, or try "
            "a different resolver."
            if faults_only
            else "Fix the mail server names in the MX records, give those servers A records, "
            "or remove the MX records that point at them."
        )
        if working:
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"{_plural(len(unresolved), 'mail server')} of {len(real)} "
                    f"{'has' if len(unresolved) == 1 else 'have'} no IP address",
                    f"{reasons}. Senders skip these and use the other mail servers, but it "
                    "usually means a typo or a server that has been removed.",
                    fix,
                )
            )
        else:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    "No mail server has an IP address",
                    f"{reasons}. Senders can't connect to any of {domain}'s mail servers, so "
                    "email to it bounces or is delayed.",
                    fix,
                )
            )

    if not findings:
        first = real[0].host
        backups = len(real) - 1
        detail = f"Mail for {domain} goes to {first}"
        detail += (
            f" first (lowest priority number); the other {_plural(backups, 'server')} "
            f"{'is a backup' if backups == 1 else 'are backups'}."
            if backups
            else "."
        )
        findings.append(
            Finding(
                CheckStatus.PASS,
                "1 mail server, with an IP address"
                if len(real) == 1
                else f"{len(real)} mail servers, all with IP addresses",
                detail,
            )
        )
    return check(findings)


# --- SPF -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class _SpfTerm:
    text: str
    name: str  # mechanism or modifier name, lower-case
    qualifier: str  # "+", "-", "~" or "?"; "" for a modifier
    value: str  # the domain or address after ":" or "=", without any CIDR length

    @property
    def modifier(self) -> bool:
        return self.qualifier == ""


@dataclass(frozen=True)
class _ParsedSpf:
    terms: tuple[_SpfTerm, ...]
    errors: tuple[str, ...]  # each makes the whole record invalid (permerror)
    unknown_modifiers: tuple[str, ...]

    def mechanisms(self, *names: str) -> list[_SpfTerm]:
        return [t for t in self.terms if not t.modifier and (not names or t.name in names)]

    def modifier(self, name: str) -> _SpfTerm | None:
        return next((t for t in self.terms if t.modifier and t.name == name), None)

    @property
    def all(self) -> _SpfTerm | None:
        return next(iter(self.mechanisms("all")), None)

    @property
    def redirect(self) -> str | None:
        """The redirect target, unless an `all` makes receivers ignore it."""
        term = self.modifier("redirect")
        return term.value if term is not None and self.all is None else None

    def lookup_terms(self) -> list[_SpfTerm]:
        terms = self.mechanisms(*_SPF_LOOKUP_MECHANISMS)
        redirect = self.modifier("redirect")
        if redirect is not None and self.all is None:
            terms.append(redirect)
        return terms


def _is_spf(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def _valid_domain_spec(spec: str) -> bool:
    """A target domain; macros (%{...}) can't be checked without a message, so allow them."""
    if "%" in spec:
        return " " not in spec
    labels = spec.rstrip(".").lower().split(".")
    return len(labels) >= 2 and all(_LABEL.fullmatch(lb) for lb in labels)


_DUAL_CIDR = re.compile(r"(?::([^/]+))?(?:/(\d+))?(?://(\d+))?")


def _parse_spf(record: str) -> _ParsedSpf:
    terms: list[_SpfTerm] = []
    errors: list[str] = []
    unknown: list[str] = []
    seen_modifiers: set[str] = set()

    for text in record.split()[1:]:
        modifier = re.fullmatch(r"([A-Za-z][A-Za-z0-9_.-]*)=(.*)", text)
        if modifier:
            name, value = modifier[1].lower(), modifier[2]
            if name in ("redirect", "exp"):
                if name in seen_modifiers:
                    errors.append(f"'{name}=' appears more than once")
                elif not _valid_domain_spec(value):
                    errors.append(f"'{text}' needs a domain after '='")
                seen_modifiers.add(name)
            else:
                unknown.append(text)
            terms.append(_SpfTerm(text, name, "", value))
            continue

        qualifier = text[0] if text[:1] in ("+", "-", "~", "?") else "+"
        body = text[1:] if text[:1] in ("+", "-", "~", "?") else text
        name, rest = re.fullmatch(r"([A-Za-z0-9]*)(.*)", body).groups()  # type: ignore[union-attr]
        name = name.lower()
        value = ""

        if name not in _SPF_MECHANISMS:
            hint = f" (did you mean {_SPF_TYPOS[name]}?)" if name in _SPF_TYPOS else ""
            errors.append(f"unknown term '{text}'{hint}")
            continue
        if name == "all":
            if rest:
                errors.append(f"'{text}': all takes no value")
        elif name in ("include", "exists"):
            value = rest[1:]
            if not rest.startswith(":") or not _valid_domain_spec(value):
                errors.append(f"'{text}' needs a domain, as in {name}:example.com")
        elif name in ("a", "mx", "ptr"):
            match = _DUAL_CIDR.fullmatch(rest)
            value = (match[1] or "") if match else ""
            if (
                not match
                or (value and not _valid_domain_spec(value))
                or (name == "ptr" and (match[2] or match[3]))
                or (match[2] and int(match[2]) > 32)
                or (match[3] and int(match[3]) > 128)
            ):
                errors.append(f"'{text}' isn't a valid {name} mechanism")
        else:  # ip4, ip6
            value = rest[1:]
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                network = None
            if not rest.startswith(":") or network is None or network.version != int(name[2]):
                errors.append(f"'{text}' isn't a valid IPv{name[2]} address or range")
        terms.append(_SpfTerm(text, name, qualifier, value))

    return _ParsedSpf(tuple(terms), tuple(errors), tuple(unknown))


@dataclass(frozen=True)
class _Fetched:
    """An include or redirect target's SPF record, or why there isn't a usable one."""

    kind: str  # "include" or "redirect": how it was first reached
    status: LookupStatus
    records: tuple[str, ...]

    @property
    def parsed(self) -> _ParsedSpf | None:
        return _parse_spf(self.records[0]) if len(self.records) == 1 else None


def _spf_targets(parsed: _ParsedSpf) -> dict[str, str]:
    """Include and redirect targets to fetch, mapped to "include" or "redirect".

    Targets with macros depend on the message being checked, so they can't be followed.
    """
    targets = [("include", t.value) for t in parsed.mechanisms("include")]
    if parsed.redirect:
        targets.append(("redirect", parsed.redirect))
    found: dict[str, str] = {}
    for kind, target in targets:
        if "%" not in target:
            found.setdefault(target.rstrip(".").lower(), kind)
    return found


def _fetch_spf_tree(
    parsed: _ParsedSpf, pool: ThreadPoolExecutor, query: Query
) -> dict[str, _Fetched]:
    """Fetch every include/redirect target's SPF record, one level at a time in parallel."""
    fetched: dict[str, _Fetched] = {}
    frontier = _spf_targets(parsed)
    for _ in range(_MAX_SPF_DEPTH):
        targets = list(frontier)[: _MAX_SPF_FETCHES - len(fetched)]
        if not targets:
            break
        for target, result in zip(
            targets, pool.map(lambda t: query(t, "TXT"), targets), strict=True
        ):
            records = tuple(t for t in _txt_records(result) if _is_spf(t))
            fetched[target] = _Fetched(frontier[target], result.status, records)
        frontier = {}
        for target in targets:
            child = fetched[target].parsed
            if child is not None:
                for name, kind in _spf_targets(child).items():
                    if name not in fetched:
                        frontier.setdefault(name, kind)
    return fetched


def _count_lookups(
    domain: str,
    parsed: _ParsedSpf,
    fetched: dict[str, _Fetched],
    depth: int = 0,
    path: tuple[str, ...] = (),
) -> list[SpfLookup]:
    """Every lookup-costing term, depth first, with includes expanded where they occur.

    A target included twice is counted twice, as receivers evaluate it twice. A loop is
    expanded only once.
    """
    path = (*path, domain)
    lookups = []
    for term in parsed.lookup_terms():
        lookups.append(SpfLookup(term.text, domain, depth))
        target = term.value.rstrip(".").lower()
        if term.name not in ("include", "redirect") or target in path or depth >= _MAX_SPF_DEPTH:
            continue
        child = fetched.get(target)
        if child is not None and child.parsed is not None:
            lookups += _count_lookups(target, child.parsed, fetched, depth + 1, path)
    return lookups


def _spf_example(hosts: list[tuple[int, str]]) -> str:
    for _, host in hosts:
        for suffix, include in _PROVIDER_SPF:
            if host.endswith(suffix):
                return f"v=spf1 include:{include} ~all"
    return "v=spf1 include:<your email provider's SPF domain> ~all"


def _check_spf(
    domain: str,
    result: LookupResult,
    pool: ThreadPoolExecutor,
    query: Query,
    timeout: float,
    mx_hosts: list[tuple[int, str]],
) -> SpfCheck:
    records = tuple(t for t in _txt_records(result) if _is_spf(t))

    def check(
        findings: list[Finding], lookups: Sequence[SpfLookup] = (), complete: bool = True
    ) -> SpfCheck:
        return SpfCheck(result.status, records, tuple(lookups), complete, tuple(findings))

    if result.status in _FAULTS:
        return check([_couldnt_check("SPF", result, domain, timeout)])
    if not records:
        null_mx = bool(mx_hosts) and all(host == "" for _, host in mx_hosts)
        fix = (
            f"{domain} accepts no email (null MX); if it never sends any either, publish a "
            "TXT record of v=spf1 -all so receivers reject anything claiming to be from it."
            if null_mx
            else f"Publish one TXT record at {domain} listing the servers that send its mail, "
            f"such as: {_spf_example(mx_hosts)}. Your email provider's setup guide gives the "
            "exact include."
        )
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    "No SPF record",
                    f"{domain} has no TXT record starting with v=spf1, so receivers can't tell "
                    "which servers may send its mail. Spoofed mail is more likely to be "
                    "delivered, and genuine mail more likely to land in spam.",
                    fix,
                )
            ]
        )
    if len(records) > 1:
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    f"{len(records)} SPF records (only one is allowed)",
                    "Receivers treat more than one v=spf1 record as an error (permerror), so "
                    "SPF fails for all of this domain's mail.",
                    "Merge them into a single TXT record: one v=spf1, every include, ip4 and "
                    "ip6 term from both, and one all at the end. Then delete the extra record.",
                )
            ]
        )

    parsed = _parse_spf(records[0])
    findings = _spf_syntax_findings(parsed)

    fetched = _fetch_spf_tree(parsed, pool, query)
    lookups = _count_lookups(domain, parsed, fetched)
    complete = True
    for target, child in fetched.items():
        kind = child.kind
        if child.status in _FAULTS:
            complete = False
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"Couldn't check {kind}:{target}",
                    f"Looking up {target}'s SPF record failed ({child.status}), so its DNS "
                    "lookups aren't counted and its record wasn't checked.",
                    "Run the check again, or try a different resolver.",
                )
            )
        elif not child.records:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"{kind}:{target} has no SPF record",
                    f"{target} "
                    + (
                        "doesn't exist"
                        if child.status is LookupStatus.NXDOMAIN
                        else "has no v=spf1 record"
                    )
                    + ", so receivers treat SPF as broken (permerror) whenever they reach "
                    "this term.",
                    f"Check the spelling of {target} against your provider's instructions, or "
                    "remove the term if you no longer use that service.",
                )
            )
        elif len(child.records) > 1:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"{kind}:{target} has {len(child.records)} SPF records",
                    f"{target} publishes more than one v=spf1 record, which receivers treat as "
                    "an error (permerror) whenever they reach this term.",
                    f"Ask whoever runs {target} to fix it, or remove the term.",
                )
            )
        elif child.parsed is not None and child.parsed.errors:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"{kind}:{target}'s SPF record is invalid",
                    f"{_sentence('; '.join(child.parsed.errors))}. Receivers treat SPF as broken "
                    "(permerror) whenever they reach this term.",
                    f"Ask whoever runs {target} to fix it, or remove the term.",
                )
            )

    count = len(lookups)
    counted = f"{count} of {SPF_LOOKUP_LIMIT} DNS lookups"
    if count > SPF_LOOKUP_LIMIT:
        findings.append(
            Finding(
                CheckStatus.FAIL,
                f"Too many DNS lookups ({count} of {SPF_LOOKUP_LIMIT})",
                f"Checking this SPF record takes {count} DNS lookups, counting everything its "
                f"includes pull in. Receivers stop at {SPF_LOOKUP_LIMIT} and treat SPF as "
                "broken (permerror), so SPF fails for all of this domain's mail.",
                "Remove includes for services you no longer use, replace a and mx with the "
                "ip4/ip6 addresses they stand for, or use your provider's flattened SPF if it "
                "offers one.",
            )
        )

    if not any(f.status is CheckStatus.FAIL for f in findings):
        all_term = parsed.all
        if all_term is not None and all_term.qualifier in ("-", "~"):
            meaning = f"Ends with {all_term.text}: {SPF_ALL_MEANINGS[all_term.qualifier]}."
        elif parsed.redirect:
            meaning = f"Uses {parsed.redirect}'s SPF policy (redirect)."
        else:
            meaning = ""  # a weak or missing all has its own warning
        if not complete:
            counted = f"at least {counted}"
        findings.insert(
            0,
            Finding(
                CheckStatus.PASS,
                "SPF record is valid",
                f"{_sentence(counted)}. {meaning}".strip(),
            ),
        )
    return check(findings, lookups, complete)


def _spf_syntax_findings(parsed: _ParsedSpf) -> list[Finding]:
    findings = []
    if parsed.errors:
        findings.append(
            Finding(
                CheckStatus.FAIL,
                "SPF record has syntax errors",
                f"{_sentence('; '.join(parsed.errors))}. Receivers treat the whole record as "
                "invalid (permerror), so SPF fails for all of this domain's mail.",
                "Correct the record. Valid terms are include, a, mx, ip4, ip6, exists, ptr, "
                "all, redirect= and exp=.",
            )
        )
    if parsed.unknown_modifiers:
        findings.append(
            Finding(
                CheckStatus.WARN,
                "Unknown SPF modifier",
                f"Receivers ignore {', '.join(parsed.unknown_modifiers)}, so it has no effect.",
                "Remove it, or check its spelling (the known modifiers are redirect= and exp=).",
            )
        )

    all_term = parsed.all
    if all_term is None and parsed.modifier("redirect") is None:
        findings.append(
            Finding(
                CheckStatus.WARN,
                "SPF record doesn't end with all",
                "Without a final all, mail from servers the record doesn't list gets a neutral "
                "result, as if there were no SPF record.",
                "Add ~all (soft fail) or -all (hard fail) at the end of the record.",
            )
        )
    elif all_term is not None:
        if all_term.qualifier == "+":
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"SPF allows anyone to send ({all_term.text})",
                    f"{all_term.text} means {SPF_ALL_MEANINGS['+']}, so SPF gives no protection "
                    "against spoofing at all.",
                    "Change it to ~all (soft fail) or -all (hard fail).",
                )
            )
        elif all_term.qualifier == "?":
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"SPF ends with a neutral {all_term.text}",
                    f"With {all_term.text}, {SPF_ALL_MEANINGS['?']}.",
                    "Change it to ~all (soft fail) or -all (hard fail) once the record lists "
                    "every server that sends your mail.",
                )
            )
        after = parsed.terms[parsed.terms.index(all_term) + 1 :]
        ignored = [t.text for t in after if not (t.modifier and t.name == "exp")]
        if ignored:
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    "SPF terms after all are ignored",
                    f"Receivers stop at {all_term.text}, so {', '.join(ignored)} "
                    f"{'has' if len(ignored) == 1 else 'have'} no effect.",
                    f"Move {'it' if len(ignored) == 1 else 'them'} before {all_term.text}, "
                    "which should be the last term.",
                )
            )
    if parsed.mechanisms("ptr"):
        findings.append(
            Finding(
                CheckStatus.WARN,
                "SPF uses the deprecated ptr mechanism",
                "ptr is slow and unreliable, and some receivers ignore it, so servers it "
                "is meant to allow may fail SPF.",
                "Replace it with ip4/ip6 ranges or an include for the servers it covers.",
            )
        )
    return findings


# --- DMARC ---------------------------------------------------------------------------------


def _is_dmarc(text: str) -> bool:
    return re.match(r"\s*v\s*=\s*DMARC1\s*(;|$)", text, re.IGNORECASE) is not None


def _parse_tags(record: str) -> tuple[list[tuple[str, str]], list[str]]:
    """`tag=value; ...` pairs (tags lower-case), and the parts that aren't tag=value."""
    tags, bad = [], []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        tag, sep, value = part.partition("=")
        if not sep or not tag.strip():
            bad.append(part)
        else:
            tags.append((tag.strip().lower(), value.strip()))
    return tags, bad


def _check_dmarc(domain: str, result: LookupResult, timeout: float) -> DmarcCheck:
    name = f"_dmarc.{domain}"
    records = tuple(t for t in _txt_records(result) if _is_dmarc(t))
    tags: list[tuple[str, str]] = []

    def check(findings: list[Finding]) -> DmarcCheck:
        return DmarcCheck(name, result.status, records, tuple(tags), tuple(findings))

    if result.status in _FAULTS:
        return check([_couldnt_check("DMARC", result, name, timeout)])
    if not records:
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    "No DMARC record",
                    f"There's no v=DMARC1 TXT record at {name}, so receivers have no "
                    f"instructions for mail that fails SPF and DKIM, and {domain} gets no "
                    "reports about who sends mail using its name. Gmail and Yahoo require "
                    "DMARC from bulk senders.",
                    f"Publish a TXT record at {name}, starting in monitoring mode: "
                    f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}. Once the reports "
                    "show your genuine mail passing, change p=none to quarantine, then reject.",
                )
            ]
        )
    if len(records) > 1:
        return check(
            [
                Finding(
                    CheckStatus.FAIL,
                    f"{len(records)} DMARC records (only one is allowed)",
                    f"{name} has more than one v=DMARC1 record, so receivers ignore DMARC for "
                    f"{domain} entirely.",
                    "Merge them into a single record and delete the others.",
                )
            ]
        )

    tags, bad = _parse_tags(records[0])
    values = dict(tags)
    findings = []
    errors = [f"'{part}' isn't tag=value" for part in bad]
    if tags[0][0] != "v":
        errors.append("v=DMARC1 must come first")
    policy = values.get("p", "").lower()
    if "p" not in values:
        errors.append("there's no policy (p=)")
    elif policy not in DMARC_POLICIES:
        errors.append(f"p={values['p']} isn't a policy (use none, quarantine or reject)")
    errors.extend(
        f"{tag}={values[tag]} isn't a policy"
        for tag in ("sp", "np")
        if tag in values and values[tag].lower() not in DMARC_POLICIES
    )
    pct = values.get("pct")
    if pct is not None and not (pct.isdigit() and 0 <= int(pct) <= 100):
        errors.append(f"pct={pct} isn't a number from 0 to 100")
    if errors:
        findings.append(
            Finding(
                CheckStatus.FAIL,
                "DMARC record is invalid",
                f"{_sentence('; '.join(errors))}. Receivers may ignore the record entirely.",
                "Correct the record. A minimal valid one is: v=DMARC1; p=none; "
                f"rua=mailto:dmarc-reports@{domain}",
            )
        )
        return check(findings)

    explanation = f"p={policy}: {DMARC_POLICIES[policy]}."
    subdomains = values.get("sp", "").lower()
    if subdomains and subdomains != policy:
        explanation += f" Subdomains (sp={subdomains}): {DMARC_POLICIES[subdomains]}."
    if policy == "none":
        findings.append(
            Finding(
                CheckStatus.WARN,
                "DMARC policy is monitoring only (p=none)",
                explanation + f" Mail spoofing {domain} isn't blocked.",
                "Watch the DMARC reports until all your genuine mail passes SPF or DKIM, then "
                "change p=none to p=quarantine, and later to p=reject.",
            )
        )
    else:
        findings.append(Finding(CheckStatus.PASS, f"DMARC policy: {policy}", explanation))
        if pct is not None and int(pct) < 100:
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"DMARC policy applies to only {pct}% of mail",
                    f"pct={pct}: receivers apply p={policy} to {pct}% of the mail that fails "
                    "DMARC and treat the rest as p=none.",
                    "Raise pct to 100 (or remove it) once you're confident genuine mail passes.",
                )
            )

    if "rua" not in values:
        findings.append(
            Finding(
                CheckStatus.WARN,
                "No DMARC report address (rua)",
                f"Without rua=, receivers don't send aggregate reports, so you can't see who "
                f"sends mail as {domain} or whether your own mail passes.",
                f"Add rua=mailto:<address>, such as a dmarc-reports@{domain} mailbox or a DMARC "
                "reporting service.",
            )
        )
    unknown = [tag for tag, _ in tags if tag not in _DMARC_TAGS]
    if unknown:
        findings.append(
            Finding(
                CheckStatus.WARN,
                "Unknown DMARC tags",
                f"Receivers ignore {', '.join(unknown)}, so "
                f"{'it has' if len(unknown) == 1 else 'they have'} no effect.",
                "Remove or correct them. Common tags are p, sp, rua, ruf, pct, adkim and aspf.",
            )
        )
    return check(findings)


# --- DKIM ----------------------------------------------------------------------------------


def _der_header(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, start, end) of the DER element at `pos`."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[pos : pos + size])
        pos += size
    if pos + length > len(data):
        raise ValueError("truncated")
    return tag, pos, pos + length


def _rsa_key_bits(key: bytes) -> int | None:
    """The modulus size of a DER RSA public key (SubjectPublicKeyInfo or bare RSAPublicKey)."""
    try:
        tag, start, _ = _der_header(key, 0)
        if tag != 0x30:
            return None
        tag, start, end = _der_header(key, start)
        if tag == 0x30:  # algorithm identifier: the key is in the BIT STRING after it
            tag, start, end = _der_header(key, end)
            if tag != 0x03:
                return None
            tag, start, _ = _der_header(key, start + 1)  # skip the unused-bits byte
            if tag != 0x30:
                return None
            tag, start, end = _der_header(key, start)
        if tag != 0x02:
            return None
        return int.from_bytes(key[start:end]).bit_length()
    except (IndexError, ValueError):
        return None


def _is_dkim(text: str) -> bool:
    tags, _ = _parse_tags(text)
    values = dict(tags)
    return "p" in values and values.get("v", "DKIM1") == "DKIM1"


def _dkim_selector(selector: str, name: str, result: LookupResult, custom: bool) -> DkimSelector:
    record = next((t for t in _txt_records(result) if _is_dkim(t)), None)
    if record is None:
        return DkimSelector(selector, name, result.status, None, custom)

    values = dict(_parse_tags(record)[0])
    key_type = values.get("k", "rsa").lower()
    key_text = re.sub(r"\s+", "", values["p"])
    if not key_text:
        return DkimSelector(selector, name, result.status, record, custom, key_type, revoked=True)
    try:
        key = base64.b64decode(key_text, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    bits = _rsa_key_bits(key) if key_type == "rsa" else None
    # An RSA key must parse; an Ed25519 key is exactly 32 bytes.
    malformed = bits is None if key_type == "rsa" else key_type == "ed25519" and len(key) != 32
    return DkimSelector(
        selector,
        name,
        result.status,
        record,
        custom,
        key_type=key_type,
        key_bits=bits,
        malformed=malformed,
    )


def describe_key(selector: DkimSelector) -> str:
    """The key's type and size for display, e.g. "RSA 2048-bit" or "Ed25519"."""
    if selector.key_bits is not None:
        return f"RSA {selector.key_bits}-bit"
    if selector.key_type == "ed25519":
        return "Ed25519"
    return (selector.key_type or "rsa").upper()


def _check_dkim(
    domain: str,
    selectors: list[str],
    custom: set[str],
    results: list[LookupResult],
    timeout: float,
    sends_mail: bool = True,
) -> DkimCheck:
    checked = tuple(
        _dkim_selector(s, f"{s}._domainkey.{domain}", r, s in custom)
        for s, r in zip(selectors, results, strict=True)
    )
    findings = []
    usable = [s for s in checked if s.found and not s.revoked and not s.malformed]

    for s, result in zip(checked, results, strict=True):
        if s.malformed:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"DKIM key at {s.selector} is malformed",
                    f"The p= value at {s.name} isn't a valid {describe_key(s)} public key, so "
                    "receivers can't verify mail signed with this selector.",
                    "Copy the DKIM record again from your email provider, making sure the "
                    "whole key was pasted in (long keys are often cut off).",
                )
            )
        elif s.key_bits is not None and s.key_bits < 1024:
            findings.append(
                Finding(
                    CheckStatus.FAIL,
                    f"DKIM key at {s.selector} is too short ({s.key_bits}-bit)",
                    "Receivers such as Gmail treat signatures from keys under 1024 bits as "
                    "invalid, and short keys can be cracked.",
                    "Generate a new 2048-bit key in your email provider's settings and publish it.",
                )
            )
        elif s.key_bits is not None and s.key_bits < 2048:
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"DKIM key at {s.selector} is {s.key_bits}-bit",
                    f"{s.key_bits}-bit keys still work, but 2048 bits is the recommended minimum.",
                    "Generate a 2048-bit key in your email provider's settings, publish it "
                    "under a new selector, and switch signing to it.",
                )
            )
        if s.custom and not s.found:
            if s.lookup_status in _FAULTS:
                findings.append(
                    _couldnt_check(f"DKIM selector {s.selector}", result, s.name, timeout)
                )
            else:
                findings.append(
                    Finding(
                        CheckStatus.FAIL,
                        f"No DKIM key at selector {s.selector}",
                        f"There's no DKIM key record at {s.name}, so receivers can't verify "
                        f"mail signed with selector {s.selector}.",
                        "Check the selector (the s= value in an email's DKIM-Signature header), "
                        "and publish the DKIM record your email provider gives you.",
                    )
                )

    if usable:
        names = ", ".join(f"{s.selector} ({describe_key(s)})" for s in usable)
        findings.insert(
            0,
            Finding(
                CheckStatus.PASS,
                f"DKIM {'key' if len(usable) == 1 else 'keys'} found",
                f"Selector {names}. Receivers can use "
                f"{'this key' if len(usable) == 1 else 'these keys'} to verify that mail "
                f"signed by {domain} hasn't been forged or altered.",
            ),
        )
    else:
        revoked = [s.selector for s in checked if s.revoked]
        # A custom selector's failure was reported above.
        faults = [
            (s, r)
            for s, r in zip(checked, results, strict=True)
            if r.status in _FAULTS and not s.custom
        ]
        if faults and not any(s.found for s in checked):
            s, result = faults[0]
            findings.append(_couldnt_check("DKIM", result, s.name, timeout))
        elif not sends_mail and not any(s.malformed for s in checked):
            note = " The empty (revoked) keys published for it say the same." if revoked else ""
            findings.append(
                Finding(
                    CheckStatus.PASS,
                    "No DKIM key needed",
                    f"{domain}'s SPF record (v=spf1 -all) says it sends no mail, so there's "
                    f"nothing to sign.{note}",
                )
            )
        elif revoked and not any(f.status is CheckStatus.FAIL for f in findings):
            one = len(revoked) == 1
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    f"DKIM {'key' if one else 'keys'} revoked",
                    f"The {'key' if one else 'keys'} at {', '.join(revoked)} "
                    f"{'has' if one else 'have'} an empty p=, meaning "
                    f"{'it has' if one else 'they have'} been withdrawn. Mail signed with "
                    f"{'it' if one else 'them'} fails DKIM.",
                    "If mail is still signed with these selectors, publish current keys for "
                    "them; otherwise check which selector your provider signs with now.",
                )
            )
        elif not any(s.found for s in checked) and not custom:
            findings.append(
                Finding(
                    CheckStatus.WARN,
                    "No DKIM key at the common selectors",
                    f"None of the selectors tried ({', '.join(selectors)}) has a DKIM key. "
                    f"{domain} may still use DKIM under another selector: DNS has no way to "
                    "list them.",
                    "Open an email sent from this domain, find the s= value in its "
                    "DKIM-Signature header, and check that selector with --selector. If DKIM "
                    "isn't set up, turn it on in your email provider's settings and publish "
                    "the record it gives you.",
                )
            )
    return DkimCheck(checked, tuple(findings))
