"""Is a domain signed with DNSSEC, and does its chain of trust validate from the root down?

The records are fetched through a resolver (with the DO bit for signatures and CD so a
validating resolver hands over broken data instead of SERVFAIL), then checked here:

- the root's keys against the built-in root trust anchors (IANA's KSK-2017 and KSK-2024);
- for each zone below: the parent's signed DS record, which must match one of the zone's
  DNSKEYs, which must sign the zone's key set;
- finally the zone's SOA and the name's A records, signed with the zone's keys.

Signatures are only valid between two dates, so a wrong system clock breaks validation;
the root zone's SOA serial (YYYYMMDDnn) shows roughly what today's date is.
"""

import ipaddress
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeVar

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS

from dnskit.core.diagnosis import Diagnosis
from dnskit.core.lookup import _choose_nameservers
from dnskit.core.nameservers import ResolverChoice
from dnskit.core.outside import DnsBlocking, blocked_diagnosis, check_blocking
from dnskit.core.reach import parse_target

_R = TypeVar("_R", bound=dns.rdata.Rdata)

# The root zone's trust anchors (https://data.iana.org/root-anchors/root-anchors.xml).
ROOT_TRUST_ANCHORS: tuple[str, ...] = (
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",  # KSK-2017
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",  # KSK-2024
)

# The root zone is re-published twice a day and its SOA cached for up to a day, so its
# serial's date trails the real date by up to about two days.
# Public resolvers that pass DNSSEC signatures along, used when this computer's DNS
# server strips them.
DNSSEC_FALLBACKS: tuple[str, ...] = ("8.8.8.8", "1.1.1.1")
CLOCK_BEHIND_DAYS = 1.5  # local clock this far before the root zone's date: wrong
CLOCK_AHEAD_DAYS = 3.0  # local clock this far after it: wrong

_ROOT = dns.name.root
_SEP_FLAG = 0x0001  # DNSKEY flag marking a key-signing key


class ZoneStatus(StrEnum):
    SECURE = "secure"  # this link in the chain validates
    UNSIGNED = "unsigned"  # no DS at the parent: DNSSEC isn't on from here down
    BOGUS = "bogus"  # signed, but something doesn't check out
    UNKNOWN = "unknown"  # the data couldn't be fetched


class DnssecStatus(StrEnum):
    SECURE = "secure"  # the whole chain validates
    INSECURE = "insecure"  # DNSSEC isn't enabled for the domain (or a zone above it)
    BOGUS = "bogus"  # DNSSEC is enabled but broken: validating resolvers will fail it
    UNKNOWN = "unknown"  # couldn't be checked


class BogusKind(StrEnum):
    NO_DNSKEY = "no_dnskey"  # DS at the parent, but the zone has no keys
    DS_MISMATCH = "ds_mismatch"  # no key matches the parent's DS
    BAD_SIGNATURE = "bad_signature"  # a signature doesn't verify
    EXPIRED = "expired"  # a signature is outside its validity dates
    MISSING_SIGNATURE = "missing_signature"  # records that should be signed aren't


class ClockState(StrEnum):
    OK = "ok"
    WRONG = "wrong"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DsInfo:
    key_tag: int
    algorithm: str  # e.g. "ECDSAP256SHA256"
    digest_type: int  # 2 = SHA-256


@dataclass(frozen=True)
class KeyInfo:
    key_tag: int
    algorithm: str
    ksk: bool  # key-signing key (SEP flag); otherwise a zone-signing key


@dataclass(frozen=True)
class ZoneCheck:
    zone: str  # with the trailing dot; "." is the root
    status: ZoneStatus
    ds: tuple[DsInfo, ...] = ()  # the parent's DS records (the trust anchors for the root)
    keys: tuple[KeyInfo, ...] = ()  # the zone's DNSKEYs
    summary: str = ""
    kind: BogusKind | None = None  # BOGUS: what's wrong


@dataclass(frozen=True)
class RecordCheck:
    name: str
    rtype: str
    status: ZoneStatus
    summary: str
    kind: BogusKind | None = None


@dataclass(frozen=True)
class ClockCheck:
    state: ClockState
    local: datetime  # this computer's clock, UTC
    reference: datetime | None  # the root zone's date (from its SOA serial)
    summary: str


@dataclass(frozen=True)
class DnssecReport:
    name: str  # without the trailing dot
    zones: tuple[ZoneCheck, ...]  # root first
    records: tuple[RecordCheck, ...]  # the zone's SOA, the name's A records
    clock: ClockCheck
    nameserver: str
    nameserver_source: str
    elapsed_ms: float
    resolver_choice: ResolverChoice | None = None
    name_missing: bool = False  # the name itself doesn't exist (NXDOMAIN)
    error: str = ""  # why it couldn't be checked at all
    signatures_stripped: bool = False  # the resolver answered, but without DNSSEC signatures
    # This computer's DNS server, when it strips signatures and DNSSEC_FALLBACKS were tried:
    # `nameserver` is then the fallback that worked, or still this server if none did.
    stripped_by: str | None = None
    blocking: DnsBlocking | None = None  # set when an outside --server didn't answer

    @property
    def status(self) -> DnssecStatus:
        statuses = [z.status for z in self.zones] + [r.status for r in self.records]
        if self.error or not self.zones:
            return DnssecStatus.UNKNOWN
        if ZoneStatus.BOGUS in statuses:
            return DnssecStatus.BOGUS
        if ZoneStatus.UNKNOWN in statuses:
            return DnssecStatus.UNKNOWN
        if ZoneStatus.UNSIGNED in statuses:
            return DnssecStatus.INSECURE
        return DnssecStatus.SECURE

    @property
    def zone(self) -> str:
        """The deepest zone checked: the domain's own zone, or where the chain stopped."""
        return self.zones[-1].zone if self.zones else "."

    @property
    def problem(self) -> ZoneCheck | RecordCheck | None:
        """The first link that isn't secure."""
        checks: list[ZoneCheck | RecordCheck] = [*self.zones, *self.records]
        return next((c for c in checks if c.status is not ZoneStatus.SECURE), None)


def dnssec_check(
    target: str, nameserver: str | None = None, timeout: float = 5.0, refresh: bool = False
) -> DnssecReport:
    """Check `target`'s DNSSEC chain of trust. An invalid name raises ValueError.

    Records come from `nameserver`, or the chosen system nameserver as in `lookup()`. When
    that system nameserver strips DNSSEC signatures (some routers and filters do), the check
    is redone through the first of DNSSEC_FALLBACKS that works, and `stripped_by` names it.
    An explicit `nameserver` is never replaced.
    """
    name = parse_target(target)
    report = _check_through(name, nameserver, timeout, refresh)
    if nameserver is not None or not report.signatures_stripped:
        return report
    with ThreadPoolExecutor(max_workers=len(DNSSEC_FALLBACKS)) as pool:
        retries = list(
            pool.map(
                lambda ns: _check_through(name, ns, timeout, False, diagnose=False),
                DNSSEC_FALLBACKS,
            )
        )
    stripped_by = report.nameserver
    usable = next((r for r in retries if not r.error), None)
    if usable is None:
        return replace(report, stripped_by=stripped_by)
    return replace(
        usable,
        stripped_by=stripped_by,
        nameserver_source=f"this computer's DNS server {stripped_by} strips DNSSEC signatures",
        resolver_choice=report.resolver_choice,
        elapsed_ms=report.elapsed_ms + max(r.elapsed_ms for r in retries),
    )


def _check_through(
    name: str, nameserver: str | None, timeout: float, refresh: bool, diagnose: bool = True
) -> DnssecReport:
    """The check through one nameserver (or the chosen system one), with no fallback.

    Without `diagnose`, no reply doesn't run `check_blocking` (for fallback attempts).
    """
    qname = dns.name.from_text(name)
    start = time.perf_counter()
    selection = _choose_nameservers(nameserver, refresh)
    servers = selection.nameservers

    def report(**fields: object) -> DnssecReport:
        base: dict[str, object] = {
            "name": name,
            "zones": (),
            "records": (),
            "nameserver": servers[0],
            "nameserver_source": selection.source,
            "elapsed_ms": (time.perf_counter() - start) * 1000,
            "resolver_choice": selection.choice,
        }
        return DnssecReport(**(base | fields))  # type: ignore[arg-type]

    suffixes = [qname.split(depth)[1] for depth in range(2, len(qname) + 1)]
    queries = [(_ROOT, "DNSKEY"), (_ROOT, "SOA")]
    queries += [(s, rtype) for s in suffixes for rtype in ("NS", "DS", "DNSKEY")]
    queries += [(qname, "A")]
    with ThreadPoolExecutor(max_workers=min(len(queries), 16)) as pool:
        fetched = dict(
            zip(
                queries,
                pool.map(lambda q: _fetch(q[0], q[1], servers, timeout), queries),
                strict=True,
            )
        )

    root_keys, root_soa = fetched[(_ROOT, "DNSKEY")], fetched[(_ROOT, "SOA")]
    clock = check_clock(root_soa, root_keys)
    if root_keys.rcode is None:
        return report(
            clock=clock,
            error=f"no response from {servers[0]} ({root_keys.error})",
            blocking=_blocking_for(nameserver) if diagnose else None,
        )
    if root_keys.rrset is None or root_keys.rrsig is None:
        return report(
            clock=clock,
            error=f"{servers[0]} doesn't return DNSSEC signatures, so nothing can be "
            "checked through it (some routers and DNS filters strip them)",
            signatures_stripped=True,
        )

    now = time.time()
    zones = [_check_root(root_keys, now)]
    parent_keys = root_keys.rrset
    name_missing = False
    for suffix in suffixes:
        if zones[-1].status is not ZoneStatus.SECURE:
            break
        ns, ds, keys = (fetched[(suffix, t)] for t in ("NS", "DS", "DNSKEY"))
        if ns.rcode == "NXDOMAIN":
            name_missing = True
            break
        if ns.cname or (ns.rrset is None and ds.rrset is None):
            continue  # not a zone of its own (or an alias): part of its parent zone
        zone = _check_zone(suffix, ds, keys, parent_keys, now)
        zones.append(zone)
        if zone.status is ZoneStatus.SECURE and keys.rrset is not None:
            parent_keys = keys.rrset

    records: list[RecordCheck] = []
    if zones[-1].status is ZoneStatus.SECURE:
        zone_name = dns.name.from_text(zones[-1].zone)
        soa = _fetch(zone_name, "SOA", servers, timeout)
        records.append(_check_records(zone_name, "SOA", soa, parent_keys, now))
        a = fetched[(qname, "A")]
        if a.rrset is not None and not a.cname:
            records.append(_check_records(qname, "A", a, parent_keys, now))
    return report(
        zones=tuple(zones), records=tuple(records), clock=clock, name_missing=name_missing
    )


def _blocking_for(nameserver: str | None) -> DnsBlocking | None:
    """When an explicit internet --server didn't answer, find out whether DNS is blocked."""
    if nameserver is None:
        return check_blocking()  # the system's own servers failed: maybe offline
    try:
        public = ipaddress.ip_address(nameserver).is_global
    except ValueError:
        return None
    return check_blocking() if public else None


# --- Fetching -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Fetched:
    rcode: str | None  # None when no server responded
    rrset: dns.rrset.RRset | None = None  # the records of the asked type at the name
    rrsig: dns.rrset.RRset | None = None  # their signatures
    cname: bool = False  # the name is an alias
    error: str = ""


def _send(query: dns.message.Message, address: str, timeout: float) -> dns.message.Message:
    response, _ = dns.query.udp_with_fallback(query, address, timeout=timeout)
    return response


def _fetch(name: dns.name.Name, rtype: str, nameservers: Sequence[str], timeout: float) -> Fetched:
    """Ask the first nameserver that responds, with signatures and checking disabled."""
    query = dns.message.make_query(name, rtype, want_dnssec=True, use_edns=0, payload=1232)
    query.flags |= dns.flags.CD
    error = "no nameserver"
    for nameserver in nameservers:
        try:
            response = _send(query, nameserver, timeout)
        except dns.exception.Timeout:
            error = "timed out"
            continue
        except (OSError, dns.exception.DNSException) as exc:
            error = str(exc) or type(exc).__name__
            continue
        return _parse(response, name, dns.rdatatype.from_text(rtype))
    return Fetched(None, error=error)


def _parse(
    response: dns.message.Message, name: dns.name.Name, rdtype: dns.rdatatype.RdataType
) -> Fetched:
    rrset = rrsig = None
    cname = False
    for found in response.answer:
        if found.name != name:
            continue
        if found.rdtype == rdtype:
            rrset = found
        elif found.rdtype == dns.rdatatype.RRSIG and found.covers == rdtype:
            rrsig = found
        elif found.rdtype == dns.rdatatype.CNAME:
            cname = True
    return Fetched(dns.rcode.to_text(response.rcode()), rrset, rrsig, cname)


# --- Validating ---------------------------------------------------------------------------


def _anchors() -> list[dns.rdata.Rdata]:
    return [
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, text)
        for text in ROOT_TRUST_ANCHORS
    ]


def _check_root(keys: Fetched, now: float) -> ZoneCheck:
    assert keys.rrset is not None and keys.rrsig is not None
    anchors = _anchors()
    info = _key_info(keys.rrset)
    ds = tuple(_ds_info(a) for a in anchors)
    matched = _matching_keys(_ROOT, keys.rrset, anchors)
    if not matched:
        return ZoneCheck(
            ".",
            ZoneStatus.BOGUS,
            ds,
            info,
            "none of the root's keys match the built-in trust anchors",
            BogusKind.DS_MISMATCH,
        )
    error = _verify(keys.rrset, keys.rrsig, matched, now)
    if error:
        return ZoneCheck(
            ".", ZoneStatus.BOGUS, ds, info, f"root key set: {error}", _error_kind(error)
        )
    tags = ", ".join(str(dns.dnssec.key_id(k)) for k in matched)
    return ZoneCheck(".", ZoneStatus.SECURE, ds, info, f"keys signed by trust anchor {tags}")


def _check_zone(
    zone: dns.name.Name,
    ds: Fetched,
    keys: Fetched,
    parent_keys: dns.rrset.RRset,
    now: float,
) -> ZoneCheck:
    text = zone.to_text()
    parent = zone.parent().to_text()
    info = _key_info(keys.rrset) if keys.rrset is not None else ()
    if ds.rcode is None or (keys.rcode is None and ds.rrset is not None):
        error = ds.error or keys.error
        return ZoneCheck(text, ZoneStatus.UNKNOWN, keys=info, summary=f"couldn't fetch: {error}")
    if ds.rrset is None:
        summary = f"no DS record at {parent}: not signed"
        if info:
            summary = f"has keys, but no DS record at {parent}: the chain stops here"
        return ZoneCheck(text, ZoneStatus.UNSIGNED, keys=info, summary=summary)

    ds_info = tuple(_ds_info(d) for d in ds.rrset)
    if ds.rrsig is None:
        return ZoneCheck(
            text,
            ZoneStatus.BOGUS,
            ds_info,
            info,
            f"the DS record at {parent} isn't signed",
            BogusKind.MISSING_SIGNATURE,
        )
    error = _verify(ds.rrset, ds.rrsig, parent_keys, now)
    if error:
        return ZoneCheck(
            text,
            ZoneStatus.BOGUS,
            ds_info,
            info,
            f"DS record at {parent}: {error}",
            _error_kind(error),
        )
    if keys.rrset is None:
        return ZoneCheck(
            text,
            ZoneStatus.BOGUS,
            ds_info,
            info,
            f"{parent} has a DS record for it, but the zone has no DNSKEY records",
            BogusKind.NO_DNSKEY,
        )
    matched = _matching_keys(zone, keys.rrset, list(ds.rrset))
    if not matched:
        ds_tags = ", ".join(str(d.key_tag) for d in ds_info)
        key_tags = ", ".join(str(k.key_tag) for k in info if k.ksk) or "none"
        return ZoneCheck(
            text,
            ZoneStatus.BOGUS,
            ds_info,
            info,
            f"the DS record at {parent} (key {ds_tags}) matches none of its keys "
            f"(key-signing keys: {key_tags})",
            BogusKind.DS_MISMATCH,
        )
    if keys.rrsig is None:
        return ZoneCheck(
            text,
            ZoneStatus.BOGUS,
            ds_info,
            info,
            "its DNSKEY records aren't signed",
            BogusKind.MISSING_SIGNATURE,
        )
    error = _verify(keys.rrset, keys.rrsig, matched, now)
    if error:
        return ZoneCheck(
            text, ZoneStatus.BOGUS, ds_info, info, f"key set: {error}", _error_kind(error)
        )
    tags = ", ".join(str(dns.dnssec.key_id(k)) for k in matched)
    return ZoneCheck(
        text, ZoneStatus.SECURE, ds_info, info, f"DS at {parent} matches key {tags}; keys signed"
    )


def _check_records(
    name: dns.name.Name, rtype: str, fetched: Fetched, keys: dns.rrset.RRset, now: float
) -> RecordCheck:
    text = name.to_text()
    if fetched.rrset is None:
        reason = fetched.error or f"no {rtype} record"
        return RecordCheck(text, rtype, ZoneStatus.UNKNOWN, f"couldn't fetch ({reason})")
    if fetched.rrsig is None:
        return RecordCheck(text, rtype, ZoneStatus.BOGUS, "not signed", BogusKind.MISSING_SIGNATURE)
    error = _verify(fetched.rrset, fetched.rrsig, keys, now)
    if error:
        return RecordCheck(text, rtype, ZoneStatus.BOGUS, error, _error_kind(error))
    signer = fetched.rrsig[0]
    expires = datetime.fromtimestamp(signer.expiration, UTC).strftime("%Y-%m-%d")
    return RecordCheck(
        text, rtype, ZoneStatus.SECURE, f"signed by key {signer.key_tag}, valid until {expires}"
    )


def _verify(
    rrset: dns.rrset.RRset,
    rrsig: dns.rrset.RRset,
    keys: dns.rrset.RRset | Sequence[dns.rdata.Rdata],
    now: float,
) -> str:
    """ "" if one of the signatures verifies with `keys`; otherwise why not."""
    if not isinstance(keys, dns.rrset.RRset):  # some of a zone's own keys
        keys = dns.rrset.from_rdata_list(rrset.name, 0, list(keys))
    try:
        dns.dnssec.validate(rrset, rrsig, {keys.name: keys}, now=now)
    except dns.exception.ValidationFailure as exc:
        return _describe_failure(rrsig, now, str(exc))
    except dns.exception.DNSException as exc:  # e.g. an unsupported algorithm
        return str(exc) or type(exc).__name__
    return ""


def _describe_failure(rrsig: dns.rrset.RRset, now: float, error: str) -> str:
    """Say plainly when the signatures are expired or not yet valid."""
    if all(sig.expiration < now for sig in rrsig):
        date = datetime.fromtimestamp(max(s.expiration for s in rrsig), UTC)
        return f"signature expired on {date:%Y-%m-%d}"
    if all(sig.inception > now for sig in rrsig):
        date = datetime.fromtimestamp(min(s.inception for s in rrsig), UTC)
        return f"signature not valid until {date:%Y-%m-%d}"
    return "signature doesn't verify" if "verify" in error.lower() or not error else error


def _error_kind(error: str) -> BogusKind:
    if error.startswith(("signature expired", "signature not valid until")):
        return BogusKind.EXPIRED
    return BogusKind.BAD_SIGNATURE


def _matching_keys(
    zone: dns.name.Name, keys: dns.rrset.RRset, ds_records: Sequence[dns.rdata.Rdata]
) -> list[DNSKEY]:
    """The DNSKEYs that one of `ds_records` vouches for."""
    matched: list[DNSKEY] = []
    for key in _as(DNSKEY, keys):
        for ds in _as(DS, ds_records):
            try:
                made = dns.dnssec.make_ds(zone, key, ds.digest_type, validating=True)
            except (dns.exception.UnsupportedAlgorithm, dns.exception.DNSException):
                continue
            if made == ds:
                matched.append(key)
                break
    return matched


def _key_info(keys: dns.rrset.RRset) -> tuple[KeyInfo, ...]:
    return tuple(
        KeyInfo(
            dns.dnssec.key_id(key),
            dns.dnssec.algorithm_to_text(key.algorithm),
            bool(key.flags & _SEP_FLAG),
        )
        for key in keys
    )


def _ds_info(ds: dns.rdata.Rdata) -> DsInfo:
    (record,) = _as(DS, [ds])
    return DsInfo(
        record.key_tag, dns.dnssec.algorithm_to_text(record.algorithm), record.digest_type
    )


def _as(kind: type[_R], records: Iterable[dns.rdata.Rdata]) -> list[_R]:
    """The records as their specific type, for the type checker (rdatasets hold Rdata)."""
    return [r for r in records if isinstance(r, kind)]


# --- Clock --------------------------------------------------------------------------------


def check_clock(soa: Fetched, keys: Fetched, now: datetime | None = None) -> ClockCheck:
    """Compare this computer's clock with the root zone's date and signature dates."""
    local = now or datetime.now(UTC)
    reference = _serial_date(soa)
    if keys.rrsig is not None:
        stamp = local.timestamp()
        if all(sig.inception > stamp or sig.expiration < stamp for sig in keys.rrsig):
            return ClockCheck(
                ClockState.WRONG,
                local,
                reference,
                f"wrong: {local:%Y-%m-%d} is outside the root signatures' validity dates",
            )
    if reference is None:
        return ClockCheck(ClockState.UNKNOWN, local, None, "couldn't check (no root zone date)")
    days = (local - reference).total_seconds() / 86400
    if days < -CLOCK_BEHIND_DAYS or days > CLOCK_AHEAD_DAYS:
        direction = "behind" if days < 0 else "ahead of"
        return ClockCheck(
            ClockState.WRONG,
            local,
            reference,
            f"wrong: {local:%Y-%m-%d}, about {abs(days):.0f} days {direction} the root zone "
            f"({reference:%Y-%m-%d})",
        )
    return ClockCheck(
        ClockState.OK, local, reference, f"looks right (root zone from {reference:%Y-%m-%d})"
    )


def _serial_date(soa: Fetched) -> datetime | None:
    """The date in the root zone's SOA serial, which is YYYYMMDDnn."""
    if soa.rrset is None:
        return None
    try:
        return datetime.strptime(str(soa.rrset[0].serial)[:8], "%Y%m%d").replace(tzinfo=UTC)
    except (ValueError, AttributeError):
        return None


# --- Explanation --------------------------------------------------------------------------

PROTECTS = (
    "DNSSEC protects against forged DNS answers: someone on the network, or a poisoned "
    "resolver cache, can't send visitors to a fake address without the signature check "
    "failing. It doesn't encrypt DNS or hide which sites you visit."
)


def explain_dnssec(report: DnssecReport) -> Diagnosis:
    """The result in plain English, with what DNSSEC is for and what to do next."""
    zone = report.zone.rstrip(".") or "the root"
    name = report.name
    if report.name_missing and report.status is DnssecStatus.SECURE:
        return Diagnosis(
            title=f"{name} doesn't exist",
            explanation=f"The chain of trust validates down to {zone}, which says {name} "
            "doesn't exist (NXDOMAIN), so there are no records of its own to check.",
            suggestion="Check the spelling, or check a name that has records.",
        )
    match report.status:
        case DnssecStatus.SECURE:
            return Diagnosis(
                title=f"DNSSEC is on and validates for {name}",
                explanation=f"Every link from the root down to {zone} is signed and checks "
                "out: each parent vouches for its child's key with a DS record, and each zone "
                f"signs its records with that key. {PROTECTS} Validating resolvers (such as "
                "8.8.8.8, 1.1.1.1 and 9.9.9.9) check this automatically.",
                suggestion="Nothing to do. When you change DNS host or keys, update the DS "
                "record at the registrar at the same time, or validation breaks.",
            )
        case DnssecStatus.INSECURE:
            return _insecure(report)
        case DnssecStatus.BOGUS:
            return _bogus(report)
    if report.blocking is not None:
        return blocked_diagnosis(report.blocking, report.nameserver, one=True)
    if report.signatures_stripped:
        tried = " and ".join(DNSSEC_FALLBACKS)
        fallback = (
            f" {tried} couldn't be used instead either (a firewall or VPN may block them)."
            if report.stripped_by
            else ""
        )
        return Diagnosis(
            title="Couldn't check DNSSEC: this network strips the signatures",
            explanation=f"This computer's DNS server ({report.nameserver}) answers without "
            "DNSSEC signatures, which some routers, DNS filters and networks remove, so "
            f"nothing can be checked through it.{fallback} This says nothing about "
            f"{name}'s DNSSEC.",
            suggestion="Run this on another network, or with a DNS server that passes the "
            f"signatures along: `dnskit dnssec {name} --server <server>`.",
        )
    reason = report.error or (report.problem.summary if report.problem else "unknown")
    return Diagnosis(
        title="Couldn't check DNSSEC",
        explanation=f"{reason[:1].upper()}{reason[1:]}.",
        suggestion="Try again, or use a resolver that passes DNSSEC records along, such as "
        f"`dnskit dnssec {name} --server 8.8.8.8`.",
    )


def _insecure(report: DnssecReport) -> Diagnosis:
    unsigned = next(z for z in report.zones if z.status is ZoneStatus.UNSIGNED)
    zone = unsigned.zone.rstrip(".")
    parent = dns.name.from_text(unsigned.zone).parent().to_text().rstrip(".") or "the root"
    if unsigned.keys:
        return Diagnosis(
            title=f"DNSSEC is only half set up for {zone}",
            explanation=f"{zone} publishes DNSSEC keys, but {parent} has no DS record for it, "
            "so no chain of trust reaches those keys and resolvers treat the domain as "
            f"unsigned. {PROTECTS}",
            suggestion="Add the DS record your DNS host shows for the zone at your registrar "
            "to finish turning DNSSEC on.",
        )
    return Diagnosis(
        title=f"DNSSEC isn't enabled for {zone}",
        explanation=f"There's no DS record for {zone} at {parent}, so there's no chain of "
        "trust to it. Lookups work normally, but resolvers can't tell a genuine answer from a "
        f"forged one. {PROTECTS}",
        suggestion="To turn it on, enable DNSSEC at your DNS host, then add the DS record it "
        "gives you at your registrar (many hosts do both in one step).",
    )


def _bogus(report: DnssecReport) -> Diagnosis:
    problem = report.problem
    assert problem is not None
    where = problem.zone if isinstance(problem, ZoneCheck) else f"{problem.name} {problem.rtype}"
    where = where.rstrip(".") or "the root"
    consequence = (
        f"Resolvers that validate DNSSEC (Google, Cloudflare, Quad9 and many ISPs) refuse to "
        f"answer for {report.name} (SERVFAIL), so it looks down to most people, while "
        "resolvers that don't validate still answer."
    )
    if problem.kind is BogusKind.EXPIRED and report.clock.state is ClockState.WRONG:
        return Diagnosis(
            title="Validation failed: this computer's clock is wrong",
            explanation=f"{where}: {problem.summary}. {_clock_sentence(report.clock)} "
            "Signatures are only valid between set dates, so with a wrong clock valid "
            "signatures look expired or not yet valid.",
            suggestion="Set the date and time automatically (Windows: Settings > Time & "
            "language > Date & time), then run the check again.",
        )
    match problem.kind:
        case BogusKind.NO_DNSKEY:
            fix = (
                "The registrar still has a DS record, but the zone has no keys: it was "
                "probably moved to a DNS host without DNSSEC. Remove the DS record at the "
                "registrar, or turn DNSSEC on at the new host."
            )
        case BogusKind.DS_MISMATCH:
            fix = (
                "The DS record at the registrar doesn't match the zone's current key, which "
                "happens after a key change or a move to a new DNS host. Replace it with the "
                "DS record your DNS host shows, or remove it to switch DNSSEC off until then."
            )
        case BogusKind.EXPIRED:
            fix = (
                "The zone's signatures have expired, so the DNS host has stopped re-signing "
                "it. Contact the DNS host; if DNSSEC can't be fixed quickly, remove the DS "
                "record at the registrar."
            )
        case _:
            fix = (
                "The zone's signatures don't match its records. Contact the DNS host; if it "
                "can't be fixed quickly, remove the DS record at the registrar."
            )
    return Diagnosis(
        title=f"DNSSEC is broken for {report.name}",
        explanation=f"{where}: {problem.summary}. {consequence}",
        suggestion=fix,
    )


def clock_diagnosis(clock: ClockCheck) -> Diagnosis | None:
    """A warning when this computer's clock looks wrong; None otherwise."""
    if clock.state is not ClockState.WRONG:
        return None
    return Diagnosis(
        title="This computer's clock looks wrong",
        explanation=f"{_clock_sentence(clock)} DNSSEC signatures are only valid between set "
        "dates, so a wrong clock makes valid signatures look expired or not yet valid and "
        "validation fails. It breaks HTTPS certificates too.",
        suggestion="Set the date and time automatically (Windows: Settings > Time & language "
        "> Date & time; macOS: System Settings > General > Date & Time).",
    )


def _clock_sentence(clock: ClockCheck) -> str:
    if clock.reference is None:
        return (
            f"This computer's date, {clock.local:%Y-%m-%d}, is outside the dates the root "
            "zone's signatures are valid for."
        )
    return (
        f"This computer's date is {clock.local:%Y-%m-%d}, but the root zone was published "
        f"on {clock.reference:%Y-%m-%d}."
    )
