"""DNSSEC's signed proof that something doesn't exist (RFC 4035 5.4, RFC 5155 8, RFC 6840 4).

In a signed zone, "there's no such name" (NXDOMAIN) and "there's no DS record here" come
with NSEC or NSEC3 records, signed by the zone, that prove it. Without checking that proof,
anyone on the path could forge a denial: hide a DS record to switch DNSSEC off for a domain
(a downgrade), or make a name that exists look missing. These functions check the proof in a
response's authority section against the zone's (already validated) keys.

NSEC records name the next name in the zone, so a record "covers" every name between its
owner and its next name. NSEC3 does the same with hashed names. A record "matches" a name
when it's owned by that name (or its hash) and lists the types that exist there.
"""

import base64
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar

import dns.dnssec
import dns.exception
import dns.name
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.NSEC3 import NSEC3
from dns.rdtypes.ANY.RRSIG import RRSIG

_R = TypeVar("_R")

_NXNAME = 128  # the type compact denial (RFC 9824) lists for a name that doesn't exist
_OPT_OUT = 0x01  # NSEC3 flag: unsigned delegations in this span have no NSEC3 records
_WILD = dns.name.Name((b"*",))


class Proof(StrEnum):
    NO_NAME = "no_name"  # the name doesn't exist
    NOT_A_ZONE = "not_a_zone"  # the name exists in the zone but isn't delegated: no DS
    UNSIGNED_ZONE = "unsigned_zone"  # the name is delegated, with no DS record
    OPT_OUT = "opt_out"  # in an NSEC3 opt-out span: at most an unsigned delegation


@dataclass(frozen=True)
class Denial:
    proof: Proof | None  # what was proven; None when nothing was
    method: str = ""  # "NSEC" or "NSEC3"
    reason: str = ""  # not proven: why, e.g. "no NSEC or NSEC3 records came with it"

    @property
    def proven(self) -> bool:
        return self.proof is not None


def prove_no_ds(
    name: dns.name.Name, authority: Sequence[dns.rrset.RRset], keys: dns.rrset.RRset, now: float
) -> Denial:
    """Check the proof that `name` has no DS record in the zone `keys` belongs to.

    Proven outcomes: UNSIGNED_ZONE (a delegation without DS), NOT_A_ZONE (a name, empty
    non-terminal or wildcard match that isn't delegated), OPT_OUT, or NO_NAME.
    """
    signed = _signed(authority, keys, now)
    if isinstance(signed, Denial):
        return signed
    nsec, nsec3 = signed
    if nsec:
        proof = _nsec_no_ds(name, nsec)
        if proof is not None:
            return Denial(proof, "NSEC")
    if nsec3:
        proof = _nsec3_no_ds(name, nsec3, keys.name)
        if proof is not None:
            return Denial(proof, "NSEC3")
    return Denial(None, reason="its NSEC/NSEC3 records don't prove it")


def prove_nxdomain(
    name: dns.name.Name, authority: Sequence[dns.rrset.RRset], keys: dns.rrset.RRset, now: float
) -> Denial:
    """Check the proof that `name` doesn't exist in the zone `keys` belongs to."""
    signed = _signed(authority, keys, now)
    if isinstance(signed, Denial):
        return signed
    nsec, nsec3 = signed
    if nsec and _nsec_no_name(name, nsec):
        return Denial(Proof.NO_NAME, "NSEC")
    if nsec3 and _nsec3_no_name(name, nsec3, keys.name):
        return Denial(Proof.NO_NAME, "NSEC3")
    return Denial(None, reason="its NSEC/NSEC3 records don't prove it")


# --- Signatures ---------------------------------------------------------------------------


def _signed(
    authority: Sequence[dns.rrset.RRset], keys: dns.rrset.RRset, now: float
) -> tuple[list[dns.rrset.RRset], list[dns.rrset.RRset]] | Denial:
    """The zone's NSEC and NSEC3 record sets whose signatures verify with `keys`."""
    zone = keys.name
    sigs = {(s.name, s.covers): s for s in authority if s.rdtype == dns.rdatatype.RRSIG}
    found = [s for s in authority if s.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)]
    if not found:
        return Denial(None, reason="no NSEC or NSEC3 records came with it")
    nsec: list[dns.rrset.RRset] = []
    nsec3: list[dns.rrset.RRset] = []
    for rrset in found:
        if rrset.rdtype == dns.rdatatype.NSEC3 and rrset.name.parent() != zone:
            continue  # NSEC3 records sit directly below the zone's apex
        if not rrset.name.is_subdomain(zone):
            continue
        rrsig = sigs.get((rrset.name, rrset.rdtype))
        if rrsig is None or not _verifies(rrset, rrsig, keys, now):
            continue
        (nsec3 if rrset.rdtype == dns.rdatatype.NSEC3 else nsec).append(rrset)
    if not nsec and not nsec3:
        return Denial(None, reason="the signatures on its NSEC/NSEC3 records don't verify")
    return nsec, nsec3


def _verifies(
    rrset: dns.rrset.RRset, rrsig: dns.rrset.RRset, keys: dns.rrset.RRset, now: float
) -> bool:
    # A signature with fewer labels than the owner was made for a wildcard and expanded;
    # NSEC records must never be used that way (RFC 4035 5.3.4).
    labels = len(rrset.name) - 1 - (1 if rrset.name.is_wild() else 0)
    usable = [s for s in _as(RRSIG, rrsig) if s.labels == labels]
    if not usable:
        return False
    try:
        dns.dnssec.validate(
            rrset,
            dns.rrset.from_rdata_list(rrsig.name, rrsig.ttl, usable),
            {keys.name: keys},
            now=now,
        )
    except dns.exception.DNSException:
        return False
    return True


# --- NSEC -----------------------------------------------------------------------------------


def _types(rdata: NSEC | NSEC3) -> set[int]:
    return {t for window, bitmap in rdata.windows for t in _bitmap_types(window, bitmap)}


def _bitmap_types(window: int, bitmap: bytes) -> Iterable[int]:
    for i, byte in enumerate(bitmap):
        for bit in range(8):
            if byte & (0x80 >> bit):
                yield window * 256 + i * 8 + bit


def _nsec(rrset: dns.rrset.RRset) -> NSEC:
    return _as(NSEC, rrset)[0]


def _covers(rrset: dns.rrset.RRset, name: dns.name.Name) -> bool:
    """Whether the NSEC record proves no name exists between its owner and its next name."""
    owner, rdata = rrset.name, _nsec(rrset)
    types = _types(rdata)
    delegation = dns.rdatatype.NS in types and dns.rdatatype.SOA not in types
    if name != owner and name.is_subdomain(owner) and (delegation or dns.rdatatype.DNAME in types):
        return False  # a delegation's or DNAME's NSEC says nothing below it (RFC 6840 4.1)
    nxt: dns.name.Name = rdata.next
    if owner < nxt:
        return bool(owner < name < nxt)
    return bool(name > owner or name < nxt)  # the zone's last NSEC: its next name is the apex


def _nsec_no_ds(name: dns.name.Name, nsec: list[dns.rrset.RRset]) -> Proof | None:
    for rrset in nsec:
        if rrset.name != name:
            continue
        types = _types(_nsec(rrset))
        if _NXNAME in types:
            return Proof.NO_NAME
        if {dns.rdatatype.DS, dns.rdatatype.CNAME, dns.rdatatype.SOA} & types:
            return None  # DS or an alias here, or the child zone's own apex record
        return Proof.UNSIGNED_ZONE if dns.rdatatype.NS in types else Proof.NOT_A_ZONE
    covering = [r for r in nsec if _covers(r, name)]
    for rrset in covering:
        nxt = _nsec(rrset).next
        if nxt != name and nxt.is_subdomain(name):
            return Proof.NOT_A_ZONE  # an empty non-terminal: names exist below it
    if covering:  # no such name: a wildcard may stand in for it
        wildcard = _WILD.concatenate(_nsec_closest_encloser(name, covering[0]))
        for rrset in nsec:
            if rrset.name == wildcard:
                types = _types(_nsec(rrset))
                if not {dns.rdatatype.DS, dns.rdatatype.CNAME} & types:
                    return Proof.NOT_A_ZONE
    return None


def _nsec_closest_encloser(name: dns.name.Name, rrset: dns.rrset.RRset) -> dns.name.Name:
    """The deepest existing ancestor of `name`, from the NSEC record covering it."""
    common = max(name.fullcompare(rrset.name)[2], name.fullcompare(_nsec(rrset).next)[2])
    return name.split(common)[1]


def _nsec_no_name(name: dns.name.Name, nsec: list[dns.rrset.RRset]) -> bool:
    for rrset in nsec:
        if rrset.name == name and _NXNAME in _types(_nsec(rrset)):
            return True  # compact denial
    for rrset in nsec:
        if not _covers(rrset, name):
            continue
        nxt = _nsec(rrset).next
        if nxt != name and nxt.is_subdomain(name):
            return False  # names exist below it: an empty non-terminal, not missing
        wildcard = _WILD.concatenate(_nsec_closest_encloser(name, rrset))
        return any(_covers(r, wildcard) for r in nsec)
    return False


# --- NSEC3 ----------------------------------------------------------------------------------


def _nsec3(rrset: dns.rrset.RRset) -> NSEC3:
    return _as(NSEC3, rrset)[0]


class _Hashes:
    """NSEC3 hashes of names, per record's parameters (all records should share them)."""

    def __init__(self, nsec3: list[dns.rrset.RRset]) -> None:
        self.records = [r for r in nsec3 if _nsec3(r).algorithm == 1]
        self.cache: dict[tuple[dns.name.Name, bytes, int], bytes] = {}

    def hash(self, name: dns.name.Name, rdata: NSEC3) -> bytes:
        key = (name, rdata.salt, rdata.iterations)
        if key not in self.cache:
            text = dns.dnssec.nsec3_hash(name, rdata.salt, rdata.iterations, 1)
            self.cache[key] = base64.b32hexdecode(text.upper())
        return self.cache[key]

    def match(self, name: dns.name.Name) -> NSEC3 | None:
        for rrset in self.records:
            rdata = _nsec3(rrset)
            if _owner_hash(rrset) == self.hash(name, rdata):
                return rdata
        return None

    def cover(self, name: dns.name.Name) -> NSEC3 | None:
        for rrset in self.records:
            rdata = _nsec3(rrset)
            owner, nxt, hashed = _owner_hash(rrset), rdata.next, self.hash(name, rdata)
            if owner is None or hashed == owner:
                continue
            if owner < nxt and owner < hashed < nxt:
                return rdata
            if owner >= nxt and (hashed > owner or hashed < nxt):
                return rdata
        return None

    def closest_encloser(
        self, name: dns.name.Name, zone: dns.name.Name
    ) -> tuple[dns.name.Name, NSEC3] | None:
        """The closest encloser proof: (closest encloser, the NSEC3 covering the next closer)."""
        candidate = name
        while candidate != zone:
            parent = candidate.parent()
            found = self.match(parent)
            if found is not None:
                types = _types(found)
                if dns.rdatatype.DNAME in types or (
                    dns.rdatatype.NS in types and dns.rdatatype.SOA not in types
                ):
                    return None  # an ancestor is a delegation: this zone can't speak for it
                cover = self.cover(candidate)
                return (parent, cover) if cover is not None else None
            candidate = parent
        return None


def _owner_hash(rrset: dns.rrset.RRset) -> bytes | None:
    try:
        return base64.b32hexdecode(rrset.name[0].decode("ascii").upper())
    except (ValueError, UnicodeDecodeError):
        return None


def _nsec3_no_ds(
    name: dns.name.Name, nsec3: list[dns.rrset.RRset], zone: dns.name.Name
) -> Proof | None:
    hashes = _Hashes(nsec3)
    found = hashes.match(name)
    if found is not None:
        types = _types(found)
        if {dns.rdatatype.DS, dns.rdatatype.CNAME, dns.rdatatype.SOA} & types:
            return None
        return Proof.UNSIGNED_ZONE if dns.rdatatype.NS in types else Proof.NOT_A_ZONE
    proof = hashes.closest_encloser(name, zone)
    if proof is None:
        return None
    encloser, cover = proof
    if cover.flags & _OPT_OUT:
        return Proof.OPT_OUT
    wildcard = hashes.match(_WILD.concatenate(encloser))
    if wildcard is not None and not {dns.rdatatype.DS, dns.rdatatype.CNAME} & _types(wildcard):
        return Proof.NOT_A_ZONE
    return None


def _nsec3_no_name(name: dns.name.Name, nsec3: list[dns.rrset.RRset], zone: dns.name.Name) -> bool:
    hashes = _Hashes(nsec3)
    if hashes.match(name) is not None:
        return False  # it exists
    proof = hashes.closest_encloser(name, zone)
    if proof is None:
        return False
    return hashes.cover(_WILD.concatenate(proof[0])) is not None


def _as(kind: type[_R], records: Iterable[object]) -> list[_R]:
    return [r for r in records if isinstance(r, kind)]
