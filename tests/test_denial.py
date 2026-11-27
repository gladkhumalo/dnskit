"""The NSEC/NSEC3 denial proofs on their own, with records signed by throwaway test zones.

Whole-chain cases (a forged NXDOMAIN, a stripped DS) are in test_dnssec.py."""

import base64
import time

import dns.dnssec
import dns.name
import dns.rrset
import pytest

from dnskit.core.denial import Proof, prove_no_ds, prove_nxdomain
from fakes import rrset
from test_dnssec import Zone, nsec3_hash

NOW = time.time()


@pytest.fixture(scope="module")
def com() -> Zone:
    return Zone("com.")


@pytest.fixture(scope="module")
def example() -> Zone:
    return Zone("example.com.")


def name(text: str) -> dns.name.Name:
    return dns.name.from_text(text)


def no_ds(zone: Zone, qname: str, *proof: list) -> Proof | None:
    authority = [r for records in proof for r in records]
    return prove_no_ds(name(qname), authority, zone.dnskey, NOW).proof


def nxdomain(zone: Zone, qname: str, *proof: list) -> Proof | None:
    authority = [r for records in proof for r in records]
    return prove_nxdomain(name(qname), authority, zone.dnskey, NOW).proof


APEX = "NS SOA RRSIG NSEC DNSKEY"
APEX3 = "NS SOA RRSIG DNSKEY NSEC3PARAM"


# --- NSEC ---------------------------------------------------------------------------------


def test_an_empty_non_terminal_has_no_ds(example: Zone) -> None:
    proof = example.nsec("example.com.", "a.b.example.com.", APEX)

    assert no_ds(example, "b.example.com.", proof) is Proof.NOT_A_ZONE
    assert nxdomain(example, "b.example.com.", proof) is None  # it exists, with no records


def test_a_wildcard_match_has_no_ds(example: Zone) -> None:
    covering = example.nsec("example.com.", "www.example.com.", APEX)
    wildcard = example.nsec("*.example.com.", "www.example.com.", "A RRSIG NSEC")

    assert no_ds(example, "other.example.com.", covering, wildcard) is Proof.NOT_A_ZONE


def test_a_wildcard_with_a_ds_proves_nothing(example: Zone) -> None:
    covering = example.nsec("example.com.", "www.example.com.", APEX)
    wildcard = example.nsec("*.example.com.", "www.example.com.", "DS RRSIG NSEC")

    assert no_ds(example, "other.example.com.", covering, wildcard) is None


def test_a_covering_record_alone_proves_no_ds_nothing(example: Zone) -> None:
    covering = example.nsec("example.com.", "www.example.com.", APEX)

    assert no_ds(example, "other.example.com.", covering) is None


def test_compact_denial_proves_the_name_missing(example: Zone) -> None:
    proof = example.nsec("gone.example.com.", "\\000.gone.example.com.", "RRSIG NSEC TYPE128")

    assert no_ds(example, "gone.example.com.", proof) is Proof.NO_NAME
    assert nxdomain(example, "gone.example.com.", proof) is Proof.NO_NAME


def test_the_zones_last_record_wraps_to_the_apex(example: Zone) -> None:
    last = example.nsec("www.example.com.", "example.com.", "A RRSIG NSEC")
    wildcard = example.nsec("example.com.", "a.example.com.", APEX)

    assert nxdomain(example, "zzz.example.com.", last, wildcard) is Proof.NO_NAME


def test_nxdomain_must_rule_out_a_wildcard(example: Zone) -> None:
    covering = example.nsec("m.example.com.", "www.example.com.", "A RRSIG NSEC")

    assert nxdomain(example, "n.example.com.", covering) is None


def test_a_delegations_record_says_nothing_below_it(com: Zone) -> None:
    """com.'s NSEC at a delegation can't prove names inside the child zone (RFC 6840 4.1)."""
    proof = com.nsec("example.com.", "f.com.", "NS RRSIG NSEC")

    assert nxdomain(com, "www.example.com.", proof) is None


def test_the_childs_apex_record_doesnt_prove_no_ds(example: Zone) -> None:
    """The child's own NSEC at its apex lists SOA: it's from the wrong side of the cut."""
    assert (
        no_ds(example, "example.com.", example.nsec("example.com.", "a.example.com.", APEX)) is None
    )


def test_a_wildcard_expanded_record_doesnt_count(com: Zone) -> None:
    """A signature made for *.com. and expanded to example.com. (RFC 4035 5.3.4)."""
    wild = rrset("*.com.", "NSEC", "f.com. NS RRSIG NSEC")
    sig = com.sign(wild)
    expanded = dns.rrset.from_rdata(name("example.com."), 300, *wild)
    expanded_sig = dns.rrset.from_rdata(name("example.com."), 300, *sig)

    denial = prove_no_ds(name("example.com."), [expanded, expanded_sig], com.dnskey, NOW)

    assert denial.reason == "the signatures on its NSEC/NSEC3 records don't verify"


def test_a_record_without_a_signature_doesnt_count(com: Zone) -> None:
    unsigned = rrset("example.com.", "NSEC", "f.com. NS RRSIG NSEC")

    denial = prove_no_ds(name("example.com."), [unsigned], com.dnskey, NOW)

    assert not denial.proven


def test_a_record_outside_the_zone_doesnt_count(com: Zone, example: Zone) -> None:
    outside = com.nsec("example.org.", "f.org.", "NS RRSIG NSEC")

    assert no_ds(com, "example.org.", outside) is None


# --- NSEC3 --------------------------------------------------------------------------------


def test_an_nsec3_empty_non_terminal_has_no_ds(example: Zone) -> None:
    assert no_ds(example, "b.example.com.", example.nsec3_match("b.example.com.", "")) is (
        Proof.NOT_A_ZONE
    )


def test_an_nsec3_wildcard_match_has_no_ds(example: Zone) -> None:
    proof = example.nsec3_match("example.com.", APEX3)
    proof += example.nsec3_cover("other.example.com.")
    proof += example.nsec3_match("*.example.com.", "A RRSIG")

    assert no_ds(example, "other.example.com.", proof) is Proof.NOT_A_ZONE


def test_an_nsec3_record_listing_soa_doesnt_prove_no_ds(example: Zone) -> None:
    assert no_ds(example, "example.com.", example.nsec3_match("example.com.", APEX3)) is None


def test_an_nsec3_nxdomain_for_a_name_that_exists_fails(example: Zone) -> None:
    proof = example.nsec3_match("www.example.com.", "A RRSIG")

    assert nxdomain(example, "www.example.com.", proof) is None


def test_an_nsec3_closest_encloser_at_a_delegation_proves_nothing(com: Zone) -> None:
    proof = com.nsec3_match("example.com.", "NS")
    proof += com.nsec3_cover("www.example.com.")
    proof += com.nsec3_cover("*.example.com.")

    assert nxdomain(com, "www.example.com.", proof) is None


def test_an_nsec3_proof_without_a_closest_encloser_fails(example: Zone) -> None:
    proof = example.nsec3_cover("missing.example.com.")

    assert nxdomain(example, "missing.example.com.", proof) is None


def test_nsec3_records_below_the_apex_only(example: Zone) -> None:
    """NSEC3 owners are one label under the zone; anything else is ignored."""
    label = dns.dnssec.nsec3_hash("missing.example.com.", "AB", 0, 1).lower()
    deep = rrset(f"{label}.sub.example.com.", "NSEC3", "1 0 0 AB 00000000000000000000000000000000")

    denial = prove_nxdomain(name("missing.example.com."), example.signed(deep), example.dnskey, NOW)

    assert denial.reason == "the signatures on its NSEC/NSEC3 records don't verify"


def test_nsec3_with_an_unknown_hash_algorithm_is_ignored(example: Zone) -> None:
    hashed = nsec3_hash("example.com.")
    label = base64.b32hexencode(hashed).decode().lower()
    record = rrset(f"{label}.example.com.", "NSEC3", "2 0 0 AB 00000000000000000000000000000000 NS")

    assert no_ds(example, "example.com.", example.signed(record)) is None


def test_an_nsec3_owner_that_isnt_a_hash_is_ignored(example: Zone) -> None:
    record = rrset("not-a-hash!.example.com.", "NSEC3", "1 0 0 AB 00000000000000000000000000000000")

    assert nxdomain(example, "missing.example.com.", example.signed(record)) is None


def test_an_nsec3_span_that_wraps_around_covers(example: Zone) -> None:
    """The zone's last NSEC3 record: its next hash is the lowest one."""
    hashed = nsec3_hash("missing.example.com.")
    owner = base64.b32hexencode((int.from_bytes(hashed) - 1).to_bytes(20)).decode().lower()
    record = rrset(f"{owner}.example.com.", "NSEC3", "1 0 0 AB 00000000000000000000000000000000")
    proof = example.signed(record) + example.nsec3_match("example.com.", APEX3)
    proof += example.nsec3_cover("*.example.com.")

    assert nxdomain(example, "missing.example.com.", proof) is Proof.NO_NAME
