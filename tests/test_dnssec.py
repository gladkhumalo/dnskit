"""DNSSEC tests with real signatures: a test root, com. and example.com., signed with
throwaway Ed25519 keys, and the root trust anchor swapped for the test root's key."""

import base64
import importlib
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import dns.dnssec
import dns.message
import dns.name
import dns.rdata
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from dnskit.core import DnsBlocking
from dnskit.core.dnssec import (
    BogusKind,
    ClockState,
    DnssecStatus,
    Fetched,
    ZoneStatus,
    check_clock,
    clock_diagnosis,
    dnssec_check,
    explain_dnssec,
)
from dnskit.core.lookup import _Selection
from fakes import FakeNetwork, question, reply, rrset

dnssec_mod = importlib.import_module("dnskit.core.dnssec")

RESOLVER = "192.0.2.53"
DAY = 86400


class Zone:
    """A zone with a key-signing key and a zone-signing key."""

    def __init__(self, name: str) -> None:
        self.name = dns.name.from_text(name)
        self.ksk_private = ed25519.Ed25519PrivateKey.generate()
        self.zsk_private = ed25519.Ed25519PrivateKey.generate()
        self.ksk = dns.dnssec.make_dnskey(self.ksk_private.public_key(), "ED25519", flags=257)
        self.zsk = dns.dnssec.make_dnskey(self.zsk_private.public_key(), "ED25519", flags=256)
        self.dnskey = dns.rrset.from_rdata(self.name, 3600, self.ksk, self.zsk)

    def ds(self) -> dns.rdata.Rdata:
        return dns.dnssec.make_ds(self.name, self.ksk, "SHA256")

    def sign(self, records: dns.rrset.RRset, ksk: bool = False, expired: bool = False):
        now = int(time.time())
        inception, expiration = (
            (now - 30 * DAY, now - DAY) if expired else (now - DAY, now + 7 * DAY)
        )
        private, key = (self.ksk_private, self.ksk) if ksk else (self.zsk_private, self.zsk)
        sig = dns.dnssec.sign(records, private, self.name, key, inception, expiration)
        return dns.rrset.from_rdata(records.name, records.ttl, sig)

    def signed(self, records: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        return [records, self.sign(records)]

    def nsec(self, owner: str, nxt: str, types: str = "RRSIG NSEC") -> list[dns.rrset.RRset]:
        """A signed NSEC record: no names between `owner` and `nxt`, `types` at `owner`."""
        return self.signed(rrset(owner, "NSEC", f"{nxt} {types}"))

    def nsec3_match(self, name: str, types: str = "RRSIG", opt_out: bool = False):
        """A signed NSEC3 record for `name` itself, listing `types`."""
        hashed = nsec3_hash(name)
        return self._nsec3(hashed, _shift(hashed, 1), types, opt_out)

    def nsec3_cover(self, name: str, opt_out: bool = False) -> list[dns.rrset.RRset]:
        """A signed NSEC3 record whose span covers `name`'s hash."""
        hashed = nsec3_hash(name)
        return self._nsec3(_shift(hashed, -1), _shift(hashed, 1), "", opt_out)

    def _nsec3(self, owner: bytes, nxt: bytes, types: str, opt_out: bool):
        label = base64.b32hexencode(owner).decode().lower()
        nxt_text = base64.b32hexencode(nxt).decode()
        flags = 1 if opt_out else 0
        return self.signed(
            rrset(f"{label}.{self.name}", "NSEC3", f"1 {flags} 0 AB {nxt_text} {types}".strip())
        )


def nsec3_hash(name: str) -> bytes:
    return base64.b32hexdecode(dns.dnssec.nsec3_hash(name, "AB", 0, 1))


def _shift(hashed: bytes, by: int) -> bytes:
    return (int.from_bytes(hashed) + by).to_bytes(len(hashed))


def today_serial() -> str:
    return f"{datetime.now(UTC):%Y%m%d}00"


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """A resolver that serves a fully signed root -> com. -> example.com. chain.

    `answers` maps (name, rtype) to (rcode, rrsets); tests change entries to break things.
    `strip` drops all signatures. Records `blocking_calls`.
    """
    root, com, example = Zone("."), Zone("com."), Zone("example.com.")
    state = SimpleNamespace(
        root=root, com=com, example=example, answers={}, strip=False, blocking_calls=0
    )

    def put(name: str, rtype: str, records: dns.rrset.RRset, signer: Zone | None, **kw) -> None:
        sets = [records] + ([signer.sign(records, **kw)] if signer else [])
        state.answers[(name, rtype)] = ("NOERROR", sets)

    def deny(name: str, rtypes: str, *proof: list, rcode: str = "NOERROR") -> None:
        """Answer `rtypes` for `name` with no records, and the proof in the authority."""
        authority = [r for records in proof for r in records]
        for rtype in rtypes.split():
            state.answers[(name, rtype)] = (rcode, [], authority)

    state.put = put
    state.deny = deny
    put(".", "DNSKEY", root.dnskey, root, ksk=True)
    put(".", "SOA", rrset(".", "SOA", f"a.root-servers.net. nstld. {today_serial()} 1 2 3 4"), root)
    for child, parent in ((com, root), (example, com)):
        name = child.name.to_text()
        put(name, "NS", rrset(name, "NS", f"ns1.{name}"), None)
        put(name, "DS", dns.rrset.from_rdata(child.name, 3600, child.ds()), parent)
        put(name, "DNSKEY", child.dnskey, child, ksk=True)
    put(
        "example.com.",
        "SOA",
        rrset("example.com.", "SOA", "ns1.example.com. admin.example.com. 1 2 3 4 5"),
        example,
    )
    put("example.com.", "A", rrset("example.com.", "A", "192.0.2.80"), example)

    def serve(strips: bool) -> object:
        """A resolver for the world; `strips` ones drop signatures when `state.strip`."""

        def resolver(query: dns.message.Message) -> dns.message.Message:
            rcode, sets, *rest = state.answers.get(question(query), ("NOERROR", []))
            authority = rest[0] if rest else []
            if strips and state.strip:
                sets = [s for s in sets if s.rdtype != dns.rdatatype.RRSIG]
                authority = [s for s in authority if s.rdtype != dns.rdatatype.RRSIG]
            return reply(query, answer=sets, authority=authority, rcode=rcode)

        return resolver

    state.serve = serve
    network = FakeNetwork()
    network.handlers[RESOLVER] = serve(strips=True)
    state.network = network

    def fake_check_blocking() -> DnsBlocking:
        state.blocking_calls += 1
        return DnsBlocking((RESOLVER,), ("OfficeVPN",), local_firewall=True)

    anchor = dns.dnssec.make_ds(".", root.ksk, "SHA256").to_text()
    monkeypatch.setattr(dnssec_mod, "ROOT_TRUST_ANCHORS", (anchor,))
    monkeypatch.setattr(dnssec_mod, "_send", network)
    monkeypatch.setattr(dnssec_mod, "check_blocking", fake_check_blocking)
    monkeypatch.setattr(
        dnssec_mod,
        "_choose_nameservers",
        lambda nameserver, refresh=False: _Selection([nameserver or RESOLVER], "test", None),
    )
    return state


def test_a_fully_signed_chain_validates(world: SimpleNamespace) -> None:
    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.SECURE
    assert [z.zone for z in report.zones] == [".", "com.", "example.com."]
    assert all(z.status is ZoneStatus.SECURE for z in report.zones)
    assert [(r.name, r.rtype, r.status) for r in report.records] == [
        ("example.com.", "SOA", ZoneStatus.SECURE),
        ("example.com.", "A", ZoneStatus.SECURE),
    ]
    example = report.zones[2]
    assert [d.key_tag for d in example.ds] == [dns.dnssec.key_id(world.example.ksk)]
    assert sorted(k.ksk for k in example.keys) == [False, True]
    assert example.keys[0].algorithm == "ED25519"
    assert report.clock.state is ClockState.OK
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "DNSSEC is on and validates for example.com"
    assert "forged" in diagnosis.explanation  # what DNSSEC protects against
    assert "doesn't encrypt" in diagnosis.explanation


def test_names_inside_a_zone_belong_to_it(world: SimpleNamespace) -> None:
    world.put("www.example.com.", "A", rrset("www.example.com.", "A", "192.0.2.81"), world.example)
    world.deny("www.example.com.", "NS DS", world.example.nsec("www.example.com.", "example.com."))

    report = dnssec_check("www.example.com")

    assert report.status is DnssecStatus.SECURE
    assert report.zone == "example.com."  # www has no NS or DS: not a zone of its own
    assert report.records[-1].name == "www.example.com."


def unsigned_delegation(world: SimpleNamespace) -> None:
    """com. proves example.com. is delegated (NS) without a DS record."""
    world.deny("example.com.", "DS", world.com.nsec("example.com.", "f.com.", "NS RRSIG NSEC"))


def test_no_ds_means_dnssec_is_off(world: SimpleNamespace) -> None:
    unsigned_delegation(world)
    del world.answers[("example.com.", "DNSKEY")]

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.INSECURE
    assert report.zones[-1].status is ZoneStatus.UNSIGNED
    assert report.zones[-1].summary == "no DS record at com. (NSEC proof): not signed"
    assert report.records == ()
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "DNSSEC isn't enabled for example.com"
    assert diagnosis.explanation.startswith("There's no DS record for example.com at com,")
    assert "registrar" in diagnosis.suggestion


def test_keys_without_a_ds_are_half_set_up(world: SimpleNamespace) -> None:
    unsigned_delegation(world)

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.INSECURE
    assert "(NSEC proof): the chain stops here" in report.zones[-1].summary
    assert explain_dnssec(report).title == "DNSSEC is only half set up for example.com"


def test_a_ds_matching_no_key_is_bogus(world: SimpleNamespace) -> None:
    other = Zone("example.com.")
    world.put("example.com.", "DS", dns.rrset.from_rdata(other.name, 3600, other.ds()), world.com)

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.BOGUS
    zone = report.zones[-1]
    assert zone.kind is BogusKind.DS_MISMATCH
    assert "matches none of its keys" in zone.summary
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "DNSSEC is broken for example.com"
    assert "SERVFAIL" in diagnosis.explanation
    assert "Replace it with the DS record" in diagnosis.suggestion


def test_a_ds_without_keys_is_bogus(world: SimpleNamespace) -> None:
    del world.answers[("example.com.", "DNSKEY")]

    report = dnssec_check("example.com")

    assert report.zones[-1].kind is BogusKind.NO_DNSKEY
    assert "Remove the DS record" in explain_dnssec(report).suggestion


def test_expired_record_signatures_are_bogus(world: SimpleNamespace) -> None:
    soa = rrset("example.com.", "SOA", "ns1.example.com. admin.example.com. 1 2 3 4 5")
    world.put("example.com.", "SOA", soa, world.example, expired=True)

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.BOGUS
    soa_check = report.records[0]
    assert soa_check.kind is BogusKind.EXPIRED
    assert soa_check.summary.startswith("signature expired on ")
    assert "stopped re-signing" in explain_dnssec(report).suggestion


def test_a_forged_record_fails_its_signature(world: SimpleNamespace) -> None:
    _, sets = world.answers[("example.com.", "A")]
    forged = rrset("example.com.", "A", "203.0.113.66")
    world.answers[("example.com.", "A")] = ("NOERROR", [forged, sets[1]])

    report = dnssec_check("example.com")

    assert report.records[-1].kind is BogusKind.BAD_SIGNATURE
    assert report.status is DnssecStatus.BOGUS


def test_a_wrong_trust_anchor_fails_at_the_root(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    stranger = Zone(".")
    monkeypatch.setattr(
        dnssec_mod,
        "ROOT_TRUST_ANCHORS",
        (dns.dnssec.make_ds(".", stranger.ksk, "SHA256").to_text(),),
    )

    report = dnssec_check("example.com")

    assert report.zones[0].status is ZoneStatus.BOGUS
    assert len(report.zones) == 1


def test_a_stripping_resolver_is_replaced_by_a_public_one(world: SimpleNamespace) -> None:
    world.strip = True
    world.network.handlers["8.8.8.8"] = world.serve(strips=False)

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.SECURE
    assert (report.nameserver, report.stripped_by) == ("8.8.8.8", RESOLVER)
    assert not report.signatures_stripped
    assert report.nameserver_source == (
        f"this computer's DNS server {RESOLVER} strips DNSSEC signatures"
    )
    assert world.blocking_calls == 0


def test_the_second_fallback_is_used_when_the_first_is_silent(world: SimpleNamespace) -> None:
    world.strip = True
    world.network.handlers["1.1.1.1"] = world.serve(strips=False)  # 8.8.8.8 times out

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.SECURE
    assert report.nameserver == "1.1.1.1"
    assert world.blocking_calls == 0  # fallbacks don't run the blocking diagnosis


def test_stripped_everywhere_cant_be_checked(world: SimpleNamespace) -> None:
    world.strip = True  # and neither fallback answers

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.UNKNOWN
    assert report.signatures_stripped
    assert (report.nameserver, report.stripped_by) == (RESOLVER, RESOLVER)
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "Couldn't check DNSSEC: this network strips the signatures"
    assert f"This computer's DNS server ({RESOLVER}) answers without" in diagnosis.explanation
    assert "8.8.8.8 and 1.1.1.1 couldn't be used instead either" in diagnosis.explanation
    assert "says nothing about example.com's DNSSEC" in diagnosis.explanation
    assert world.blocking_calls == 0


def test_an_explicit_server_is_never_replaced(world: SimpleNamespace) -> None:
    world.strip = True
    world.network.handlers["8.8.8.8"] = world.serve(strips=False)

    report = dnssec_check("example.com", nameserver=RESOLVER)

    assert report.signatures_stripped
    assert report.stripped_by is None
    assert not [a for a, _, _ in world.network.sent if a != RESOLVER]
    assert "couldn't be used instead" not in explain_dnssec(report).explanation


def test_no_fallback_when_signatures_arrive(world: SimpleNamespace) -> None:
    dnssec_check("example.com")

    assert {a for a, _, _ in world.network.sent} == {RESOLVER}


def test_a_blocked_outside_server_is_explained(world: SimpleNamespace) -> None:
    report = dnssec_check("example.com", nameserver="1.1.1.1")  # no handler: times out

    assert report.status is DnssecStatus.UNKNOWN
    assert world.blocking_calls == 1
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "Direct DNS queries are blocked by the VPN"
    assert "No reply from 1.1.1.1" in diagnosis.explanation
    assert "1.1.1.1 is almost certainly fine; it just can't" in diagnosis.explanation
    assert "kill switch" in diagnosis.explanation


def test_a_silent_private_server_isnt_called_blocked(world: SimpleNamespace) -> None:
    report = dnssec_check("example.com", nameserver="192.168.1.1")

    assert world.blocking_calls == 0
    assert "no response from 192.168.1.1" in report.error


def test_a_name_that_doesnt_exist(world: SimpleNamespace) -> None:
    proof = world.example.nsec("example.com.", "www.example.com.", "NS SOA RRSIG NSEC DNSKEY")
    world.deny("missing.example.com.", "NS DS DNSKEY A", proof, rcode="NXDOMAIN")

    report = dnssec_check("missing.example.com")

    assert report.name_missing
    assert report.status is DnssecStatus.SECURE
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "missing.example.com doesn't exist"
    assert "signed NSEC/NSEC3 records prove" in diagnosis.explanation


def test_invalid_names_raise(world: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="is not a valid domain name"):
        dnssec_check("not a domain!")


# --- Clock --------------------------------------------------------------------------------


def soa_fetched(serial: str) -> Fetched:
    return Fetched("NOERROR", rrset(".", "SOA", f"a.root-servers.net. nstld. {serial} 1 2 3 4"))


NO_KEYS = Fetched("NOERROR")


def test_clock_matching_the_root_zone_is_ok() -> None:
    now = datetime(2026, 10, 31, 9, tzinfo=UTC)
    clock = check_clock(soa_fetched("2026103000"), NO_KEYS, now)

    assert clock.state is ClockState.OK
    assert clock.summary == "looks right (root zone from 2026-10-30)"
    assert clock_diagnosis(clock) is None


@pytest.mark.parametrize(
    ("now", "direction"),
    [(datetime(2025, 1, 3, tzinfo=UTC), "behind"), (datetime(2027, 6, 1, tzinfo=UTC), "ahead")],
)
def test_clock_far_from_the_root_zone_is_wrong(now: datetime, direction: str) -> None:
    clock = check_clock(soa_fetched("2026103000"), NO_KEYS, now)

    assert clock.state is ClockState.WRONG
    assert direction in clock.summary
    diagnosis = clock_diagnosis(clock)
    assert diagnosis is not None and diagnosis.title == "This computer's clock looks wrong"
    assert "2026-10-30" in diagnosis.explanation
    assert "automatically" in diagnosis.suggestion


def test_clock_outside_the_root_signatures_is_wrong(world: SimpleNamespace) -> None:
    keys = dnssec_mod._parse(
        reply(
            dns.message.make_query(".", "DNSKEY"),
            answer=world.answers[(".", "DNSKEY")][1],
        ),
        dns.name.root,
        dns.rdatatype.DNSKEY,
    )
    clock = check_clock(Fetched(None), keys, datetime.now(UTC) + timedelta(days=60))

    assert clock.state is ClockState.WRONG
    assert "validity dates" in clock.summary


def test_clock_without_a_root_zone_date_is_unknown() -> None:
    clock = check_clock(Fetched(None), NO_KEYS)

    assert clock.state is ClockState.UNKNOWN


def test_a_wrong_clock_is_blamed_for_expired_signatures(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.put(
        ".",
        "SOA",
        rrset(".", "SOA", "a.root-servers.net. nstld. 2020010100 1 2 3 4"),
        world.root,
    )
    soa = rrset("example.com.", "SOA", "ns1.example.com. admin.example.com. 1 2 3 4 5")
    world.put("example.com.", "SOA", soa, world.example, expired=True)

    report = dnssec_check("example.com")

    assert report.clock.state is ClockState.WRONG
    diagnosis = explain_dnssec(report)
    assert "clock is wrong" in diagnosis.title


# --- More ways a chain can break ---------------------------------------------------------------


def test_an_unsigned_ds_is_bogus(world: SimpleNamespace) -> None:
    ds = dns.rrset.from_rdata(world.example.name, 3600, world.example.ds())
    world.put("example.com.", "DS", ds, None)

    report = dnssec_check("example.com")

    zone = report.zones[-1]
    assert (zone.status, zone.kind) == (ZoneStatus.BOGUS, BogusKind.MISSING_SIGNATURE)
    assert zone.summary == "the DS record at com. isn't signed"


def test_unsigned_keys_are_bogus(world: SimpleNamespace) -> None:
    world.put("example.com.", "DNSKEY", world.example.dnskey, None)

    report = dnssec_check("example.com")

    assert report.zones[-1].kind is BogusKind.MISSING_SIGNATURE
    assert report.zones[-1].summary == "its DNSKEY records aren't signed"


def test_an_unsigned_record_is_bogus(world: SimpleNamespace) -> None:
    world.put("example.com.", "A", rrset("example.com.", "A", "192.0.2.80"), None)

    report = dnssec_check("example.com")

    record = report.records[-1]
    assert (record.status, record.kind, record.summary) == (
        ZoneStatus.BOGUS,
        BogusKind.MISSING_SIGNATURE,
        "not signed",
    )


def test_a_zone_without_a_soa_cant_be_checked(world: SimpleNamespace) -> None:
    del world.answers[("example.com.", "SOA")]

    report = dnssec_check("example.com")

    soa = report.records[0]
    assert (soa.rtype, soa.status, soa.summary) == (
        "SOA",
        ZoneStatus.UNKNOWN,
        "couldn't fetch (no SOA record)",
    )
    assert report.status is DnssecStatus.UNKNOWN
    assert explain_dnssec(report).title == "Couldn't check DNSSEC"


def test_a_name_without_an_a_record_is_checked_through_its_zone(world: SimpleNamespace) -> None:
    del world.answers[("example.com.", "A")]

    report = dnssec_check("example.com")

    assert [r.rtype for r in report.records] == ["SOA"]
    assert report.status is DnssecStatus.SECURE


def test_root_keys_signed_by_the_wrong_key_are_bogus(world: SimpleNamespace) -> None:
    world.put(".", "DNSKEY", world.root.dnskey, world.root)  # by the ZSK, not the anchored KSK

    report = dnssec_check("example.com")

    assert report.zones[0].status is ZoneStatus.BOGUS
    assert report.zones[0].summary.startswith("root key set: ")


def test_signatures_not_valid_yet_say_so(world: SimpleNamespace) -> None:
    soa = rrset("example.com.", "SOA", "ns1.example.com. admin.example.com. 1 2 3 4 5")
    now = int(time.time())
    sig = dns.dnssec.sign(
        soa,
        world.example.zsk_private,
        world.example.name,
        world.example.zsk,
        now + DAY,
        now + 9 * DAY,
    )
    world.answers[("example.com.", "SOA")] = (
        "NOERROR",
        [soa, dns.rrset.from_rdata(soa.name, soa.ttl, sig)],
    )

    report = dnssec_check("example.com")

    assert report.records[0].summary.startswith("signature not valid until ")


def test_a_forged_record_gets_the_generic_fix(world: SimpleNamespace) -> None:
    _, sets = world.answers[("example.com.", "A")]
    world.answers[("example.com.", "A")] = (
        "NOERROR",
        [rrset("example.com.", "A", "203.0.113.66"), sets[1]],
    )

    suggestion = explain_dnssec(dnssec_check("example.com")).suggestion

    assert "don't match its records" in suggestion


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (ConnectionResetError(104, "reset by peer"), "reset by peer"),
        (dns.exception.FormError("bad"), "bad"),
    ],
)
def test_a_failed_fetch_leaves_the_link_unknown(
    world: SimpleNamespace, error: Exception, message: str
) -> None:
    serve = world.network.handlers[RESOLVER]

    def failing(query: dns.message.Message):
        return error if question(query) == ("example.com.", "DS") else serve(query)

    world.network.handlers[RESOLVER] = failing

    report = dnssec_check("example.com")

    zone = report.zones[-1]
    assert zone.status is ZoneStatus.UNKNOWN
    assert message in zone.summary
    assert report.status is DnssecStatus.UNKNOWN


def test_an_unreadable_root_serial_leaves_the_clock_unknown(world: SimpleNamespace) -> None:
    world.put(".", "SOA", rrset(".", "SOA", "a.root-servers.net. nstld. 1 1 2 3 4"), world.root)

    report = dnssec_check("example.com")

    assert report.clock.reference is None
    assert report.clock.state is ClockState.UNKNOWN
    assert report.status is DnssecStatus.SECURE  # the chain itself still validates


# --- Denials must be proven ----------------------------------------------------------------


def test_a_stripped_ds_is_not_reported_as_unsigned(world: SimpleNamespace) -> None:
    """Someone on the path hides example.com's DS and keys (a downgrade), with no proof."""
    world.deny("example.com.", "DS DNSKEY")

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.BOGUS
    zone = report.zones[-1]
    assert (zone.zone, zone.status, zone.kind) == (
        "example.com.",
        ZoneStatus.BOGUS,
        BogusKind.UNPROVEN_DENIAL,
    )
    assert zone.summary == (
        "com. says there's no DS record, but no NSEC or NSEC3 records came with it"
    )
    diagnosis = explain_dnssec(report)
    assert diagnosis.title == "A DNSSEC denial for example.com can't be verified"
    assert "may be forged" in diagnosis.explanation
    assert "--server 8.8.8.8" in diagnosis.suggestion


def test_a_forged_nxdomain_is_not_reported_as_missing(world: SimpleNamespace) -> None:
    world.put("www.example.com.", "A", rrset("www.example.com.", "A", "192.0.2.81"), world.example)
    world.deny("www.example.com.", "NS DS DNSKEY A", rcode="NXDOMAIN")

    report = dnssec_check("www.example.com")

    assert not report.name_missing
    assert report.status is DnssecStatus.BOGUS
    zone = report.zones[-1]
    assert (zone.zone, zone.kind) == ("www.example.com.", BogusKind.UNPROVEN_DENIAL)
    assert zone.summary == (
        "example.com. says it doesn't exist, but no NSEC or NSEC3 records came with it"
    )


def test_an_nxdomain_only_for_the_ds_query_needs_proof_too(world: SimpleNamespace) -> None:
    world.deny("www.example.com.", "DS", rcode="NXDOMAIN")

    report = dnssec_check("www.example.com")

    assert report.zones[-1].kind is BogusKind.UNPROVEN_DENIAL


def test_the_nxdomain_proof_may_come_with_the_ds_answer(world: SimpleNamespace) -> None:
    proof = world.example.nsec("example.com.", "www.example.com.", "NS SOA RRSIG NSEC DNSKEY")
    world.deny("missing.example.com.", "NS", rcode="NXDOMAIN")
    world.deny("missing.example.com.", "DS", proof, rcode="NXDOMAIN")

    assert dnssec_check("missing.example.com").name_missing


def test_a_replayed_proof_for_another_name_doesnt_count(world: SimpleNamespace) -> None:
    """A genuine, signed NSEC record that's about a different part of com."""
    world.deny("example.com.", "DS DNSKEY", world.com.nsec("a.com.", "b.com.", "NS RRSIG NSEC"))

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.BOGUS
    assert report.zones[-1].summary.endswith("but its NSEC/NSEC3 records don't prove it")


def test_a_proof_signed_by_the_wrong_zone_doesnt_count(world: SimpleNamespace) -> None:
    proof = world.example.signed(rrset("example.com.", "NSEC", "f.com. NS RRSIG NSEC"))
    world.deny("example.com.", "DS DNSKEY", proof)

    report = dnssec_check("example.com")

    assert report.zones[-1].summary.endswith(
        "but the signatures on its NSEC/NSEC3 records don't verify"
    )


def test_a_proof_whose_record_lists_a_ds_doesnt_count(world: SimpleNamespace) -> None:
    proof = world.com.nsec("example.com.", "f.com.", "NS DS RRSIG NSEC")
    world.deny("example.com.", "DS DNSKEY", proof)

    assert dnssec_check("example.com").status is DnssecStatus.BOGUS


def test_an_nsec3_proof_of_an_unsigned_delegation(world: SimpleNamespace) -> None:
    world.deny("example.com.", "DS DNSKEY", world.com.nsec3_match("example.com.", "NS"))

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.INSECURE
    assert report.zones[-1].summary == "no DS record at com. (NSEC3 proof): not signed"


def test_an_nsec3_opt_out_span_is_unsigned(world: SimpleNamespace) -> None:
    """Like most of .com: unsigned delegations have no NSEC3 records of their own."""
    proof = world.com.nsec3_match("com.", "NS SOA RRSIG DNSKEY NSEC3PARAM")
    proof += world.com.nsec3_cover("example.com.", opt_out=True)
    world.deny("example.com.", "DS DNSKEY", proof)

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.INSECURE
    assert report.zones[-1].summary == "no DS record at com. (NSEC3 opt-out proof): not signed"


def test_an_nsec3_span_without_opt_out_proves_no_ds_only_for_a_wildcard(
    world: SimpleNamespace,
) -> None:
    proof = world.com.nsec3_match("com.", "NS SOA RRSIG DNSKEY NSEC3PARAM")
    proof += world.com.nsec3_cover("example.com.")
    world.deny("example.com.", "DS DNSKEY", proof)

    assert dnssec_check("example.com").status is DnssecStatus.BOGUS


def test_an_nsec3_nxdomain_proof(world: SimpleNamespace) -> None:
    proof = world.example.nsec3_match("example.com.", "NS SOA RRSIG DNSKEY NSEC3PARAM")
    proof += world.example.nsec3_cover("missing.example.com.")
    proof += world.example.nsec3_cover("*.example.com.")
    world.deny("missing.example.com.", "NS DS DNSKEY A", proof, rcode="NXDOMAIN")

    report = dnssec_check("missing.example.com")

    assert report.name_missing
    assert report.status is DnssecStatus.SECURE


def test_an_nsec3_nxdomain_proof_must_rule_out_a_wildcard(world: SimpleNamespace) -> None:
    proof = world.example.nsec3_match("example.com.", "NS SOA RRSIG DNSKEY NSEC3PARAM")
    proof += world.example.nsec3_cover("missing.example.com.")
    world.deny("missing.example.com.", "NS DS DNSKEY A", proof, rcode="NXDOMAIN")

    report = dnssec_check("missing.example.com")

    assert not report.name_missing
    assert report.zones[-1].kind is BogusKind.UNPROVEN_DENIAL


def test_a_failed_ds_query_is_unknown_not_unsigned(world: SimpleNamespace) -> None:
    world.answers[("example.com.", "DS")] = ("SERVFAIL", [])

    report = dnssec_check("example.com")

    assert report.status is DnssecStatus.UNKNOWN
    assert report.zones[-1].summary == "couldn't fetch: SERVFAIL"


def test_compact_denial_shows_a_missing_name(world: SimpleNamespace) -> None:
    """Some signers answer NOERROR with an NSEC listing NXNAME instead of NXDOMAIN."""
    proof = world.example.nsec("gone.example.com.", "\000.gone.example.com.", "RRSIG NSEC TYPE128")
    world.deny("gone.example.com.", "NS DS DNSKEY A", proof)

    report = dnssec_check("gone.example.com")

    assert report.name_missing
    assert report.status is DnssecStatus.SECURE
