# dnskit

A command-line DNS troubleshooting toolkit. A web UI is planned later, so the code is
structured so the DNS logic can be reused by more than one front end.

## Architecture

- `src/dnskit/core/` — all DNS logic. Functions take plain arguments and return typed
  dataclasses. Core code must **never** print, and must not import `rich` or `typer`.
  Expected failures (NXDOMAIN, timeouts, no answer) are reported as data on the result
  (`LookupStatus`), not by printing or raising. Invalid input raises `ValueError`.
  - `lookup.py` — `lookup(name, rtypes, nameserver, timeout) -> LookupReport`. Queries every
    rtype in parallel (one thread and one `dns.resolver.Resolver` per type — don't share a
    resolver across threads). Defaults to `DEFAULT_RTYPES` (A, AAAA, MX, CNAME, NS, TXT).
  - `nameservers.py` — reads system nameservers, probes them (`probe`, `probe_all`) and
    picks one (`choose_nameserver` → `ResolverChoice`, cached on disk).
    `configured_nameservers()` is dnspython's raw list; `system_nameservers()` is only the
    ones on a connected adapter (`classify_nameservers` → `SystemNameservers` with
    `usable` / `ignored`). Everything that queries "system" servers uses the latter.
  - `adapters.py` — `scan_adapters() -> AdapterScan` (adapters, connected or not, and each
    one's DNS servers; never raises — failures go in `.error`). Windows: ctypes
    `GetAdaptersAddresses` (fast, same data as `Get-DnsClientServerAddress`) plus the
    registry's `NameServer`/`DhcpNameServer` values for ghosts. macOS: `ifconfig -a` +
    `scutil --dns` (scoped section). Linux: `/sys/class/net` + `resolvectl dns`. Bridge
    members (`Adapter.bridged_into`) have no IP settings, so they're excluded from
    `AdapterScan.connected`. Windows finds them by walking `GetIfStackTable` down from each
    adapter through filter layers (`bridge_members`), since `GetAdaptersAddresses` omits
    them; macOS reads `member:` lines; Linux reads `<bridge>/brif/`. `Adapter.vpn`
    (`is_vpn`) guesses VPNs from name/description keywords (`_VPN_WORDS`); generic tunnel
    names (`tun0`, `utun3`, `wg0`) count only with DNS servers, since macOS always has idle
    `utun`s. `AdapterScan.connected_vpns` lists the connected ones. Command
    output is parsed by pure `parse_*` functions so tests use sample text. It runs on every
    lookup, so keep it fast (no PowerShell).
  - `local.py` — `local_check(timeout) -> LocalReport` for `dnskit local`: adapters,
    every mentioned server probed (`ServerCheck`: adapters, `used`, `ghost`), hosts file
    entries that override DNS (`parse_hosts`), the OS's flush command (`flush_command`),
    and `Problem`s (severity, title, detail, fix, `ProblemKind` — wording lives here, like
    `diagnosis.py`; the kind lets `doctor` weigh them).
    The CLI exits 1 only on `Severity.ERROR`. VPN-aware: with a VPN connected, an in-use
    server that fails and isn't on a VPN adapter is `ServerCheck.vpn_blocked` and gets one
    grouped "outside the VPN" warning that says not to remove it, never the usual "remove
    it" fix. `ServerCheck.public` names well-known public resolvers (`WELL_KNOWN_RESOLVERS`);
    when one fails, the wording says it's blocked (firewall/VPN), not down. It runs in two
    parallel phases: probes + interception checks, then NXDOMAIN hijack checks on the
    in-use servers that answered and the IPv6 check through them (fastest first), so the
    total stays ~1 s per timeout. Results: `LocalReport.hijack`, `.interception`, `.ipv6`.
    `probe_ghosts=False` (used by `doctor`) leaves ghosts untested (`ServerCheck.probed`
    False, never `failed`), saving the dead ones' timeout.
  - `integrity.py` — honest-DNS checks, no fallback (`ask()`: one UDP query to one server,
    never raises → `RawAnswer`). `check_nxdomain` asks for a random `dnskit-nx-<hex>.com`;
    an address back is hijacking. `check_google` asks 8.8.8.8 for
    `o-o.myaddr.l.google.com` TXT (Google answers with its resolver's address, checked
    against `_GOOGLE_NETWORKS`, which must cover every prefix in Google's
    `publicdns.json`); `check_cloudflare` asks 1.1.1.1 for `whoami.cloudflare`
    CH TXT (only Cloudflare answers with an address). Pure `classify_*` functions turn a
    `RawAnswer` into a `Verdict` (OK / SUSPECT / UNKNOWN); no response is UNKNOWN, never
    interception.
  - `connectivity.py` — `tcp_connect` (→ `ConnectAttempt`, `ConnectError` refused /
    timed out / unreachable / failed; never raises) and `check_ipv6` (`ipv6_source_address`
    via a connected UDP socket, then AAAA for `www.google.com` and a connection to 443).
    No IPv6 address is `NOT_AVAILABLE` (fine), not a problem; `BROKEN` = AAAA works but
    connecting fails.
  - `reach.py` — `reach(target, port, ...) -> ReachReport` for `dnskit reach`: A + AAAA in
    parallel via `_choose_nameservers`/`_query_one`, then `tcp_connect` to up to
    `MAX_ADDRESSES_PER_FAMILY` of each. `verdict` is DNS (no address, or only 0.0.0.0 /
    loopback = blocked by a DNS filter), CONNECTION or REACHABLE; `explain_reach` words it
    as a `Diagnosis`. IPv6 attempts that are unreachable (no IPv6 here) are ignored when
    judging. CLI exits 0 / 1 (DNS) / 3 (connection) / 2 (bad input). `parse_target`
    accepts URLs.
  - `reverse.py` — `reverse_lookup(ip, ...) -> ReverseReport`. Validates with `parse_ip`
    (IPv4/IPv6, strips IPv6 zone ids) before any network access, then reuses
    `_choose_nameservers` / `_query_one` from `lookup.py` for the PTR query.
  - `compare.py` — `compare(name, rtype, timeout) -> CompareReport`. Queries
    `PUBLIC_RESOLVERS` (Google, Cloudflare, Quad9) plus every system nameserver (deduped by
    IP, labelled `System #n` in system order) in parallel, each **alone** via `_query_one`
    with `[ns]` so no fallback hides a resolver's own answer. Answers compare as
    (status, set of values): order and TTL ignored, names case-insensitive (not TXT).
    NXDOMAIN/NO_ANSWER are answers; other statuses are `Agreement.FAILED` and excluded. The
    most common answer is the majority; a tie means no majority (everyone `DIFFERS`). The
    CLI exits 1 unless `all_agree`. Default timeout `COMPARE_TIMEOUT_S` (2 s), since the
    slowest resolver sets the total time. The majority logic is `rank_answers()`
    (→ `Ranking`), shared with `propagation.py`.
  - `outside.py` — for commands that query internet servers directly. When those time
    out, `check_blocking()` → `DnsBlocking` (this computer's own DNS servers that answer,
    connected VPN names, and `local_firewall`: a TCP connect to 9.9.9.9:53 refused with
    EACCES/WSAEACCES 10013, i.e. a firewall on this computer such as a VPN kill switch).
    `blocked_diagnosis(blocking, what, alternative, one)` words it: blocked by the VPN,
    blocked by a firewall, or offline (own servers silent too). Only call it when outside
    servers failed, since it probes and opens a socket.
  - `trace.py` — `trace(target, rtype, timeout) -> TraceReport` for `dnskit trace`.
    Iterative from `ROOT_SERVERS` (RD off, EDNS 1232, TCP on truncation via `_send`):
    each level asks up to `SERVERS_PER_LEVEL` servers at once, first usable reply wins,
    the rest are `failures`. A referral must be strictly below the current zone. No
    glue → the NS names' A records via `_query_one` on `system_nameservers()`. Steps end
    REFERRAL / ANSWER / NXDOMAIN / NO_ANSWER / FAILED (`FailReason`). If the root level
    fails with NO_RESPONSE, `check_blocking()`; when the own DNS works, the trace is
    redone through it (`TraceMode.VIA_RESOLVER`: NS of each parent of the name, then
    the records). `explain_trace` (final step) and `trace_blocked_diagnosis` word it.
  - `dnssec.py` — `dnssec_check(target, nameserver, timeout, refresh) -> DnssecReport`.
    Fetches through the chosen resolver (DO + CD, so broken data comes back instead of
    SERVFAIL), all queries in parallel, then validates itself with `dns.dnssec`
    (needs `cryptography`: the `dnspython[dnssec]` dependency): root DNSKEYs against
    `ROOT_TRUST_ANCHORS` (KSK-2017 + KSK-2024), then per zone cut (a parent of the
    name with NS or DS) the signed DS, a DNSKEY matching it, and the signed key set;
    then the zone's SOA and the name's A. `ZoneStatus` per link, `DnssecStatus`
    overall, `BogusKind` for the fix. `check_clock` compares the clock with the root SOA
    serial (YYYYMMDDnn) and the root RRSIG dates. No reply from a public `--server` →
    `check_blocking()`. A resolver that answers without RRSIGs sets
    `DnssecReport.signatures_stripped`; then, without `--server`, `dnssec_check` redoes the
    check through `DNSSEC_FALLBACKS` (8.8.8.8, 1.1.1.1; `_check_through(...,
    diagnose=False)`, so no `check_blocking`) and returns the first that works, with
    `stripped_by` = the system server (still `signatures_stripped` if none worked). CLI exits 0 for SECURE and INSECURE (DNSSEC off isn't an error).
  - `propagation.py` — `propagation(target, rtype, timeout) -> PropagationReport`:
    every `PROPAGATION_RESOLVERS` entry (14: `GLOBAL_REGION` anycast ones first, then
    fixed-location ones by region; only fixed-location resolvers get a region) alone via
    `_query_one` with `retry_after=PROPAGATION_RETRY_S` (0.5 s re-sends inside the 1.5 s
    `PROPAGATION_TIMEOUT_S`; dnspython alone waits 2 s before re-sending, so one lost
    packet would time out a healthy far-away resolver), ranked with `rank_answers`. More than half failing →
    `check_blocking()`; fewer than two answers with a blocking result is `blocked`
    (no percentage). `complete` = at least two answered and none differs. `location_based` (A/AAAA, every anycast resolver
    that answered — at least two — in the majority, only fixed-location ones differ, all
    with addresses) words it as probable geo-DNS instead; it doesn't change the exit code.
  - `doctor.py` — `doctor(target, quick, timeout, on_progress) -> DoctorReport` for
    `dnskit doctor`. No DNS logic of its own: runs `local_check(probe_ghosts=False)`,
    `lookup`, `compare` (A), `reach`, `email_check` and `dnssec_check` in one pool
    (`--quick` skips `SLOW_CHECKS`: compare, email, DNSSEC), after warming the resolver
    choice once so the domain checks don't all probe. Local and lookup start first; the
    `NEEDS_DOMAIN` checks start once the lookup is in or after `LOOKUP_WAIT_S` (0.5 s).
    NXDOMAIN is confirmed via `FALLBACK_RESOLVERS` (`_confirm_missing`): agreed (or no
    answer) → `name_missing`, dependents `CheckRun.reason = SKIP_NO_DOMAIN` (results
    dropped if they had started), score 0; a public resolver finding it → `found_by`, a
    MACHINE major issue. `compare` also `tcp_connect`s to each distinct address answer
    (`answer_checks`): working different addresses are a NOTE (CDN); MAJOR only when some
    resolvers say NXDOMAIN/NO_ANSWER/SERVFAIL/refused while others answer, or an answer
    doesn't respond (timeouts don't count). DNSSEC uses `dnssec_check`'s own fallback for
    stripping resolvers (`dnssec_via`); if none worked, a MACHINE note. DKIM WARNs with
    no selector found are notes. `on_progress(check, state)` is called from worker threads;
    a check that raises becomes `CheckState.ERROR`. `find_issues` turns results into
    `Issue`s (`Area` MACHINE / DOMAIN, `Impact` CRITICAL / MAJOR / MINOR / NOTE, wording
    reused from each check's own explain function), sorted by impact, this computer first
    on ties. It avoids double blame: DNS broken here (`local.has_errors`) hides the
    domain's "couldn't ask" failures; broken DNSSEC explains failed lookups and SERVFAILs;
    a name that fails gets no DNSSEC/email advice; email is MINOR without MX.
    `DoctorReport.failed(check)` still marks such checks failed. `score` = 100 −
    `IMPACT_PENALTY`, at most `MAX_PENALTY_PER_CHECK` per check; `doctor_verdict` words
    it. CLI exits 1 unless `healthy` (no critical/major).
  - `mail.py` (not `email.py`, which would shadow the stdlib package) —
    `email_check(domain, selectors, nameserver, timeout, refresh) -> EmailReport` for
    `dnskit email`. Validates with `normalize_domain` (IDNA, rejects email addresses/URLs)
    before any network access, picks nameservers with `_choose_nameservers` and queries with
    `_query_one` like `lookup`. Stage 1 runs MX, TXT, `_dmarc` TXT and every DKIM selector
    (`DKIM_SELECTORS` + custom) in parallel; stage 2 resolves MX hosts (A/AAAA) while
    fetching SPF include/redirect targets level by level. If MX is NXDOMAIN, or every stage-1
    query failed the same way, `domain_status` says so and the checks are None. Each check
    (`MxCheck`, `SpfCheck`, `DmarcCheck`, `DkimCheck`, base `EmailSection`) carries its raw
    data and `Finding`s (`CheckStatus` PASS/WARN/FAIL, title, explanation, fix — wording
    lives here) in logical order; `status` is the worst, `headline` the first worst. A failed
    query is a FAIL ("Couldn't check …", wording from `explain()`). SPF counts lookups depth
    first (`SpfLookup`), an include reached twice counts twice, loops expand once, macros
    aren't followed; > `SPF_LOOKUP_LIMIT` fails. A domain with exactly `v=spf1 -all` needs no
    DKIM. The CLI exits 1 if `report.failed`.
  - `config.py` — the optional TOML settings file (`config_path()`: `DNSKIT_CONFIG`, else
    `%APPDATA%\dnskit\config.toml` / `~/.config/dnskit/config.toml`). `load_config` →
    `Config` (`settings[command]` with `[defaults]` merged under each command's own
    section, only for settings in `COMMAND_SETTINGS`; `compare_resolvers` as (label, IP);
    `propagation_resolvers` as `PublicResolver`, `region = "global"` → anycast). Unknown
    sections/settings, wrong types and bad resolver entries raise `ConfigError` (a
    ValueError) naming `[section] setting`. Missing file = empty config. `write_template`
    never overwrites. Setting names are long option names (`type`, `selectors`, `json`).
  - `serialize.py` — `to_data(value)`: any report (dataclasses, enums by value, tuples,
    sorted sets, ISO datetimes, paths/IPs as text) → JSON-ready data, for `--json`. Field
    conventions: numeric `*_ms` rounded to `MS_DECIMALS` (1), numeric `*_at` (Unix time) →
    ISO 8601 UTC. A `LookupResult` of a `TEXT_RTYPES` type gets its values through
    `txt_text` (lookup.py; also used by `mail.py`): unquoted, strings joined, escapes undone.
    Reports themselves keep dnspython's quoted text.
  - `batch.py` — `read_domains(text)` → `BatchLine`s (line numbers kept, `#` comments and
    blanks skipped, `parse_target`, invalid ones get `error`); `run_batch(lines, check,
    ...)` → `BatchReport` (`BatchItem` per distinct domain in file order: `ok`, one-line
    `summary` from `summarize_lookup/doctor/email`, the full report, or `error` if the
    check raised; `invalid`, `duplicates`; doctor's summary is the score and the top
    non-note issue, or "no issues"). Up to `parallel` (≤ `MAX_PARALLEL`) at once;
    `on_done` from worker threads. Doctor: `local_check(probe_ghosts=False)` once, passed
    as `doctor(local=...)`.
  - `watch.py` — `watch(target, rtype, nameserver, interval, timeout, sleep, now)` validates
    (name, type, `interval ≥ MIN_INTERVAL_S`) then returns an endless iterator of
    `WatchSample`s, one `lookup` each, sleeping between. Only real answers (`answer_key`
    not None: OK, NXDOMAIN, NO_ANSWER) are compared, with the last real one; `previous` is
    set on a change. Failed lookups never count. `matches(value)` ignores case and the
    final dot. Every value of every real answer is remembered: on a change, `new_values`
    holds the ones never seen before; `rotating` = a change between two answers with
    records and no new values (a CDN pool), `new_change` = any other change.
    `watch_summary(samples)` → `WatchSummary` (counts, `SeenValue`s in first-seen order,
    sorted within an answer). The CLI alerts (CHANGED, beep, `--exit-on-change`) only on
    `new_change`, or on any change with `--strict` (config `[watch] strict`), and prints
    the summary on every stop, Ctrl+C included.
  - `diagnosis.py` — `explain()` / `explain_reverse()` turn a `LookupStatus` into a
    `Diagnosis` (title, plain-English explanation, next-step suggestion). It lives in core so
    the web UI can reuse the wording; keep its text free of CLI flags where possible.
- `src/dnskit/cli/` — presentation only. `app.py` parses arguments with Typer and calls
  into `core`; `render.py` turns core results into Rich output. No DNS logic here.
  - The entry point is `run()` (the `dnskit` script and `python -m dnskit`): it calls the
    app and turns a Windows `OSError(EINVAL)` from a closed pipe into a quiet exit 1, which
    covers Typer's own console (--help, usage errors) as `PipeSafeConsole` covers ours.
  - Every command's `--help` = a docstring/`help=` (what it does) + `epilog=_epilog(examples,
    exit_codes)`. Keep the exit codes there in step with the guide.
  - The `main` callback loads the config (except for `dnskit config`, which reports a
    broken file itself; a broken file is exit 2 for every other command) and sets
    `ctx.default_map` from it, so each command's options default to its section
    (`_PARAMETER_NAMES` maps `type`→`rtype`, `selectors`→`selector`, `json`→`as_json`);
    the command line still wins. `current_config()` gives the resolver lists.
  - Every command has `--json`: `_emit_json(command, report, exit_code, summary,
    diagnosis)` prints one object (`command`, `dnskit_version`, `exit_code`, `summary`,
    `diagnosis`, `report` via `to_data`); `_fail` prints errors as JSON too. Exit codes
    don't change. `watch --json` is JSON Lines (`_print_json_line`, `event` check/end).
    Live progress (`doctor`, `batch`) only on a terminal and never with `--json`.
- A future `dnskit/web/` package will import from `core` the same way the CLI does.

When adding a feature: put the logic in `core` first, return a dataclass, then add the CLI
command and a renderer for it.
The `dnskit-change` skill (`.claude/skills/dnskit-change/SKILL.md`) is the full checklist
for a change: code, tests, live checks, the guide, and the commit/PR routine.

## README screenshots

The README's examples are SVG screenshots in `docs/images/`, not text. `python
scripts/readme_screenshots.py [name ...]` regenerates them: each `Shot` runs the real command
in-process with `cli_app.console` swapped for a recording `Console` (not a terminal, so no
live progress) and `save_svg`. `use_demo_computer()` replaces `scan_adapters`,
`configured_nameservers` and `read_hosts` in every `dnskit.core` module with a demo profile
(Wi-Fi, 1.1.1.1 + 8.8.8.8, no hosts entries) and the displayed cache path, so no image shows
a real machine; queries and connections stay real. Domains are reserved examples.
`tests/test_readme_screenshots.py` checks capture offline and that every README image
exists. The guide keeps its text examples.

## User guide

`docs/USER_GUIDE.md` is the user-facing reference. Keep it current in the same change as
the code: any new or changed command, option, output line, error message, exit code or
file must be updated there. That includes the quick-reference table, the command's section
with a real example (captured from an actual run, with personal IPs replaced), the error
section if a new `Diagnosis` was added, and a row in the "Guide changelog". README stays
short and links to the guide.

## Resolver selection (why it works this way)

dnspython tries system nameservers strictly in registry order with a 2 s per-server timeout
and, unlike the Windows DNS client, never learns that one is dead. A non-responding server
first in the list therefore added ~2 s to every query. dnspython also reads the registry
entries of disconnected adapters and of adapters that no longer exist ("ghosts"), which
Windows ignores; so `system_nameservers()` keeps only servers on a connected adapter
(loopback stubs always; everything if adapters can't be matched or nothing would be
left). Then, without `--server`, `lookup` and `reverse` use `choose_nameserver`, which probes all system nameservers in parallel and picks
the **fastest**; the rest stay as fallbacks (by latency, non-responders last). Keep these
properties when changing it:

- **The choice is cached** (`cache_path()`, `resolver.json` under `%LOCALAPPDATA%\dnskit`
  or `~/.cache/dnskit`; override with `DNSKIT_CACHE_DIR`) for `CACHE_TTL_S` (5 min), so
  repeated commands use the same nameserver instead of whichever won a close race. A cached
  choice is only reused for the exact same system nameserver list (a different list means
  the network changed). A choice where nothing answered is never cached. Any cache
  read/write problem is silently a miss.
- A fresh probe **waits for every server** (up to `PROBE_TIMEOUT_S`, 1 s) so it can report
  failed and slow (> `SLOW_THRESHOLD_MS`) servers. That costs up to 1 s when a server is
  dead, which is why it's cached rather than done per command.
- **`--server` always wins**: it skips `choose_nameserver` entirely, so the cache is never
  read or written. `--refresh` re-probes (and re-caches) instead of using the cache.
  `dnskit resolvers` always re-probes, shows every server's latency, and refreshes the cache.
- The resolver is chosen once per report and shown once (`nameserver`, `nameserver_source`,
  `resolver_choice`), on success and failure alike. Don't add per-record nameservers. The
  CLI footer lists failed/slow servers from `resolver_choice` and notes a cached choice's
  age.

## Error handling

Every `LookupStatus` other than `OK` must have a `Diagnosis` in `diagnosis.py` (a test
enforces this). When adding a status, add its explanation, its short table label in
`cli/render.py` (`_STATUS_LABELS`), and tests for both.

How dnspython failures map to statuses (`_query_one` / `_classify_nameserver_errors`):

- `NXDOMAIN` → NXDOMAIN; `NoAnswer` → NO_ANSWER; `dns.exception.Timeout` → TIMEOUT.
- `NoNameservers` carries `kwargs["errors"]`, one `(server, tcp, port, error, response)`
  entry per failed attempt; `error` is an exception or rcode text. Any `"SERVFAIL"` →
  SERVFAIL. **All** errors being "no route" `OSError`s (ENETUNREACH etc., or Windows WSA
  codes 10050/10051/10065) → NO_NETWORK. Anything else (REFUSED, connection reset from a
  closed port, a mix) → NO_NAMESERVERS. Don't call it NO_NETWORK unless every server was
  unreachable.

Rendering rules: in a multi-type lookup, a type with no records is normal, so NO_ANSWER is
explained only when it's every type's result (or a single `--type` lookup). Identical
failures across types share one panel. Exit codes: 0 success (or the name exists), 1
lookup failed / name doesn't exist, 2 invalid input.

## Conventions

- Type hints on every function signature and dataclass field.
- Every new feature gets tests in `tests/`. The default test suite must not hit the live
  network:
  - An autouse fixture points `DNSKIT_CACHE_DIR` at a temp dir, so no test touches the
    real resolver cache.
  - Core lookup and reverse tests use the `env` fixture (`tests/conftest.py`), which
    monkeypatches `_make_resolver`, `system_nameservers` and `choose_nameserver` on the
    `dnskit.core.lookup` module and returns knobs (`responses`, `choice`, `system`) plus
    what was queried and `choose_calls`. Build choices with `make_choice({ns: latency})`. Fakes live in `tests/fakes.py`; use `no_nameservers(...)` to
    build realistic `NoNameservers` errors. (`dnskit.core.lookup` as an attribute is the
    re-exported function, so conftest gets the module via `importlib.import_module`.)
  - `FakeResolver` answers by `(name, rtype)` key first, then by `rtype`. Email tests
    (`tests/test_mail.py`) use the `env` fixture with `(name, rtype)` keys only (names
    without a trailing dot), `txt(...)` for quoted TXT answers and `rsa_key(bits)` for DKIM
    keys. Parallel queries arrive in any order, so compare `env.queried` as a set.
  - Compare tests (`tests/test_compare.py`) use their own `cmp_env` fixture: a per-server
    fake resolver patched in as `lookup_mod._make_resolver`, plus `system_nameservers` on
    the `dnskit.core.compare` module.
  - Nameserver tests monkeypatch `dnskit.core.nameservers.probe`, and `_now` to test
    cache expiry.
  - No test may read the real system configuration. Adapter tests (`tests/test_adapters.py`)
    feed sample command output to the `parse_*` functions, patch `adapters_mod._run`, and
    pass a temp dir as `sys_net` to `_linux_scan`; `classify_nameservers` takes explicit
    `configured` and `scan` arguments. `dnskit local` tests (`tests/test_local.py`) use the
    `local_env` fixture, which patches `scan_adapters`, `configured_nameservers`,
    `probe_all`, `read_hosts`, `platform_name`, `flush_command`, `check_nxdomain`,
    `check_google`, `check_cloudflare` and `check_ipv6` on `dnskit.core.local` (knobs:
    `hijacked`, `google`, `cloudflare`, `ipv6`). `tests/test_integrity.py` fakes
    `dns.query.udp` and feeds `RawAnswer`s to the classifiers; `tests/test_connectivity.py`
    uses loopback sockets (a listening and a closed port) plus a fake `socket.socket`;
    `tests/test_reach.py` builds on `env` and patches `tcp_connect` and `read_hosts` on
    `dnskit.core.reach`.
  - Code that sends its own DNS messages (`trace`, `dnssec`) has a module-level
    `_send(query, address, timeout)`; tests replace it with `fakes.FakeNetwork`
    (per-address handlers returning `fakes.reply(query, answer=..., authority=...)`
    built from `fakes.rrset(...)`; no handler = timeout) and patch `check_blocking`.
    `tests/test_trace.py`'s `net` fixture is a root → com. → example.com. delegation
    (also patches `_query_one` and `system_nameservers` for glue-less lookups); the
    first reply at a level wins, so don't assert which of the parallel servers did.
    `tests/test_dnssec.py` signs a test root/com./example.com. with throwaway Ed25519
    keys and patches `ROOT_TRUST_ANCHORS` and `_choose_nameservers` (`world.strip` makes
    the system resolver drop RRSIGs; `world.serve(strips=False)` is a fallback); its root SOA
    serial is today's date so the clock check passes. `tests/test_propagation.py`
    patches `_query_one` and `check_blocking`; `tests/test_outside.py` patches
    `scan_adapters`, `classify_nameservers`, `probe_all` and `socket.socket`.
    `tests/test_doctor.py`'s `checks` fixture patches every check function and
    `system_nameservers`/`choose_nameserver` on `dnskit.core.doctor` and returns healthy
    results (knobs: `local`, `lookup`, `compare`, `reach`, `email`, `dnssec`, `crash`,
    `public` for lookups with `nameserver=`, `dead` addresses for its fake
    `tcp_connect`, `lookup_delay`); DNSSEC results are stubs, with
    `explain_dnssec`/`clock_diagnosis` patched.
    `tests/test_batch.py`'s `fakes` patches `lookup`, `doctor`, `email_check`,
    `local_check` (and `summarize_doctor`) on `dnskit.core.batch`; `tests/test_watch.py`
    patches `lookup` on `dnskit.core.watch` and passes `sleep`/`now`. `tests/test_config.py`
    uses `parse_config(text, path)`. An autouse fixture points `DNSKIT_CONFIG` at a temp
    file, so no test reads the user's config; CLI tests write it with `write_config(...)`.
    CLI `batch`/`watch` tests patch `run_batch`/`watch` on `dnskit.cli.app`; their
    `sample(...)` helper marks a change's values as new unless `new_values` is given
    (pass `()` for rotation).
    The Windows ctypes/registry readers can only be checked with a live run.
  - CLI tests use `typer.testing.CliRunner` and patch the core functions imported into
    `dnskit.cli.app` (e.g. `lookup`, `reverse_lookup`, `choose_nameserver`). Assert on
    `plain(result.output)`, which strips the ANSI colours Typer forces in CI.
- Python 3.11+; ruff handles linting and formatting (line length 100). Its rules are in
  pyproject.toml; `TID251` bans `rich`/`typer` imports outside `dnskit.cli` (and tests),
  enforcing the core rule. The en dash (–) is an allowed character.
- mypy runs **strict** on `src/` (`[tool.mypy]`; tests aren't type-checked). Platform code
  must type-check on every OS: guard Windows-only code with `if sys.platform != "win32":
  return ...` (mypy skips the rest elsewhere), and use
  `# type: ignore[attr-defined,unused-ignore]` for `ctypes.windll`. Check other platforms
  locally with `mypy --platform linux` / `--platform darwin`.
- Coverage: `pytest --cov` (branch coverage, `fail_under = 95`; core is ~99%). The ctypes
  readers in adapters.py are `# pragma: no cover` (they need a live Windows system).
- Before committing: `ruff check .`, `ruff format .`, `mypy`, `pytest --cov`. CI
  (`.github/workflows/ci.yml`) runs all four on every push (and on pull requests from
  forks; a PR from this repository's own branch isn't run twice), on Ubuntu,
  Windows and macOS × Python 3.11 and 3.13, and uploads coverage.xml from one job.
- CONTRIBUTING.md is the contributor-facing version of these conventions; keep it in step.
- The version lives only in `pyproject.toml`; `dnskit.__version__` reads the installed
  metadata (`importlib.metadata`), so reinstall (`pip install -e .`) after changing it.
  User-visible changes get a line under `## [Unreleased]` in CHANGELOG.md (Keep a
  Changelog). Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`: tag must match
  the version, build + `twine check`, install the wheel, then a GitHub Release whose notes
  are `scripts/release_notes.py X.Y.Z` (that version's section). No PyPI publishing.

## Commands

```bash
.venv\Scripts\activate                      # activate the virtualenv (Windows)
pip install -e ".[dev]"                     # install with dev tools
dnskit lookup example.com                   # all default record types
dnskit lookup example.com -t MX -s 1.1.1.1  # one type, explicit nameserver
dnskit reverse 8.8.8.8                      # reverse (PTR) lookup, IPv4 or IPv6
dnskit lookup example.com --refresh         # re-probe instead of the cached choice
dnskit compare example.com -t MX            # same query via public + system resolvers
dnskit email example.com --selector s1      # MX, SPF, DMARC, DKIM checks (+ a selector)
dnskit resolvers                            # probe system nameservers, refresh cache
dnskit local                                # adapters, DNS servers, ghosts, hosts file, checks
dnskit reach example.com -p 443             # DNS problem (exit 1), connection (3) or neither
dnskit trace example.com                    # delegation from the root servers down
dnskit dnssec example.com                   # DS/DNSKEY chain of trust + clock check
dnskit propagation example.com -t MX        # 14 public resolvers worldwide, % agreeing
dnskit doctor example.com --quick           # health score + ranked issues (no email/DNSSEC)
dnskit batch domains.txt -c doctor          # lookup/doctor/email on a list, summary table
dnskit watch example.com --until 192.0.2.1  # re-check every 30 s, beep on change
dnskit lookup example.com --json            # any command: one JSON object (watch: JSON Lines)
dnskit config                               # settings file location and contents (--init)
pytest --cov                                # tests + coverage (fails under 95%)
ruff check . && ruff format .               # lint + format
mypy                                        # strict type check of src/
```
