# Changelog

All notable changes to dnskit are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and dnskit uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-13

The first release. Every command explains what it finds in plain English, with a suggested
fix, and works on Windows, macOS and Linux with Python 3.11 or newer.

### Added

#### Commands

- `doctor`: a full health check of this computer and a domain in one command. It runs the
  `local`, `lookup`, `compare`, `reach`, `email` and `dnssec` checks in parallel with a
  live progress list. The result is a score out of 100, a verdict, and issues ranked
  critical, major, minor or note, split into "this computer" and "the domain", each with a
  fix. `--quick` skips the comparison, email and DNSSEC checks.
- `lookup`: A, AAAA, MX, CNAME, NS and TXT queried in parallel and shown in one table.
  `--type` limits it to one type, and `--server` picks the nameserver.
- `reverse`: the hostname for an IPv4 or IPv6 address (PTR).
- `compare`: the same question to Google, Cloudflare, Quad9 and every system DNS server,
  each asked alone, with answers that differ from the majority highlighted.
- `email`: MX (with each mail server's addresses), SPF (syntax, a single record, `all`,
  and the 10-lookup limit counted across includes), DMARC (the policy explained) and DKIM
  (common selectors plus `--selector`, and key size). Each check passes, warns or fails,
  with a fix.
- `local`: this computer's DNS setup.
  - Lists each adapter and its DNS servers, and tests every server.
  - Finds dead, slow and "ghost" servers (left over from old or disconnected adapters),
    and hosts file entries that override DNS.
  - Detects NXDOMAIN hijacking and interception of 8.8.8.8 and 1.1.1.1, and checks IPv6.
  - Prints the command that flushes the DNS cache.
  - Knows about VPNs and network bridges.
- `reach`: whether a site's problem is DNS or the connection. It resolves the name and
  connects to port 443 (or `--port`). Exits 1 for a DNS problem and 3 for a connection
  problem.
- `trace`: the delegation from the root servers down, step by step, showing which level
  fails and why.
- `dnssec`: the chain of trust from the root trust anchors down (DS, DNSKEY and
  signatures at every level) and a check of the computer's clock. It retries through
  8.8.8.8 or 1.1.1.1 when the local DNS server strips signatures.
- `propagation`: 14 public resolvers worldwide (global anycast ones, and fixed-location
  ones in the Americas, Europe and Asia), with the percentage giving the same answer. It
  recognises answers that differ by location (CDN or geo-DNS).
- `resolvers`: each system DNS server's response time, and which one dnskit uses.
- `batch`: `lookup`, `doctor` or `email` on a list of domains, a few at a time, ending in
  a summary table.
- `watch`: re-checks a record every N seconds, beeps when it changes, and lists every
  value seen when stopped. Addresses already seen count as rotation (a CDN), not a change,
  unless `--strict` is given. Also has `--until`, `--count` and `--exit-on-change`.
- `config`: shows or creates (`--init`) a TOML settings file, with defaults per command
  and custom resolver lists for `compare` and `propagation`.

#### Across all commands

- `--json` on every command: one object with `command`, `exit_code`, `summary`,
  `diagnosis` and the full report (`watch` writes JSON Lines). Exit codes are stable:
  0 success, 1 problem found, 2 invalid input, 3 connection problem (`reach`).
- Automatic nameserver choice. The fastest working system DNS server is picked and
  remembered for 5 minutes, and only servers on connected adapters are used. Failed or slow
  servers are reported under results. `--refresh` re-checks.
- A plain-English explanation and next step for every failure: NXDOMAIN, no records,
  SERVFAIL, timeouts, no network, refused, and DNS to outside servers blocked by a VPN or
  firewall.
- `--help` on every command, with examples and exit codes. `python -m dnskit` works like
  `dnskit`.
- The [User Guide](https://github.com/gladkhumalo/dnskit/blob/main/docs/USER_GUIDE.md): every command, option and error message, plus
  troubleshooting recipes.

[Unreleased]: https://github.com/gladkhumalo/dnskit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gladkhumalo/dnskit/releases/tag/v0.1.0
