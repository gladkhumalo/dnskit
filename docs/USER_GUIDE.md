# dnskit User Guide

The complete reference for **dnskit**, a command-line DNS troubleshooting toolkit: what
each command does, every option, how to read the output, what each error means, and
step-by-step recipes for common DNS problems.

> **Version:** this guide describes dnskit 0.1.0 (`dnskit --version`). See
> [Guide changelog](#guide-changelog) for what was added when.

## Contents

1. [What dnskit is for](#1-what-dnskit-is-for)
2. [Installation](#2-installation)
3. [Quick reference](#3-quick-reference)
   - [Which command for which situation](#which-command-for-which-situation)
4. [DNS in two minutes](#4-dns-in-two-minutes)
5. [Commands](#5-commands)
   - [`dnskit doctor`](#dnskit-doctor)
   - [`dnskit lookup`](#dnskit-lookup)
   - [`dnskit reverse`](#dnskit-reverse)
   - [`dnskit compare`](#dnskit-compare)
   - [`dnskit email`](#dnskit-email)
   - [`dnskit local`](#dnskit-local)
   - [`dnskit reach`](#dnskit-reach)
   - [`dnskit trace`](#dnskit-trace)
   - [`dnskit dnssec`](#dnskit-dnssec)
   - [`dnskit propagation`](#dnskit-propagation)
   - [`dnskit resolvers`](#dnskit-resolvers)
   - [`dnskit batch`](#dnskit-batch)
   - [`dnskit watch`](#dnskit-watch)
   - [`dnskit config`](#dnskit-config)
   - [Global options](#global-options)
6. [Reading the output](#6-reading-the-output)
7. [How dnskit chooses a nameserver](#7-how-dnskit-chooses-a-nameserver)
8. [When a lookup fails: every error explained](#8-when-a-lookup-fails-every-error-explained)
9. [Troubleshooting recipes](#9-troubleshooting-recipes)
10. [Using dnskit in scripts](#10-using-dnskit-in-scripts)
11. [Files and environment variables](#11-files-and-environment-variables)
12. [FAQ](#12-faq)
13. [Guide changelog](#guide-changelog)

---

## 1. What dnskit is for

When a website won't load, email isn't arriving, or a DNS change "isn't working yet",
dnskit helps you find out why. It:

- **Runs a full health check** (`dnskit doctor`): this computer and a domain, with a
  score out of 100 and a ranked list of fixes, telling your own machine's problems apart
  from the domain's.
- **Looks up all the common record types at once** (A, AAAA, MX, CNAME, NS, TXT) and shows
  them in one table.
- **Explains failures in plain English**, such as "domain doesn't exist" or "query timed
  out", with a suggested next step.
- **Does reverse lookups**, finding the hostname for an IPv4 or IPv6 address.
- **Compares resolvers**, asking Google, Cloudflare, Quad9 and your own DNS servers the
  same question and highlighting any that give a different answer.
- **Checks your computer's own DNS setup**: every network adapter and its DNS servers,
  which servers are dead, slow or "ghosts", and hosts file entries that override DNS.
  dnskit avoids the bad servers automatically. It also checks whether your DNS is being
  hijacked or intercepted, and whether IPv6 works.
- **Tells you whether a site's problem is DNS or the connection**, by looking it up and
  then connecting to it.
- **Traces a domain's delegation** from the root servers down, showing which level
  breaks when a domain doesn't work for anyone.
- **Checks DNSSEC**: whether it's enabled and whether the chain of trust validates from
  the root down, with a warning when the computer's clock is wrong.
- **Checks propagation** after a DNS change, asking 14 public resolvers around the world.
- **Checks many domains at once** (`dnskit batch`) and **watches a record** until it changes
  (`dnskit watch`).
- **Prints JSON** for scripts (`--json` on every command), and remembers your preferred
  settings in a config file (`dnskit config`).
- **Explains VPNs and firewalls that block DNS** to outside servers, instead of just
  timing out.

---

## 2. Installation

You need **Python 3.11 or newer** (`python --version`).

**The quickest way: pipx.** [pipx](https://pipx.pypa.io/) installs a command-line tool in
its own environment and puts it on your PATH, so `dnskit` works in every terminal without
activating anything:

```bash
pipx install dnskit
```

`pipx upgrade dnskit` moves to the newest release, and `pip install dnskit` works too, in a
virtual environment. dnskit comes from [PyPI](https://pypi.org/project/dnskit/); each
[GitHub release](https://github.com/gladkhumalo/dnskit/releases) has the same files
attached. [CHANGELOG.md](../CHANGELOG.md) lists what changed in each release.

**From a copy of the code** (for the latest unreleased changes, or to work on dnskit; you
also need **git**):

```bash
git clone https://github.com/gladkhumalo/dnskit.git
cd dnskit
python -m venv .venv
```

Activate the virtual environment:

```bash
.venv\Scripts\activate
```

That's for Windows (PowerShell or cmd). On macOS or Linux use
`source .venv/bin/activate`.

Then install:

```bash
pip install .
```

Developers should use `pip install -e ".[dev]"` instead, which also installs pytest,
pytest-cov, ruff and mypy and picks up code changes without reinstalling. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the checks to run before a pull request.

Check it works:

```bash
dnskit --version
```

**Tips**

- With a virtual environment, `dnskit` is available whenever it's active. `pipx install .`
  in the repository folder installs your copy for every terminal instead.
- Tab completion for your shell: run `dnskit --install-completion` once, then restart the
  shell.

---

## 3. Quick reference

| I want to… | Command |
|---|---|
| Check everything at once and get a ranked list of fixes | `dnskit doctor example.com` |
| A faster health check, without email, DNSSEC and the resolver comparison | `dnskit doctor example.com --quick` |
| See all common records for a domain | `dnskit lookup example.com` |
| See one record type | `dnskit lookup example.com -t MX` |
| Ask a specific DNS server | `dnskit lookup example.com -s 8.8.8.8` |
| Wait longer for slow servers | `dnskit lookup example.com --timeout 10` |
| Re-check my DNS servers before looking up | `dnskit lookup example.com --refresh` |
| Find the hostname for an IP | `dnskit reverse 8.8.8.8` |
| Reverse-lookup an IPv6 address | `dnskit reverse 2001:4860:4860::8888` |
| Check whether all resolvers give the same answer | `dnskit compare example.com` |
| Compare one record type across resolvers | `dnskit compare example.com -t MX` |
| Check a domain's email setup (MX, SPF, DMARC, DKIM) | `dnskit email example.com` |
| Also check a specific DKIM selector | `dnskit email example.com --selector s2024` |
| Check this computer's whole DNS setup | `dnskit local` |
| Find out how to flush the DNS cache | `dnskit local` |
| Check whether my DNS is hijacked or intercepted, and whether IPv6 works | `dnskit local` |
| Find out whether a site's problem is DNS or the connection | `dnskit reach example.com` |
| Test a port other than 443 | `dnskit reach example.com -p 22` |
| Follow a domain's delegation from the root servers | `dnskit trace example.com` |
| Check whether DNSSEC is on and valid | `dnskit dnssec example.com` |
| Check whether a DNS change has spread worldwide | `dnskit propagation example.com -t A` |
| See which of my DNS servers work | `dnskit resolvers` |
| Check a list of domains from a file | `dnskit batch domains.txt` |
| Health-check a list of domains | `dnskit batch domains.txt --check doctor --quick` |
| Be told when a record changes | `dnskit watch example.com` |
| Wait until a new IP address is live | `dnskit watch example.com --until 203.0.113.80` |
| Get any result as JSON for a script | `dnskit <command> ... --json` |
| See or create my settings file | `dnskit config` / `dnskit config --init` |
| Get help for any command | `dnskit <command> --help` |
| Show the version | `dnskit --version` |

**Exit codes:** `0` success, `1` lookup failed or the name doesn't exist, `2` invalid input.
`compare` uses `1` when resolvers disagree, `email` when any check fails, and `local` when
it finds an error. `reach` uses `1` for a DNS problem and `3` for a connection problem. `trace` uses `1`
unless it reached the records, `dnssec` when DNSSEC is broken or couldn't be checked, and
`propagation` until every resolver agrees, `doctor` when it finds a critical or major
issue, `batch` when a domain isn't OK, and `watch` when `--until` wasn't reached (`130`
after Ctrl+C) (see [section 10](#10-using-dnskit-in-scripts)).

### Which command for which situation

If you know the symptom but not the command, start here. When in doubt, run
`dnskit doctor` first: it runs most of the others and says where to look next.

| Situation | Start with | Then |
|---|---|---|
| "Something's wrong with our domain and I don't know what" | `dnskit doctor example.com` | the command its top issue names |
| A website won't load for me | `dnskit reach example.com` | `local` if DNS is the problem on this computer only |
| A website won't load for anyone | `dnskit trace example.com` | `dnssec` if resolvers return SERVFAIL |
| Everything is slow or broken on this computer only | `dnskit local` | `resolvers` to see which DNS server is slow |
| A site works on my phone but not on this network | `dnskit compare example.com` | `local` (hijacking, interception, hosts file) |
| I changed a DNS record and want to know whether it's live | `dnskit lookup example.com -t A` | `propagation` to see how far it has spread |
| Our email lands in spam or bounces | `dnskit email example.com` | `reverse` on the sending server's IP |
| I'm moving to a new DNS host, registrar or email provider | `dnskit doctor example.com` (before and after) | `trace` and `dnssec` after changing nameservers |
| Some people can reach the domain and others can't | `dnskit dnssec example.com` | `propagation` for a recent change |
| An unknown IP address is in my logs | `dnskit reverse 203.0.113.7` | |
| Things broke after connecting a VPN | `dnskit local` | `doctor` to see what still works |
| I'm waiting for a change to go live | `dnskit watch example.com --until <new value>` | `propagation` for other countries |
| I look after many domains | `dnskit batch domains.txt --check doctor` | `doctor` on the ones that aren't OK |

---

## 4. DNS in two minutes

DNS turns names (like `example.com`) into the information computers need. That
information is stored as **records**, and each record has a **type**:

| Type | What it holds | Example value | Used for |
|---|---|---|---|
| **A** | An IPv4 address | `93.184.215.14` | Connecting to a website or server |
| **AAAA** | An IPv6 address | `2606:2800:21f:cb07::1` | The same, over IPv6 |
| **MX** | A mail server, with a priority | `10 mail.example.com.` | Where email for the domain is delivered; **lower number = tried first** |
| **CNAME** | An alias for another name | `github.com.` | `www.example.com` pointing at another name |
| **NS** | The domain's authoritative nameservers | `ns1.example-dns.com.` | Who is in charge of the domain's records |
| **TXT** | Free text | `"v=spf1 -all"` | Email security (SPF, DKIM, DMARC) and ownership checks |
| **PTR** | A hostname for an IP address | `dns.google.` | Reverse lookups (`dnskit reverse`) |

Other words used in this guide:

- **TTL (time to live):** how many seconds other servers may cache a record before asking
  again. After you change a record, the old value can linger for up to its TTL.
- **Resolver / nameserver:** the server your computer asks to look names up. Your network
  usually gives you one (often your router); public ones include `1.1.1.1` (Cloudflare)
  and `8.8.8.8` (Google).
- **Authoritative nameserver:** the server that holds the domain's real records (the NS
  records point to it). Resolvers ask it and cache the answers.
- **Trailing dot:** `mail.example.com.` ends with a dot because it is a fully qualified
  name. It's normal and you can ignore it.

dnskit accepts any record type dnspython knows (for example `SOA`, `SRV`, `CAA`) with
`--type`, but by default it queries the six most useful ones above.

---

## 5. Commands

### `dnskit doctor`

A full health check in one command: this computer's DNS setup first, then the domain.
It runs the other commands' checks together and ends with a **health score out of 100**,
a short verdict and a list of issues, most important first, each with a fix. If you
don't know where a problem is, start here.

**When to use it:**

- A customer says your website is down, and you don't know whether the problem is their
  side, your network or the domain. One run checks all of it and says which.
- Before and after moving a domain to a new DNS host or hosting company, as a checklist:
  records, email, DNSSEC and the connection in one go.
- A daily check of your important domains from a script: `dnskit doctor example.com
  --quick` exits with `1` when something needs attention.
- Handing a problem to someone less technical: the score and the ranked list say what to
  fix first.

```bash
dnskit doctor <domain> [--quick] [--timeout SECONDS]
```

| Option | Default | What it does |
|---|---|---|
| `--quick` | off | Skip the slower checks: the resolver comparison, email and DNSSEC. |
| `--timeout` | `3.0` | Seconds to wait for each query of the domain checks. |

The domain can also be a URL (`https://example.com/page`).

What it checks, at the same time:

| Check | Same as | Skipped by `--quick` |
|---|---|---|
| This computer: adapters, DNS servers (failing, slow, ghosts), VPN, hosts file, hijacking, interception, IPv6 | `dnskit local` (without testing ghost servers) | no |
| Records (A, AAAA, MX, CNAME, NS, TXT) | `dnskit lookup` | no |
| Answers from public resolvers and this computer's DNS servers, and whether each different address works | `dnskit compare` (A) | yes |
| Connection to the domain on port 443: is a problem DNS or the connection? | `dnskit reach` | no |
| Email: MX, SPF, DMARC, DKIM | `dnskit email` | yes |
| DNSSEC chain of trust, and the clock | `dnskit dnssec` | yes |

While it works, a live list shows each check with a spinner and how long it has been
running, then a tick or a cross when it finishes. The list disappears when the report is
printed, and isn't shown when the output goes to a file or another program.

#### Issues and the score

Each issue belongs to **This computer** or to **the domain**, and has an impact:

| Impact | Meaning | Points |
|---|---|---|
| **CRITICAL** | Something doesn't work at all: no DNS server answers, the domain doesn't resolve, DNSSEC is broken. | −40 |
| **MAJOR** | Works badly, or for some people only: hijacking or interception, broken IPv6, a dead DNS server, the site doesn't accept connections, a failing email check, a wrong clock, a hosts file entry for the domain. Also: some resolvers can't find the domain (or fail) while others answer it; a resolver's answer is an address that doesn't respond; this computer's DNS server says the domain doesn't exist while public resolvers find it. | −15 |
| **MINOR** | Worth tidying up: a slow DNS server, an email warning, DNSSEC not enabled. | −5 |
| **NOTE** | Good to know, nothing to fix: ghost DNS servers, servers blocked while a VPN is on, resolvers giving different addresses that all work (a CDN), no DKIM key at the common selectors, a network that strips DNSSEC signatures. Listed in one line each, with the command that has the details. | 0 |

A domain that **doesn't exist** scores **0**, whatever else was found.

The score starts at 100. No single check can take off more than 40 points, so a handful
of email warnings doesn't outweigh a broken website. The issues are sorted by impact;
on a tie, this computer's come first, since a problem here can make the domain look
broken. The section with the most important issue is printed first.

doctor avoids blaming the domain for something else's fault, and counting one problem
several times:

- **A domain that doesn't exist**: when this computer's DNS server says the domain doesn't
  exist (NXDOMAIN), doctor asks 8.8.8.8 (then 1.1.1.1) to make sure. If they agree, or
  can't be asked, the checks that need the domain (the resolver comparison, the
  connection, email and DNSSEC) show **skipped (domain doesn't exist)**, the score is 0,
  and the verdict says **example.com doesn't exist**. If a public resolver does find it,
  the problem is this computer's DNS server (a filter, or an old cached answer): that's a
  major issue under **This computer**, and the other checks run as usual.
- **Different answers from resolvers**: sites on a CDN give each resolver addresses near
  it, so different addresses are normal. doctor connects to each different address on
  port 443: if they all work, it's a note. It's a major issue only when some resolvers
  can't find the domain (NXDOMAIN, no address, SERVFAIL, refused) while others answer it,
  or when one of the addresses doesn't respond. Resolvers that time out don't count: a VPN
  or firewall blocking them is reported under **This computer**.
- **A DNS server that strips DNSSEC signatures**: some routers and filters remove them, so
  DNSSEC can't be checked through them. DNSSEC is then checked through 8.8.8.8 or
  1.1.1.1 instead (as `dnskit dnssec` does), and the checks table shows **(via 8.8.8.8)**. If neither can be used
  either, it's a note under **This computer** (the network strips DNSSEC), not a problem
  with the domain.
- **DKIM**: DNS can't list a domain's DKIM selectors, so finding no key at the common
  ones proves nothing: it's a note. A weak, revoked or malformed key is still an issue.
- When this computer can't use DNS at all, the domain's failures aren't listed. The
  verdict says **This computer can't use DNS**, and that the domain couldn't be checked.
- When DNSSEC is broken, the failing lookups, connection and email checks are explained
  by that one issue. They show **✗ failed (explained below)** in the checks table.
- Email failures for a domain without MX records count as minor.

#### How the checks run

doctor checks this computer and looks up the domain first, at the same time. The other
domain checks start as soon as the lookup shows the domain exists (or after half a second,
since "doesn't exist" comes back quickly and a slow lookup means something else is wrong).
The check of this computer doesn't test ghost DNS servers, since nothing uses them; that
saves waiting a second for the dead ones. `dnskit local` still tests them.

doctor contacts public resolvers in three cases, which sends them the domain name: the
resolver comparison (Google, Cloudflare and Quad9), DNSSEC when your DNS server strips
signatures (8.8.8.8, then 1.1.1.1), and confirming that a domain doesn't exist (8.8.8.8,
then 1.1.1.1). `--quick` skips the first two, but still confirms a missing domain.

#### Example: a healthy domain

```text
$ dnskit doctor example.com
Health check for example.com
Check                                                          Result                Time
This computer: adapters, DNS servers, VPN, hijacking,          ✓ OK (2 notes)      410 ms
interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)                          ✓ OK                299 ms
Answers from public resolvers and this computer's DNS servers  ✓ OK                159 ms
Connection to the domain (port 443)                            ✓ OK                174 ms
Email: MX, SPF, DMARC, DKIM                                    ! 1 issue           360 ms
DNSSEC chain of trust                                          ✓ OK (via 8.8.8.8)  453 ms

Health score: 95/100
┌─ Healthy, with a few things to tidy up ─────────────────────────────────────────────────┐
│ This computer looks fine. example.com has 1 issue; the most important: email (DMARC):   │
│ no DMARC report address (rua).                                                          │
│                                                                                         │
│ Next step: Start at the top of the list: Add rua=mailto:<address>, such as a            │
│ dmarc-reports@example.com mailbox or a DMARC reporting service.                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

example.com
1. MINOR Email (DMARC): no DMARC report address (rua)
   Without rua=, receivers don't send aggregate reports, so you can't see who sends mail as
   example.com or whether your own mail passes.
   Fix: Add rua=mailto:<address>, such as a dmarc-reports@example.com mailbox or a DMARC
   reporting service.

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 6 checks in parallel · 815 ms total
```

example.com has no DMARC report address, a minor issue (−5). The ghost DNS servers are
notes: dnskit and Windows already ignore them, so they cost nothing. This network's DNS
server strips DNSSEC signatures, so DNSSEC was checked through 8.8.8.8.

#### Example: a site on a CDN

```text
$ dnskit doctor google.com
Health check for google.com
Check                                                     Result                     Time
This computer: adapters, DNS servers, VPN, hijacking,     ✓ OK (2 notes)           284 ms
interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)                     ✓ OK                     420 ms
Answers from public resolvers and this computer's DNS     ✓ OK (1 note)            171 ms
servers
Connection to the domain (port 443)                       ✓ OK                     173 ms
Email: MX, SPF, DMARC, DKIM                               ✓ OK (1 note)            611 ms
DNSSEC chain of trust                                     ! 1 issue (via 8.8.8.8)  616 ms

Health score: 95/100
┌─ Healthy, with a few things to tidy up ─────────────────────────────────────────────────┐
│ This computer looks fine. google.com has 1 issue; the most important: DNSSEC isn't      │
│ enabled for google.com.                                                                 │
│                                                                                         │
│ Next step: Start at the top of the list: To turn it on, enable DNSSEC at your DNS host, │
│ then add the DS record it gives you at your registrar (many hosts do both in one step). │
└─────────────────────────────────────────────────────────────────────────────────────────┘

google.com
1. MINOR DNSSEC isn't enabled for google.com
   There's no DS record for google.com at com, so there's no chain of trust to it. Lookups
   work normally, but resolvers can't tell a genuine answer from a forged one. DNSSEC
   protects against forged DNS answers: someone on the network, or a poisoned resolver
   cache, can't send visitors to a fake address without the signature check failing. It
   doesn't encrypt DNS or hide which sites you visit.
   Fix: To turn it on, enable DNSSEC at your DNS host, then add the DS record it gives you
   at your registrar (many hosts do both in one step).
Notes, nothing to fix:
  · Resolvers give different addresses for google.com — dnskit compare
  · Email (DKIM): no DKIM key at the common selectors — dnskit email

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 6 checks in parallel · 1096 ms total
```

The resolvers gave different addresses, but doctor connected to each and they all work,
so it's a note. So is the missing DKIM key at the common selectors: google.com signs its
mail with a selector of its own.

#### Example: something is broken

dnssec-failed.org is a test domain whose DNSSEC is deliberately broken:

```text
$ dnskit doctor dnssec-failed.org
Health check for dnssec-failed.org
Check                                                 Result                         Time
This computer: adapters, DNS servers, VPN,            ✓ OK (2 notes)               239 ms
hijacking, interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)                 ✗ failed (explained below)  3269 ms
Answers from public resolvers and this computer's     ✓ OK                        1720 ms
DNS servers
Connection to the domain (port 443)                   ✗ failed (explained below)  2131 ms
Email: MX, SPF, DMARC, DKIM                           ✓ OK                        3345 ms
DNSSEC chain of trust                                 ✗ 1 issue (via 8.8.8.8)     2785 ms

Health score: 60/100
┌─ Something is broken ───────────────────────────────────────────────────────────────────┐
│ This computer looks fine. dnssec-failed.org has 1 issue; the most important: DNSSEC is  │
│ broken for dnssec-failed.org.                                                           │
│                                                                                         │
│ Next step: Start at the top of the list: The DS record at the registrar doesn't match   │
│ the zone's current key, which happens after a key change or a move to a new DNS host.   │
│ Replace it with the DS record your DNS host shows, or remove it to switch DNSSEC off    │
│ until then.                                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘

dnssec-failed.org
1. CRITICAL DNSSEC is broken for dnssec-failed.org
   dnssec-failed.org: the DS record at org. (key 42069) matches none of its keys
   (key-signing keys: 50719). Resolvers that validate DNSSEC (Google, Cloudflare, Quad9 and
   many ISPs) refuse to answer for dnssec-failed.org (SERVFAIL), so it looks down to most
   people, while resolvers that don't validate still answer.
   Fix: The DS record at the registrar doesn't match the zone's current key, which happens
   after a key change or a move to a new DNS host. Replace it with the DS record your DNS
   host shows, or remove it to switch DNSSEC off until then.

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 6 checks in parallel · 3922 ms total
```

#### Example: `--quick`

```text
$ dnskit doctor example.com --quick
Health check for example.com
Check                                                           Result               Time
This computer: adapters, DNS servers, VPN, hijacking,           ✓ OK (2 notes)     283 ms
interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)                           ✓ OK                89 ms
Answers from public resolvers and this computer's DNS servers   skipped (--quick)
Connection to the domain (port 443)                             ✓ OK               163 ms
Email: MX, SPF, DMARC, DKIM                                     skipped (--quick)
DNSSEC chain of trust                                           skipped (--quick)

Health score: 100/100
┌─ Healthy: no problems found ────────────────────────────────────────────────────────────┐
│ This computer's DNS setup and example.com both checked out. 2 notes below for           │
│ information; nothing needs changing. This was a quick check, so the resolver            │
│ comparison, email and DNSSEC weren't checked.                                           │
│                                                                                         │
│ Next step: Nothing to do.                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 3 checks in parallel · 309 ms total
```

The verdict says what wasn't checked.

#### Example: a domain that doesn't exist

```text
$ dnskit doctor does-not-exist-dnskit-test.com
Health check for does-not-exist-dnskit-test.com
Check                                              Result                            Time
This computer: adapters, DNS servers, VPN,         ✓ OK (2 notes)                  329 ms
hijacking, interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)              ✗ 1 issue                       296 ms
Answers from public resolvers and this computer's  skipped (domain doesn't exist)
DNS servers
Connection to the domain (port 443)                skipped (domain doesn't exist)
Email: MX, SPF, DMARC, DKIM                        skipped (domain doesn't exist)
DNSSEC chain of trust                              skipped (domain doesn't exist)

Health score: 0/100
┌─ does-not-exist-dnskit-test.com doesn't exist ──────────────────────────────────────────┐
│ DNS says there's no such domain (NXDOMAIN), so it can't work for anyone, and the checks │
│ that need it (the resolver comparison, the connection, email and DNSSEC) were skipped.  │
│ The score is 0.                                                                         │
│                                                                                         │
│ Next step: Check the spelling for typos. If this domain used to work, its registration  │
│ may have expired — check it with a WHOIS lookup.                                        │
└─────────────────────────────────────────────────────────────────────────────────────────┘

does-not-exist-dnskit-test.com
1. CRITICAL does-not-exist-dnskit-test.com: domain doesn't exist
   does-not-exist-dnskit-test.com isn't registered in DNS — the nameserver answered that no
   such name exists (NXDOMAIN).
   Fix: Check the spelling for typos. If this domain used to work, its registration may
   have expired — check it with a WHOIS lookup.

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 2 checks in parallel · 592 ms total
```

Exit codes: `0` when there's no critical or major issue (minor issues and notes are fine),
`1` otherwise, `2` for invalid input.

### `dnskit lookup`

Look up DNS records for a name.

**When to use it:**

- You've just added a record, such as an A record for a new server or a TXT record that
  Google or Microsoft asked for to verify your domain, and want to see what DNS now says.
- Before moving to a new email or DNS provider: note the current MX and NS records so you
  can compare afterwards.
- Finding out which service a name really points to: `www` is often a CNAME to a CDN or a
  website builder.
- Checking whether one particular DNS server knows a name, such as an internal name on the
  office server: `dnskit lookup intranet.example.local -s 10.0.0.53`.

```text
dnskit lookup NAME [--type TYPE] [--server IP] [--timeout SECONDS] [--refresh]
```

| Option | Short | Default | What it does |
|---|---|---|---|
| `NAME` | | *(required)* | The domain name to look up, such as `example.com` or `www.example.com`. |
| `--type` | `-t` | A, AAAA, MX, CNAME, NS, TXT | Query only this one record type. Case doesn't matter (`mx` works). |
| `--server` | `-s` | automatic | The IP address of the nameserver to ask. Overrides the automatic choice. |
| `--timeout` | | `5.0` | Seconds to wait for an answer before giving up. |
| `--refresh` | | off | Re-check your system's nameservers instead of using the remembered choice (see [section 7](#7-how-dnskit-chooses-a-nameserver)). |

#### Example: all record types

```text
$ dnskit lookup example.com
example.com
┌───────┬────────────────────────────────────┬───────┐
│ Type  │ Value                              │   TTL │
├───────┼────────────────────────────────────┼───────┤
│ A     │ 104.20.23.154                      │   166 │
│       │ 172.66.147.243                     │   166 │
├───────┼────────────────────────────────────┼───────┤
│ AAAA  │ 2606:4700:10::6814:179a            │    82 │
│       │ 2606:4700:10::ac42:93f3            │    82 │
├───────┼────────────────────────────────────┼───────┤
│ MX    │ 0 .                                │   248 │
├───────┼────────────────────────────────────┼───────┤
│ CNAME │ no records                         │       │
├───────┼────────────────────────────────────┼───────┤
│ NS    │ hera.ns.cloudflare.com.            │ 86126 │
│       │ elliott.ns.cloudflare.com.         │ 86126 │
├───────┼────────────────────────────────────┼───────┤
│ TXT   │ "v=spf1 -all"                      │   300 │
└───────┴────────────────────────────────────┴───────┘
Resolver: 1.1.1.1 (auto: fastest of 3 system nameservers, 14 ms) · 61 ms total
```

What this tells you:

- The site has two IPv4 and two IPv6 addresses.
- `MX 0 .` is a "null MX": the domain explicitly accepts **no** email.
- **CNAME: no records** is normal. A domain's top level (the "apex") can't have a CNAME.
- Its DNS is hosted by Cloudflare (the NS records).
- The SPF record `v=spf1 -all` says no server may send email as this domain.
- The last line shows which nameserver answered and how long the whole lookup took.

#### Example: one record type

```text
$ dnskit lookup gmail.com -t MX
gmail.com
┌──────┬─────────────────────────────────────┬─────┐
│ Type │ Value                               │ TTL │
├──────┼─────────────────────────────────────┼─────┤
│ MX   │ 10 alt1.gmail-smtp-in.l.google.com. │ 224 │
│      │ 40 alt4.gmail-smtp-in.l.google.com. │ 224 │
│      │ 30 alt3.gmail-smtp-in.l.google.com. │ 224 │
│      │ 5 gmail-smtp-in.l.google.com.       │ 224 │
│      │ 20 alt2.gmail-smtp-in.l.google.com. │ 224 │
└──────┴─────────────────────────────────────┴─────┘
Resolver: 1.1.1.1 (auto: fastest of 3 system nameservers, 14 ms; cached, probed 40s ago) · 39 ms total
```

Records come back in the order the server sent them. For MX, the **lowest number wins**:
mail goes to `gmail-smtp-in.l.google.com` (priority 5) first, and the others are backups.

#### Example: following an alias

```text
$ dnskit lookup www.github.com -t CNAME
www.github.com
┌───────┬─────────────┬──────┐
│ Type  │ Value       │  TTL │
├───────┼─────────────┼──────┤
│ CNAME │ github.com. │ 3158 │
└───────┴─────────────┴──────┘
```

`www.github.com` is an alias for `github.com`. To find its address, look up `github.com`.

#### Example: asking a specific server

```bash
dnskit lookup example.com -s 8.8.8.8
```

The footer then reads `Resolver: 8.8.8.8 (--server)`. `--server` takes an **IP address**,
not a hostname. Use it to compare what different resolvers see, or to bypass a misbehaving
local resolver.

---

### `dnskit reverse`

Find the hostname for an IP address (a reverse DNS or PTR lookup).

**When to use it:**

- An IP address turns up in a firewall log, a mail log or a list of connections, and you
  want to know whose it is.
- Mail from your server is rejected or marked as spam: many receivers check that the
  sending IP has a reverse name (PTR record) that matches your mail server's name.
- Your hosting provider says they've set the reverse name for your server's IP, and you
  want to confirm it.

```text
dnskit reverse IP [--server IP] [--timeout SECONDS] [--refresh]
```

| Option | Short | Default | What it does |
|---|---|---|---|
| `IP` | | *(required)* | An IPv4 address (`8.8.8.8`) or IPv6 address (`2001:4860:4860::8888`). An IPv6 zone such as `%eth0` is ignored. |
| `--server` | `-s` | automatic | Nameserver IP to ask. |
| `--timeout` | | `5.0` | Seconds to wait. |
| `--refresh` | | off | Re-check your system's nameservers first. |

#### Example: IPv4

```text
$ dnskit reverse 8.8.8.8
8.8.8.8 (IPv4)
┌─────────────┬───────┐
│ Hostname    │   TTL │
├─────────────┼───────┤
│ dns.google. │ 79977 │
└─────────────┴───────┘
PTR name: 8.8.8.8.in-addr.arpa.
Resolver: 1.1.1.1 (auto: fastest of 3 system nameservers, 14 ms; cached, probed 2s ago) · 90 ms total
```

**PTR name** is the special name DNS actually stores the answer under: the address
reversed, followed by `in-addr.arpa` (IPv4) or `ip6.arpa` (IPv6). dnskit builds it for
you. It's shown so you can check it with other tools.

#### Example: IPv6

```text
$ dnskit reverse 2001:4860:4860::8888
2001:4860:4860::8888 (IPv6)
┌─────────────┬───────┐
│ Hostname    │   TTL │
├─────────────┼───────┤
│ dns.google. │ 74377 │
└─────────────┴───────┘
PTR name: 8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa.
```

#### Example: an address with no name

Many addresses have no reverse name. For a private address (one used inside a home or
office network), dnskit tells you to ask your local DNS server:

```text
$ dnskit reverse 192.168.1.1 -s 1.1.1.1
┌─ No reverse DNS name (192.168.1.1, IPv4) ─────────────────────────────────────────┐
│ 192.168.1.1 has no PTR record, so there's no hostname registered for it.          │
│                                                                                   │
│ Next step: 192.168.1.1 is a private or reserved address, so public resolvers      │
│ can't know its name. Ask your local network's DNS server (usually your router) by │
│ passing its IP as the resolver.                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

Following that advice means running `dnskit reverse 192.168.1.1 -s 192.168.1.1`, if your
router is at `192.168.1.1`. For a public address, the advice is to ask its owner (usually
the ISP or hosting provider) to add a PTR record.

#### Example: invalid input

```text
$ dnskit reverse 999.1.1.1
Error: '999.1.1.1' is not a valid IP address. Use an IPv4 address like 8.8.8.8 or an IPv6
address like 2001:4860:4860::8888.
```

The address is checked before anything is sent over the network. The exit code is `2`.

---

### `dnskit compare`

Ask several resolvers the same question at the same time and see whether they agree.

**When to use it:**

- A site works on your phone's mobile data but not on the office or home network: is your
  network's DNS server giving a different answer from Google and Cloudflare?
- You changed a record a few minutes ago: does your own DNS server still serve the old
  answer while the public resolvers already have the new one?
- You suspect your ISP, router or company filter blocks a site through DNS.

```text
dnskit compare NAME [--type TYPE] [--timeout SECONDS]
```

| Option | Short | Default | What it does |
|---|---|---|---|
| `NAME` | | *(required)* | The domain name to look up. |
| `--type` | `-t` | `A` | The record type to compare. Any type `lookup` accepts works. |
| `--timeout` | | `2.0` | Seconds to wait for **each** resolver. All resolvers are asked at once, so this is also roughly the longest the command takes. |

**Who is asked:**

- The public resolvers **Google** (`8.8.8.8`), **Cloudflare** (`1.1.1.1`) and **Quad9**
  (`9.9.9.9`).
- **Every DNS server your computer uses**, labelled `System #1`, `System #2`… in the same
  order and numbering as `dnskit resolvers`. Ghost servers that aren't on a connected
  adapter are left out (see [section 7](#7-how-dnskit-chooses-a-nameserver)).

A server that is both public and in your system list is only asked once, and labelled with
both, for example `Cloudflare / system #2`. Each resolver is asked on its own, with no
falling back to another server, so every row really is that server's own answer.

#### Example: everyone agrees

```text
$ dnskit compare example.com
example.com A across 4 resolvers
┌────────────────────────┬─────────────┬────────────────┬─────┬─────────┬──────────┐
│ Resolver               │ IP          │ Answer         │ TTL │    Time │          │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼──────────┤
│ Google                 │ 8.8.8.8     │ 104.20.23.154  │ 134 │   22 ms │          │
│                        │             │ 172.66.147.243 │     │         │          │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼──────────┤
│ Cloudflare / system #2 │ 1.1.1.1     │ 104.20.23.154  │  16 │   19 ms │          │
│                        │             │ 172.66.147.243 │     │         │          │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼──────────┤
│ Quad9                  │ 9.9.9.9     │ 104.20.23.154  │ 118 │   18 ms │          │
│                        │             │ 172.66.147.243 │     │         │          │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼──────────┤
│ System #1              │ 192.168.1.1 │ timed out      │     │ 2112 ms │ ✗ failed │
└────────────────────────┴─────────────┴────────────────┴─────┴─────────┴──────────┘
✓ All 3 resolvers that answered agree. 1 failed: System #1 (timed out).
Queried 4 resolvers in parallel · 2122 ms total
```

What this tells you:

- Every resolver that answered returned the same two addresses, so the record is
  consistent everywhere.
- **TTL** differs between resolvers. That's normal: it counts down in each resolver's cache,
  so it shows how long until that resolver asks again. TTL isn't part of the comparison.
- **Time** is how long that resolver took to answer.
- Your router (`System #1`) didn't answer. It's marked **✗ failed** and left out of the
  comparison instead of stopping the command. The total time is about 2 seconds because
  dnskit waited the full `--timeout` for it.

#### Example: a resolver disagrees

```text
$ dnskit compare google.com
google.com A across 4 resolvers
┌────────────────────────┬─────────────┬────────────────┬─────┬─────────┬───────────┐
│ Resolver               │ IP          │ Answer         │ TTL │    Time │           │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼───────────┤
│ Google                 │ 8.8.8.8     │ 192.178.54.46  │ 239 │   21 ms │ majority  │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼───────────┤
│ Cloudflare / system #2 │ 1.1.1.1     │ 192.178.54.14  │ 296 │   20 ms │ ≠ differs │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼───────────┤
│ Quad9                  │ 9.9.9.9     │ 142.251.216.14 │ 201 │   19 ms │ ≠ differs │
├────────────────────────┼─────────────┼────────────────┼─────┼─────────┼───────────┤
│ System #1              │ 192.168.1.1 │ 192.178.54.46  │ 239 │   19 ms │ majority  │
└────────────────────────┴─────────────┴────────────────┴─────┴─────────┴───────────┘
≠ 2 of 4 resolvers disagree with the majority answer (given by 2): Cloudflare / system #2,
Quad9. Different addresses can be normal for sites on a CDN, which give each resolver a
nearby server.
```

- The most common answer is marked **majority**. Resolvers with a different answer are
  highlighted in yellow and marked **≠ differs**.
- If the top answers are tied (for example two resolvers say one thing and two say
  another), there is no majority, so no resolver is singled out. Every resolver that
  answered is marked **varies** in grey, without yellow highlighting, and the summary says
  how many different answers there were.
- For a big site like this one, differences are **expected**. CDNs and large providers
  hand each resolver addresses close to it. For your own domain, a difference usually means
  a recent change hasn't reached every cache yet, or a resolver is filtering or rewriting
  answers.

#### How answers are compared

- **Order doesn't matter.** Resolvers often return the same records shuffled. dnskit
  compares them as a set, and shows each resolver's records sorted (MX by priority) so
  rows are easy to compare by eye.
- **TTL is ignored**, since it naturally differs between caches.
- **Case is ignored for names** (`Mail.Example.com.` equals `mail.example.com.`), but not for
  TXT values, where case can matter.
- **"Doesn't exist" and "no records" count as answers.** If most resolvers return
  addresses but one says the domain doesn't exist (NXDOMAIN), that one is marked
  **≠ differs**. If they all say NXDOMAIN, they agree.
- **Failures don't count.** A resolver that timed out, returned SERVFAIL, refused, or
  couldn't be reached is shown in red with the reason and **✗ failed**, and is left out.

#### The summary line

| Summary | Meaning | Exit code |
|---|---|---|
| `✓ All N resolvers agree.` | Every resolver gave the same answer. | `0` |
| `✓ All N resolvers that answered agree. K failed: …` | Every resolver that answered agreed; the ones listed failed. | `0` |
| `≠ K of N resolvers disagree with the majority answer…` | Some resolvers gave a different answer; they are listed. | `1` |
| `≠ Resolvers disagree, with no majority…` | The answers were tied; there is no single most common answer. | `1` |
| `No resolver answered.` | Every resolver failed. Check your network connection. | `1` |

The last line shows how many resolvers were asked and the total time.

---

### `dnskit email`

Check a domain's email DNS setup in one go: where its mail is delivered (**MX**), which
servers may send its mail (**SPF**), what receivers should do with forged mail (**DMARC**),
and the keys that sign its mail (**DKIM**). Each check is shown as **pass**, **warn** or
**fail**, with a plain-English explanation and a suggested fix, and the output ends with a
summary.

**When to use it:**

- Mail you send lands in the recipient's spam folder or bounces, often because SPF, DKIM
  or DMARC is missing or wrong.
- You're setting up a new email provider, such as Microsoft 365 or Google Workspace, and
  want to confirm every record is in place before switching over.
- You've added a newsletter or helpdesk service that sends mail as your domain: check that
  its SPF include didn't push you over the 10-lookup limit, and add its DKIM selector with
  `--selector`.
- A domain that never sends email (a parked or brand domain): check it's locked down so
  nobody can send forged mail from it.

```text
dnskit email DOMAIN [--selector SELECTOR]... [--server IP] [--timeout SECONDS] [--refresh]
```

| Option | Short | Default | What it does |
|---|---|---|---|
| `DOMAIN` | | *(required)* | The domain to check, such as `example.com`. Just the domain: not an email address or a URL. |
| `--selector` | | *(none)* | An extra DKIM selector to check, on top of the common ones. Repeat it to check several (`--selector s1 --selector s2`). |
| `--server` | `-s` | automatic | Nameserver IP to ask. |
| `--timeout` | | `5.0` | Seconds to wait for each query. |
| `--refresh` | | off | Re-check your system's nameservers first. |

All the queries run in parallel, against the same nameserver `lookup` would use.

#### What it checks

| Check | Looks at | Passes when |
|---|---|---|
| **MX** | The domain's MX records, then the A and AAAA records of each mail server they name. | There is at least one MX record and every mail server has an IP address. A *null MX* (`0 .`, "this domain receives no email") also passes. |
| **SPF** | The domain's TXT records that start with `v=spf1`, and every record they `include` or `redirect` to. | There is exactly one SPF record, every term is valid, it ends with `~all` or `-all` (or a `redirect=`), and checking it takes at most 10 DNS lookups. |
| **DMARC** | The TXT record at `_dmarc.DOMAIN` that starts with `v=DMARC1`. | There is exactly one, it's valid, and its policy is `p=quarantine` or `p=reject`. |
| **DKIM** | The TXT record at `SELECTOR._domainkey.DOMAIN` for the selectors `google` (Google Workspace), `selector1` and `selector2` (Microsoft 365), `default` and `k1` (cPanel, Mailchimp and others), plus any `--selector`. | At least one selector has a key, and every key found is valid and at least 2048 bits (1024-bit keys get a warning). |

The three results:

| Result | Meaning |
|---|---|
| `✓ pass` | Set up correctly. Shown as one line with a short explanation. |
| `! warn` | Email works, but something is weak, risky or unusual, such as `p=none`, `?all`, a 1024-bit key, or no DKIM key at the common selectors. Shown in a yellow box with a fix. |
| `✗ fail` | Something is missing or broken in a way that hurts delivery or lets others forge the domain's mail, or the check couldn't be done (for example a timeout). Shown in a red box with a fix. |

#### Example: everything passes

A domain on Google Workspace, whose SPF record hands over to another domain's record
(`redirect=`):

```text
$ dnskit email takealot.com
Email DNS check for takealot.com

MX · where mail for the domain is delivered ───────────────────────────────────────────────
┌──────────┬─────────────────────────┬────────────────────────┐
│ Priority │ Mail server             │ Addresses              │
├──────────┼─────────────────────────┼────────────────────────┤
│        1 │ aspmx.l.google.com      │ 142.251.127.26         │
│          │                         │ 2a00:1450:4001:c21::1a │
│        5 │ alt1.aspmx.l.google.com │ 192.178.213.26         │
│          │                         │ 2a00:1450:4025:c01::1b │
│        5 │ alt2.aspmx.l.google.com │ 172.253.152.26         │
│          │                         │ 2a00:1450:4010:c22::1b │
│       10 │ aspmx2.googlemail.com   │ 142.250.147.27         │
│          │                         │ 2a00:1450:4025:c01::1a │
│       10 │ aspmx3.googlemail.com   │ 172.253.152.26         │
│          │                         │ 2a00:1450:4010:c22::1b │
└──────────┴─────────────────────────┴────────────────────────┘
✓ 5 mail servers, all with IP addresses — Mail for takealot.com goes to aspmx.l.google.com
first (lowest priority number); the other 4 servers are backups.

SPF · which servers may send its mail ─────────────────────────────────────────────────────
Record: v=spf1 redirect=_sljmh4rts.sdmarc.net
DNS lookups: 8 of 10
  redirect=_sljmh4rts.sdmarc.net
    include:spf1.takealot.com (in _sljmh4rts.sdmarc.net)
    include:_spf.google.com (in _sljmh4rts.sdmarc.net)
    include:mail.zendesk.com (in _sljmh4rts.sdmarc.net)
    include:spf.mandrillapp.com (in _sljmh4rts.sdmarc.net)
    include:transmail.net (in _sljmh4rts.sdmarc.net)
    include:_spf.123formbuilder.com (in _sljmh4rts.sdmarc.net)
      include:_spf1.123formbuilder.com (in _spf.123formbuilder.com)
✓ SPF record is valid — 8 of 10 DNS lookups. Uses _sljmh4rts.sdmarc.net's SPF policy
(redirect).

DMARC · what receivers do with mail that fails SPF and DKIM ───────────────────────────────
Record at _dmarc.takealot.com: v=DMARC1; p=quarantine;
rua=mailto:a.ljmh4rts@sdmarc.net,mailto:postmaster@takealot.com;
ruf=mailto:postmaster@takealot.com; adkim=r; aspf=r
✓ DMARC policy: quarantine — p=quarantine: mail that fails DMARC is put in the spam or junk
folder.

DKIM · keys that sign its mail ────────────────────────────────────────────────────────────
┌───────────┬──────────────┐
│ Selector  │ Key          │
├───────────┼──────────────┤
│ google    │ RSA 2048-bit │
│ selector1 │ not found    │
│ selector2 │ not found    │
│ default   │ not found    │
│ k1        │ not found    │
└───────────┴──────────────┘
Looked up <selector>._domainkey.takealot.com
✓ DKIM key found — Selector google (RSA 2048-bit). Receivers can use this key to verify
that mail signed by takealot.com hasn't been forged or altered.

Summary
┌───────┬────────┬───────────────────────────────────────┐
│ Check │ Result │                                       │
├───────┼────────┼───────────────────────────────────────┤
│ MX    │ ✓ pass │ 5 mail servers, all with IP addresses │
│ SPF   │ ✓ pass │ SPF record is valid                   │
│ DMARC │ ✓ pass │ DMARC policy: quarantine              │
│ DKIM  │ ✓ pass │ DKIM key found                        │
└───────┴────────┴───────────────────────────────────────┘
✓ All 4 checks passed.
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 23 ms; cached, probed 43s ago) ·
710 ms total
Nameserver problems (probed 43s ago; run `dnskit resolvers` for details): no response from
192.168.1.1, 192.168.1.2
```

The SPF lines show every term that costs a DNS lookup, indented under the record that
contains it, so you can see which include uses up the 10-lookup budget.

#### Example: problems found

A domain with no DMARC record and an SPF record that needs too many lookups:

```text
$ dnskit email gov.za
Email DNS check for gov.za

MX · where mail for the domain is delivered ───────────────────────────────────────────────
┌──────────┬─────────────┬───────────────┐
│ Priority │ Mail server │ Addresses     │
├──────────┼─────────────┼───────────────┤
│      100 │ mta.gov.za  │ 163.195.1.225 │
└──────────┴─────────────┴───────────────┘
✓ 1 mail server, with an IP address — Mail for gov.za goes to mta.gov.za.

SPF · which servers may send its mail ─────────────────────────────────────────────────────
Record: v=spf1 mx a ip4:163.195.16.25/32 ip4:163.195.16.101/32 ip4:163.195.1.225/32
ip4:163.195.16.237/32 include:_spf.synaq.com ~all
DNS lookups: 12 of 10 (too many)
  mx
  a
  include:_spf.synaq.com
    include:_blocka.synaq.com (in _spf.synaq.com)
      include:stspg-customer.com (in _blocka.synaq.com)
      include:em.synaq.com (in _blocka.synaq.com)
      include:servers.mcsv.net (in _blocka.synaq.com)
      include:eversrv.com (in _blocka.synaq.com)
        include:us.eversrv.com (in eversrv.com)
        include:za.eversrv.com (in eversrv.com)
    include:_blockb.synaq.com (in _spf.synaq.com)
    include:_blockc.synaq.com (in _spf.synaq.com)
┌─ ✗ Too many DNS lookups (12 of 10) ─────────────────────────────────────────────────────┐
│ Checking this SPF record takes 12 DNS lookups, counting everything its includes pull    │
│ in. Receivers stop at 10 and treat SPF as broken (permerror), so SPF fails for all of   │
│ this domain's mail.                                                                     │
│                                                                                         │
│ Fix: Remove includes for services you no longer use, replace a and mx with the ip4/ip6  │
│ addresses they stand for, or use your provider's flattened SPF if it offers one.        │
└─────────────────────────────────────────────────────────────────────────────────────────┘

DMARC · what receivers do with mail that fails SPF and DKIM ───────────────────────────────
┌─ ✗ No DMARC record ─────────────────────────────────────────────────────────────────────┐
│ There's no v=DMARC1 TXT record at _dmarc.gov.za, so receivers have no instructions for  │
│ mail that fails SPF and DKIM, and gov.za gets no reports about who sends mail using its │
│ name. Gmail and Yahoo require DMARC from bulk senders.                                  │
│                                                                                         │
│ Fix: Publish a TXT record at _dmarc.gov.za, starting in monitoring mode: v=DMARC1;      │
│ p=none; rua=mailto:dmarc-reports@gov.za. Once the reports show your genuine mail        │
│ passing, change p=none to quarantine, then reject.                                      │
└─────────────────────────────────────────────────────────────────────────────────────────┘

DKIM · keys that sign its mail ────────────────────────────────────────────────────────────
┌───────────┬───────────┐
│ Selector  │ Key       │
├───────────┼───────────┤
│ google    │ not found │
│ selector1 │ not found │
│ selector2 │ not found │
│ default   │ not found │
│ k1        │ not found │
└───────────┴───────────┘
Looked up <selector>._domainkey.gov.za
┌─ ! No DKIM key at the common selectors ─────────────────────────────────────────────────┐
│ None of the selectors tried (google, selector1, selector2, default, k1) has a DKIM key. │
│ gov.za may still use DKIM under another selector: DNS has no way to list them.          │
│                                                                                         │
│ Fix: Open an email sent from this domain, find the s= value in its DKIM-Signature       │
│ header, and check that selector with --selector. If DKIM isn't set up, turn it on in    │
│ your email provider's settings and publish the record it gives you.                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Summary
┌───────┬────────┬─────────────────────────────────────┐
│ Check │ Result │                                     │
├───────┼────────┼─────────────────────────────────────┤
│ MX    │ ✓ pass │ 1 mail server, with an IP address   │
│ SPF   │ ✗ fail │ Too many DNS lookups (12 of 10)     │
│ DMARC │ ✗ fail │ No DMARC record                     │
│ DKIM  │ ! warn │ No DKIM key at the common selectors │
└───────┴────────┴─────────────────────────────────────┘
✗ 2 of 4 checks failed, 1 with warnings. Fix the problems marked ✗ above.
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 23 ms; cached, probed 45s ago) ·
648 ms total
Nameserver problems (probed 45s ago; run `dnskit resolvers` for details): no response from
192.168.1.1, 192.168.1.2
```

#### Example: a domain that sends and receives no email

`example.com` says it neither receives (null MX) nor sends (`v=spf1 -all`) email, so it
needs no DKIM key:

```text
$ dnskit email example.com
Email DNS check for example.com

MX · where mail for the domain is delivered ───────────────────────────────────────────────
✓ Doesn't accept email (null MX) — example.com publishes a null MX record, which tells
senders it never receives email.

SPF · which servers may send its mail ─────────────────────────────────────────────────────
Record: v=spf1 -all
✓ SPF record is valid — 0 of 10 DNS lookups. Ends with -all: mail from servers not listed
should be rejected (hard fail).

DMARC · what receivers do with mail that fails SPF and DKIM ───────────────────────────────
Record at _dmarc.example.com: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
✓ DMARC policy: reject — p=reject: mail that fails DMARC is refused outright.
┌─ ! No DMARC report address (rua) ───────────────────────────────────────────────────────┐
│ Without rua=, receivers don't send aggregate reports, so you can't see who sends mail   │
│ as example.com or whether your own mail passes.                                         │
│                                                                                         │
│ Fix: Add rua=mailto:<address>, such as a dmarc-reports@example.com mailbox or a DMARC   │
│ reporting service.                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────┘

DKIM · keys that sign its mail ────────────────────────────────────────────────────────────
┌───────────┬────────────────────┐
│ Selector  │ Key                │
├───────────┼────────────────────┤
│ google    │ revoked (empty p=) │
│ selector1 │ revoked (empty p=) │
│ selector2 │ revoked (empty p=) │
│ default   │ revoked (empty p=) │
│ k1        │ revoked (empty p=) │
└───────────┴────────────────────┘
Looked up <selector>._domainkey.example.com
✓ No DKIM key needed — example.com's SPF record (v=spf1 -all) says it sends no mail, so
there's nothing to sign. The empty (revoked) keys published for it say the same.

Summary
┌───────┬────────┬────────────────────────────────┐
│ Check │ Result │                                │
├───────┼────────┼────────────────────────────────┤
│ MX    │ ✓ pass │ Doesn't accept email (null MX) │
│ SPF   │ ✓ pass │ SPF record is valid            │
│ DMARC │ ! warn │ No DMARC report address (rua)  │
│ DKIM  │ ✓ pass │ No DKIM key needed             │
└───────┴────────┴────────────────────────────────┘
! No check failed, but 1 of 4 has warnings. 3 passed. See the suggestions marked ! above.
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 23 ms; cached, probed 47s ago) ·
244 ms total
Nameserver problems (probed 47s ago; run `dnskit resolvers` for details): no response from
192.168.1.1, 192.168.1.2
```

#### SPF: the 10-lookup limit

Receivers give up on an SPF record that needs more than 10 DNS lookups and treat SPF as
broken (`permerror`), so **all** of the domain's mail fails SPF. dnskit counts the terms
that cost a lookup (`include`, `a`, `mx`, `ptr`, `exists` and `redirect`), following every
`include` and `redirect` into the records they point at, as receivers do. `ip4`, `ip6` and
`all` are free. An include whose record couldn't be fetched isn't counted, so the count is
then shown as "at least N". Includes that use macros (`%{i}`) depend on the message and
aren't followed.

#### DMARC policies

| Policy | What receivers do with mail that fails DMARC | Result |
|---|---|---|
| `p=none` | Deliver it as normal and only send reports. Monitoring only: forged mail isn't blocked. | warn |
| `p=quarantine` | Put it in the spam or junk folder. | pass |
| `p=reject` | Refuse it outright. | pass |

dnskit also warns when there's no report address (`rua=`), when `pct=` applies the policy
to only part of the mail, and about unknown tags. A record with no `p=`, or with an invalid
value, fails.

#### DKIM selectors

DKIM keys live at `SELECTOR._domainkey.DOMAIN`, and DNS has no way to list a domain's
selectors, so dnskit can only try likely ones. If none of them has a key, that's a warning,
not a failure: the domain may sign with a selector dnskit didn't guess (google.com itself
does). To find the real one, open an email sent from the domain, look at the
`DKIM-Signature` header, and read its `s=` value:

```text
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s2024; ...
```

Then check it with `dnskit email example.com --selector s2024`. A selector given with
`--selector` that has no key **fails**, since you've said it should exist.

#### The summary line

| Summary | Meaning | Exit code |
|---|---|---|
| `✓ All 4 checks passed.` | Everything is set up correctly. | `0` |
| `! No check failed, but N of 4 have warnings.` | Email works; see the suggestions marked `!`. | `0` |
| `✗ N of 4 checks failed…` | At least one check failed; see the problems marked `✗`. | `1` |

If the domain doesn't exist, or every query failed the same way (for example no network),
dnskit shows that one problem instead of the four checks, and exits `1`. Invalid input (an
email address instead of a domain, or an invalid selector) exits `2`.

---

### `dnskit local`

Check this computer's own DNS setup in one go: every network adapter and its DNS servers,
whether each server works, "ghost" servers, the hosts file, and how to flush the DNS cache.
It ends with a plain-English list of problems and how to fix them. Works on Windows, macOS
and Linux.

**When to use it:**

- Websites are slow or won't load on this computer, while other devices on the same
  network are fine.
- DNS behaves oddly after connecting or disconnecting a VPN, or after moving between
  networks (home, office, hotel Wi-Fi).
- Mistyped addresses open an advertising or search page instead of an error (NXDOMAIN
  hijacking), or you suspect the network intercepts or filters DNS.
- You need the right command to flush this computer's DNS cache.

```text
dnskit local [--timeout SECONDS]
```

| Option | Default | What it does |
|---|---|---|
| `--timeout` | `1.0` | How long to wait for each DNS server's test query before calling it "no response". |

#### Example

On a Windows laptop whose Ethernet cable is unplugged, with a leftover entry from an old
network (the **Network checks** table, shown in the next example, is left out here):

```text
$ dnskit local
Network adapters (Windows)
┌─────────────────────────────┬──────────────┬──────────────────────┐
│ Adapter                     │ Status       │ DNS servers          │
├─────────────────────────────┼──────────────┼──────────────────────┤
│ Wi-Fi                       │ connected    │ 192.168.1.1, 1.1.1.1 │
│ Ethernet                    │ disconnected │ 192.168.0.1, 1.1.1.1 │
│ Contoso VPN Virtual Adapter │ disconnected │ none                 │
└─────────────────────────────┴──────────────┴──────────────────────┘
DNS servers (test query, 1 s timeout)
┌─────────────┬────────────────────────────────┬─────────────┬─────────────────┐
│ Server      │ Adapter                        │    Response │                 │
├─────────────┼────────────────────────────────┼─────────────┼─────────────────┤
│ 192.168.1.1 │ Wi-Fi                          │       30 ms │                 │
│ 1.1.1.1     │ Wi-Fi, Ethernet (disconnected) │       28 ms │                 │
│ 192.168.0.1 │ Ethernet (disconnected)        │ no response │ ghost (ignored) │
│ 10.0.0.1    │ none                           │ no response │ ghost (ignored) │
└─────────────┴────────────────────────────────┴─────────────┴─────────────────┘
Hosts file: no entries override DNS (C:\WINDOWS\System32\drivers\etc\hosts)
Flush the DNS cache: ipconfig /flushdns
Browsers keep their own DNS cache too; restart the browser if a site still goes to the old address.

┌─ ! Ghost DNS server 192.168.0.1 (on disconnected Ethernet) ─────────────────────────┐
│ It's set on Ethernet, which is disconnected. Windows ignores it until that adapter  │
│ reconnects, but programs that read the system configuration directly (such as       │
│ dnspython) still try it. It doesn't respond, so they wait for it to time out.       │
│                                                                                     │
│ Fix: Nothing to do. dnskit ignores it too. If it doesn't answer once Ethernet       │
│ reconnects, change that adapter's DNS settings.                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
┌─ ! Ghost DNS server 10.0.0.1 ───────────────────────────────────────────────────────┐
│ It's in the system configuration but on no network adapter, probably left behind by │
│ a removed adapter, a VPN or an old DHCP lease. Programs that read the system        │
│ configuration directly (such as dnspython) still try it. It doesn't respond, so     │
│ they wait for it to time out.                                                       │
│                                                                                     │
│ Fix: dnskit ignores it. To remove it, delete 10.0.0.1 from these values under       │
│ HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces in the registry  │
│ (needs administrator rights): {00000002-…} (DhcpNameServer).                        │
└─────────────────────────────────────────────────────────────────────────────────────┘
DNS is working (2 of 2 servers in use responding), with 2 warnings (see above).
Tested 4 DNS servers in parallel · 1099 ms total
```

#### Example: a VPN is connected

With a WireGuard VPN connected, the internet provider's DNS servers on the other adapter
stop answering. That's the VPN at work, not a fault, so dnskit says so instead of
suggesting you remove them (disconnected adapters left out):

```text
$ dnskit local
Network adapters (Windows)
┌────────────┬────────────────────────────────────┬────────────────────────────┐
│ Adapter    │ Status                             │ DNS servers                │
├────────────┼────────────────────────────────────┼────────────────────────────┤
│ OfficeVPN  │ connected, VPN                     │ 8.8.8.8                    │
│ Ethernet 2 │ connected                          │ 203.0.113.53, 203.0.113.54 │
│ WiFi       │ connected, bridged into Ethernet 2 │ uses Ethernet 2's          │
└────────────┴────────────────────────────────────┴────────────────────────────┘
DNS servers (test query, 1 s timeout)
┌──────────────────┬────────────┬─────────────┬─────────────────┐
│ Server           │ Adapter    │    Response │                 │
├──────────────────┼────────────┼─────────────┼─────────────────┤
│ 8.8.8.8 (Google) │ OfficeVPN  │       33 ms │                 │
│ 203.0.113.53     │ Ethernet 2 │ no response │ blocked by VPN? │
│ 203.0.113.54     │ Ethernet 2 │ no response │ blocked by VPN? │
└──────────────────┴────────────┴─────────────┴─────────────────┘
Network checks
┌────────────────────────────────────┬────────────────────────────────────────────────────┐
│ Check                              │ Result                                             │
├────────────────────────────────────┼────────────────────────────────────────────────────┤
│ NXDOMAIN hijacking: 8.8.8.8        │ ✓ answers "doesn't exist" honestly                 │
│ Interception: 8.8.8.8 (Google)     │ ✓ answered by Google (172.253.249.211)             │
│ Interception: 1.1.1.1 (Cloudflare) │ ? couldn't tell (no response)                      │
│ IPv6                               │ – not available (no IPv6 address); IPv4 is used,   │
│                                    │ which is fine                                      │
└────────────────────────────────────┴────────────────────────────────────────────────────┘
Hosts file: no entries override DNS (C:\WINDOWS\System32\drivers\etc\hosts)
Flush the DNS cache: ipconfig /flushdns
Browsers keep their own DNS cache too; restart the browser if a site still goes to the old
address.

┌─ ! DNS servers outside the VPN aren't responding ────────────────────────────────────────┐
│ 203.0.113.53 (Ethernet 2), 203.0.113.54 (Ethernet 2) didn't answer within 1 s while      │
│ OfficeVPN (VPN) is connected. Many VPNs send all traffic through the tunnel, or block    │
│ DNS queries that go around it (DNS leak protection), so DNS servers on other adapters    │
│ can't be reached while the VPN is on. They are probably fine.                            │
│                                                                                          │
│ Fix: Don't remove them. To test them, disconnect OfficeVPN and run dnskit local again.   │
│ Meanwhile, lookups use the DNS servers that do answer.                                   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
DNS is working (1 of 3 servers in use responding), with 1 warning (see above).
Tested 3 DNS servers in parallel · 1059 ms total
```

What each part means:

- **Network adapters** lists every adapter, connected ones first, with the DNS servers set
  on it. On Windows this is the same information as `Get-DnsClientServerAddress`.
- An adapter that's part of a network bridge is listed right under the adapter it's bridged
  into. It has no network settings of its own (the bridge has them), so its DNS servers read
  **uses <bridge>'s**, and it doesn't count as a connected adapter for the checks below:

  ```text
  ┌────────────┬────────────────────────────────────┬───────────────────┐
  │ Adapter    │ Status                             │ DNS servers       │
  ├────────────┼────────────────────────────────────┼───────────────────┤
  │ Ethernet 2 │ connected                          │ 192.168.1.1       │
  │ WiFi       │ connected, bridged into Ethernet 2 │ uses Ethernet 2's │
  └────────────┴────────────────────────────────────┴───────────────────┘
  ```
- **VPN** in the Status column marks an adapter that looks like a VPN by its name or
  description: anything mentioning VPN, TAP, WireGuard, Wintun, Tailscale, ZeroTier,
  NordLynx, AnyConnect, GlobalProtect or FortiClient. Tunnel interfaces such as `tun0`,
  `utun3` or `wg0` count when they have DNS servers set (macOS always has a few unused
  `utun` tunnels).
- **DNS servers** tests every server mentioned anywhere, all at once, and shows which
  adapters it belongs to. **no response** (red) means it didn't answer within `--timeout`.
  A yellow time with **slow** means it answered, but took more than 250 ms. **✗ failing**
  marks a server that's in use but not answering. Well-known public resolvers show their
  provider, e.g. `1.1.1.1 (Cloudflare)`; Google, Cloudflare, Quad9 and OpenDNS are
  recognised.
- **blocked by VPN?** marks a server in use that didn't answer while a VPN is connected,
  when the server isn't the VPN's own. Many VPNs route all traffic through the tunnel, or
  block DNS that goes around it to prevent DNS leaks, so the server is most likely fine.
  Disconnect the VPN and run `dnskit local` again to test it properly.
- **A public resolver that doesn't answer** (1.1.1.1, 8.8.8.8, 9.9.9.9 and the like) is
  almost never down. Its panel says so: no response usually means a firewall, antivirus,
  VPN or the network itself (common at work, schools and hotels) is blocking it.
- **ghost (ignored)** marks a server that's in the system configuration but isn't on any
  connected adapter. See [What's a ghost DNS server?](#12-faq).
- **Network checks** test whether the DNS answers you get are honest, and whether IPv6
  works. **✓** passed, **!** found a problem (explained in a panel below), **?** couldn't
  tell (usually because a VPN or firewall blocked the test), **–** not applicable.
  - **NXDOMAIN hijacking** asks each DNS server in use that answered for a random made-up
    name (like `dnskit-nx-3f9c….com`). An honest server says the name doesn't exist
    (NXDOMAIN). A server that returns an address instead is hijacking mistyped names,
    usually to show a search or advertising page.
  - **Interception** asks Google (8.8.8.8) for `o-o.myaddr.l.google.com` (TXT), which
    Google answers with the address of its own DNS server, and Cloudflare (1.1.1.1) for
    `whoami.cloudflare` (class CH, TXT), which only Cloudflare answers with your address.
    If the answer comes from an address that isn't Google's, or Cloudflare's test gets
    SERVFAIL, REFUSED or no address, something on the way (router, network, ISP or VPN)
    answered in their place. No reply at all is reported as **?**, not as interception.
  - **IPv6** checks whether this computer has an IPv6 address. If it does, dnskit looks up
    `www.google.com`'s IPv6 (AAAA) address and connects to it on port 443. No IPv6 at all
    is fine (apps use IPv4). **Broken** means AAAA lookups work but IPv6 connections fail,
    which makes apps that try IPv6 first slow.
- **Hosts file** lists entries that send a name somewhere without asking DNS (the standard
  `localhost` lines are left out). The **Effect** column says `blocked` (points at
  `0.0.0.0`, as ad blockers do), `this computer` (points at `127.0.0.1`) or `redirect` (any
  other address). Only the first 15 lines are shown.
- **Flush the DNS cache** is the right command for your OS: `ipconfig /flushdns` on
  Windows, `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder` on macOS, and
  `sudo resolvectl flush-caches` on Linux with systemd-resolved (or `sudo nscd
  --invalidate=hosts` with nscd). dnskit only prints it; it doesn't run it.
- **Problem panels** explain each problem and how to fix it. Red panels with **✗** are
  errors (DNS doesn't work); yellow panels with **!** are warnings (DNS works, but something
  is misconfigured or slow).
- **The summary line** is `✓ No problems found.`, `DNS is working … with N warnings`, or
  `✗ DNS isn't working properly`.

Problems it can report:

| Problem | Severity |
|---|---|
| No network adapter is connected | error |
| No DNS servers on the connected adapters | error |
| No DNS server is responding (every server in use failed) | error |
| A DNS server in use isn't responding | warning |
| DNS servers outside the VPN aren't responding (a VPN is connected) | warning |
| A DNS server is slow | warning |
| Ghost DNS server | warning |
| A DNS server answers for names that don't exist (NXDOMAIN hijacking) | warning |
| Queries to 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare) appear to be intercepted | warning |
| IPv6 is broken (AAAA lookups work, IPv6 connections fail) | warning |
| The hosts file overrides DNS for some names | warning |
| Couldn't read the network adapters or the hosts file | warning |

**Exit code:** `0` when DNS works (warnings only, or no problems), `1` when there's an
error.

**Where the information comes from:**

| | Adapters | DNS servers per adapter |
|---|---|---|
| Windows | Windows networking API (`GetAdaptersAddresses`) | The same API; the registry for ghost entries |
| macOS | `ifconfig -a` | `scutil --dns` |
| Linux | `/sys/class/net` | `resolvectl dns` (systemd-resolved) |

On Linux without systemd-resolved, the system doesn't say which adapter a DNS server
belongs to. dnskit then tests the servers in `/etc/resolv.conf` and can't detect ghosts.

---

### `dnskit reach`

"The site won't load": is it DNS, the connection, or neither? `reach` looks up the name's
IPv4 (A) and IPv6 (AAAA) addresses, tries a TCP connection to port 443 (HTTPS) on each,
and tells you where the problem is.

**When to use it:**

- "The website won't load": find out whether it's DNS (the name doesn't resolve or is
  blocked by a filter) or the connection (the server is down or a firewall blocks it), so
  you know whether to call the DNS provider or the hosting company.
- Checking whether a server's other services answer from here: SSH (`-p 22`), remote
  desktop (`-p 3389`) or mail (`-p 25`).
- After changing a firewall rule, confirming the port is now open.

```text
dnskit reach DOMAIN [--port PORT] [--server IP] [--timeout SECONDS] [--refresh]
```

| Option | Default | What it does |
|---|---|---|
| `DOMAIN` | | The site's name. A URL such as `https://example.com/page` works too. |
| `--port`, `-p` | `443` | The TCP port to connect to (1–65535), e.g. `80` for plain HTTP or `22` for SSH. |
| `--server`, `-s` | automatic | Look the name up with this DNS server, as with `lookup`. |
| `--timeout` | `5.0` | Seconds to wait for each lookup and each connection. |
| `--refresh` | off | Re-check the system DNS servers instead of using the cached choice. |

Up to 4 addresses of each type are tried, all at once; the rest are counted below the
table. A connection is only opened and closed again: nothing is sent, so it's safe on any
port.

#### Example: everything works

```text
$ dnskit reach www.google.com
www.google.com on port 443
┌───────────────────────┬──────┬─────────────────┐
│ Address               │ Type │      Connection │
├───────────────────────┼──────┼─────────────────┤
│ 142.251.155.119       │ IPv4 │         ✓ 22 ms │
│ 142.251.156.119       │ IPv4 │         ✓ 22 ms │
│ 142.251.153.119       │ IPv4 │         ✓ 21 ms │
│ 142.251.154.119       │ IPv4 │         ✓ 21 ms │
│ 2001:4860:4827:7700:: │ IPv6 │ – no IPv6 route │
│ 2001:4860:4828:7700:: │ IPv6 │ – no IPv6 route │
│ 2001:4860:482a:7700:: │ IPv6 │ – no IPv6 route │
│ 2001:4860:482c:7700:: │ IPv6 │ – no IPv6 route │
└───────────────────────┴──────┴─────────────────┘
… and 8 more addresses, not tried
┌─ ✓ Neither: DNS and the connection both work ───────────────────────────────────────────┐
│ www.google.com resolved to 16 addresses, and 142.251.154.119 accepted a connection on   │
│ port 443 in 21 ms.                                                                      │
│                                                                                         │
│ Next step: If the site still doesn't load, the problem is past the connection: the web  │
│ server, its certificate, or the browser. Try another browser or a private window, and   │
│ flush the DNS cache (dnskit local shows the command).                                   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 29 ms; cached, probed 2 min ago)
· 86 ms total
```

**– no IPv6 route** means this computer has no IPv6 connection, so apps use IPv4: that's
fine and isn't counted as a failure. If IPv6 *is* available but its connections fail while
IPv4 works, the panel says so, because apps that try IPv6 first will be slow.

#### Example: the connection is the problem

```text
$ dnskit reach example.com --port 81 --timeout 2
example.com on port 81
┌─────────────────────────┬──────┬─────────────────┐
│ Address                 │ Type │      Connection │
├─────────────────────────┼──────┼─────────────────┤
│ 104.20.23.154           │ IPv4 │     ✗ timed out │
│ 172.66.147.243          │ IPv4 │     ✗ timed out │
│ 2606:4700:10::6814:179a │ IPv6 │ – no IPv6 route │
│ 2606:4700:10::ac42:93f3 │ IPv6 │ – no IPv6 route │
└─────────────────────────┴──────┴─────────────────┘
┌─ ✗ The problem is the connection: port 81 isn't reachable ──────────────────────────────┐
│ DNS works: example.com resolved to 104.20.23.154, 172.66.147.243, but no connection to  │
│ port 81 got a reply. Something between this computer and the server drops it: a         │
│ firewall here or on the network, a VPN, or the server itself is down.                   │
│                                                                                         │
│ Next step: Check whether other sites load. If they do, try another network (such as a   │
│ phone hotspot) to see whether this network blocks it, and check the site's status page. │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 29 ms; cached, probed 2 min ago)
· 2073 ms total
```

#### Example: DNS is the problem

```text
$ dnskit reach https://exampel.invalid/
No addresses for exampel.invalid (A: domain does not exist (NXDOMAIN), AAAA: domain does
not exist (NXDOMAIN))
┌─ ✗ The problem is DNS: domain doesn't exist ────────────────────────────────────────────┐
│ exampel.invalid isn't registered in DNS — the nameserver answered that no such name     │
│ exists (NXDOMAIN).                                                                      │
│                                                                                         │
│ Next step: Check the spelling for typos. If this domain used to work, its registration  │
│ may have expired — check it with a WHOIS lookup.                                        │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (auto: fastest of 3 system nameservers, 29 ms; cached, probed 2 min ago)
· 54 ms total
```

#### Verdicts

| Verdict | What it means | Exit code |
|---|---|---|
| **Neither: DNS and the connection both work** | At least one address accepted a connection. If the site still fails, look at the browser, the certificate or the web server. | `0` |
| **The problem is DNS** | No usable address: the name doesn't exist, has no A/AAAA records, the lookup timed out or failed (explained as in [section 8](#8-when-a-lookup-fails-every-error-explained)), or the DNS server answered `0.0.0.0` / `127.0.0.1`, which is how ad blockers and filters **block** a name. | `1` |
| **The problem is the connection** | DNS gave addresses, but none accepted a connection. **refused**: the server answered but nothing listens on that port. **timed out**: a firewall or VPN drops it, or the server is down. **unreachable**: no route to that address (for example, an IPv6-only site on a computer without IPv6). | `3` |

If this computer's hosts file has an entry for the name, the panel mentions it: browsers
use the hosts file instead of DNS, so they may behave differently from `reach`.

Invalid input (not a domain name, or a port outside 1–65535) exits with `2`.

---

### `dnskit trace`

Follows a name's **delegation** from the top of DNS down, like `dig +trace`: it asks a root
server, which refers it to the top-level domain's servers (`com.`), which refer it to the
domain's own nameservers, which give the answer. Each step shows who was asked, where they
pointed, and how long they took. Use it when a domain is broken **for everyone**, to see at
which level it breaks.

**When to use it:**

- A domain stopped working for everyone, not just you: find out whether the fault is at
  the top-level domain (often an expired registration), at the nameservers your registrar
  lists, or at your DNS host.
- After changing nameservers at the registrar (for example when moving DNS to Cloudflare),
  confirming that the delegation now points to the new ones.
- One of a domain's nameservers doesn't serve it any more (a lame delegation), so lookups
  fail now and then.

```text
dnskit trace DOMAIN [--type TYPE] [--timeout SECONDS]
```

| Option | Default | What it does |
|---|---|---|
| `DOMAIN` | | The name to trace. A URL works too. |
| `--type`, `-t` | `A` | The record type to ask for at the end. |
| `--timeout` | `2.0` | Seconds to wait for each level's nameservers. |

At each level, up to 3 of that level's nameservers are asked at once and the first useful
reply is used, so one dead server doesn't slow the trace down; the dead one is listed
under the step ("timed out; another server answered"). The queries are **non-recursive**:
each server only says what it knows itself, so the trace shows the real delegation, not a
resolver's cached copy. When a referral has no addresses for the nameservers (no "glue",
because they're in another domain), their addresses are looked up and the step says so.

```text
$ dnskit trace example.com
example.com. A (from the root servers down)
└── . (root)  asked a.root-servers.net. (198.41.0.4) · 190 ms
    → referral to com. a.gtld-servers.net., b.gtld-servers.net., c.gtld-servers.net. and 10
    more (13 servers)
    └── com.  asked b.gtld-servers.net. (192.33.14.30) · 51 ms
        → referral to example.com. elliott.ns.cloudflare.com., hera.ns.cloudflare.com.
        └── example.com.  asked elliott.ns.cloudflare.com. (108.162.195.228) · 29 ms
            ✓ answer: 104.20.23.154, 172.66.147.243
3 steps · 274 ms total
```

#### What each step can end with

| Step result | Meaning |
|---|---|
| **→ referral to** *zone* | This level passed the query down to *zone*'s nameservers (listed). |
| **✓ answer** | The domain's nameservers gave the records (CNAMEs are shown as `CNAME target`). |
| **✗ the name doesn't exist (NXDOMAIN)** | That level says the name doesn't exist. From the `com.` servers it means the domain isn't registered. |
| **no *TYPE* records** | The name exists but has no records of that type. |
| **✗ failed at this level** | No server at this level gave a useful reply. Each server's error is listed. |

When a level fails, a red panel says which level and why:

| Failure | What it means |
|---|---|
| **The domain's nameservers didn't respond** | The levels above worked, so your connection is fine: the domain's DNS servers are down, or a firewall in front of them drops queries. Everyone has the same problem. |
| **…aren't serving it (lame delegation)** | The nameservers answered but refused, or answered without the records or a referral. Usually the registrar still lists old nameservers after a move to a new DNS host. |
| **…returned a server failure** | The nameservers replied SERVFAIL: a problem at the DNS host. |
| **…nameservers have no address** | The nameserver names at the registrar don't exist (often a typo). |
| **Too many referrals** | The delegation loops. |

#### When direct queries are blocked

`trace` has to talk to the root servers and every level's nameservers itself. Many VPNs
and firewalls only let DNS through to their own server, so those queries just time out.
When no root server responds, dnskit checks this computer's own DNS server and whether a
VPN is connected, explains the block (see
[Direct DNS queries are blocked](#direct-dns-queries-are-blocked)), and then follows the
delegation **through your own DNS server** instead: for each level it asks which
nameservers serve it. That shows the same chain, but not how each nameserver answers or
how fast, and the heading says "through *resolver*: direct queries are blocked".

The same trace on a computer whose VPN blocks outside DNS:

```text
$ dnskit trace example.com
example.com. A (through 8.8.8.8: direct queries are blocked)
└── . (root)  asked 8.8.8.8 · 257 ms
    → referral to com. a.gtld-servers.net., b.gtld-servers.net., c.gtld-servers.net. and 10
    more (13 servers)
    └── com.  asked 8.8.8.8 · 20 ms
        → referral to example.com. elliott.ns.cloudflare.com., hera.ns.cloudflare.com.
        └── example.com.  asked 8.8.8.8 · 19 ms
            ✓ answer: 104.20.23.154, 172.66.147.243
┌─ Direct DNS queries are blocked by the VPN ─────────────────────────────────────────────┐
│ No reply from the root servers, but this computer's own DNS server (8.8.8.8) works.     │
│ OfficeVPN (VPN) is connected, and VPNs usually block DNS to every server except         │
│ their own, so DNS can't leak outside the tunnel (DNS leak protection). This computer    │
│ itself refused to connect to an outside DNS server, so the block is a firewall on this  │
│ computer (the VPN's kill switch). The root servers are almost certainly fine; they just │
│ can't be reached from here.                                                             │
│                                                                                         │
│ Next step: Disconnect OfficeVPN and run this again, or run it on another network.       │
│ Meanwhile, the trace shown was done through 8.8.8.8 instead: it shows each level's      │
│ nameservers, but not how each of them answers or how fast.                              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
3 steps · 3370 ms total
```

Exit code `0` when the trace reached the records, `1` for anything else (doesn't exist, no
records of the type, a level failed), `2` for invalid input.

---

### `dnskit dnssec`

Checks whether a domain uses **DNSSEC** and whether its **chain of trust** validates from
the root down, and explains the result in plain English.

DNSSEC adds signatures to DNS records. Each zone signs its records with its keys (DNSKEY),
and its parent vouches for those keys with a DS record, all the way up to the root, whose
key everyone already trusts. A resolver that validates DNSSEC can then prove an answer
really came from the domain's owner. **It protects against forged answers** (someone on
the network, or a poisoned resolver cache, sending you to a fake address). It does
**not** encrypt DNS or hide which sites you visit.

**When to use it:**

- A domain works through some DNS servers but fails (SERVFAIL) through Google, Cloudflare
  or Quad9: the classic sign of broken DNSSEC.
- Before moving a domain to a new DNS host or registrar: changing keys without updating
  the DS record at the registrar takes the domain offline for most people.
- A security review asks whether your domains use DNSSEC.
- Many secure sites fail on one computer only: the clock check shows whether the
  computer's date is wrong.

```text
dnskit dnssec DOMAIN [--server IP] [--timeout SECONDS] [--refresh]
```

| Option | Default | What it does |
|---|---|---|
| `DOMAIN` | | The name to check. |
| `--server`, `-s` | automatic | The DNS server to fetch the records through, as with `lookup`. |
| `--timeout` | `5.0` | Seconds to wait for each query. |
| `--refresh` | off | Re-check the system DNS servers instead of using the cached choice. |

dnskit checks every signature itself, so the result doesn't depend on whether your DNS
server validates. For each zone from the root down to the domain's own zone it checks:

1. **The root**: its keys match the root's published trust anchors (built into dnskit) and
   sign its key set.
2. **Each zone below** (`com.`, `example.com.`): the parent has a signed **DS** record, the
   DS matches one of the zone's **keys**, and that key signs the zone's key set.
3. **The records**: the zone's SOA record and the name's A records are signed with the
   zone's keys, and the signatures haven't expired.

The records are fetched through your normal DNS server (with checking turned off, so a
validating server hands over broken data instead of just failing), so `dnssec` works on a
VPN that blocks outside DNS.

Some routers, DNS filters and networks **strip DNSSEC signatures** from the answers, so
nothing can be checked through them. When your DNS server does that, `dnssec` redoes the
check through 8.8.8.8 (or 1.1.1.1 if 8.8.8.8 doesn't answer) and says so above the table:
**This computer's DNS server (…) strips DNSSEC signatures, so this was checked through
8.8.8.8.** That sends the domain name to Google (or Cloudflare). If neither can be used
either, the result is **Couldn't check DNSSEC: this network strips the signatures**, which
says nothing about the domain itself. A server you name with `--server` is always used,
never replaced.

#### Example: DNSSEC is on

This network's DNS server strips signatures, so the check went through 8.8.8.8:

```text
$ dnskit dnssec www.isc.org
This computer's DNS server (192.0.2.101) strips DNSSEC signatures, so this was checked
through 8.8.8.8.
DNSSEC chain of trust for www.isc.org
┌────────────────┬───────────────────────┬────────────────────────┬───────────────────────┐
│ Zone           │ DS (at parent)        │ Keys                   │ Result                │
├────────────────┼───────────────────────┼────────────────────────┼───────────────────────┤
│ . (root)       │ trust anchors 20326,  │ 2 KSK + 1 ZSK          │ ✓ keys signed by      │
│                │ 38696                 │ (RSASHA256)            │ trust anchor 20326,   │
│                │                       │                        │ 38696                 │
│ org.           │ 26974                 │ 2 KSK + 3 ZSK          │ ✓ DS at . matches key │
│                │                       │ (RSASHA256)            │ 26974; keys signed    │
│ isc.org.       │ 7250                  │ 1 KSK + 1 ZSK          │ ✓ DS at org. matches  │
│                │                       │ (ECDSAP256SHA256)      │ key 7250; keys signed │
│ isc.org. SOA   │                       │                        │ ✓ signed by key       │
│                │                       │                        │ 27566, valid until    │
│                │                       │                        │ 2026-11-16            │
│ www.isc.org. A │                       │                        │ ✓ signed by key       │
│                │                       │                        │ 27566, valid until    │
│                │                       │                        │ 2026-11-12            │
└────────────────┴───────────────────────┴────────────────────────┴───────────────────────┘
Clock: ✓ looks right (root zone from 2026-11-01)
┌─ ✓ DNSSEC is on and validates for www.isc.org ──────────────────────────────────────────┐
│ Every link from the root down to isc.org is signed and checks out: each parent vouches  │
│ for its child's key with a DS record, and each zone signs its records with that key.    │
│ DNSSEC protects against forged DNS answers: someone on the network, or a poisoned       │
│ resolver cache, can't send visitors to a fake address without the signature check       │
│ failing. It doesn't encrypt DNS or hide which sites you visit. Validating resolvers     │
│ (such as 8.8.8.8, 1.1.1.1 and 9.9.9.9) check this automatically.                        │
│                                                                                         │
│ Next step: Nothing to do. When you change DNS host or keys, update the DS record at the │
│ registrar at the same time, or validation breaks.                                       │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (this computer's DNS server 192.0.2.101 strips DNSSEC signatures) · 1086
ms total
```

**KSK** (key-signing key) signs the zone's keys and is what the parent's DS points to;
**ZSK** (zone-signing key) signs the other records. The numbers are key tags, which is how
DS records, keys and signatures refer to each other.

#### Example: DNSSEC is broken

`dnssec-failed.org` is a test domain that is broken on purpose:

```text
$ dnskit dnssec dnssec-failed.org
This computer's DNS server (192.0.2.101) strips DNSSEC signatures, so this was checked
through 8.8.8.8.
DNSSEC chain of trust for dnssec-failed.org
┌────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┐
│ Zone               │ DS (at parent)       │ Keys                 │ Result               │
├────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ . (root)           │ trust anchors 20326, │ 2 KSK + 1 ZSK        │ ✓ keys signed by     │
│                    │ 38696                │ (RSASHA256)          │ trust anchor 20326,  │
│                    │                      │                      │ 38696                │
│ org.               │ 26974                │ 2 KSK + 3 ZSK        │ ✓ DS at . matches    │
│                    │                      │ (RSASHA256)          │ key 26974; keys      │
│                    │                      │                      │ signed               │
│ dnssec-failed.org. │ 42069                │ 1 KSK + 1 ZSK        │ ✗ the DS record at   │
│                    │                      │ (ECDSAP256SHA256)    │ org. (key 42069)     │
│                    │                      │                      │ matches none of its  │
│                    │                      │                      │ keys (key-signing    │
│                    │                      │                      │ keys: 50719)         │
└────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┘
Clock: ✓ looks right (root zone from 2026-11-01)
┌─ ✗ DNSSEC is broken for dnssec-failed.org ──────────────────────────────────────────────┐
│ dnssec-failed.org: the DS record at org. (key 42069) matches none of its keys           │
│ (key-signing keys: 50719). Resolvers that validate DNSSEC (Google, Cloudflare, Quad9    │
│ and many ISPs) refuse to answer for dnssec-failed.org (SERVFAIL), so it looks down to   │
│ most people, while resolvers that don't validate still answer.                          │
│                                                                                         │
│ Next step: The DS record at the registrar doesn't match the zone's current key, which   │
│ happens after a key change or a move to a new DNS host. Replace it with the DS record   │
│ your DNS host shows, or remove it to switch DNSSEC off until then.                      │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (this computer's DNS server 192.0.2.101 strips DNSSEC signatures; cached,
probed 7s ago) · 4055 ms total
```

#### Results

| Result | What it means | Exit code |
|---|---|---|
| **✓ DNSSEC is on and validates** | Every link checks out. | `0` |
| **– DNSSEC isn't enabled** | The parent has no DS record for the zone, so it's unsigned (most domains are). Lookups work normally, without forgery protection. If the zone has keys but no DS, the panel says it's **only half set up**: the DS was never added at the registrar. | `0` |
| **✗ DNSSEC is broken** | A link fails: the DS matches none of the zone's keys, the zone has no keys although its parent has a DS, or a signature is expired or doesn't verify. Validating resolvers (Google, Cloudflare, Quad9, many ISPs) then refuse to answer for the domain (SERVFAIL), so it looks down to most people. The panel says what to fix at the registrar or DNS host. | `1` |
| **? Couldn't check DNSSEC** | The DNS server didn't respond. If an outside `--server` doesn't respond because a VPN or firewall blocks it, the panel explains that instead. When your DNS server **strips DNSSEC signatures** and 8.8.8.8 and 1.1.1.1 can't be used either, it says **this network strips the signatures**. | `1` |
| ***name* doesn't exist** | The chain validates, but the name itself doesn't exist. | `1` |

Example of the most common result, DNSSEC not enabled:

```text
$ dnskit dnssec google.com
This computer's DNS server (192.0.2.101) strips DNSSEC signatures, so this was checked
through 8.8.8.8.
DNSSEC chain of trust for google.com
┌─────────────┬────────────────────────┬────────────────────────┬─────────────────────────┐
│ Zone        │ DS (at parent)         │ Keys                   │ Result                  │
├─────────────┼────────────────────────┼────────────────────────┼─────────────────────────┤
│ . (root)    │ trust anchors 20326,   │ 2 KSK + 1 ZSK          │ ✓ keys signed by trust  │
│             │ 38696                  │ (RSASHA256)            │ anchor 38696, 20326     │
│ com.        │ 19718                  │ 1 KSK + 1 ZSK          │ ✓ DS at . matches key   │
│             │                        │ (ECDSAP256SHA256)      │ 19718; keys signed      │
│ google.com. │ none                   │ none                   │ – no DS record at com.: │
│             │                        │                        │ not signed              │
└─────────────┴────────────────────────┴────────────────────────┴─────────────────────────┘
Clock: ✓ looks right (root zone from 2026-11-01)
┌─ – DNSSEC isn't enabled for google.com ─────────────────────────────────────────────────┐
│ There's no DS record for google.com at com, so there's no chain of trust to it. Lookups │
│ work normally, but resolvers can't tell a genuine answer from a forged one. DNSSEC      │
│ protects against forged DNS answers: someone on the network, or a poisoned resolver     │
│ cache, can't send visitors to a fake address without the signature check failing. It    │
│ doesn't encrypt DNS or hide which sites you visit.                                      │
│                                                                                         │
│ Next step: To turn it on, enable DNSSEC at your DNS host, then add the DS record it     │
│ gives you at your registrar (many hosts do both in one step).                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (this computer's DNS server 192.0.2.101 strips DNSSEC signatures; cached,
probed 9s ago) · 562 ms total
```

#### The clock check

Signatures are only valid between two dates, so a computer whose clock is far off sees
valid signatures as expired or not yet valid, and validation fails (HTTPS certificates
fail too). dnskit compares the clock with the root zone's date (its SOA serial is the date
it was published, `YYYYMMDDnn`) and with the root signatures' validity dates. The
**Clock:** line shows the result; when the clock looks wrong, a yellow **This computer's
clock looks wrong** panel appears, and if signatures failed because of the date, the result
says **Validation failed: this computer's clock is wrong** instead of blaming the domain.

---

### `dnskit propagation`

After changing a DNS record, how far has the change spread? `propagation` asks 14 public
resolvers for the record, all at once, and shows what share give the same answer: global
anycast resolvers, plus resolvers with a fixed location in the Americas, Europe and Asia.

**When to use it:**

- You moved your website to a new server and changed its A record: do people elsewhere see
  the new address yet?
- You switched email provider and changed the MX records: `dnskit propagation example.com
  -t MX` shows how far the change has spread.
- A customer in another country still sees the old site after a change.

```text
dnskit propagation DOMAIN [--type TYPE] [--timeout SECONDS]
```

| Option | Default | What it does |
|---|---|---|
| `DOMAIN` | | The name to check. |
| `--type`, `-t` | `A` | The record type to check, e.g. `MX` or `TXT`. |
| `--timeout` | `1.5` | Seconds to wait for each resolver. An unanswered query is re-sent every 0.5 s within that time, so a lost packet doesn't count as a failure. |

The resolvers are shown in groups:

| Group | Resolvers |
|---|---|
| **Global (anycast)** | Google, Cloudflare, Quad9, OpenDNS, Hurricane Electric, Control D, AdGuard |
| **Americas** | CIRA Shield (Canada) |
| **Europe** | DNS.WATCH (Germany), Yandex (Russia) |
| **Asia** | KT (South Korea), AliDNS, DNSPod and 114DNS (China) |

**Anycast** resolvers have sites all over the world and answer from the one nearest to
you, so they show what people near you see, not what other regions see; a note under the
table says so. Only resolvers with a fixed location are listed under a region.

Every resolver is asked at once, so the command takes as long as the slowest answer: about
half a second normally, and at most about 2 s when a resolver doesn't respond at all.

Answers are compared like in `compare` (order and TTL ignored). The most common answer is
the **majority**; resolvers giving another answer are marked **≠ differs**, and the summary
line gives the percentage of responding resolvers that give the majority answer.

| Result | What it means | Exit code |
|---|---|---|
| **✓ Fully propagated** | Every resolver that answered agrees (at least two answered). | `0` |
| **… Still propagating: N%** | Some resolvers still give another answer. They update when their cached copy expires: the panel says within how long, from the longest remaining TTL among them. | `1` |
| **… Probably location-based DNS** | Only resolvers in other countries differ, and every global resolver agrees with the most common answer (A and AAAA only). That's what a CDN or geo-DNS does: it gives each region its own servers. Not an error, but dnskit can't be sure, so it still exits `1`. | `1` |
| **No consensus** | The top answers are tied. | `1` |
| **✗ blocked / no answers** | Too few resolvers could be reached (see below). | `1` |

The most common answer isn't necessarily the **new** one: check it against what you set.
Domains on a CDN or geo-DNS give different addresses in different regions on purpose, so
for them some differences are normal. When the global anycast resolvers all agree and only
fixed-location resolvers abroad differ, dnskit says the difference is **probably
location-based** rather than a change still spreading: a change that hasn't propagated
would show up at some of the many anycast sites too.

Example. Yandex's different answer is real geo-DNS: example.com is on Cloudflare, which
gives Russian visitors other addresses:

```text
$ dnskit propagation example.com
example.com A across 14 public resolvers
┌──────────────────┬────────────────────┬──────────────┬────────────────┬─────┬───────────┐
│ Region           │ Resolver           │ Location     │ Answer         │ TTL │           │
├──────────────────┼────────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Global (anycast) │ Google 8.8.8.8     │ nearest site │ 104.20.23.154  │ 300 │ majority  │
│                  │                    │              │ 172.66.147.243 │     │           │
│                  │ Cloudflare 1.1.1.1 │ nearest site │ 104.20.23.154  │ 138 │ majority  │
│                  │                    │              │ 172.66.147.243 │     │           │
│                  │ Quad9 9.9.9.9      │ nearest site │ 104.20.23.154  │  59 │ majority  │
│                  │                    │              │ 172.66.147.243 │     │           │
│                  │ OpenDNS            │ nearest site │ 104.20.23.154  │ 106 │ majority  │
│                  │ 208.67.222.222     │              │ 172.66.147.243 │     │           │
│                  │ Hurricane Electric │ nearest site │ 104.20.23.154  │ 300 │ majority  │
│                  │ 74.82.42.42        │              │ 172.66.147.243 │     │           │
│                  │ Control D          │ nearest site │ 104.20.23.154  │ 215 │ majority  │
│                  │ 76.76.2.0          │              │ 172.66.147.243 │     │           │
│                  │ AdGuard            │ nearest site │ 104.20.23.154  │  60 │ majority  │
│                  │ 94.140.14.140      │              │ 172.66.147.243 │     │           │
├──────────────────┼────────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Americas         │ CIRA Shield        │ Canada       │ 104.20.23.154  │ 164 │ majority  │
│                  │ 149.112.121.10     │              │ 172.66.147.243 │     │           │
├──────────────────┼────────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Europe           │ DNS.WATCH          │ Germany      │ 104.20.23.154  │  11 │ majority  │
│                  │ 84.200.69.80       │              │ 172.66.147.243 │     │           │
│                  │ Yandex 77.88.8.8   │ Russia       │ 8.6.112.0      │ 289 │ ≠ differs │
│                  │                    │              │ 8.47.69.0      │     │           │
├──────────────────┼────────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Asia             │ KT 168.126.63.1    │ South Korea  │ 104.20.23.154  │  81 │ majority  │
│                  │                    │              │ 172.66.147.243 │     │           │
│                  │ AliDNS 223.5.5.5   │ China        │ 104.20.23.154  │ 209 │ majority  │
│                  │                    │              │ 172.66.147.243 │     │           │
│                  │ DNSPod             │ China        │ 104.20.23.154  │  31 │ majority  │
│                  │ 119.29.29.29       │              │ 172.66.147.243 │     │           │
│                  │ 114DNS             │ China        │ 104.20.23.154  │  79 │ majority  │
│                  │ 114.114.114.114    │              │ 172.66.147.243 │     │           │
└──────────────────┴────────────────────┴──────────────┴────────────────┴─────┴───────────┘
Global (anycast) resolvers answer from their site nearest to you, so they show what people
near you see, not what other regions see.
93% of the resolvers that answered (13 of 14) give the most common answer
┌─ … Probably location-based DNS, not propagation ────────────────────────────────────────┐
│ All 7 global resolvers agree, and the 1 resolver that differs is in another country     │
│ (Yandex in Russia). Sites on a CDN or geo-DNS give each region its own nearby servers   │
│ on purpose, so this is normal for them. If you didn't just change this record, nothing  │
│ is wrong.                                                                               │
│                                                                                         │
│ Next step: If you did change it, check that the most common answer is the value you     │
│ set: if it is, the change has reached the resolvers near you. Run this again later:     │
│ answers that are location-based stay different, while stale ones catch up when their    │
│ TTL runs out.                                                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘
Queried 14 resolvers in parallel · 418 ms total
```

#### When outside resolvers are blocked

When more than half of the resolvers don't respond, dnskit checks whether a VPN or
firewall is blocking DNS to outside servers (see
[Direct DNS queries are blocked](#direct-dns-queries-are-blocked)). If fewer than two
resolvers answered, propagation can't be measured from this computer, and the panel says
so instead of showing a meaningless 100%: for example "Only 1 of 14 resolvers could be
reached, so propagation can't be measured from here", with a suggestion to use an online
propagation checker.

---

### `dnskit resolvers`

Check every DNS server your computer uses: which respond, how fast, and which one dnskit
will use.

**When to use it:**

- Every lookup, or the first command after changing network, is slow: see which DNS server
  is dead or slow.
- Checking which DNS server this computer and dnskit are using right now.
- After changing the DNS server settings on an adapter, confirming the new servers answer.

```text
dnskit resolvers [--timeout SECONDS]
```

| Option | Default | What it does |
|---|---|---|
| `--timeout` | `1.0` | How long to wait for each server before calling it "no response". |

#### Example

```text
$ dnskit resolvers
System nameservers (in system order)
┌───┬──────────────┬─────────────┬──────────────────┐
│ # │ Nameserver   │     Latency │                  │
├───┼──────────────┼─────────────┼──────────────────┤
│ 1 │ 192.168.1.1  │ no response │                  │
│ 2 │ 1.1.1.1      │       14 ms │ ← used by lookup │
│ 3 │ 8.8.8.8      │       68 ms │                  │
└───┴──────────────┴─────────────┴──────────────────┘
Slow means slower than 250 ms. 1.1.1.1 is cached as the lookup choice for 5 min
(C:\Users\you\AppData\Local\dnskit\resolver.json).
```

- **#** is the order your operating system lists the servers in.
- **Latency** is how long a small test query took. **no response** (red) means the server
  didn't answer within the timeout. **N ms (slow)** (yellow) means it answered, but took
  more than 250 ms.
- **← used by lookup** marks the fastest server. `lookup` and `reverse` will use it for the
  next 5 minutes.

Running `resolvers` always re-checks every server and updates the remembered choice. If
no server answers, it says so and exits with code `1`.

On Windows these servers come from your network adapter settings. Elsewhere they come from
`/etc/resolv.conf`. Only servers on a **connected** adapter are listed, as in
[section 7](#7-how-dnskit-chooses-a-nameserver). Any others are named on an extra line:

```text
Ignored (not on a connected adapter): 192.168.0.1, 10.0.0.1. Run `dnskit local` for details.
```

---

### `dnskit batch`

Runs `lookup`, `doctor` or `email` on every domain in a text file, a few at a time, and ends
with a summary table.

**When to use it:**

- You look after many domains and want to check them all at once, for example every
  morning or after a change at your DNS host.
- Before renewing or moving a set of domains, to see which still resolve and which have
  email problems.
- From a scheduled task with `--json`, to feed a dashboard or send an alert.

```text
dnskit batch FILE [--check lookup|doctor|email] [--parallel N] [--quick] [--server IP]
             [--timeout SECONDS] [--json]
```

| Option | Default | What it does |
|---|---|---|
| `FILE` | | A text file with one domain (or URL) per line. Blank lines and `#` comments are skipped. `-` reads the list from standard input. |
| `--check`, `-c` | `lookup` | What to run on each domain: `lookup` (does it resolve, which records), `doctor` (health score) or `email` (MX, SPF, DMARC, DKIM). |
| `--parallel` | `4` | How many domains to check at the same time (1–16). |
| `--quick` | off | With `--check doctor`: skip the slower checks, as `doctor --quick` does. |
| `--server`, `-s` | automatic | With `lookup` or `email`: ask this DNS server. |
| `--timeout` | the command's own | Seconds to wait, as for the command run. |
| `--json` | off | Print JSON instead (see [section 10](#10-using-dnskit-in-scripts)). |

A domain listed twice is checked once. A line that isn't a domain is reported under the
table and makes the exit code `1`. With `--check doctor`, this computer is checked once,
before the domains, instead of once per domain. With `--check email`, the DKIM selectors
from the config file's `[email]` section are checked too.

While it works, a spinner shows how many domains are done; it isn't shown when the output
goes to a file or another program.

Each row is **✓ OK** or **✗ not OK**:

| Check | OK means | The summary shows |
|---|---|---|
| `lookup` | The name exists (even with some record types empty). | How many records of each type it has, or why it failed. |
| `doctor` | No critical or major issue. | The score and the most important issue (notes aside), or **no issues**. |
| `email` | No check fails (warnings are fine). | The most important finding. |

#### Example

The file:

```text
# Our domains
example.com
google.com
https://www.isc.org/
example-dnskit-typo.com    # a typo
not a domain
```

```text
$ dnskit batch domains.txt
dnskit lookup for 4 domains
┌──────┬─────────────────────────┬──────────┬─────────────────────────────────┬────────┐
│ Line │ Domain                  │ Result   │ Summary                         │   Time │
├──────┼─────────────────────────┼──────────┼─────────────────────────────────┼────────┤
│    2 │ example.com             │ ✓ OK     │ A 2, AAAA 2, MX 1, NS 2, TXT 2  │ 201 ms │
│    3 │ google.com              │ ✓ OK     │ A 1, AAAA 1, MX 1, NS 4, TXT 17 │ 199 ms │
│    4 │ www.isc.org             │ ✓ OK     │ A 4, AAAA 4                     │ 351 ms │
│    5 │ example-dnskit-typo.com │ ✗ not OK │ Domain doesn't exist            │ 187 ms │
└──────┴─────────────────────────┴──────────┴─────────────────────────────────┴────────┘
Skipped line 6: 'not a domain' is not a valid domain name. Use a name like example.com.
3 OK · 1 not OK · 1 invalid line · 0.4 s total
```

```text
$ dnskit batch domains.txt --check doctor
This computer: OK (checked once for every domain; details: dnskit local)
dnskit doctor for 4 domains
┌──────┬─────────────────────────┬──────────┬───────────────────────────────────┬─────────┐
│ Line │ Domain                  │ Result   │ Summary                           │    Time │
├──────┼─────────────────────────┼──────────┼───────────────────────────────────┼─────────┤
│    2 │ example.com             │ ✓ OK     │ 95/100 · Email (DMARC): no DMARC  │  626 ms │
│      │                         │          │ report address (rua)              │         │
│    3 │ google.com              │ ✓ OK     │ 95/100 · DNSSEC isn't enabled for │  756 ms │
│      │                         │          │ google.com                        │         │
│    4 │ www.isc.org             │ ✓ OK     │ 85/100 · Email (MX): no MX        │ 1101 ms │
│      │                         │          │ records                           │         │
│    5 │ example-dnskit-typo.com │ ✗ not OK │ 0/100 · example-dnskit-typo.com:  │  662 ms │
│      │                         │          │ domain doesn't exist              │         │
└──────┴─────────────────────────┴──────────┴───────────────────────────────────┴─────────┘
Skipped line 6: 'not a domain' is not a valid domain name. Use a name like example.com.
3 OK · 1 not OK · 1 invalid line · 1.4 s total
```

Exit codes: `0` when every domain is OK and every line is a domain; `1` otherwise; `2` when
the file can't be read or has no domains in it.

### `dnskit watch`

Looks a record up again every few seconds and says when the answer changes, with a beep.

**When to use it:**

- You changed a record and want to know the moment your DNS server serves the new value:
  `--until` stops as soon as it does.
- During a migration, to see exactly when an address flips, and whether it flips back.
- Leaving a window open to notice when a site's address changes unexpectedly.

```text
dnskit watch DOMAIN [--type TYPE] [--server IP] [--interval SECONDS] [--until VALUE]
             [--count N] [--exit-on-change] [--timeout SECONDS] [--json]
```

| Option | Default | What it does |
|---|---|---|
| `DOMAIN` | | The name to watch. A URL works too. |
| `--type`, `-t` | `A` | The record type to watch. |
| `--server`, `-s` | automatic | Ask this DNS server. Without it, your own DNS server (the fastest, as for `lookup`) is asked, so you see what this computer sees. |
| `--interval` | `30` | Seconds between checks (at least 1). |
| `--until` | | Stop once the answer includes this value, such as the new IP address or the new mail server's name. |
| `--count` | | Stop after this many checks. |
| `--exit-on-change` | off | Stop at the first change (rotation doesn't count, unless `--strict`). |
| `--strict` | off | Count every change as **CHANGED**, including rotation between addresses already seen. |
| `--timeout` | `5.0` | Seconds to wait for each lookup. |
| `--json` | off | Print one JSON object per check instead (see [section 10](#10-using-dnskit-in-scripts)). |

Each check prints one line: the time, the answer (sorted, with its TTL) and whether it
changed. The order of the records and the TTL counting down don't count as changes. A
lookup that fails (a timeout, say) is shown in red but never counts as a change, so a
flaky connection doesn't set off false alarms; the next real answer is compared with the
last real one. **Doesn't exist** is a real answer, so a new name appearing is a change.

Every address (or name) in every answer is remembered. Sites on a CDN, and round-robin
names, hand out addresses from a pool, so the answer changes often without anything really
changing. When a new answer only has addresses already seen, the line says **rotating
(CDN)** in blue, without a beep. **CHANGED** (in yellow, with a beep) is kept for answers
that bring something new. With `--strict`, every change is **CHANGED**, as in earlier
versions. Rotation doesn't stop `--exit-on-change`, unless `--strict` is on.

When it stops (`--count`, `--until`, `--exit-on-change`, or Ctrl+C), `watch` says how many
times the answer changed and rotated, and lists **everything seen**: each address, how many
checks returned it, and when it was first and last seen.

Your DNS server keeps an answer until its TTL runs out, so after a change it can take up
to the old TTL (shown on every line) before the new value appears. To see the new value
straight away, watch through a public resolver that hasn't cached it yet, or ask the
domain's own nameserver with `--server`.

#### Example

```text
$ dnskit watch example.com --interval 2 --count 3
Watching example.com A every 2 s (Ctrl+C to stop)
10:45:34  104.20.23.154, 172.66.147.243 (TTL 49)  first answer, from 1.1.1.1
10:45:36  104.20.23.154, 172.66.147.243 (TTL 8)  unchanged
10:45:38  104.20.23.154, 172.66.147.243 (TTL 120)  unchanged
Stopped after 3 checks; the answer didn't change.
Everything seen
┌────────────────┬────────┬────────────┬───────────┐
│ Answer         │ Checks │ First seen │ Last seen │
├────────────────┼────────┼────────────┼───────────┤
│ 104.20.23.154  │      3 │ 10:45:34   │ 10:45:38  │
│ 172.66.147.243 │      3 │ 10:45:34   │ 10:45:38  │
└────────────────┴────────┴────────────┴───────────┘
```

Waiting for a new address, and stopping as soon as it arrives:

```bash
dnskit watch example.com --until 203.0.113.80 --interval 60
```

When the answer changes, the line says **CHANGED** and what it was before. `pool.ntp.org`
hands out time servers from a pool, a few at a time, so it changes on almost every check;
once some servers come round again, the lines say **rotating (CDN)** instead:

```text
$ dnskit watch pool.ntp.org --interval 1 --count 8 --server 1.1.1.1
Watching pool.ntp.org A every 1 s (Ctrl+C to stop)
10:45:05  155.232.19.6, 155.232.19.7, 196.10.52.57, 196.10.55.58 (TTL 120)  first answer,
from 1.1.1.1
10:45:06  139.84.231.151, 196.10.54.58, 196.10.55.58, 196.49.100.58 (TTL 119)  CHANGED (was
155.232.19.6, 155.232.19.7, 196.10.52.57, 196.10.55.58 (TTL 120))
10:45:07  102.222.156.151, 196.10.54.57, 196.49.100.57, 196.49.100.58 (TTL 26)  CHANGED
(was 139.84.231.151, 196.10.54.58, 196.10.55.58, 196.49.100.58 (TTL 119))
10:45:08  139.84.231.151, 196.10.52.57, 196.49.100.57, 196.49.100.58 (TTL 67)  rotating
(CDN) (all seen before)
10:45:09  102.222.156.151, 160.119.230.39, 196.10.54.57, 196.10.55.57 (TTL 120)  CHANGED
(was 139.84.231.151, 196.10.52.57, 196.49.100.57, 196.49.100.58 (TTL 67))
10:45:10  139.84.231.151, 155.232.19.7, 196.10.52.57, 196.10.52.58 (TTL 117)  CHANGED (was
102.222.156.151, 160.119.230.39, 196.10.54.57, 196.10.55.57 (TTL 120))
10:45:11  139.84.231.151, 196.10.52.57, 196.10.55.57, 196.49.100.58 (TTL 110)  rotating
(CDN) (all seen before)
10:45:12  102.202.120.27, 196.10.54.58, 196.49.100.57, 196.49.100.58 (TTL 119)  CHANGED
(was 139.84.231.151, 196.10.52.57, 196.10.55.57, 196.49.100.58 (TTL 110))
Stopped after 8 checks; the answer changed 5 times and rotated 2 times between addresses
already seen.
Everything seen
┌─────────────────┬────────┬────────────┬───────────┐
│ Answer          │ Checks │ First seen │ Last seen │
├─────────────────┼────────┼────────────┼───────────┤
│ 155.232.19.6    │      1 │ 10:45:05   │ 10:45:05  │
│ 155.232.19.7    │      2 │ 10:45:05   │ 10:45:10  │
│ 196.10.52.57    │      4 │ 10:45:05   │ 10:45:11  │
│ 196.10.55.58    │      2 │ 10:45:05   │ 10:45:06  │
│ 139.84.231.151  │      4 │ 10:45:06   │ 10:45:11  │
│ 196.10.54.58    │      2 │ 10:45:06   │ 10:45:12  │
│ 196.49.100.58   │      5 │ 10:45:06   │ 10:45:12  │
│ 102.222.156.151 │      2 │ 10:45:07   │ 10:45:09  │
│ 196.10.54.57    │      2 │ 10:45:07   │ 10:45:09  │
│ 196.49.100.57   │      3 │ 10:45:07   │ 10:45:12  │
│ 160.119.230.39  │      1 │ 10:45:09   │ 10:45:09  │
│ 196.10.55.57    │      2 │ 10:45:09   │ 10:45:11  │
│ 196.10.52.58    │      1 │ 10:45:10   │ 10:45:10  │
│ 102.202.120.27  │      1 │ 10:45:12   │ 10:45:12  │
└─────────────────┴────────┴────────────┴───────────┘
```

Exit codes: `0` when stopped as asked (`--count`, `--exit-on-change`, or `--until`
reached); `1` when `--count` ran out before `--until` was reached; `130` after Ctrl+C;
`2` for invalid input.

### `dnskit config`

Shows where the config file is and what it sets, or creates a starter file.

**When to use it:**

- You always use the same DNS server, record type or timeout and are tired of typing it.
- Your company has its own resolvers that `compare` and `propagation` should ask.
- Scripts should always get JSON (`json = true` under `[defaults]`).

```text
dnskit config [--init] [--path] [--json]
```

| Option | What it does |
|---|---|
| `--init` | Create a commented starter file, if there's none yet. |
| `--path` | Only print where the file is (whether or not it exists). |
| `--json` | Print the settings as JSON. |

The file is **TOML**, in `%APPDATA%\dnskit\config.toml` on Windows and
`~/.config/dnskit/config.toml` elsewhere (or `$XDG_CONFIG_HOME/dnskit/`). Set
`DNSKIT_CONFIG` to use another file. Everything in it is optional:

- **`[defaults]`** applies to every command that has the setting.
- **A command's own section** (`[lookup]`, `[doctor]`, `[watch]`, …) applies to that
  command and wins over `[defaults]`.
- **Options on the command line always win** over the file.
- **`[compare]` and `[propagation]`** can also hold a `resolvers` list that replaces the
  built-in public resolvers. `compare` still adds this computer's DNS servers, and
  `doctor` uses the `[compare]` list for its comparison.

| Setting | Commands | Value |
|---|---|---|
| `server` | lookup, reverse, email, reach, dnssec, watch | A DNS server's IP. |
| `timeout` | every command | Seconds, above 0. |
| `json` | every command | `true` to always print JSON. |
| `type` | lookup, compare, trace, propagation, watch | A record type, such as `"MX"`. |
| `selectors` | email (and `batch --check email`) | A list of DKIM selectors, such as `["s1", "s2"]`. |
| `port` | reach | A TCP port. |
| `quick` | doctor, batch | `true` to skip the slower checks. |
| `check`, `parallel` | batch | `"lookup"`, `"doctor"` or `"email"`; how many at a time. |
| `interval`, `strict` | watch | Seconds between checks; `true` to count rotation as a change. |

Each `resolvers` entry needs a `name` and an `address`. For `propagation` it can also have
a `location` (a country) and a `region` (used for grouping); `region = "global"` marks an
anycast resolver, which goes in the **Global (anycast)** group.

A mistake in the file stops every command with exit code `2` and says which setting is
wrong, for example: **Error in the config file: …config.toml: [lookup] timeout must be a
number above 0, not 'fast'.** `dnskit config` shows the same message.

#### Example

```text
$ dnskit config
No config file at C:\Users\you\AppData\Roaming\dnskit\config.toml.
dnskit uses its built-in defaults. Run `dnskit config --init` to create a commented starter
file there.
```

A small file:

```toml
[defaults]
server = "1.1.1.1"

[lookup]
timeout = 3.0

[doctor]
quick = true

[compare]
resolvers = [
    { name = "Google", address = "8.8.8.8" },
    { name = "Quad9", address = "9.9.9.9" },
]
```

```text
$ dnskit config
Config file: C:\Users\you\AppData\Roaming\dnskit\config.toml
Settings
┌─────────┬─────────┬───────────┐
│ Command │ Setting │ Value     │
├─────────┼─────────┼───────────┤
│ lookup  │ server  │ '1.1.1.1' │
│         │ timeout │ 3.0       │
│ reverse │ server  │ '1.1.1.1' │
│ email   │ server  │ '1.1.1.1' │
│ reach   │ server  │ '1.1.1.1' │
│ dnssec  │ server  │ '1.1.1.1' │
│ doctor  │ quick   │ True      │
│ watch   │ server  │ '1.1.1.1' │
└─────────┴─────────┴───────────┘
compare resolvers: Google (8.8.8.8), Quad9 (9.9.9.9)
```

`server` under `[defaults]` shows up for every command that has a `--server` option.

### Global options

| Option | What it does |
|---|---|
| `--json` | On every command: print the result as JSON instead of a report (see [section 10](#10-using-dnskit-in-scripts)). |
| `--version` | Print the dnskit version. |
| `--help` | Help for dnskit, or for a command (`dnskit lookup --help`): what it does, every option, examples and its exit codes. |
| `--install-completion` | Set up tab completion for your shell. |
| `--show-completion` | Print the completion script, to install it yourself. |

---

## 6. Reading the output

A lookup's output has up to four parts.

**1. The results table.** It has one section per record type. A type with no records shows a
short dimmed reason instead of values:

| Reason in table | Meaning |
|---|---|
| `no records` | The name exists but has no records of this type. Often normal. |
| `domain does not exist (NXDOMAIN)` | The name isn't in DNS at all. |
| `server failure (SERVFAIL)` | The resolver couldn't get an answer. |
| `timed out` | No answer within `--timeout`. |
| `no network` | No nameserver could be reached at all. |
| `refused by all nameservers` | Every server rejected the query. |

**2. Explanation panels.** For anything that needs attention, a boxed panel gives the
problem, a plain-English explanation, and a **Next step**. Red panels are faults (server
failure, timeout, no network, refused). Yellow panels are answers that may surprise you
(no records, name doesn't exist). If several record types fail the same way, they share
one panel, with the types listed in its title.

In a full lookup, a few types having no records is normal (most domains have no CNAME at
the top level), so dnskit only explains "no records" when **no** type had any. With
`--type`, it's always explained.

**3. The resolver line.** For example:

```text
Resolver: 1.1.1.1 (auto: fastest of 3 system nameservers, 14 ms; cached, probed 2 min ago) · 61 ms total
```

| Part | Meaning |
|---|---|
| `1.1.1.1` | The nameserver that was asked. |
| `auto: fastest of 3 system nameservers, 14 ms` | dnskit picked it automatically, as the fastest of your 3 configured servers (14 ms in the check). |
| `cached, probed 2 min ago` | That choice was remembered from a check 2 minutes ago, not made just now. |
| `--server` | Shown instead when you chose the server yourself. |
| `system order (no nameserver answered probe)` | Shown instead when none of your servers answered the check. dnskit then tries them in your system's order. |
| `61 ms total` | How long the whole lookup took. |

**4. Nameserver problems** (only when there are some):

```text
Nameserver problems (probed 0s ago; run `dnskit resolvers` for details): no response from
192.168.1.1; slow: 10.0.0.53 (400 ms)
```

This lists your configured DNS servers that are dead or slow. dnskit already works around
them, but other programs on your computer may not. See
[Recipe: everything is slow](#lookups-or-web-browsing-are-slow). The line doesn't appear
when all servers are healthy, or when you use `--server`.

---

## 7. How dnskit chooses a nameserver

Computers often have several DNS servers configured, and some of them can be dead, such
as a router that doesn't serve DNS or a leftover entry from an old VPN. A program that
asks them in order waits about 2 seconds on each dead one, on **every** query. dnskit
avoids this:

1. **Use only servers on connected adapters.** The system configuration (on Windows, the
   registry) also lists servers of disconnected adapters, and leftovers from adapters that
   no longer exist. Windows itself only uses the servers of connected adapters, and so does
   dnskit. Local stubs such as `127.0.0.53` (systemd-resolved) are always kept. If no
   server is on a connected adapter (for example, you're offline), or the OS doesn't say
   which adapter a server belongs to, dnskit uses them all. `dnskit local` shows which
   servers were left out and why.
2. **Check all servers at once.** It sends each configured server a tiny test query in
   parallel and waits up to 1 second for replies.
3. **Use the fastest.** That server is asked first. The others stay as backups, fastest
   first, with the non-responding ones last.
4. **Remember the choice for 5 minutes.** Repeated commands use the same server, so
   results are consistent and you don't pay for the check each time.

The remembered choice is thrown away and the check is redone when:

- **5 minutes have passed.**
- **Your server list changes**, for example when you join a different Wi-Fi network,
  connect a VPN, or plug in a cable.
- **You pass `--refresh`** to `lookup` or `reverse`.
- **You run `dnskit resolvers`**, which always re-checks.

`--server` always wins. It skips all of this, and the remembered choice is neither used nor
changed.

If no server answers the check, nothing is remembered and the next command checks again.

**Cost:** a fresh check takes up to 1 second extra when one of your servers is dead,
because dnskit waits to confirm which ones failed. That happens at most once every 5
minutes. Commands that use the remembered choice skip it.

---

## 8. When a lookup fails: every error explained

The panel always suggests a next step. Here's what each failure means and what to try.

### Domain doesn't exist (NXDOMAIN)

```text
$ dnskit lookup does-not-exist.invalid
┌─ Domain doesn't exist ──────────────────────────────────────────────────────────┐
│ does-not-exist.invalid isn't registered in DNS — the nameserver answered that   │
│ no such name exists (NXDOMAIN).                                                 │
│                                                                                 │
│ Next step: Check the spelling for typos. If this domain used to work, its       │
│ registration may have expired — check it with a WHOIS lookup.                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Meaning:** the DNS system answered definitively: this name doesn't exist. Your connection
is fine.
**Try:** check the spelling. Check whether the domain's registration expired. For a
subdomain (`shop.example.com`), the record may simply not have been created.
**Exit code:** `1`.

### No records

```text
$ dnskit lookup github.com -t AAAA
github.com
┌──────┬────────────┬─────┐
│ Type │ Value      │ TTL │
├──────┼────────────┼─────┤
│ AAAA │ no records │     │
└──────┴────────────┴─────┘
┌─ No AAAA records ─────────────────────────────────────────────────────────────────┐
│ github.com exists, but has no AAAA records.                                       │
│                                                                                   │
│ Next step: This is often normal (for example, many domains have no AAAA records). │
│ Run `dnskit lookup github.com` to see which record types it does have.            │
└───────────────────────────────────────────────────────────────────────────────────┘
```

**Meaning:** the name exists, but has nothing of that type. Here, GitHub has no IPv6
address.
**Try:** run a full `dnskit lookup` to see what records it does have.
**Exit code:** `0`, because the name exists.

### Nameserver failure (SERVFAIL)

```text
$ dnskit lookup dnssec-failed.org -t A
┌─ Nameserver failure (SERVFAIL) ─────────────────────────────────────────────────┐
│ The resolver tried to look up dnssec-failed.org but failed. This usually points │
│ to a problem with the domain's own nameservers or a broken DNSSEC signature,    │
│ not with your connection.                                                       │
│                                                                                 │
│ Next step: Try a different public resolver (such as 1.1.1.1 or 8.8.8.8). If     │
│ they fail too, the domain's DNS hosting is broken — contact the domain owner or │
│ their DNS provider.                                                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Meaning:** your resolver is reachable, but it couldn't get a valid answer from the
domain's own servers. `dnssec-failed.org` is a deliberately broken test domain.
**Try:** `-s 1.1.1.1` and `-s 8.8.8.8`. If both fail, the problem is on the domain's side.
**Exit code:** `1`.

### Query timed out

```text
$ dnskit lookup example.com -t A -s 192.0.2.1 --timeout 2
┌─ Query timed out ───────────────────────────────────────────────────────────────┐
│ No nameserver replied within 2 seconds.                                         │
│                                                                                 │
│ Next step: Check your internet connection, then try a different resolver (such  │
│ as 1.1.1.1) or a longer timeout. A firewall or VPN blocking DNS (port 53) can   │
│ also cause this.                                                                │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Meaning:** a server was asked but never replied.
**Try:** check your connection, try another resolver, or raise `--timeout`. Corporate
firewalls and some VPNs block DNS to outside servers.
**Exit code:** `1`.

### No network connection

**Meaning:** no nameserver could be reached at all. Your computer appears to be offline or
has no route to the internet.
**Try:** check Wi-Fi, Ethernet or VPN. `dnskit resolvers` shows which servers are
reachable.
**Exit code:** `1`.

### All nameservers refused or failed

**Meaning:** servers were reachable but rejected the query. For example, a company DNS
server may only answer its own network.
**Try:** a public resolver (`-s 1.1.1.1`), or `dnskit resolvers` to see which servers
respond.
**Exit code:** `1`.

### No reverse DNS name

**Meaning:** the IP address has no PTR record (see the
[`reverse` examples](#example-an-address-with-no-name)).
**Try:** for a private address, ask your router (`-s <router IP>`). For a public address,
ask the IP's owner.
**Exit code:** `1`.

### Direct DNS queries are blocked

*Shown by `trace`, `propagation`, and `dnssec --server` with an outside server.*

These commands talk to servers on the internet directly (root servers, public resolvers).
When those don't respond but this computer's own DNS server works, something only lets DNS
through to that server. The panel says which:

- **Direct DNS queries are blocked by the VPN**: a VPN is connected. VPNs usually block DNS
  to every server except their own, so queries can't leak outside the tunnel (DNS leak
  protection). Disconnect it and run the command again, or use another network.
- **Direct DNS queries are blocked by a firewall**: no VPN is connected, so a firewall is
  the likely cause. Work, school and hotel networks often allow only their own DNS server.
  Try another network (a phone hotspot works).
- If this computer refused to even open a connection to an outside DNS server (on Windows,
  error 10013), the panel adds that the block is **a firewall on this computer**, such as a
  VPN's kill switch.
- **No DNS server answers: this computer looks offline**: not even this computer's own DNS
  servers answer. Check the connection; `dnskit local` goes through the setup.

The outside servers are almost certainly fine. `trace` still follows the delegation
through your own DNS server, `propagation` can't measure anything from here, and `dnssec`
works without `--server`, since it fetches everything through your own DNS server.

### Invalid input

| Message | Cause |
|---|---|
| `Unknown record type: FOO. Common types are A, AAAA, MX, CNAME, NS, TXT.` | Misspelled `--type`. |
| `'999.1.1.1' is not a valid IP address…` | `reverse` was given something that isn't an IP address. |
| `nameserver dns.google is not a … IP address…` | `--server` was given a hostname. It needs an IP address. |
| `No system nameservers configured…` | The computer has no DNS servers set, usually because it's offline. Pass `--server`. |
| `'bob@example.com' looks like an email address. Pass just the domain, such as example.com.` | `email` was given an email address. Pass the part after the `@`. |
| `'https://example.com' is not a domain name…` / `'…' is not a valid domain name…` | `email` was given a URL, or something that isn't a domain. |
| `'a b' is not a valid DKIM selector…` / `Pass just the DKIM selector, not the full name…` | `--selector` was given something other than a selector, such as `s1._domainkey.example.com` instead of `s1`. |

**Exit code:** `2` for invalid input. `dnskit resolvers` with no configured servers exits
`1`.

---

## 9. Troubleshooting recipes

### "Is my website's DNS set up correctly?"

Start with the health check, which covers the records, the connection, email and DNSSEC
and ranks what needs fixing:

```bash
dnskit doctor example.com
```

To look at the records yourself:

```bash
dnskit lookup example.com
dnskit lookup www.example.com
```

Check that the **A** (and **AAAA**, if you use IPv6) records point at your server's IP,
and that `www` either has the same A records or a **CNAME** to the main domain. Check that
the **NS** records name the DNS provider you expect.

### "Email isn't arriving"

```bash
dnskit email example.com
```

This checks the domain's MX, SPF, DMARC and DKIM records and says what to fix (see
[`dnskit email`](#dnskit-email)). In short:

- **MX** must list your mail provider's servers, and each must have an IP address. No MX
  records, or `0 .`, means the domain receives no email.
- **SPF** must be one TXT record starting with `v=spf1` that includes your provider, ends
  with `~all` or `-all`, and needs at most 10 DNS lookups.
- **DMARC** (`_dmarc.example.com`) should exist, ideally with `p=quarantine` or `p=reject`.
- **DKIM** should have a key at the selector your provider signs with. If dnskit doesn't
  find one, check the selector from a message header with `--selector`.

To see the raw records instead, use `dnskit lookup example.com -t MX`,
`dnskit lookup example.com -t TXT` and `dnskit lookup _dmarc.example.com -t TXT`.

If you run a mail server, also check that its IP has a matching reverse name:
`dnskit reverse <mail server IP>`. Many receivers reject mail from IPs without one.

### "I changed a DNS record. Has it updated yet?"

See how far the change has spread, across 14 public resolvers around the world:

```bash
dnskit propagation example.com -t A
```

Resolvers still giving the old answer are marked **≠ differs**, and the panel says within
how long their cached copies expire. On a VPN or a network that blocks outside DNS, this
can't be measured; `propagation` says so.

Or compare the public resolvers with your own DNS servers:

```bash
dnskit compare example.com -t A
```

Resolvers still showing the old value are marked **≠ differs**. You can also ask a single
resolver with `dnskit lookup example.com -t A -s 8.8.8.8`.

To see the true current value, ask the domain's own (authoritative) nameserver. `--server`
needs an IP, so look up the nameserver's address first:

```bash
dnskit lookup example.com -t NS
dnskit lookup ns1.your-dns-host.com -t A
dnskit lookup example.com -t A -s <that IP>
```

If the authoritative server shows the new value but resolvers show the old one, the
change is made and caches will catch up within the old record's **TTL** (in seconds).

### "My domain doesn't work for anyone"

When a domain fails everywhere (not just on your computer), the problem is in its DNS
hosting. Find the level that breaks:

```bash
dnskit trace example.com
```

- The trace stops at **example.com.** with **didn't respond**: the domain's nameservers
  are down. Contact the DNS host.
- **lame delegation**: the registrar lists nameservers that don't serve the domain, often
  after moving DNS hosts. Fix the nameservers at the registrar.
- **NXDOMAIN** from the `com.` servers: the domain isn't registered, or has expired.

If the trace works but validating resolvers such as 8.8.8.8 return SERVFAIL, check DNSSEC:

```bash
dnskit dnssec example.com
```

**DNSSEC is broken** usually means the DS record at the registrar no longer matches the
zone's keys (after a key change or a move), or the DNS host stopped re-signing the zone.

### "Lookups (or web browsing) are slow"

```bash
dnskit local
```

If any server in use is marked **✗ failing** or **slow**, that's likely the cause for
other programs. dnskit avoids it, but your browser may not. The problem panel says which
adapter it's on: remove or fix that server in the adapter's DNS settings, or in your
router's. **Ghost** servers don't slow Windows down, but they do slow down tools that read
the system configuration directly, such as Python programs using dnspython.

### "A site goes to the wrong place on this computer only"

```bash
dnskit local
```

Look at the **Hosts file** section. An entry there sends the name to a fixed address
without asking DNS, so the computer ignores the real DNS record. Remove the line (as an
administrator), then run the **Flush the DNS cache** command dnskit prints and restart the
browser.

### "The site works on my phone but not my computer"

```bash
dnskit lookup example.com
dnskit lookup example.com -s 1.1.1.1
```

If the second command works and the first fails or shows different addresses, your
computer's DNS servers are the problem: a stale entry, a VPN, or a filtering DNS service.
Check them with `dnskit local`, which also checks the hosts file.

If DNS looks fine, find out whether the computer can connect at all:

```bash
dnskit reach example.com
```

Its verdict says whether the problem is DNS, the connection (a firewall, VPN or the
network blocking it), or neither (then it's the browser or the site).

### "Is my network's DNS lying to me?"

Some networks (hotels, schools, companies, parental-control services) block or redirect
sites by changing DNS answers. Compare your own DNS servers with the public ones:

```bash
dnskit compare blocked-site.example
```

If the `System #…` rows show a different address (or NXDOMAIN) while Google, Cloudflare
and Quad9 agree with each other, your network's DNS is filtering that name.

`dnskit local` checks two more ways DNS can be bent, in its **Network checks** table:
**NXDOMAIN hijacking** (made-up names get an address, usually an advertising page) and
**interception** (queries sent to 8.8.8.8 or 1.1.1.1 are secretly answered by someone
else, so even `compare`'s "public" rows may not be what they seem).

### "Whose server is this IP address?"

```bash
dnskit reverse 203.0.113.50
```

The reverse name often reveals the hosting company or ISP, such as
`ec2-….compute.amazonaws.com` or `….googleusercontent.com`. No name doesn't mean
anything is wrong; many addresses simply have none.

### "I just switched network or connected a VPN"

dnskit notices when your list of DNS servers changes and re-checks them automatically.
If the list stayed the same but a server stopped working, force a re-check:

```bash
dnskit lookup example.com --refresh
```

With a VPN connected, `dnskit local` may show your usual DNS servers as **blocked by
VPN?**. That's expected: many VPNs block DNS outside the tunnel. Don't remove those
servers; disconnect the VPN and run `dnskit local` again to test them.

### "I'm moving my domain to a new DNS host, registrar or email provider"

Moves are when domains break, usually from a forgotten record or DNSSEC. **Before** the
move, record how things are now:

```bash
dnskit doctor example.com
dnskit lookup example.com > records-before.txt
dnskit email example.com
dnskit dnssec example.com
```

- Recreate every record from `records-before.txt` at the new host, including TXT records
  (domain verification, SPF) and the `_dmarc` record. Check subdomains you use too, such as
  `dnskit lookup www.example.com`.
- A day ahead, lower the TTL of the records you'll change (to 300 seconds, say), so the
  switch spreads in minutes instead of hours.
- If `dnssec` says **DNSSEC is on**, don't just change the nameservers: the DS record at
  the registrar still vouches for the old host's keys, and the domain fails for most people
  as soon as the new host answers. Either follow the new host's DNSSEC transfer steps, or
  remove the DS record first and wait a day before moving.

**After** changing the nameservers at the registrar:

```bash
dnskit trace example.com
dnskit propagation example.com -t NS
dnskit dnssec example.com
dnskit doctor example.com
```

`trace` should show the `com.` servers referring to the new nameservers, `propagation`
shows how many resolvers have noticed, and `doctor` should come back as healthy as it did
before. For a new email provider, check the new MX records and the provider's DKIM
selector: `dnskit propagation example.com -t MX` and `dnskit email example.com --selector
<selector>`.

### "Some people can reach my site and others can't"

When it works for some people and not others, the cause is usually one of these, roughly
from most to least likely:

```bash
dnskit dnssec example.com
dnskit propagation example.com
dnskit trace example.com
dnskit reach example.com
```

- **Broken DNSSEC** (`dnssec` says **DNSSEC is broken**): resolvers that validate (Google,
  Cloudflare, Quad9 and many ISPs) refuse to answer, while the rest still work.
- **A recent change still spreading** (`propagation` marks resolvers **≠ differs**): some
  people get the old address until their resolver's copy expires. **Probably
  location-based** instead means a CDN gives different countries different addresses on
  purpose.
- **One nameserver down or lame** (`trace` shows **didn't respond** or **lame delegation**
  for one of the domain's servers): resolvers that happen to ask that one fail. Run the
  trace a few times, since each run may pick different servers.
- **Broken IPv6** (`reach` connects to the IPv4 addresses but not the IPv6 ones): people
  with IPv6 get a slow or failing site. Fix the server's IPv6, or remove the AAAA records.
  This needs a computer that has IPv6 itself; without it, `reach` can't test the IPv6
  addresses and says so.

### "I want my domains checked automatically every day"

`dnskit doctor` exits with `1` when it finds a critical or major issue, so a scheduled task
can warn you. `--quick` keeps it fast; run the full check (with email and DNSSEC) weekly,
or daily if a broken DS record would hurt.

**PowerShell** (for example from Task Scheduler):

```powershell
foreach ($domain in "example.com", "example.org") {
    dnskit doctor $domain --quick | Out-Null
    if ($LASTEXITCODE -ne 0) { "$domain needs attention: run dnskit doctor $domain" }
}
```

**bash** (for example from cron):

```bash
for domain in example.com example.org; do
    dnskit doctor "$domain" --quick > /dev/null || echo "$domain needs attention"
done
```

To keep the report rather than just the warning, write it to a file: `dnskit doctor
example.com > report.txt`. The live progress list isn't written to files.

---

## 10. Using dnskit in scripts

dnskit's exit codes make it easy to use in scripts:

| Code | Meaning |
|---|---|
| `0` | Success. For `lookup`, the name exists, even if some record types are empty. |
| `1` | The lookup failed (timeout, SERVFAIL, no network…), the name doesn't exist, the reverse name wasn't found, or `resolvers` found no working server. |
| `2` | Invalid input: an unknown record type or invalid IP address. |

`dnskit compare` uses the codes differently, to answer "do the resolvers agree?":

| Code | Meaning |
|---|---|
| `0` | Every resolver that answered gave the same answer. Failed resolvers don't affect this, and agreeing that a name doesn't exist counts. |
| `1` | At least one resolver disagreed, or no resolver answered. |
| `2` | Invalid input (unknown record type). |

`dnskit email` uses `0` when no check failed (warnings are fine), `1` when any check failed
or the domain doesn't exist, and `2` for invalid input. For example, to check your domains
every night:

```bash
dnskit email example.com > /dev/null || echo "example.com's email DNS needs attention"
```

`dnskit local` uses `0` when DNS works (even with warnings such as ghost servers) and `1`
when it finds an error: no connected adapter, no DNS servers, or no server responding.

`dnskit reach` tells the two kinds of failure apart:

| Code | Meaning |
|---|---|
| `0` | Reachable: DNS works and at least one address accepted a connection. |
| `1` | DNS problem: no usable address (doesn't exist, no A/AAAA records, lookup failed, or blocked with `0.0.0.0`). |
| `2` | Invalid input (not a domain name, or a port outside 1–65535). |
| `3` | Connection problem: DNS gave addresses, but none accepted a connection. |

For example, to watch a server's SSH port:

```bash
dnskit reach server.example.com -p 22 > /dev/null || echo "can't reach server.example.com:22 (exit $?)"
```

`dnskit trace` uses `0` when it reached the records and `1` otherwise. `dnskit dnssec`
uses `0` when the chain validates or DNSSEC isn't enabled, and `1` when DNSSEC is broken,
couldn't be checked, or the name doesn't exist, so a nightly check catches a broken DS
record before visitors do:

```bash
dnskit dnssec example.com > /dev/null || echo "example.com's DNSSEC needs attention"
```

`dnskit batch` uses `0` when every domain is OK, `1` when one isn't (or a line isn't a
domain), and `2` when the file can't be read or lists no domains. `dnskit watch` uses `0`
when it stopped as asked, `1` when `--count` ran out before `--until` was reached, and
`130` after Ctrl+C.

`dnskit propagation` uses `0` when every resolver that answered gives the same answer and
`1` otherwise (still propagating, probably location-based, or too few resolvers reachable). All three use `2` for
invalid input.

`dnskit doctor` uses `0` when it found no critical or major issue (minor issues and
notes are fine), `1` otherwise, and `2` for invalid input:

```bash
dnskit doctor example.com --quick > /dev/null || echo "example.com needs attention"
```

For example, to alert when your domain's address isn't the same everywhere:

```bash
dnskit compare example.com -t A > /dev/null || echo "resolvers disagree about example.com"
```

#### JSON output

Every command takes `--json` and then prints one JSON object instead of the report, with
the same exit code. Its fields:

| Field | What it holds |
|---|---|
| `command` | The command, such as `"doctor"`. |
| `dnskit_version` | The dnskit version that produced it. |
| `exit_code` | The exit code, also returned by the process. |
| `summary` | The short answer, such as `score` and `healthy` for `doctor`, `verdict` for `reach`, `all_agree` for `compare`, `status` for `dnssec`, `percent` and `complete` for `propagation`. |
| `diagnosis` | The plain-English explanation shown in the report's panel (`title`, `explanation`, `suggestion`), or `null`. |
| `report` | Everything the command found: every record, server, check and timing. Enums are strings (`"ok"`, `"nxdomain"`, `"major"`). Fields ending in `_ms` are milliseconds, rounded to 0.1. Dates and times (such as `probed_at`) are ISO 8601, in UTC. TXT records' values are their text, without the quotes DNS tools usually show, and with multi-part records joined into one string. |

Invalid input also prints JSON, with an `error` field and `exit_code` `2`.

```text
$ dnskit reverse 8.8.8.8 --json
{
  "command": "reverse",
  "dnskit_version": "0.1.0",
  "exit_code": 0,
  "summary": {
    "hostnames": [
      "dns.google."
    ]
  },
  "diagnosis": null,
  "report": {
    "ip": "8.8.8.8",
    "version": 4,
    "ptr_name": "8.8.8.8.in-addr.arpa.",
    "nameserver": "1.1.1.1",
    "nameserver_source": "auto: fastest of 3 system nameservers, 14 ms",
    "result": {
      "rtype": "PTR",
      "status": "ok",
      "records": [
        {
          "value": "dns.google.",
          "ttl": 81568
        }
      ],
      "elapsed_ms": 24.0
    },
    "elapsed_ms": 74.2,
    "resolver_choice": {
      "nameserver": "1.1.1.1",
      "probes": [
        {
          "nameserver": "8.8.8.8",
          "latency_ms": 16.9
        },
        {
          "nameserver": "1.1.1.1",
          "latency_ms": 14.1
        },
        {
          "nameserver": "192.0.2.101",
          "latency_ms": 14.6
        }
      ],
      "probed_at": "2026-11-02T08:43:52.937179+00:00",
      "from_cache": true
    }
  }
}
```

**PowerShell:**

```powershell
$result = dnskit doctor example.com --quick --json | ConvertFrom-Json
if ($result.summary.score -lt 90) { "example.com: $($result.diagnosis.title)" }
```

**bash** (with `jq`):

```bash
dnskit doctor example.com --quick --json | jq -r '.summary.score'
```

`dnskit watch --json` prints **one compact object per line** (JSON Lines), so a script can
read each check as it happens:

- **`"event": "check"` lines** have `changed` (any difference), `rotating` (only addresses
  already seen), `alert` (what the report calls **CHANGED**: any change with `--strict`,
  otherwise only new answers), `answered`, and the `sample` with its `new_values`.
- **The `"event": "end"` line** has the reason, the number of checks, `changes` (alerts),
  `rotations`, `seen` (every value with `times`, `first` and `last`), and the exit code.

```text
$ dnskit watch example.com --interval 2 --count 2 --json
{"command": "watch", "event": "check", "changed": false, "rotating": false, "alert": false, "answered": true, "sample": {"number": 1, "at": "2026-11-02T08:45:40.209007+00:00", "name": "example.com", "rtype": "A", "nameserver": "1.1.1.1", "result": {"rtype": "A", "status": "ok", "records": [{"value": "172.66.147.243", "ttl": 4}, {"value": "104.20.23.154", "ttl": 4}], "elapsed_ms": 17.5}, "previous": null, "new_values": []}}
{"command": "watch", "event": "check", "changed": false, "rotating": false, "alert": false, "answered": true, "sample": {"number": 2, "at": "2026-11-02T08:45:42.258491+00:00", "name": "example.com", "rtype": "A", "nameserver": "1.1.1.1", "result": {"rtype": "A", "status": "ok", "records": [{"value": "172.66.147.243", "ttl": 41}, {"value": "104.20.23.154", "ttl": 41}], "elapsed_ms": 10.2}, "previous": null, "new_values": []}}
{"command": "watch", "event": "end", "reason": "Stopped", "checks": 2, "changes": 0, "rotations": 0, "seen": [{"value": "104.20.23.154", "times": 2, "first": "2026-11-02T08:45:40.209007+00:00", "last": "2026-11-02T08:45:42.258491+00:00"}, {"value": "172.66.147.243", "times": 2, "first": "2026-11-02T08:45:40.209007+00:00", "last": "2026-11-02T08:45:42.258491+00:00"}], "exit_code": 0}
```

`dnskit batch --json` prints one object whose `summary` counts the domains (`domains`, `ok`,
`not_ok`, `invalid_lines`) and whose `report.items` hold each domain's line, `ok`,
`summary` and full report.

**PowerShell:**

```powershell
dnskit lookup example.com -t A | Out-Null
if ($LASTEXITCODE -eq 0) { "example.com resolves" } else { "example.com is broken" }
```

**bash:**

```bash
if dnskit lookup example.com -t A > /dev/null; then echo "resolves"; else echo "broken"; fi
```

Pass `--server` in scripts when you need repeatable results that don't depend on the
machine's DNS settings.

Piping into a command that stops reading early, such as `dnskit compare example.com | head -3`,
is fine: dnskit stops quietly with exit code `1` once the reader has gone, on Windows as well
as Linux and macOS.

---

## 11. Files and environment variables

| Item | Purpose |
|---|---|
| `%LOCALAPPDATA%\dnskit\resolver.json` (Windows) | The remembered nameserver choice. |
| `~/.cache/dnskit/resolver.json` (macOS/Linux, or `$XDG_CACHE_HOME/dnskit/`) | The same, on other systems. |
| `DNSKIT_CACHE_DIR` | Set this to keep the remembered choice in a different folder. |
| `%APPDATA%\dnskit\config.toml` (Windows) | Your settings, if you created the file (see [`dnskit config`](#dnskit-config)). |
| `~/.config/dnskit/config.toml` (macOS/Linux, or `$XDG_CONFIG_HOME/dnskit/`) | The same, on other systems. |
| `DNSKIT_CONFIG` | Set this to use a different settings file. |

The resolver file is safe to delete at any time. dnskit simply re-checks your servers on the next
run. If the file is damaged or the folder isn't writable, dnskit carries on without it.

dnskit does **not** cache DNS answers themselves. Every lookup asks the nameserver fresh.

---

## 12. FAQ

**Why does the first command take about a second longer than the next ones?**
The first run checks all your DNS servers and waits up to 1 second for any dead ones.
The result is remembered for 5 minutes, so later commands skip the check.

**Why do I get different answers from `-s 1.1.1.1` and `-s 8.8.8.8`?**
Usually caching: one resolver still has the old value until its TTL runs out. Big sites
also return different addresses depending on where you ask from.

**`dnskit compare` says resolvers disagree about a big website. Is something wrong?**
Probably not. Large sites and CDNs give each resolver addresses near it, so different
answers for `A` and `AAAA` are normal for them. Disagreement matters most for your own
domain, and for record types like `MX`, `NS` and `TXT`, which should be the same
everywhere.

**Why does `dnskit compare` take about 2 seconds?**
One of your DNS servers in use isn't answering, and dnskit waits up to `--timeout` (2 s)
for each resolver before marking it failed. Lower it with `--timeout 1`, or fix the dead
server (see `dnskit local`).

**What's a ghost DNS server?**
A DNS server that's in the system configuration but isn't on any connected network
adapter. On Windows, the registry keeps the DNS servers of disconnected adapters, and
sometimes of adapters, VPNs or DHCP leases that are long gone. Windows ignores them, but
programs that read the registry directly (such as Python's dnspython) try them in order
and wait about 2 seconds for each dead one. dnskit ignores them too, and `dnskit local`
lists them with where they come from and how to remove them. Compare the
`Get-DnsClientServerAddress` PowerShell command, which only shows adapters' servers.

**Does `dnskit local` change anything or flush the cache for me?**
No. It only reads the system configuration and sends each DNS server one test query. It
prints the flush command for you to run.

**Why is CNAME always "no records" for my domain?**
The top level of a domain (`example.com`, not `www.example.com`) isn't allowed a CNAME.
That's expected.

**Can I pass a hostname to `--server`?**
No, it needs an IP address. Look the server up first with `dnskit lookup <host> -t A`.

**Does dnskit change my system's DNS settings?**
No. It only reads them. The only file it writes is the remembered choice in
[section 11](#11-files-and-environment-variables).

**Why doesn't dnskit use the order my computer lists DNS servers in?**
Because a dead server first in the list would add about 2 seconds to every query. See
[section 7](#7-how-dnskit-chooses-a-nameserver).

**Can I save dnskit's output to a file, or pipe it to another command?**
Yes. Redirected or piped output (`> out.txt`, `| Out-Null`, `| findstr`) is always UTF-8,
so symbols like ✓, ≠ and the table borders come through, and the exit code is the
command's real one. Colours are left out when the output isn't going to a console. Older
versions crashed on Windows with `UnicodeEncodeError: 'charmap' codec can't encode
character` and exited with `1`. If symbols look garbled in a saved file, open it as
UTF-8 (in Windows PowerShell 5.1: `Get-Content out.txt -Encoding UTF8`).

**Why are some of my DNS servers missing from `resolvers` and `compare`?**
They're ghosts: listed in the system configuration but not on a connected adapter. Run
`dnskit local` to see them.

---

## Guide changelog

This guide is updated with every new feature.

| Version / change | What was added |
|---|---|
| 0.1.0, initial | `lookup` (all common types in parallel, `--type`, `--server`, `--timeout`), automatic fastest-nameserver choice, `resolvers`. |
| 0.1.0, errors and reverse | Plain-English explanations for every failure; `reverse` for IPv4 and IPv6. |
| 0.1.0, cached resolver | The nameserver choice is remembered for 5 minutes, `--refresh`, and failed or slow nameservers are reported under results. |
| 0.1.0, compare | `compare` asks Google, Cloudflare, Quad9 and every system nameserver in parallel and highlights answers that differ from the majority. |
| 0.1.0, local | `local` lists adapters and their DNS servers, tests each server, detects ghost servers and hosts file overrides, and prints the flush command. `lookup`, `reverse`, `compare` and `resolvers` now use only DNS servers on connected adapters. |
| 0.1.0, bridges and ties | `local` shows bridged adapters (e.g. Wi-Fi in a network bridge) under the adapter they're bridged into, instead of hiding them. `compare` marks every resolver **varies**, not **≠ differs**, when there's no majority. |
| 0.1.0, closed pipes | Piping into a command that stops reading early (`dnskit ... \| head -3`) no longer prints a traceback on Windows; dnskit exits quietly with code `1`, as on Linux and macOS. |
| 0.1.0, email | `email` checks a domain's MX (with each mail server's addresses), SPF (syntax, one record, `all`, the 10-lookup limit across includes), DMARC (policy explained) and DKIM (common selectors plus `--selector`, key size), each as pass / warn / fail with a fix. |
| 0.1.0, redirected output | Redirecting or piping output on Windows (`> file`, `\| Out-Null`) no longer crashes with `UnicodeEncodeError` or exits with `1`: output is written as UTF-8. New FAQ entry. |
| 0.1.0, VPN-aware local | `local` marks VPN adapters. With a VPN connected, servers on other adapters that don't answer are marked **blocked by VPN?** and explained, not flagged for removal. A silent well-known public resolver (1.1.1.1, 8.8.8.8, 9.9.9.9…) is explained as blocked, not down. |
| 0.1.0, network checks and reach | `local` adds a **Network checks** table: NXDOMAIN hijacking (a random made-up name per DNS server in use), interception of 8.8.8.8 (`o-o.myaddr.l.google.com`) and 1.1.1.1 (`whoami.cloudflare` CH), and IPv6 health, each with a warning panel when it fails. New `reach` command: resolves a name, connects to port 443 (or `--port`) on its addresses, and says whether the problem is DNS (exit `1`), the connection (exit `3`) or neither. |
| 0.1.0, trace, dnssec and propagation | New `trace` (follows the delegation from the root servers down, showing each level's server, referral and time, and which level fails and why), `dnssec` (DS and DNSKEY at every level, signatures verified from the root trust anchors down, plain-English result, clock check) and `propagation` (14 public resolvers: global anycast ones, and fixed-location ones in the Americas, Europe and Asia; 1.5 s timeout with re-sends; percentage giving the same answer, `--type`). All three explain VPNs and firewalls that block DNS to outside servers; `trace` then follows the delegation through this computer's own DNS server. New error entry: [Direct DNS queries are blocked](#direct-dns-queries-are-blocked). New recipe: "My domain doesn't work for anyone". |
| 0.1.0, location-based answers | `propagation` says **Probably location-based DNS, not propagation** when every global resolver agrees and only resolvers in other countries give different addresses (a CDN or geo-DNS), instead of "still propagating". |
| 0.1.0, doctor | New `doctor` command: runs the `local`, `lookup`, `compare`, `reach`, `email` and `dnssec` checks in parallel with a live progress list, then gives a health score out of 100, a plain-English verdict and the issues ranked by impact (critical, major, minor, note), split into this computer and the domain, each with a fix. `--quick` skips the comparison, email and DNSSEC. `local`'s interception check now knows all of Google's published Public DNS address ranges: 8.8.8.8 answering from 34.153.64.0/25 was wrongly reported as intercepted. |
| 0.1.0, scenarios | Every command's section starts with **When to use it**: short real-life situations where it helps. New table in the quick reference: [Which command for which situation](#which-command-for-which-situation), from the symptom to the command to run first. New recipes: moving a domain to a new DNS host, registrar or email provider; a site only some people can reach; checking domains automatically every day. |
| 0.1.0, doctor scoring | `doctor` verdicts are more trustworthy. Resolvers giving different addresses that all work (a CDN) is a note, not an issue; it's major only when some resolvers can't find the domain while others can, or an address doesn't respond. A domain that doesn't exist (confirmed with 8.8.8.8) scores 0 and its dependent checks show **skipped (domain doesn't exist)**. A DNS server that strips DNSSEC signatures makes doctor check DNSSEC through 8.8.8.8 or 1.1.1.1 (**via 8.8.8.8**), or adds a note under This computer. No DKIM key at the common selectors is a note. Ghost DNS servers aren't tested, so a run takes about half a second instead of over one. Notes name the command with the details. |
| 0.1.0, DNSSEC fallback | `dnssec` (not just `doctor`) redoes the check through 8.8.8.8, then 1.1.1.1, when this computer's DNS server strips DNSSEC signatures, and says so above the table and in the Resolver line. If neither can be used, the result is **Couldn't check DNSSEC: this network strips the signatures**. `--server` is never replaced. "DNSSEC isn't enabled" now reads "There's no DS record for google.com at com…". The doctor section lists when doctor contacts public resolvers, including with `--quick`. Examples recaptured. |
| 0.1.0, JSON, batch, watch and config | `--json` on every command (one object with `command`, `exit_code`, `summary`, `diagnosis` and the full `report`; invalid input too). New `batch` (lookup, doctor or email on a list of domains, a few at a time, with a summary table; this computer checked once for doctor), `watch` (re-checks a record every N seconds, beeps on a change, `--until`, `--count`, `--exit-on-change`; failed lookups never count as changes; JSON Lines with `--json`) and `config` (shows or creates a TOML settings file with defaults per command and custom resolver lists for compare and propagation). New files: the config file and `DNSKIT_CONFIG`. |
| 0.1.0, JSON and watch polish | `--json`: timings rounded to 0.1 ms, `probed_at` in ISO 8601, TXT values without quotes (multi-part records joined). `watch` remembers every address seen: changes between addresses already seen say **rotating (CDN)** in blue, without a beep, and don't stop `--exit-on-change`; `--strict` (or `strict = true` in the config) brings back the old behaviour. On stopping, it lists everything seen. `batch --check doctor` shows the most important issue in the Summary column, or **no issues**. |
| 0.1.0, release checks | Every command's `--help` ends with examples and its exit codes, and the main `--help` says where to start (`dnskit doctor`). `dnskit --help | head` no longer prints a traceback on Windows when the reader stops early. `python -m dnskit` works like the `dnskit` command. New CONTRIBUTING.md; the README is rewritten with an example of every command. |
| 0.1.0, release | Installation starts with `pipx install dnskit` from PyPI; git is only needed to install from a copy of the code. New CHANGELOG.md. |
