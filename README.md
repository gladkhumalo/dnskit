# dnskit

**Find out why DNS isn't working, in plain English.**

dnskit is a command-line DNS troubleshooting toolkit. It tells you why a name doesn't
resolve, why a site won't load or email doesn't arrive, and whether the problem is your
computer, your network or the domain itself. Every result comes with an explanation and a
suggested fix, not just raw records.

- **One-command health check** with a score and a ranked list of fixes (`doctor`)
- **Lookups, reverse lookups and comparisons** across public resolvers and your own
- **Email checks**: MX, SPF (with the 10-lookup limit), DMARC and DKIM
- **Your computer's DNS setup**: dead or "ghost" DNS servers, hosts-file overrides, NXDOMAIN
  hijacking, intercepted DNS, broken IPv6, and the command to flush the cache
- **The full delegation chain** from the root servers (`trace`) and **DNSSEC** validation
- **Propagation** checks across 14 resolvers worldwide, and **watch** to see a change go live
- **For scripts**: `--json` on every command, `batch` for lists of domains, and a config file
- **VPN- and firewall-aware**: says so when DNS to outside servers is blocked, instead of
  just timing out

Works on Windows, macOS and Linux. Built on [dnspython](https://www.dnspython.org/),
[Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/).

📖 **[The dnskit User Guide](docs/USER_GUIDE.md)** covers every command and option, every
error message, and step-by-step recipes for common DNS problems.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [How DNS works, in one trace](#how-dns-works-in-one-trace)
- [Commands](#commands)
- [JSON, batch, watch and config](#json-batch-watch-and-config)
- [Exit codes](#exit-codes)
- [Contributing](#contributing)
- [License](#license)

## Installation

dnskit needs **Python 3.11 or newer** (`python --version` to check).

```bash
git clone https://github.com/gladkhumalo/dnskit.git
cd dnskit
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install .
dnskit --help
```

The `dnskit` command works whenever the virtual environment is active. To install it for
your user instead, use [pipx](https://pipx.pypa.io/): run `pipx install .` in the folder.

## Quick start

Not sure where a problem is? Start with `doctor`. It checks your computer's DNS setup and
the domain (records, the connection, email and DNSSEC) at the same time, and ranks what it
finds:

```text
$ dnskit doctor example.com
Health check for example.com
Check                                                      Result                Time
This computer: adapters, DNS servers, VPN, hijacking,      ✓ OK (2 notes)      288 ms
interception, IPv6
Records (A, AAAA, MX, CNAME, NS, TXT)                      ✓ OK                 87 ms
Answers from public resolvers and this computer's DNS      ✓ OK                139 ms
servers
Connection to the domain (port 443)                        ✓ OK                167 ms
Email: MX, SPF, DMARC, DKIM                                ! 1 issue           149 ms
DNSSEC chain of trust                                      ✓ OK (via 8.8.8.8)  362 ms

Health score: 95/100
┌─ Healthy, with a few things to tidy up ─────────────────────────────────────────────┐
│ This computer looks fine. example.com has 1 issue; the most important: email        │
│ (DMARC): no DMARC report address (rua).                                             │
│                                                                                     │
│ Next step: Start at the top of the list: Add rua=mailto:<address>, such as a        │
│ dmarc-reports@example.com mailbox or a DMARC reporting service.                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

example.com
1. MINOR Email (DMARC): no DMARC report address (rua)
   Without rua=, receivers don't send aggregate reports, so you can't see who sends
   mail as example.com or whether your own mail passes.
   Fix: Add rua=mailto:<address>, such as a dmarc-reports@example.com mailbox or a
   DMARC reporting service.

This computer
Notes, nothing to fix:
  · Ghost DNS server 198.51.100.8 (on disconnected Ethernet) — dnskit local
  · Ghost DNS server 198.51.100.5 — dnskit local

Ran 6 checks in parallel · 506 ms total
```

It separates problems with **this computer** from problems with **the domain**, and lists
notes (things worth knowing, with nothing to fix) separately. From there:

- `dnskit lookup example.com` to see the records themselves
- `dnskit reach example.com` when a site won't load: is it DNS or the connection?
- `dnskit local` when everything is slow or broken on one computer
- `dnskit <command> --help` for any command's options, examples and exit codes

## How DNS works, in one trace

Nobody has the whole DNS: it's a tree of servers, each responsible for one level of
names. To find `example.com`, a resolver (your DNS server, or 8.8.8.8) asks its way down
the tree. `dnskit trace` does exactly that, one step at a time, and shows each step:

```text
$ dnskit trace example.com
example.com. A (from the root servers down)
└── . (root)  asked a.root-servers.net. (198.41.0.4) · 184 ms
    → referral to com. a.gtld-servers.net., b.gtld-servers.net., c.gtld-servers.net.
    and 10 more (13 servers)
    └── com.  asked b.gtld-servers.net. (192.33.14.30) · 11 ms
        → referral to example.com. elliott.ns.cloudflare.com., hera.ns.cloudflare.com.
        └── example.com.  asked elliott.ns.cloudflare.com. (108.162.195.228) · 10 ms
            ✓ answer: 104.20.23.154, 172.66.147.243
3 steps · 212 ms total
```

1. **The root servers** (`.`) don't know `example.com`, but they know who runs `com.`.
   They *refer* the question to the `com.` servers. There are 13 root server names,
   hard-coded into every resolver; that's where every lookup starts.
2. **The `com.` servers** don't know the address either, but they know which nameservers
   the domain's owner chose at the registrar: here `elliott` and `hera.ns.cloudflare.com`.
   This list is the domain's **delegation**.
3. **The domain's own nameservers** are *authoritative* for `example.com`: they hold its
   records and give the final answer.

A resolver then caches the answer for its **TTL** (time to live, in seconds), so the next
lookup skips the whole walk. That's also why a changed record takes a while to reach
everyone: resolvers keep serving the old answer until its TTL runs out.

When a domain fails for everyone, the trace shows which level breaks. For example, the
`com.` servers saying "no such domain" means it isn't registered (or expired). A
nameserver that doesn't answer means the DNS host is down. A *lame delegation* means the
registrar points at nameservers that don't serve the domain.

## Commands

| Command | What it answers |
|---|---|
| [`doctor`](#quick-start) | Is everything OK? A score and a ranked list of fixes. |
| [`lookup`](#lookup) | What records does this name have? |
| [`reverse`](#reverse) | Whose is this IP address? |
| [`compare`](#compare) | Do public resolvers and mine give the same answer? |
| [`email`](#email) | Is the domain's email set up right (MX, SPF, DMARC, DKIM)? |
| [`local`](#local) | Is this computer's DNS setup healthy? |
| [`resolvers`](#resolvers) | Which of my DNS servers answer, and how fast? |
| [`reach`](#reach) | A site won't load: is it DNS or the connection? |
| [`trace`](#how-dns-works-in-one-trace) | Where in the delegation does a domain break? |
| [`dnssec`](#dnssec) | Is DNSSEC on, and does it validate? |
| [`propagation`](#propagation) | Has my change reached resolvers worldwide? |
| [`batch`](#batch) | Check a whole list of domains. |
| [`watch`](#watch) | Tell me when the answer changes. |
| [`config`](#config) | My default settings and resolvers. |

### lookup

Looks up A, AAAA, MX, CNAME, NS and TXT at once, through the fastest of your DNS servers
(`--type` for one type, `--server` to ask a specific server):

```text
$ dnskit lookup example.com
example.com
┌───────┬────────────────────────────────────┬───────┐
│ Type  │ Value                              │   TTL │
├───────┼────────────────────────────────────┼───────┤
│ A     │ 104.20.23.154                      │   266 │
│       │ 172.66.147.243                     │   266 │
├───────┼────────────────────────────────────┼───────┤
│ AAAA  │ 2606:4700:10::6814:179a            │   114 │
│       │ 2606:4700:10::ac42:93f3            │   114 │
├───────┼────────────────────────────────────┼───────┤
│ MX    │ 0 .                                │   217 │
├───────┼────────────────────────────────────┼───────┤
│ CNAME │ no records                         │       │
├───────┼────────────────────────────────────┼───────┤
│ NS    │ hera.ns.cloudflare.com.            │ 67799 │
│       │ elliott.ns.cloudflare.com.         │ 67799 │
├───────┼────────────────────────────────────┼───────┤
│ TXT   │ "v=spf1 -all"                      │   300 │
│       │ "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9" │   300 │
└───────┴────────────────────────────────────┴───────┘
Resolver: 192.0.2.101 (auto: fastest of 3 system nameservers, 16 ms) · 292 ms total
```

When a lookup fails, a panel says why ("Domain doesn't exist", "Query timed out", …) and
what to try next.

### reverse

Finds the hostname for an IPv4 or IPv6 address (its PTR record), for an unknown address in
a log or to check a mail server's reverse name:

```text
$ dnskit reverse 8.8.8.8
8.8.8.8 (IPv4)
┌─────────────┬───────┐
│ Hostname    │   TTL │
├─────────────┼───────┤
│ dns.google. │ 74346 │
└─────────────┴───────┘
PTR name: 8.8.8.8.in-addr.arpa.
Resolver: 192.0.2.101 (auto: fastest of 3 system nameservers, 16 ms; cached, probed 2s
ago) · 82 ms total
```

### compare

Asks Google, Cloudflare, Quad9 and each of your own DNS servers the same question, and
marks any that disagree. Useful when a site works on one network but not another:

```text
$ dnskit compare example.com
example.com A across 4 resolvers
┌────────────────────────┬─────────────┬────────────────┬─────┬───────┬──┐
│ Resolver               │ IP          │ Answer         │ TTL │  Time │  │
├────────────────────────┼─────────────┼────────────────┼─────┼───────┼──┤
│ Google / system #1     │ 8.8.8.8     │ 104.20.23.154  │ 300 │ 25 ms │  │
│                        │             │ 172.66.147.243 │     │       │  │
├────────────────────────┼─────────────┼────────────────┼─────┼───────┼──┤
│ Cloudflare / system #2 │ 1.1.1.1     │ 104.20.23.154  │ 185 │ 24 ms │  │
│                        │             │ 172.66.147.243 │     │       │  │
├────────────────────────┼─────────────┼────────────────┼─────┼───────┼──┤
│ Quad9                  │ 9.9.9.9     │ 104.20.23.154  │ 298 │ 23 ms │  │
│                        │             │ 172.66.147.243 │     │       │  │
├────────────────────────┼─────────────┼────────────────┼─────┼───────┼──┤
│ System #3              │ 192.0.2.101 │ 104.20.23.154  │ 261 │ 23 ms │  │
│                        │             │ 172.66.147.243 │     │       │  │
└────────────────────────┴─────────────┴────────────────┴─────┴───────┴──┘
✓ All 4 resolvers agree.
Queried 4 resolvers in parallel · 32 ms total
```

### email

Checks where mail is delivered (MX), who may send it (SPF), what receivers do with forged
mail (DMARC), and the signing keys (DKIM), each as pass, warn or fail with a fix:

<details>
<summary><code>$ dnskit email example.com</code></summary>

```text
$ dnskit email example.com
Email DNS check for example.com

MX · where mail for the domain is delivered ───────────────────────────────────────────
✓ Doesn't accept email (null MX) — example.com publishes a null MX record, which tells
senders it never receives email.

SPF · which servers may send its mail ─────────────────────────────────────────────────
Record: v=spf1 -all
✓ SPF record is valid — 0 of 10 DNS lookups. Ends with -all: mail from servers not
listed should be rejected (hard fail).

DMARC · what receivers do with mail that fails SPF and DKIM ───────────────────────────
Record at _dmarc.example.com: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
✓ DMARC policy: reject — p=reject: mail that fails DMARC is refused outright.
┌─ ! No DMARC report address (rua) ───────────────────────────────────────────────────┐
│ Without rua=, receivers don't send aggregate reports, so you can't see who sends    │
│ mail as example.com or whether your own mail passes.                                │
│                                                                                     │
│ Fix: Add rua=mailto:<address>, such as a dmarc-reports@example.com mailbox or a     │
│ DMARC reporting service.                                                            │
└─────────────────────────────────────────────────────────────────────────────────────┘

DKIM · keys that sign its mail ────────────────────────────────────────────────────────
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
! No check failed, but 1 of 4 has warnings. 3 passed. See the suggestions marked !
above.
Resolver: 192.0.2.101 (auto: fastest of 3 system nameservers, 16 ms; cached, probed 7s
ago) · 100 ms total
```

</details>

### local

Checks this computer: every network adapter and its DNS servers, servers that are dead,
slow or "ghosts" (left in the configuration by an old adapter or VPN), hosts-file entries
that override DNS, NXDOMAIN hijacking, interception by the network, and IPv6. It ends with
the problems found and the command to flush the DNS cache:

<details>
<summary><code>$ dnskit local</code></summary>

```text
$ dnskit local
Network adapters (Windows)
┌────────────────────────────┬───────────────────────────┬────────────────────────────┐
│ Adapter                    │ Status                    │ DNS servers                │
├────────────────────────────┼───────────────────────────┼────────────────────────────┤
│ Ethernet 2                 │ connected                 │ 192.0.2.101, 1.1.1.1,      │
│                            │                           │ 8.8.8.8                    │
│ WiFi                       │ connected, bridged into   │ uses Ethernet 2's          │
│                            │ Ethernet 2                │                            │
│ Local Area Connection      │ disconnected, VPN         │ none                       │
│ Ethernet                   │ disconnected              │ 198.51.100.8, 1.1.1.1      │
│ Contoso VPN Virtual        │ disconnected, VPN         │ none                       │
│ Adapter                    │                           │                            │
│ Local Area Connection* 1   │ disconnected              │ none                       │
│ Local Area Connection* 2   │ disconnected              │ none                       │
└────────────────────────────┴───────────────────────────┴────────────────────────────┘
DNS servers (test query, 1 s timeout)
┌──────────────────────┬──────────────────────────────┬─────────────┬─────────────────┐
│ Server               │ Adapter                      │    Response │                 │
├──────────────────────┼──────────────────────────────┼─────────────┼─────────────────┤
│ 192.0.2.101          │ Ethernet 2                   │       33 ms │                 │
│ 1.1.1.1 (Cloudflare) │ Ethernet 2, Ethernet         │       31 ms │                 │
│                      │ (disconnected)               │             │                 │
│ 8.8.8.8 (Google)     │ Ethernet 2                   │       32 ms │                 │
│ 198.51.100.8         │ Ethernet (disconnected)      │ no response │ ghost (ignored) │
│ 198.51.100.5         │ none                         │ no response │ ghost (ignored) │
└──────────────────────┴──────────────────────────────┴─────────────┴─────────────────┘
Network checks
┌────────────────────────────────────┬────────────────────────────────────────────────┐
│ Check                              │ Result                                         │
├────────────────────────────────────┼────────────────────────────────────────────────┤
│ NXDOMAIN hijacking: 1.1.1.1        │ ✓ answers "doesn't exist" honestly             │
│ NXDOMAIN hijacking: 8.8.8.8        │ ✓ answers "doesn't exist" honestly             │
│ NXDOMAIN hijacking: 192.0.2.101    │ ✓ answers "doesn't exist" honestly             │
│ Interception: 8.8.8.8 (Google)     │ ✓ answered by Google (173.194.171.217)         │
│ Interception: 1.1.1.1 (Cloudflare) │ ✓ answered by Cloudflare                       │
│ IPv6                               │ – not available (no IPv6 address); IPv4 is     │
│                                    │ used, which is fine                            │
└────────────────────────────────────┴────────────────────────────────────────────────┘
Hosts file: no entries override DNS (C:\WINDOWS\System32\drivers\etc\hosts)
Flush the DNS cache: ipconfig /flushdns
Browsers keep their own DNS cache too; restart the browser if a site still goes to the
old address.

┌─ ! Ghost DNS server 198.51.100.8 (on disconnected Ethernet) ────────────────────────┐
│ It's set on Ethernet, which is disconnected. Windows ignores it until that adapter  │
│ reconnects, but programs that read the system configuration directly (such as       │
│ dnspython) still try it. It doesn't respond, so they wait for it to time out.       │
│                                                                                     │
│ Fix: Nothing to do. dnskit ignores it too. If it doesn't answer once Ethernet       │
│ reconnects, change that adapter's DNS settings.                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
┌─ ! Ghost DNS server 198.51.100.5 ───────────────────────────────────────────────────┐
│ It's in the system configuration but on no network adapter, probably left behind by │
│ a removed adapter, a VPN or an old DHCP lease. Programs that read the system        │
│ configuration directly (such as dnspython) still try it. It doesn't respond, so     │
│ they wait for it to time out.                                                       │
│                                                                                     │
│ Fix: dnskit ignores it. To remove it, delete 198.51.100.5 from these values under   │
│ HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces in the registry  │
│ (needs administrator rights): {00000000-0000-0000-0000-000000000001}                │
│ (DhcpNameServer), {00000000-0000-0000-0000-000000000002} (DhcpNameServer).          │
└─────────────────────────────────────────────────────────────────────────────────────┘
DNS is working (3 of 3 servers in use responding), with 2 warnings (see above).
Tested 5 DNS servers in parallel · 1084 ms total
```

</details>

### resolvers

Tests each DNS server this computer uses and marks the one dnskit uses (the fastest). The
choice is remembered for 5 minutes, so commands don't each wait for a dead server:

```text
$ dnskit resolvers
System nameservers (in system order)
┌───┬─────────────┬─────────┬──────────────────┐
│ # │ Nameserver  │ Latency │                  │
├───┼─────────────┼─────────┼──────────────────┤
│ 1 │ 8.8.8.8     │  126 ms │                  │
│ 2 │ 1.1.1.1     │   18 ms │                  │
│ 3 │ 192.0.2.101 │   17 ms │ ← used by lookup │
└───┴─────────────┴─────────┴──────────────────┘
Ignored (not on a connected adapter): 198.51.100.8, 198.51.100.5. Run `dnskit local`
for details.
Slow means slower than 250 ms. 192.0.2.101 is cached as the lookup choice for 5 min
(C:\Users\you\AppData\Local\dnskit\resolver.json).
```

### reach

"The website won't load": looks the name up, connects to port 443 (or `--port`) on each
address, and says whether the problem is DNS, the connection, or neither:

```text
$ dnskit reach example.com
example.com on port 443
┌─────────────────────────┬──────┬─────────────────┐
│ Address                 │ Type │      Connection │
├─────────────────────────┼──────┼─────────────────┤
│ 104.20.23.154           │ IPv4 │         ✓ 24 ms │
│ 172.66.147.243          │ IPv4 │         ✓ 10 ms │
│ 2606:4700:10::ac42:93f3 │ IPv6 │ – no IPv6 route │
│ 2606:4700:10::6814:179a │ IPv6 │ – no IPv6 route │
└─────────────────────────┴──────┴─────────────────┘
┌─ ✓ Neither: DNS and the connection both work ───────────────────────────────────────┐
│ example.com resolved to 4 addresses, and 172.66.147.243 accepted a connection on    │
│ port 443 in 10 ms.                                                                  │
│                                                                                     │
│ Next step: If the site still doesn't load, the problem is past the connection: the  │
│ web server, its certificate, or the browser. Try another browser or a private       │
│ window, and flush the DNS cache (dnskit local shows the command).                   │
└─────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 192.0.2.101 (auto: fastest of 3 system nameservers, 17 ms; cached, probed 5s
ago) · 103 ms total
```

### dnssec

Checks every link of the DNSSEC chain of trust from the root down, verifies the signatures
itself, and warns when this computer's clock is wrong (which breaks validation):

<details>
<summary><code>$ dnskit dnssec example.com</code></summary>

```text
$ dnskit dnssec example.com
This computer's DNS server (192.0.2.101) strips DNSSEC signatures, so this was checked
through 8.8.8.8.
DNSSEC chain of trust for example.com
┌──────────────────┬─────────────────────┬──────────────────────┬─────────────────────┐
│ Zone             │ DS (at parent)      │ Keys                 │ Result              │
├──────────────────┼─────────────────────┼──────────────────────┼─────────────────────┤
│ . (root)         │ trust anchors       │ 2 KSK + 1 ZSK        │ ✓ keys signed by    │
│                  │ 20326, 38696        │ (RSASHA256)          │ trust anchor 38696, │
│                  │                     │                      │ 20326               │
│ com.             │ 19718               │ 1 KSK + 1 ZSK        │ ✓ DS at . matches   │
│                  │                     │ (ECDSAP256SHA256)    │ key 19718; keys     │
│                  │                     │                      │ signed              │
│ example.com.     │ 2371                │ 1 KSK + 3 ZSK        │ ✓ DS at com.        │
│                  │                     │ (ECDSAP256SHA256)    │ matches key 2371;   │
│                  │                     │                      │ keys signed         │
│ example.com. SOA │                     │                      │ ✓ signed by key     │
│                  │                     │                      │ 34505, valid until  │
│                  │                     │                      │ 2026-11-03          │
│ example.com. A   │                     │                      │ ✓ signed by key     │
│                  │                     │                      │ 34505, valid until  │
│                  │                     │                      │ 2026-11-03          │
└──────────────────┴─────────────────────┴──────────────────────┴─────────────────────┘
Clock: ✓ looks right (root zone from 2026-11-02)
┌─ ✓ DNSSEC is on and validates for example.com ──────────────────────────────────────┐
│ Every link from the root down to example.com is signed and checks out: each parent  │
│ vouches for its child's key with a DS record, and each zone signs its records with  │
│ that key. DNSSEC protects against forged DNS answers: someone on the network, or a  │
│ poisoned resolver cache, can't send visitors to a fake address without the          │
│ signature check failing. It doesn't encrypt DNS or hide which sites you visit.      │
│ Validating resolvers (such as 8.8.8.8, 1.1.1.1 and 9.9.9.9) check this              │
│ automatically.                                                                      │
│                                                                                     │
│ Next step: Nothing to do. When you change DNS host or keys, update the DS record at │
│ the registrar at the same time, or validation breaks.                               │
└─────────────────────────────────────────────────────────────────────────────────────┘
Resolver: 8.8.8.8 (this computer's DNS server 192.0.2.101 strips DNSSEC signatures;
cached, probed 10s ago) · 276 ms total
```

</details>

### propagation

After changing a record: asks 14 public resolvers (global anycast ones, plus ones in fixed
countries) and shows what share give the same answer. It tells a change still spreading
apart from a CDN's location-based answers:

<details>
<summary><code>$ dnskit propagation example.com</code></summary>

```text
$ dnskit propagation example.com
example.com A across 14 public resolvers
┌─────────────────┬─────────────────┬──────────────┬────────────────┬─────┬───────────┐
│ Region          │ Resolver        │ Location     │ Answer         │ TTL │           │
├─────────────────┼─────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Global          │ Google 8.8.8.8  │ nearest site │ 104.20.23.154  │ 300 │ majority  │
│ (anycast)       │                 │              │ 172.66.147.243 │     │           │
│                 │ Cloudflare      │ nearest site │ 104.20.23.154  │ 168 │ majority  │
│                 │ 1.1.1.1         │              │ 172.66.147.243 │     │           │
│                 │ Quad9 9.9.9.9   │ nearest site │ 104.20.23.154  │ 197 │ majority  │
│                 │                 │              │ 172.66.147.243 │     │           │
│                 │ OpenDNS         │ nearest site │ 104.20.23.154  │ 285 │ majority  │
│                 │ 208.67.222.222  │              │ 172.66.147.243 │     │           │
│                 │ Hurricane       │ nearest site │ 104.20.23.154  │  92 │ majority  │
│                 │ Electric        │              │ 172.66.147.243 │     │           │
│                 │ 74.82.42.42     │              │                │     │           │
│                 │ Control D       │ nearest site │ 104.20.23.154  │  84 │ majority  │
│                 │ 76.76.2.0       │              │ 172.66.147.243 │     │           │
│                 │ AdGuard         │ nearest site │ 104.20.23.154  │  60 │ majority  │
│                 │ 94.140.14.140   │              │ 172.66.147.243 │     │           │
├─────────────────┼─────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Americas        │ CIRA Shield     │ Canada       │ 104.20.23.154  │ 190 │ majority  │
│                 │ 149.112.121.10  │              │ 172.66.147.243 │     │           │
├─────────────────┼─────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Europe          │ DNS.WATCH       │ Germany      │ 104.20.23.154  │ 111 │ majority  │
│                 │ 84.200.69.80    │              │ 172.66.147.243 │     │           │
│                 │ Yandex          │ Russia       │ 8.6.112.0      │  81 │ ≠ differs │
│                 │ 77.88.8.8       │              │ 8.47.69.0      │     │           │
├─────────────────┼─────────────────┼──────────────┼────────────────┼─────┼───────────┤
│ Asia            │ KT 168.126.63.1 │ South Korea  │ 104.20.23.154  │  97 │ majority  │
│                 │                 │              │ 172.66.147.243 │     │           │
│                 │ AliDNS          │ China        │ 104.20.23.154  │ 300 │ majority  │
│                 │ 223.5.5.5       │              │ 172.66.147.243 │     │           │
│                 │ DNSPod          │ China        │ 104.20.23.154  │ 300 │ majority  │
│                 │ 119.29.29.29    │              │ 172.66.147.243 │     │           │
│                 │ 114DNS          │ China        │ 104.20.23.154  │  32 │ majority  │
│                 │ 114.114.114.114 │              │ 172.66.147.243 │     │           │
└─────────────────┴─────────────────┴──────────────┴────────────────┴─────┴───────────┘
Global (anycast) resolvers answer from their site nearest to you, so they show what
people near you see, not what other regions see.
93% of the resolvers that answered (13 of 14) give the most common answer
┌─ … Probably location-based DNS, not propagation ────────────────────────────────────┐
│ All 7 global resolvers agree, and the 1 resolver that differs is in another country │
│ (Yandex in Russia). Sites on a CDN or geo-DNS give each region its own nearby       │
│ servers on purpose, so this is normal for them. If you didn't just change this      │
│ record, nothing is wrong.                                                           │
│                                                                                     │
│ Next step: If you did change it, check that the most common answer is the value you │
│ set: if it is, the change has reached the resolvers near you. Run this again later: │
│ answers that are location-based stay different, while stale ones catch up when      │
│ their TTL runs out.                                                                 │
└─────────────────────────────────────────────────────────────────────────────────────┘
Queried 14 resolvers in parallel · 1034 ms total
```

</details>

## JSON, batch, watch and config

### JSON

Every command takes `--json` and prints one JSON object instead of the report, with the
same exit code: `command`, `exit_code`, a short `summary`, the plain-English `diagnosis`,
and the full `report`. Timings are milliseconds, dates ISO 8601. For example, only the
summary and diagnosis of a `reach`:

```text
$ dnskit reach example.com --json   (summary and diagnosis only)
{
  "summary": {
    "verdict": "reachable"
  },
  "diagnosis": {
    "title": "Neither: DNS and the connection both work",
    "explanation": "example.com resolved to 4 addresses, and 104.20.23.154 accepted a connection on port 443 in 19 ms.",
    "suggestion": "If the site still doesn't load, the problem is past the connection: the web server, its certificate, or the browser. Try another browser or a private window, and flush the DNS cache (dnskit local shows the command)."
  }
}
```

```powershell
$result = dnskit doctor example.com --quick --json | ConvertFrom-Json
if ($result.summary.score -lt 90) { "example.com: $($result.diagnosis.title)" }
```

### batch

Runs `lookup`, `doctor` or `email` on every domain in a text file (one per line, `#`
comments allowed, `-` for standard input), a few at a time, and ends with a summary:

```text
$ cat domains.txt
# Our domains
example.com
google.com
https://www.isc.org/
example-dnskit-typo.com    # a typo
not a domain

$ dnskit batch domains.txt --check doctor
This computer: OK (checked once for every domain; details: dnskit local)
dnskit doctor for 4 domains
┌──────┬─────────────────────────┬──────────┬───────────────────────────────┬─────────┐
│ Line │ Domain                  │ Result   │ Summary                       │    Time │
├──────┼─────────────────────────┼──────────┼───────────────────────────────┼─────────┤
│    2 │ example.com             │ ✓ OK     │ 95/100 · Email (DMARC): no    │  797 ms │
│      │                         │          │ DMARC report address (rua)    │         │
│    3 │ google.com              │ ✓ OK     │ 95/100 · DNSSEC isn't enabled │ 1006 ms │
│      │                         │          │ for google.com                │         │
│    4 │ www.isc.org             │ ✓ OK     │ 85/100 · Email (MX): no MX    │ 1338 ms │
│      │                         │          │ records                       │         │
│    5 │ example-dnskit-typo.com │ ✗ not OK │ 0/100 ·                       │  473 ms │
│      │                         │          │ example-dnskit-typo.com:      │         │
│      │                         │          │ domain doesn't exist          │         │
└──────┴─────────────────────────┴──────────┴───────────────────────────────┴─────────┘
Skipped line 6: 'not a domain' is not a valid domain name. Use a name like example.com.
3 OK · 1 not OK · 1 invalid line · 1.6 s total
```

### watch

Re-checks a record every few seconds (30 by default) and beeps when the answer changes.
`--until` stops as soon as the new value is live. Answers that only rotate between
addresses already seen (a CDN) say "rotating (CDN)" instead of "CHANGED":

```text
$ dnskit watch example.com --interval 2 --count 3
Watching example.com A every 2 s (Ctrl+C to stop)
11:28:26  104.20.23.154, 172.66.147.243 (TTL 235)  first answer, from 192.0.2.101
11:28:28  104.20.23.154, 172.66.147.243 (TTL 233)  unchanged
11:28:30  104.20.23.154, 172.66.147.243 (TTL 231)  unchanged
Stopped after 3 checks; the answer didn't change.
Everything seen
┌────────────────┬────────┬────────────┬───────────┐
│ Answer         │ Checks │ First seen │ Last seen │
├────────────────┼────────┼────────────┼───────────┤
│ 104.20.23.154  │      3 │ 11:28:26   │ 11:28:30  │
│ 172.66.147.243 │      3 │ 11:28:26   │ 11:28:30  │
└────────────────┴────────┴────────────┴───────────┘
```

```bash
dnskit watch example.com --until 203.0.113.80 --interval 60
```

### config

An optional TOML file sets each command's defaults and can replace the resolvers that
`compare` and `propagation` ask. The command line always wins. `dnskit config --init`
creates a commented starter file, and `dnskit config` shows where it is and what it sets:

```toml
[defaults]
server = "1.1.1.1"      # ask this DNS server instead of choosing the fastest

[doctor]
quick = true

[compare]
resolvers = [
    { name = "Google", address = "8.8.8.8" },
    { name = "Office DNS", address = "10.0.0.53" },
]
```

The file is `%APPDATA%\dnskit\config.toml` on Windows and `~/.config/dnskit/config.toml`
elsewhere; set `DNSKIT_CONFIG` to use another.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success: the name exists, the check passed, everything agrees. |
| `1` | A problem was found: the lookup failed, a check failed, resolvers disagree. |
| `2` | Invalid input: not a domain, an unknown record type, a broken config file. |
| `3` | `reach` only: DNS works but the connection doesn't. |
| `130` | `watch` only: stopped with Ctrl+C. |

Each command's `--help` lists its own exit codes, and the guide has
[the full list](docs/USER_GUIDE.md#10-using-dnskit-in-scripts).

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
setting up a development environment, the architecture, and how changes are tested.

## License

dnskit is released under the [MIT License](LICENSE): you may use, change and share it,
including commercially, as long as the copyright notice comes along. It comes with no
warranty.
