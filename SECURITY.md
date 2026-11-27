# Security policy

## Reporting a vulnerability

Please **don't report security vulnerabilities in public issues, discussions or pull
requests.** Report them privately through GitHub instead:

1. Go to the repository's [**Security** tab](https://github.com/gladkhumalo/dnskit/security).
2. Click **Report a vulnerability**.
3. Describe the problem: what an attacker could do, the steps or input that trigger it, the
   dnskit version (`dnskit --version`), and your operating system.

Only the maintainer can see the report. We aim to give an initial response within 14 days.
The reply comes in the same private advisory, where you can also discuss the fix and its
disclosure. Once a fix is released, the advisory is published, crediting you unless you'd
rather not be named.

## Supported versions

Only the **latest release** gets security fixes. Fixes ship as a new release rather than as
patches to older ones, so please upgrade before reporting:

```bash
pipx upgrade dnskit
```

The latest release is listed on the [Releases page](https://github.com/gladkhumalo/dnskit/releases)
and in [CHANGELOG.md](CHANGELOG.md).
