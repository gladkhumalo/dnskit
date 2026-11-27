# Contributing to dnskit

Thanks for helping. Bug reports, fixes, new checks and better explanations are all welcome.
dnskit is MIT-licensed: by contributing, you agree that your contribution is released
under the same [license](LICENSE).

## Reporting a bug

Open an issue with:

- what you ran and what you expected;
- the output, preferably with `--json` (for example `dnskit lookup example.com --json`);
- your OS, Python version and `dnskit --version`;
- whether a VPN, firewall or DNS filter is involved. Many DNS problems only show up on one
  network, and dnskit's behaviour differs when outside DNS is blocked.

Remove anything you'd rather not share first: your ISP's DNS server addresses, internal
hostnames, VPN names.

**Security vulnerabilities are different:** don't open a public issue. Report them privately,
as described in [SECURITY.md](SECURITY.md).

## Development setup

You need Python 3.11 or newer.

```bash
git clone https://github.com/gladkhumalo/dnskit.git
cd dnskit
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -e ".[dev]"
```

## Checks

These run in CI on Linux, Windows and macOS with Python 3.11 and 3.13, on every push.
Run them before you open a pull request:

```bash
ruff check .            # lint
ruff format .           # format
mypy                    # type check (strict, src/ only)
pytest --cov            # tests, with coverage (must stay at 95% or above)
```

### Locked CI dependencies

CI doesn't install whatever is newest: it installs from hash-locked files in
`.github/requirements/`, so a tampered or surprise release of a tool can't slip in.

| Input (what to install) | Lock (exact versions + hashes) | Used by |
|---|---|---|
| `dev.in` | `dev.txt` | the checks in `ci.yml` (all three systems, Python 3.11 and 3.13) |
| `build.in` | `build.txt` | the release build in `build.yml` (Ubuntu) |

Dependabot updates the locks weekly. After changing pyproject.toml's dependencies or dev
extras, or an `.in` file, regenerate the lock with pip-tools **under Python 3.11** (the oldest
supported version, so the 3.11 jobs can install every pinned version):

```bash
cd .github/requirements
pip-compile --allow-unsafe --generate-hashes --no-emit-index-url --strip-extras --output-file=dev.txt dev.in
pip-compile --allow-unsafe --generate-hashes --no-emit-index-url --strip-extras --output-file=build.txt build.in
```

`tests/test_requirements.py` fails if `dev.in` misses a dependency from pyproject.toml or a
lock is missing something its `.in` file lists. A package that only one system needs has to
be listed in the `.in` file by name (see the comments there), or the lock compiled on another
system leaves it out and that system's job fails.

## How the code is organised

```text
src/dnskit/
  core/   all DNS logic: plain functions that return frozen dataclasses
  cli/    Typer commands (app.py) and Rich rendering (render.py), nothing else
tests/    one test file per core module, plus test_cli.py
docs/USER_GUIDE.md   the user-facing reference
```

The most important rule: **`core` never prints and never imports `rich` or `typer`.** A
web interface is planned, and it will reuse `core` as it is. Ruff enforces the import part.
In `core`:

- **Invalid input** (not a domain, an unknown record type) raises `ValueError` before any
  network access.
- **Expected failures** (NXDOMAIN, timeouts, blocked queries) are data on the result, never
  exceptions.
- **Plain-English explanations** live in `core` too (`Diagnosis`, `Problem`, `Finding`,
  `Issue`), so every front end words things the same way. Keep them free of command-line
  flags where you can.

`CLAUDE.md` describes each module in detail, including why resolver selection, the cache
and the DNSSEC fallback work the way they do. Read the part about the module you're
changing.

## Adding or changing a command

1. **Core first.** Put the logic in a `core` module and return a dataclass. Reuse what's
   there: `lookup._query_one` and `_choose_nameservers` for queries, `diagnosis.explain`
   for wording, `compare.rank_answers` for comparing answers, `outside.check_blocking`
   when outside servers are silent. Export the public names from `core/__init__.py`.
2. **Then the CLI.** Add the command to `cli/app.py` with the same shape as the others:
   - `--json` (`_emit_json`, or `_fail` for bad input, which exits 2);
   - help text with examples and exit codes (`_epilog`);
   - a renderer in `cli/render.py`.

   Wrap any text that didn't come from you in `escape(...)` from `dnskit.cli.render` (not
   Rich's own): Rich treats `[something]` as markup and silently drops it, and DNS data
   can carry control characters that a terminal would run as commands. dnskit's `escape`
   shows them as zone-file escapes instead. If an option should be settable in the
   config file, add it to `COMMAND_SETTINGS` in `core/config.py`.
3. **Keep exit codes stable.** Scripts depend on them.

## Tests

**Every pull request that adds or changes behaviour includes tests for it**, in the same pull
request. New features and bug fixes without tests aren't merged.

- **Never touch the live network or the real system configuration.** Fixtures fake the
  resolver, the network and the OS. `tests/fakes.py` has a fake resolver and a fake
  network, and each test file has a fixture for its module (`env`, `world`, `net`,
  `checks`, …). Autouse fixtures point the resolver cache and the config file at temporary
  paths.
- **Cover** the happy path, every status or verdict the change adds, the wording users
  see, the exit codes, invalid input (exit 2, nothing queried) and `--json`.
- **Parallel code is everywhere in dnskit, so never assert on order or timing.**
  - Compare results as sets or sorted lists.
  - Prove that things run concurrently with a `threading.Barrier`.
  - Where "the first reply wins", delay the reply that should lose.
  - A flaky test gets made deterministic, never retried.
- CLI tests use Typer's `CliRunner`, patch the core function imported into `dnskit.cli.app`,
  and compare against `plain(result.output)`.

## Documentation

A change to a command, option, message, exit code or file updates
**[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** in the same pull request:

- the quick reference;
- the command's section;
- the error section, for a new explanation;
- the scripting section, for exit codes and JSON;
- a row in the guide changelog.

**Examples must come from real runs**, never typed by hand. Run with a fixed width:

```bash
COLUMNS=92 PYTHONIOENCODING=utf-8 dnskit <command> ...
```

Replace personal details in examples (ISP DNS servers with `203.0.113.53`, VPN names,
user folders). Documentation addresses (`192.0.2.x`, `203.0.113.x`) and well-known public
resolvers are fine.

The README shows **screenshots** instead of text: SVGs in `docs/images/`, made by Rich's
console recording. Regenerate them after changing a command's output (they need a network
that allows DNS to outside servers):

```bash
python scripts/readme_screenshots.py            # all of them
python scripts/readme_screenshots.py lookup     # or just some
```

The script runs every command on a demo computer (one Wi-Fi adapter using 1.1.1.1 and
8.8.8.8, an empty hosts file) against the reserved example domains, so the images never show
a real machine's details. A new screenshot goes in its `SHOTS` list.

The console is 104 columns wide, so the resolver footer ("… · 22 ms total") fits on one line.
Each SVG embeds the font it uses (a subset of Fira Code, downloaded once per run and checked
against a SHA-256), because GitHub and PyPI show SVGs as images, which can't download a web
font: without it, browsers fall back to another font and the table borders don't line up.
Check the images afterwards: a resolver that times out once shows up in the picture, so
rerun just that one (`python scripts/readme_screenshots.py batch`).

## Pull requests

- Start a branch from an up-to-date `main`. Base the pull request on `main`, not on
  another open pull request.
- Write commit messages that say why, not just what. Mention anything you checked by hand,
  such as a run with a VPN on.
- In the pull request, list what you tested and what you couldn't (for example, macOS or a
  real VPN).
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
  would notice.

## Releasing

The version is set in one place, `version` in `pyproject.toml`; `dnskit --version` reads it
from the installed package. To release:

1. In a pull request, set the new `version` and rename `## [Unreleased]` in CHANGELOG.md
   to `## [X.Y.Z] - YYYY-MM-DD`, with a fresh empty `## [Unreleased]` above it and the
   compare links at the bottom updated. Merge it.
2. Tag the merge commit on `main` and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "dnskit X.Y.Z"
   git push origin vX.Y.Z
   ```

The `Release` workflow (`.github/workflows/release.yml`) then checks the tag matches the
version, builds the wheel and source archive, checks they install and run, signs SLSA build
provenance for them (`actions/attest`, attached to the release as
`dnskit-X.Y.Z.sigstore.json`), and creates the GitHub Release with that version's
changelog section (`scripts/release_notes.py`) as its notes. Only after that succeeds does it upload the same files to PyPI, in the `pypi`
environment, which waits for a maintainer's approval (Actions → the run → Review
deployments). The upload uses PyPI's Trusted Publishing: there's no API token anywhere.

To try a release first, run the **TestPyPI** workflow by hand (Actions → TestPyPI → Run
workflow), choosing `main` or a branch under **Use workflow from**: it builds that branch.
There's deliberately no way to build a different ref than the one it runs from, since that
code would run with the other ref's cache access. It runs the same build, uploads it to
test.pypi.org (a version that's already there is skipped: TestPyPI never accepts the same
version twice), then installs it back from TestPyPI and runs it. Check the project page there, especially
that the README and its screenshots display.

The README's images use absolute `raw.githubusercontent.com/.../main/` URLs, so they also
show on PyPI. A new screenshot only appears once it's merged to `main`.
