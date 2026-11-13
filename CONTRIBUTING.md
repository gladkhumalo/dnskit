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

   Wrap any text that didn't come from you in `rich.markup.escape(...)`: Rich treats
   `[something]` as markup and silently drops it. If an option should be settable in the
   config file, add it to `COMMAND_SETTINGS` in `core/config.py`.
3. **Keep exit codes stable.** Scripts depend on them.

## Tests

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
version, builds the wheel and source archive, checks they install and run, and creates the
GitHub Release with that version's changelog section (`scripts/release_notes.py`) as its
notes. Nothing is published to PyPI.
