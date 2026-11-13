---
name: dnskit-change
description: Checklist for any change to dnskit, from code to merged PR. Use it for a new or changed command, option, check, message, exit code or config setting, and for fixing a CI failure. Covers core-first design, offline tests, live verification, updating docs/USER_GUIDE.md with real captured examples, CLAUDE.md, and the branch, commit and PR routine.
---

# Changing dnskit

CLAUDE.md describes how the code is laid out and why. This skill is the routine for making a
change without missing a step. Work through the sections in order.

## 1. Before writing code

- Read the CLAUDE.md bullet for the module you'll change. Most features reuse what exists:
  `_choose_nameservers` / `_query_one` for lookups, `explain()` for wording,
  `rank_answers` for comparing answers, and `check_blocking` when outside servers are
  silent.
- Check the PR state before reusing an old branch. A commit pushed after its PR merged
  never reaches main. That already happened once, with the DNSSEC fallback:
  ```bash
  gh pr view <n> --json state -q .state
  ```
- Start every change on a new branch from an up-to-date main:
  `git checkout main && git pull && git checkout -b <type>/<topic>`. If a branch builds
  on an open PR, say so in the PR body, and merge that PR's later fixes into the branch.
- Avoid stacked PRs (a PR whose base is another PR's branch). If both are merged within
  seconds, GitHub doesn't retarget the second to main, so it merges into the first's
  branch and never reaches main. The skill itself was lost that way once. If stacking
  can't be avoided, retarget it before it's merged: `gh pr edit <n> --base main`. After a
  merge, check that the change is on main: `git ls-tree -r --name-only origin/main`.

## 2. Core first

- **Location.** The logic goes in `src/dnskit/core/<module>.py` and returns a frozen
  dataclass. Core never prints, and never imports `rich` or `typer`.
- **Errors.**
  - Invalid input raises `ValueError` before any network access. Use `parse_target`
    (domains and URLs), `parse_ip`, `_validate_rtype` and `normalize_domain`.
  - Expected failures (NXDOMAIN, timeouts, no answer, blocked) are data on the result,
    never exceptions.
- **Wording.** Plain-English explanations (`Diagnosis`, `Problem`, `Finding`, `Issue`)
  live in core, so the planned web UI can reuse them. Avoid CLI flags in them where you
  can, and never start a sentence with a lower-case domain name.
- **Exports.** Add the module's public names to `src/dnskit/core/__init__.py`: both the
  import and `__all__`.
- **Commands that call other commands' core functions** (as `doctor` and `batch` do) must
  reuse them, not copy their logic. Add a parameter when a caller needs to change
  something, as `doctor(local=...)` and `compare(resolvers=...)` do.

## 3. CLI

- **The command.** Add it to `src/dnskit/cli/app.py`. Every command:
  - has help text (docstring or `help=`) and `epilog=_epilog(examples, exit_codes)`;
  - takes `as_json: JsonOption = False`;
  - reports bad input with `_fail(command, str(exc), as_json)`, which exits 2;
  - computes its exit code once, then either calls `_emit_json(command, report, code,
    summary, diagnosis)` or renders, then calls `_exit(code)`.
- **Long-running work.** `watch`-style output prints one `_print_json_line` per event.
  Live progress (`Live(...)`, like `DoctorProgress` and `BatchProgress`) only when
  `console.is_terminal and not as_json`.
- **Rendering.** Add a renderer to `src/dnskit/cli/render.py`. Wrap every piece of
  outside text in `escape(...)`: Rich treats `[lookup]` and `[defaults]` as markup tags
  and silently drops them.
- **Config settings.** If the new option should be settable in the config file, add it to
  `COMMAND_SETTINGS` in `core/config.py`, under its long option name without the dashes.
  If that name differs from the Python parameter name, add the pair to
  `_PARAMETER_NAMES` in `app.py`. Mention it in `CONFIG_TEMPLATE` when it's useful.
- **Exit codes.** Keep existing ones stable. Scripts rely on them, and the guide lists
  them in two places (see section 6).

## 4. Tests (never the live network)

- **Fixtures.** Use the fixture CLAUDE.md names for the module: `env`, `cmp_env`,
  `local_env`, `net`, `world`, `checks`, `fakes`, `resolvers`, `answers`. Fakes live in
  `tests/fakes.py`.
- **Isolation.** Autouse fixtures point `DNSKIT_CACHE_DIR` and `DNSKIT_CONFIG` at temp
  paths. In CLI tests, write a config with `write_config(...)`.
- **CLI tests** use `runner.invoke(cli_app.app, [...])`, patch the core function on
  `dnskit.cli.app`, and assert on `plain(result.output)`. For JSON, parse
  `result.stdout`.
- **A new command** gets an entry in `setup_for` and `JSON_SUMMARY_KEYS` in
  `tests/test_cli.py`, so the parametrized `--json` test covers it.
- **Parallel code.** Never assert on the order or timing of parallel work. CI has failed
  three times on races (reach order, doctor threads, the trace dead server):
  - compare parallel results as sets or sorted lists;
  - prove things run concurrently with a `threading.Barrier`, not by counting threads;
  - when "first reply wins", delay the reply that should lose.
- **Other operating systems.** CI runs every test on Windows, Linux and macOS, including
  tests that fake another OS with `sys.platform`. Environment variable names are
  case-sensitive on Linux and macOS but not on Windows, so a test can pass locally and fail
  in CI.
- **Shape.** Cover the happy path, every new status or verdict, the wording that users
  see, the exit codes, bad input (exit 2, nothing queried), and `--json`.

## 5. Verify

```bash
.venv/Scripts/ruff check .
.venv/Scripts/ruff format .
.venv/Scripts/python -m mypy
.venv/Scripts/python -m pytest -q --cov
```

- mypy is strict on `src/`, and CI runs it on Windows, macOS and Linux: check platform code
  with `mypy --platform linux` and `--platform darwin` too. Coverage must stay at 95% or
  above; new core code should be fully covered.

- Run a new test that involves threads or timing several times in a row.
- **Run the real command** too, with output forced to a known width and encoding:
  `PYTHONIOENCODING=utf-8 COLUMNS=92 .venv/Scripts/dnskit <command> ...`. Read the output
  as a user would: wording, wrapping, double brackets, what's missing.
- **Shell quirks on Windows.** Bash heredocs with nested quotes and PowerShell nested
  arrays both break. Write multi-line edit scripts with the Write tool into the
  scratchpad, then run them with `.venv/Scripts/python`. `sed` mangles non-ASCII text
  (`—`, `·`, `✓`); use Edit for those lines.
- **VPNs matter.** Many VPNs block every outside DNS server except one or two. Say whether
  a live run was made with a VPN on or off, and list what you couldn't check.

## 6. Docs (in the same change)

`docs/USER_GUIDE.md` must match the code. For a new or changed command, update:

1. **Contents.** A link to the command's section.
2. **Section 1.** An intro bullet, for a new capability.
3. **Section 3.**
   - The quick-reference table.
   - The **Exit codes** paragraph under it.
   - "Which command for which situation", if a symptom leads to the command.
4. **The command's section.**
   - A short description.
   - **When to use it** (3 or 4 real situations).
   - The usage line and options table.
   - What the output means.
   - Real examples.
   - Exit codes.
5. **Section 8.** A new `Diagnosis` gets an entry here.
6. **Section 10 (scripts).** Exit codes, and anything new in `--json`.
7. **Section 11.** New files or environment variables.
8. **Guide changelog.** One row.

Also update README (its section for the command, with a screenshot: add a `Shot` to
`scripts/readme_screenshots.py` and run it, then reference `docs/images/<name>.svg`; rerun it
for any command whose output changed), CLAUDE.md (the architecture bullet, testing notes
and the Commands block), and CONTRIBUTING.md if a convention changed.

Add a line under `## [Unreleased]` in CHANGELOG.md for anything a user would notice (Keep a
Changelog sections: Added, Changed, Fixed, Removed). Releasing is in CONTRIBUTING.md.

**Examples must be captured from real runs** at 92 columns, never typed by hand:

- To get a real "changed" or "broken" state, find one that exists: `pool.ntp.org`
  rotates addresses, `dnssec-failed.org` has broken DNSSEC, and a made-up
  `*-dnskit-*.com` doesn't exist.
- Don't feature real typo-squat domains (`exmaple.com` exists).
- Replace personal data with documentation addresses (RFC 5737: 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and generic names, keeping lengths the same so captured
  tables stay aligned:
  - the ISP's DNS servers → `203.0.113.53` / `203.0.113.54`;
  - this computer's LAN DNS servers → e.g. `192.0.2.101`, `198.51.100.8`;
  - VPN and adapter names → `OfficeVPN`, `Ethernet 2`, `Contoso VPN Virtual Adapter`;
  - registry interface GUIDs → `{00000000-0000-0000-0000-000000000001}`;
  - long temp or user paths → the usual location (for example
    `C:\Users\you\AppData\Roaming\dnskit\config.toml`).
  - Public resolvers (8.8.8.8, 1.1.1.1, …) and example domains can stay.
- After changing wording, rerun every example that shows it. Recapture whole blocks
  rather than editing them.

## 7. Commit and PR

- Write the commit message to the scratchpad and use `git commit -F <file>`.
  - Subject: imperative, under about 70 characters.
  - Body: why, what changed, and what was verified live.
  - End with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Write the PR body to the scratchpad too, with `## Summary` and `## Test plan`
  (checkboxes, including the unchecked "not run with the VPN on" when that's true). End
  it with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. Then run:
  ```bash
  gh pr create --base main --title "..." --body-file <file>
  ```
  For later updates, use `gh pr edit <n> --body-file <file>`.
- After opening the PR, check it with the app's PR status tool. CI runs ruff and pytest
  plus mypy, on every push, on Ubuntu, Windows and macOS × Python 3.11 and 3.13.
- **When CI fails:**
  1. Read the log: `gh run view <id> --log-failed`.
  2. Check whether the failing commit is still the branch head.
  3. Fix the cause. A flaky test gets made deterministic, never retried.
  4. Push. Merge the fix into any branch built on top.
- Merge only when the user asks.

## 8. Report back

Tell the user, briefly:

- what changed and how it behaves, with live numbers;
- anything surprising found on the way, and what you did about it;
- what isn't verified;
- any follow-up worth doing.

Don't repeat the PR body.
