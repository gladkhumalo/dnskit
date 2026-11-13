"""Print one version's section of CHANGELOG.md, for the GitHub Release notes.

    python scripts/release_notes.py 0.1.0

The section is everything between its `## [0.1.0] - <date>` heading and the next `## `
heading, without the heading itself (the release has its own title). Exits 1 if the
changelog has no section for that version, so a release can't go out without notes.
"""

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def release_notes(changelog: str, version: str) -> str | None:
    """The notes for `version`, or None if the changelog has no section for it."""
    heading = re.compile(rf"^## \[{re.escape(version)}\](?: - .*)?$", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        return None
    rest = changelog[match.end() :]
    end = re.search(r"^## |^\[[^\]]+\]: ", rest, re.MULTILINE)  # next section, or the links
    return rest[: end.start() if end else len(rest)].strip() + "\n"


def main(args: list[str]) -> int:
    if len(args) != 1:
        sys.stderr.write("usage: release_notes.py VERSION\n")
        return 2
    version = args[0].removeprefix("v")
    notes = release_notes(CHANGELOG.read_text(encoding="utf-8"), version)
    if notes is None:
        sys.stderr.write(f"CHANGELOG.md has no section for {version}\n")
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
