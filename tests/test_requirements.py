"""CI installs from hash-locked files in .github/requirements/ (see CONTRIBUTING.md)."""

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCKS = ROOT / ".github" / "requirements"


def names(requirements: list[str]) -> set[str]:
    """Normalized package names, without extras, versions or markers."""
    return {
        re.split(r"[\[<>=!~;\s]", r.strip(), maxsplit=1)[0].lower().replace("_", "-")
        for r in requirements
    }


def in_file(name: str) -> list[str]:
    lines = (LOCKS / f"{name}.in").read_text(encoding="utf-8").splitlines()
    return [line for line in lines if line.strip() and not line.startswith("#")]


def test_dev_in_has_every_dependency_in_pyproject() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    needed = names(project["dependencies"]) | names(project["optional-dependencies"]["dev"])

    assert needed - names(in_file("dev")) == set(), "add these to dev.in and recompile"


@pytest.mark.parametrize("name", ["dev", "build"])
def test_every_input_is_locked_with_hashes(name: str) -> None:
    lock = (LOCKS / f"{name}.txt").read_text(encoding="utf-8")
    # "name==version \" with its first "--hash=sha256:..." on the next line
    pinned = re.findall(r"^([a-z0-9][a-z0-9._-]*)==\S+ \\\n\s+--hash=sha256:", lock, re.MULTILINE)

    assert names(in_file(name)) - names(pinned) == set(), f"recompile {name}.txt"
    assert "with Python 3.11" in lock  # the oldest supported Python, so 3.11 jobs can install
