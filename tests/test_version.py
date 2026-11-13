import tomllib
from pathlib import Path

from dnskit import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_the_version_comes_from_pyproject() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert __version__ == project["version"]


def test_the_changelog_has_an_entry_for_this_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert f"## [{__version__}] - " in changelog
    link = f"https://github.com/gladkhumalo/dnskit/releases/tag/v{__version__}"
    assert f"[{__version__}]: {link}" in changelog
