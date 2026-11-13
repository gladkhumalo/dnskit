import importlib.util
from pathlib import Path

import pytest

from dnskit import __version__

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_notes.py"

CHANGELOG = """\
# Changelog

## [Unreleased]

## [0.2.0] - 2027-01-02

### Fixed

- Something.

## [0.1.0] - 2026-11-13

### Added

- Everything.

[Unreleased]: https://example.com/compare/v0.2.0...HEAD
[0.2.0]: https://example.com/v0.2.0
"""


@pytest.fixture(scope="module")
def notes():
    spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_section_ends_at_the_next_version(notes) -> None:
    assert notes.release_notes(CHANGELOG, "0.2.0") == "### Fixed\n\n- Something.\n"


def test_the_last_section_ends_at_the_links(notes) -> None:
    assert notes.release_notes(CHANGELOG, "0.1.0") == "### Added\n\n- Everything.\n"


def test_a_missing_version_has_no_notes(notes) -> None:
    assert notes.release_notes(CHANGELOG, "0.3.0") is None
    assert notes.release_notes(CHANGELOG, "0.1") is None  # no prefix matches


def test_the_real_changelog_has_notes_for_this_version(notes, capsys) -> None:
    assert notes.main([f"v{__version__}"]) == 0  # the tag's "v" is dropped

    out = capsys.readouterr().out
    assert out.strip()
    assert "## [" not in out


def test_no_section_is_an_error(notes, capsys) -> None:
    assert notes.main(["99.0.0"]) == 1
    assert "no section for 99.0.0" in capsys.readouterr().err
