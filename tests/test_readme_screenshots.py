import html
import importlib
import importlib.util
import pkgutil
import re
from pathlib import Path

import pytest

import dnskit.core
from dnskit import __version__
from dnskit.cli import app as cli_app
from dnskit.core import ProbeResult, local_check

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "readme_screenshots.py"
README_IMAGES = "https://raw.githubusercontent.com/gladkhumalo/dnskit/main/docs/images/"


def load_script():
    spec = importlib.util.spec_from_file_location("readme_screenshots", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def screenshots(monkeypatch: pytest.MonkeyPatch):
    """The script, with every global it replaces put back after the test."""
    for name in ("console", "err_console", "cache_path"):
        monkeypatch.setattr(cli_app, name, getattr(cli_app, name))
    for info in pkgutil.iter_modules(dnskit.core.__path__, "dnskit.core."):
        module = importlib.import_module(info.name)
        for name in ("scan_adapters", "configured_nameservers", "read_hosts"):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, getattr(module, name))
    return load_script()


def test_capture_saves_the_command_and_its_output(screenshots, tmp_path: Path) -> None:
    shot = screenshots.Shot("version", ("--version",))

    path = screenshots.capture(shot, tmp_path / "domains.txt", out_dir=tmp_path)

    svg = path.read_text(encoding="utf-8")
    assert path == tmp_path / "version.svg"
    assert svg.startswith("<svg")
    shown = svg_text(svg)
    assert "$ dnskit --version" in shown  # the prompt line
    assert f"dnskit {__version__}" in shown  # the command's output


def svg_text(svg: str) -> str:
    """The SVG's visible text: Rich splits styled text into pieces, and uses &#160; for spaces."""
    pieces = re.findall(r">([^<]*)</text>", svg)
    return html.unescape("".join(pieces)).replace(chr(0xA0), " ")


def test_the_domains_file_shows_as_domains_txt(screenshots, tmp_path: Path) -> None:
    shot = screenshots.Shot("x", ("--version", "{domains}"))

    svg = screenshots.capture(shot, tmp_path / "list.txt", out_dir=tmp_path).read_text("utf-8")

    assert "domains.txt" in svg and "list.txt" not in svg


def test_the_demo_computer_replaces_this_one(screenshots, monkeypatch: pytest.MonkeyPatch) -> None:
    local_mod = importlib.import_module("dnskit.core.local")
    probed: list[list[str]] = []

    def fake_probe_all(candidates, timeout):
        probed.append(list(candidates))
        return [ProbeResult(ns, 10.0) for ns in candidates]

    for name in ("probe_all", "check_nxdomain", "check_google", "check_cloudflare", "check_ipv6"):
        monkeypatch.setattr(local_mod, name, getattr(local_mod, name))
    monkeypatch.setattr(local_mod, "probe_all", fake_probe_all)
    monkeypatch.setattr(local_mod, "check_nxdomain", lambda ns, t: _unknown_hijack(local_mod, ns))
    monkeypatch.setattr(local_mod, "check_google", lambda t: _unknown(local_mod, "Google"))
    monkeypatch.setattr(local_mod, "check_cloudflare", lambda t: _unknown(local_mod, "Cloudflare"))
    monkeypatch.setattr(local_mod, "check_ipv6", lambda ns, t: _no_ipv6(local_mod))

    screenshots.use_demo_computer()
    report = local_check()

    assert [a.name for a in report.scan.adapters] == ["Wi-Fi"]
    assert probed == [["1.1.1.1", "8.8.8.8"]]
    assert report.hosts.entries == ()
    assert str(cli_app.cache_path()).replace("\\", "/") == "~/.cache/dnskit/resolver.json"


def test_every_screenshot_in_the_readme_exists() -> None:
    readme = (SCRIPT.parents[1] / "README.md").read_text(encoding="utf-8")
    names = {s.name for s in load_script().SHOTS}

    used = set(re.findall(r"docs/images/([a-z-]+)\.svg", readme))

    assert used == names
    # Absolute URLs, so the images also show on PyPI, which can't resolve relative paths.
    assert re.findall(r"\]\((?!https://)[^)]*docs/images/", readme) == []
    assert readme.count(f"]({README_IMAGES}") == len(names)
    for name in names:
        assert (SCRIPT.parents[1] / "docs" / "images" / f"{name}.svg").exists()


def test_readme_links_work_on_pypi() -> None:
    """PyPI shows the README without the repository, so links to files must be full URLs."""
    readme = (SCRIPT.parents[1] / "README.md").read_text(encoding="utf-8")

    targets = re.findall(r"\]\(([^)]+)\)", readme)

    assert targets
    relative = [t for t in targets if not t.startswith(("https://", "http://", "#"))]
    assert relative == []


def _unknown(local_mod, provider):
    integrity = importlib.import_module("dnskit.core.integrity")
    return integrity.InterceptionCheck(provider, "x", integrity.Verdict.UNKNOWN, None, "no answer")


def _unknown_hijack(local_mod, nameserver):
    integrity = importlib.import_module("dnskit.core.integrity")
    return integrity.HijackCheck(nameserver, "x", integrity.Verdict.OK, (), "honest")


def _no_ipv6(local_mod):
    connectivity = importlib.import_module("dnskit.core.connectivity")
    state = connectivity.IPv6State.NOT_AVAILABLE
    return connectivity.IPv6Check(state, None, "www.google.com", None, "not available")
