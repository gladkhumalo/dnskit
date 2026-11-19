"""Regenerate the README's screenshots (docs/images/*.svg).

    python scripts/readme_screenshots.py            # all of them
    python scripts/readme_screenshots.py lookup     # only some, by name

Each command runs in-process, exactly as `dnskit` would, with its output recorded by a Rich
console and saved with `Console.save_svg`. The DNS queries and connections are real, so run
it on a network that allows DNS to outside servers (not behind a VPN that blocks them).

So that the screenshots show no real computer's details, every command sees the same demo
computer: one Wi-Fi adapter whose DNS servers are 1.1.1.1 and 8.8.8.8, and a hosts file with
nothing in it. The domains are the reserved examples (example.com, example.net, …).

GitHub and PyPI show each SVG as an image, and an image can't download the web font Rich
links to, so a viewer's browser would draw it with whatever monospace font it has: box
characters of the wrong size, and table borders that don't line up. So each SVG embeds the
font itself (Fira Code, as Rich uses, under the SIL Open Font License): just the characters
that image uses, without ligatures, so `->` and `==` look as they do in a terminal. Needs
fontTools (`pip install -e ".[dev]"`).
"""

import base64
import contextlib
import hashlib
import html
import importlib
import io
import os
import pkgutil
import re
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.terminal_theme import MONOKAI

import dnskit.core
from dnskit.cli import app as cli_app
from dnskit.core import Adapter, AdapterScan, HostsFile
from dnskit.core.local import hosts_path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
# Columns. The resolver footer ("Resolver: … (auto: fastest of 2 system nameservers, 36 ms;
# cached, probed 1s ago) · 22 ms total") is about 101; this leaves room for slower timings.
WIDTH = 104

# The Fira Code release Rich's SVGs link to, with the files' SHA-256, checked on download.
FONT_URL = "https://cdnjs.cloudflare.com/ajax/libs/firacode/6.2.0/woff2/FiraCode-{weight}.woff2"
FONT_SHA256 = {
    "Regular": "a6ce59520b90e15d7062ffef214f94c8add5a4085c0bbb1683602ef227a4d1fe",
    "Bold": "d778c19803c672d294663e9283c7b752cc125ab266f0ddb8e53b039da92caf67",
}
# Rich's @font-face rules: `src: local("FiraCode-Regular"), url(...) ..., url(...) ...;`
_FONT_SRC = re.compile(r'src: local\("FiraCode-(Regular|Bold)"\).*?;', re.DOTALL)

DEMO_DNS = ("1.1.1.1", "8.8.8.8")
DEMO_SCAN = AdapterScan(
    adapters=(Adapter("{demo-wifi}", "Wi-Fi", "Wireless network adapter", True, DEMO_DNS),),
    dns_per_adapter=True,
)
DEMO_DOMAINS = """\
# Our domains
example.com
example.org
https://www.example.net/
does-not-exist.example    # a typo
not a domain
"""


@dataclass(frozen=True)
class Shot:
    name: str  # docs/images/<name>.svg
    args: tuple[str, ...]


SHOTS: tuple[Shot, ...] = (
    Shot("doctor", ("doctor", "example.com")),
    Shot("trace", ("trace", "example.com")),
    Shot("lookup", ("lookup", "example.com")),
    Shot("lookup-missing", ("lookup", "does-not-exist.example")),
    Shot("reverse", ("reverse", "8.8.8.8")),
    Shot("compare", ("compare", "example.com")),
    Shot("email", ("email", "example.com")),
    Shot("local", ("local",)),
    Shot("resolvers", ("resolvers",)),
    Shot("reach", ("reach", "example.com")),
    Shot("dnssec", ("dnssec", "example.com")),
    Shot("propagation", ("propagation", "example.com")),
    Shot("batch", ("batch", "{domains}", "--check", "doctor", "--quick")),
    Shot("watch", ("watch", "example.com", "--interval", "2", "--count", "3")),
)


def use_demo_computer() -> None:
    """Every module that reads this computer's setup reads the demo computer instead."""
    demo: dict[str, Callable[..., Any]] = {
        "scan_adapters": lambda: DEMO_SCAN,
        "configured_nameservers": lambda: list(DEMO_DNS),
        "read_hosts": lambda path=None: HostsFile(str(hosts_path()), ()),
    }
    for module_info in pkgutil.iter_modules(dnskit.core.__path__, "dnskit.core."):
        module = importlib.import_module(module_info.name)
        for name, fake in demo.items():
            if hasattr(module, name):
                setattr(module, name, fake)
    # `resolvers` prints where its cache is; show the usual place, not this run's temp dir.
    display = Path("~/.cache/dnskit/resolver.json")
    cli_app.cache_path = lambda: display  # type: ignore[attr-defined]


def download_fonts() -> dict[str, bytes]:
    """Fira Code Regular and Bold (woff2), checked against FONT_SHA256."""
    fonts = {}
    for weight, expected in FONT_SHA256.items():
        url = FONT_URL.format(weight=weight)
        with urllib.request.urlopen(url, timeout=30) as response:
            data: bytes = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"{url} isn't the expected file (SHA-256 mismatch)")
        fonts[weight] = data
    return fonts


def svg_characters(svg: str) -> set[str]:
    """Every character the SVG's text shows."""
    texts = re.findall(r"<text[^>]*>([^<]*)</text>", svg)
    return set(html.unescape("".join(texts)))


def subset_font(font: bytes, characters: set[str]) -> bytes:
    """`font` cut down to `characters`, as woff2, without ligatures or other substitutions."""
    from fontTools import subset  # only needed here; tests that don't embed don't need it

    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = []  # no ligatures: `->` stays two characters, as in a terminal
    options.name_IDs = ["*"]  # keep the copyright and licence notices
    options.notdef_outline = True
    subsetter = subset.Subsetter(options)
    loaded = subset.load_font(io.BytesIO(font), options)
    subsetter.populate(unicodes=[ord(c) for c in characters])
    subsetter.subset(loaded)
    out = io.BytesIO()
    subset.save_font(loaded, out, options)
    return out.getvalue()


def embed_fonts(svg: str, fonts: dict[str, bytes]) -> str:
    """Rich's SVG with its web-font links replaced by the fonts themselves."""
    found = len(_FONT_SRC.findall(svg))
    if found != len(fonts):  # Rich's SVG template changed: update _FONT_SRC
        raise RuntimeError(f"expected {len(fonts)} @font-face rules in the SVG, found {found}")
    characters = svg_characters(svg)
    data = {
        weight: base64.b64encode(subset_font(font, characters)).decode("ascii")
        for weight, font in fonts.items()
    }

    def embedded(match: re.Match[str]) -> str:
        return f'src: url("data:font/woff2;base64,{data[match.group(1)]}") format("woff2");'

    svg = _FONT_SRC.sub(embedded, svg)
    notice = "<!-- Font: Fira Code (subset), The Fira Code Project Authors, SIL OFL 1.1 -->"
    return svg.replace("<style>", f"{notice}\n    <style>", 1)


def capture(
    shot: Shot,
    domains_file: Path,
    out_dir: Path = IMAGES,
    fonts: dict[str, bytes] | None = None,
) -> Path:
    """Run one command and save its output as docs/images/<name>.svg, with `fonts` embedded."""
    console = Console(
        record=True,
        width=WIDTH,
        file=io.StringIO(),  # not a terminal: no live progress, just the report
        color_system="truecolor",
        legacy_windows=False,
    )
    cli_app.console = console  # type: ignore[assignment]
    cli_app.err_console = console  # type: ignore[assignment]
    args = [str(domains_file) if a == "{domains}" else a for a in shot.args]
    shown = " ".join("domains.txt" if a == str(domains_file) else a for a in args)
    console.print(f"[bold green]$[/bold green] dnskit {shown}", highlight=False)
    with contextlib.suppress(SystemExit):  # the exit code doesn't matter for a picture
        cli_app.app(args, prog_name="dnskit", standalone_mode=False)
    svg = console.export_svg(title=f"dnskit {shown}", theme=MONOKAI)
    if fonts:
        svg = embed_fonts(svg, fonts)
    path = out_dir / f"{shot.name}.svg"
    path.write_text(svg, encoding="utf-8")
    return path


def main(names: Sequence[str]) -> int:
    unknown = set(names) - {s.name for s in SHOTS}
    if unknown:
        sys.stderr.write(f"Unknown screenshot: {', '.join(sorted(unknown))}\n")
        return 2
    IMAGES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        # A fresh resolver cache and no config file, so every run starts the same way.
        os.environ["DNSKIT_CACHE_DIR"] = str(Path(tmp) / "cache")
        os.environ["DNSKIT_CONFIG"] = str(Path(tmp) / "config.toml")
        domains = Path(tmp) / "domains.txt"
        domains.write_text(DEMO_DOMAINS, encoding="utf-8")
        use_demo_computer()
        fonts = download_fonts()
        for shot in SHOTS:
            if names and shot.name not in names:
                continue
            path = capture(shot, domains, fonts=fonts)
            sys.stdout.write(f"wrote {path.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
