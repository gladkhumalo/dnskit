"""Regenerate the README's screenshots (docs/images/*.svg).

    python scripts/readme_screenshots.py            # all of them
    python scripts/readme_screenshots.py lookup     # only some, by name

Each command runs in-process, exactly as `dnskit` would, with its output recorded by a Rich
console and saved with `Console.save_svg`. The DNS queries and connections are real, so run
it on a network that allows DNS to outside servers (not behind a VPN that blocks them).

So that the screenshots show no real computer's details, every command sees the same demo
computer: one Wi-Fi adapter whose DNS servers are 1.1.1.1 and 8.8.8.8, and a hosts file with
nothing in it. The domains are the reserved examples (example.com, example.net, …).
"""

import contextlib
import importlib
import io
import os
import pkgutil
import sys
import tempfile
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
WIDTH = 92  # columns, as in the guide's text examples

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


def capture(shot: Shot, domains_file: Path, out_dir: Path = IMAGES) -> Path:
    """Run one command and save its output as docs/images/<name>.svg."""
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
    path = out_dir / f"{shot.name}.svg"
    console.save_svg(str(path), title=f"dnskit {shown}", theme=MONOKAI)
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
        for shot in SHOTS:
            if names and shot.name not in names:
                continue
            path = capture(shot, domains)
            sys.stdout.write(f"wrote {path.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
