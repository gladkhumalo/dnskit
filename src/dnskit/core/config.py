"""User settings: a TOML file with each command's default options and custom resolver lists.

The file is optional. `[defaults]` applies to every command that has the setting, a
command's own section (`[lookup]`, `[doctor]`, …) overrides it, and options on the command
line override both. `[compare]` and `[propagation]` can also replace the public resolvers
they ask. A broken file raises ConfigError (a ValueError) naming the file and the setting.
"""

import os
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dnskit.core.propagation import GLOBAL_REGION, PublicResolver
from dnskit.core.reverse import parse_ip

CONFIG_ENV = "DNSKIT_CONFIG"

_STR, _FLOAT, _INT, _BOOL, _STRS = "text", "number", "whole number", "true or false", "list of text"

# The settings each command accepts, by name, with the kind of value. Names are the long
# option names without the dashes (`--type` is `type`, `--selector` is `selectors`).
_TIMEOUT = {"timeout": _FLOAT, "json": _BOOL}
COMMAND_SETTINGS: dict[str, dict[str, str]] = {
    "lookup": {"type": _STR, "server": _STR, **_TIMEOUT},
    "reverse": {"server": _STR, **_TIMEOUT},
    "compare": {"type": _STR, **_TIMEOUT},
    "email": {"selectors": _STRS, "server": _STR, **_TIMEOUT},
    "resolvers": {**_TIMEOUT},
    "local": {**_TIMEOUT},
    "reach": {"port": _INT, "server": _STR, **_TIMEOUT},
    "trace": {"type": _STR, **_TIMEOUT},
    "dnssec": {"server": _STR, **_TIMEOUT},
    "propagation": {"type": _STR, **_TIMEOUT},
    "doctor": {"quick": _BOOL, **_TIMEOUT},
    "batch": {"check": _STR, "parallel": _INT, "quick": _BOOL, **_TIMEOUT},
    "watch": {"type": _STR, "server": _STR, "interval": _FLOAT, "strict": _BOOL, **_TIMEOUT},
}
# Sections that also hold a resolver list, and the fields each entry has (name: required).
_RESOLVER_FIELDS: dict[str, dict[str, bool]] = {
    "compare": {"name": True, "address": True},
    "propagation": {"name": True, "address": True, "location": False, "region": False},
}

CONFIG_TEMPLATE = """\
# dnskit settings. Every setting is optional: delete or comment out what you don't need.
# Options given on the command line always win over this file.

[defaults]
# Applies to every command that has the setting.
# server = "1.1.1.1"     # ask this DNS server instead of choosing the fastest system one
# json = true            # always print JSON

# [lookup]
# type = "A"             # one record type instead of A, AAAA, MX, CNAME, NS and TXT
# timeout = 5.0

# [email]
# selectors = ["s2024", "mailjet"]   # your own DKIM selectors, checked every time

# [doctor]
# quick = true

# [watch]
# interval = 60.0        # seconds between checks

# [batch]
# check = "doctor"       # lookup, doctor or email
# parallel = 4

# [compare]
# Replaces Google, Cloudflare and Quad9. This computer's DNS servers are always added.
# resolvers = [
#     { name = "Google", address = "8.8.8.8" },
#     { name = "Office DNS", address = "10.0.0.53" },
# ]

# [propagation]
# Replaces the 14 built-in resolvers. region = "global" marks an anycast resolver.
# resolvers = [
#     { name = "Google", address = "8.8.8.8", region = "global" },
#     { name = "Telkom", address = "196.43.1.14", location = "South Africa", region = "Africa" },
# ]
"""


class ConfigError(ValueError):
    """The config file can't be read, or a setting in it is wrong."""


@dataclass(frozen=True)
class Config:
    path: Path
    exists: bool
    # Command name -> setting name -> value, with [defaults] already merged in.
    settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    compare_resolvers: tuple[tuple[str, str], ...] | None = None  # (label, IP)
    propagation_resolvers: tuple[PublicResolver, ...] | None = None

    def for_command(self, command: str) -> dict[str, Any]:
        return dict(self.settings.get(command, {}))


def config_path() -> Path:
    """Where the config file is. Override with DNSKIT_CONFIG."""
    if override := os.environ.get(CONFIG_ENV):
        return Path(override)
    if sys.platform == "win32" and (appdata := os.environ.get("APPDATA")):
        return Path(appdata) / "dnskit" / "config.toml"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / "dnskit" / "config.toml"


def load_config(path: Path | None = None) -> Config:
    """Read and check the config file. A missing file is an empty config."""
    path = path or config_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Config(path, exists=False)
    except OSError as exc:
        raise ConfigError(f"Can't read {path}: {exc.strerror or exc}.") from exc
    return parse_config(text, path)


def parse_config(text: str, path: Path) -> Config:
    """Check a config file's text; every problem raises ConfigError naming the setting."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} isn't valid TOML: {exc}.") from exc

    def fail(where: str, problem: str) -> ConfigError:
        return ConfigError(f"{path}: {where} {problem}.")

    known = {"defaults", *COMMAND_SETTINGS}
    for section, values in data.items():
        if section not in known:
            raise fail(f"[{section}]", f"isn't a dnskit section (use {_listed(sorted(known))})")
        if not isinstance(values, dict):
            raise fail(section, "must be a section, like [" + section + "]")

    defaults = data.get("defaults", {})
    every = {
        name: kind for settings in COMMAND_SETTINGS.values() for name, kind in settings.items()
    }
    for name, value in defaults.items():
        if name not in every:
            raise fail(f"[defaults] {name}", "isn't a setting any command has")
        _check(value, every[name], f"[defaults] {name}", fail)

    settings: dict[str, dict[str, Any]] = {}
    for command, allowed in COMMAND_SETTINGS.items():
        own = dict(data.get(command, {}))
        own.pop("resolvers", None) if command in _RESOLVER_FIELDS else None
        for name, value in own.items():
            if name not in allowed:
                raise fail(f"[{command}] {name}", f"isn't a setting (use {_listed(allowed)})")
            _check(value, allowed[name], f"[{command}] {name}", fail)
        merged = {k: v for k, v in defaults.items() if k in allowed} | own
        if merged:
            settings[command] = merged

    compare = _resolver_list(data, "compare", fail)
    propagation = _resolver_list(data, "propagation", fail)
    return Config(
        path,
        exists=True,
        settings=settings,
        compare_resolvers=tuple((r["name"], r["address"]) for r in compare) if compare else None,
        propagation_resolvers=tuple(_public_resolver(r) for r in propagation)
        if propagation
        else None,
    )


def _check(value: Any, kind: str, where: str, fail: Any) -> None:
    ok = {
        _STR: isinstance(value, str),
        _FLOAT: isinstance(value, int | float) and not isinstance(value, bool) and value > 0,
        _INT: isinstance(value, int) and not isinstance(value, bool) and value > 0,
        _BOOL: isinstance(value, bool),
        _STRS: isinstance(value, list) and all(isinstance(v, str) for v in value),
    }[kind]
    if not ok:
        positive = " above 0" if kind in (_FLOAT, _INT) else ""
        raise fail(where, f"must be a {kind}{positive}, not {value!r}")


def _resolver_list(data: dict[str, Any], section: str, fail: Any) -> list[dict[str, str]]:
    entries = data.get(section, {}).get("resolvers")
    if entries is None:
        return []
    where = f"[{section}] resolvers"
    if not isinstance(entries, list) or not entries:
        raise fail(where, "must be a list of resolvers, like [{ name = ..., address = ... }]")
    fields = _RESOLVER_FIELDS[section]
    checked = []
    for n, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise fail(f"{where} entry {n}", "must be a table like { name = ..., address = ... }")
        for key, value in entry.items():
            if key not in fields:
                raise fail(f"{where} entry {n}", f"has an unknown field {key!r}")
            if not isinstance(value, str) or not value.strip():
                raise fail(f"{where} entry {n} {key}", "must be text")
        for key, required in fields.items():
            if required and key not in entry:
                raise fail(f"{where} entry {n}", f"needs a {key}")
        try:
            parse_ip(entry["address"])
        except ValueError:
            raise fail(
                f"{where} entry {n}", f"has an address that isn't an IP: {entry['address']!r}"
            ) from None
        checked.append(entry)
    addresses = [e["address"] for e in checked]
    if len(set(addresses)) < len(addresses):
        raise fail(where, "lists the same address twice")
    return checked


def _public_resolver(entry: dict[str, str]) -> PublicResolver:
    region = entry.get("region", "Other")
    if region.lower() in ("global", GLOBAL_REGION.lower()):
        return PublicResolver(entry["name"], entry["address"], "nearest site", GLOBAL_REGION)
    return PublicResolver(entry["name"], entry["address"], entry.get("location", "unknown"), region)


def write_template(path: Path | None = None) -> Path:
    """Create a commented starter config file. An existing file raises ConfigError."""
    path = path or config_path()
    if path.exists():
        raise ConfigError(f"{path} already exists; edit it instead.")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Can't write {path}: {exc.strerror or exc}.") from exc
    return path


def _listed(names: Iterable[str]) -> str:
    items = list(names)
    return ", ".join(items[:-1]) + " or " + items[-1] if len(items) > 1 else items[0]
