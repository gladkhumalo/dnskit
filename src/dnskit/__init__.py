"""dnskit — a command-line DNS troubleshooting toolkit."""

from importlib.metadata import PackageNotFoundError, version

try:
    # The version is set in one place, pyproject.toml, and read from the installed package.
    __version__ = version("dnskit")
except PackageNotFoundError:  # pragma: no cover - running from a source tree, not installed
    __version__ = "0+unknown"
