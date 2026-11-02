"""Reports as plain JSON-ready data, for `--json` and for other front ends.

Every report is a frozen dataclass of dataclasses, enums, tuples and a few standard types,
so one generic conversion covers them all: fields by name, enums by value, tuples and sets
as lists (sets sorted), datetimes in ISO 8601, paths and IP addresses as text. Two field
conventions are applied too: `*_ms` timings are rounded to 0.1 ms, and `*_at` Unix times
become ISO 8601. TXT records' values are their text, without quotes.
"""

import dataclasses
import ipaddress
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from dnskit.core.lookup import TEXT_RTYPES, LookupResult, txt_text

MS_DECIMALS = 1


def to_data(value: Any) -> Any:
    """`value` as nested dicts, lists, strings, numbers, booleans and None."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Enum):
        return to_data(value.value)
    if isinstance(value, LookupResult) and value.rtype in TEXT_RTYPES:
        data = _fields(value)
        data["records"] = [
            {**record, "value": txt_text(record["value"])} for record in data["records"]
        ]
        return data
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _fields(value)
    if isinstance(value, dict):
        return {str(to_data(k)): to_data(v) for k, v in value.items()}
    if isinstance(value, set | frozenset):
        return sorted((to_data(v) for v in value), key=str)
    if isinstance(value, list | tuple):
        return [to_data(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path | ipaddress.IPv4Address | ipaddress.IPv6Address):
        return str(value)
    if hasattr(value, "__dict__"):  # a plain object, e.g. a test stand-in
        return {k: _field(k, to_data(v)) for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def _fields(value: Any) -> dict[str, Any]:
    return {
        f.name: _field(f.name, to_data(getattr(value, f.name))) for f in dataclasses.fields(value)
    }


def _field(name: str, data: Any) -> Any:
    """Apply the naming conventions to one already-converted field."""
    is_number = isinstance(data, int | float) and not isinstance(data, bool)
    if is_number and name.endswith("_ms"):
        return round(data, MS_DECIMALS)
    if is_number and name.endswith("_at"):
        return datetime.fromtimestamp(data, UTC).isoformat()
    return data
