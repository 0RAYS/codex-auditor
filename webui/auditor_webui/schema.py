"""Shared typed structures for the WebUI."""

from __future__ import annotations

from typing import Final

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type RowValue = JsonValue
type RowDict = dict[str, RowValue]

BUSY_STATUSES: Final[frozenset[str]] = frozenset({"running"})
SESSION_TYPES: Final[frozenset[str]] = frozenset({"mining", "debug"})
TARGET_COLORS: Final[tuple[str, ...]] = ("green", "blue", "amber", "rose", "violet", "cyan")
SECURITY_RATINGS: Final[frozenset[str]] = frozenset({"low", "medium", "high"})


def row_str(row: RowDict, key: str, default: str = "") -> str:
    value = row.get(key)
    if value is None:
        return default
    return str(value)


def row_optional_str(row: RowDict, key: str) -> str | None:
    value = row.get(key)
    return None if value is None else str(value)


def row_int(row: RowDict, key: str, default: int = 0) -> int:
    value = row.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default
