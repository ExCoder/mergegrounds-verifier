"""Strict JSON parsing and the canonical representation used for digests/signatures."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any


class StrictJSONError(ValueError):
    """The input is not strict JSON or contains duplicate object member names."""


def _reject_constant(value: str) -> None:
    raise StrictJSONError(f"non-finite JSON number is prohibited: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def loads_strict(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("JSON input must be UTF-8") from exc
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError(str(exc)) from exc
    _enforce_shape(value)
    return value


def _enforce_shape(value: Any, *, max_depth: int = 64, max_nodes: int = 200_000) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise StrictJSONError(f"JSON document exceeds {max_nodes} structural nodes")
        if depth > max_depth:
            raise StrictJSONError(f"JSON nesting exceeds {max_depth} levels")
        if isinstance(current, float) and not math.isfinite(current):
            raise StrictJSONError("non-finite JSON number is prohibited")
        if isinstance(current, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in current):
            raise StrictJSONError("unpaired Unicode surrogate is prohibited")
        if isinstance(current, dict):
            for key in current:
                if any(0xD800 <= ord(char) <= 0xDFFF for char in key):
                    raise StrictJSONError(
                        "unpaired Unicode surrogate in object member is prohibited"
                    )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def load_strict(path: str | Path, *, max_bytes: int = 4 * 1024 * 1024) -> Any:
    source = Path(path)
    size = source.stat().st_size
    if size > max_bytes:
        raise StrictJSONError(f"JSON document exceeds {max_bytes} bytes")
    return loads_strict(source.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    """Return the repository's stable JSON encoding.

    This is a deliberately narrow profile: UTF-8, sorted keys, no insignificant
    whitespace and no NaN/Infinity. Producers MUST use this exact profile.
    """

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise StrictJSONError(f"value cannot be represented as canonical JSON: {exc}") from exc
    return encoded.encode("utf-8")


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
