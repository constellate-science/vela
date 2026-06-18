#!/usr/bin/env python3
"""Canonical encoding and content identifiers for the Vela Sidon producer profile.

The profile deliberately uses a restricted JSON value domain: null, booleans,
integers, strings, arrays, and objects with string keys. Floating-point values
are rejected. This makes the reference canonicalization reproducible across the
Rust/Python/TypeScript implementations without relying on host float behavior.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

CANON_DOMAIN = b"vela.canonical-json-subset.v1\x00"


def _normalize(value: Any, path: str = "$", *, normalize_unicode: bool = True) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise TypeError(f"floating-point value forbidden at {path}")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value) if normalize_unicode else value
    if isinstance(value, list):
        return [_normalize(v, f"{path}[{i}]", normalize_unicode=normalize_unicode) for i, v in enumerate(value)]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"non-string object key at {path}: {key!r}")
            nkey = unicodedata.normalize("NFC", key) if normalize_unicode else key
            if nkey in out:
                raise ValueError(f"duplicate key after NFC normalization at {path}: {nkey!r}")
            out[nkey] = _normalize(child, f"{path}.{nkey}", normalize_unicode=normalize_unicode)
        return out
    raise TypeError(f"unsupported canonical value at {path}: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    normalized = _normalize(value)
    text = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_value(value: Any) -> str:
    return sha256_bytes(CANON_DOMAIN + canonical_bytes(value))


def digest(value: Any) -> str:
    return "sha256:" + sha256_value(value)


def content_id(prefix: str, value: Any) -> str:
    if not prefix.endswith("_"):
        raise ValueError("content-id prefix must end with '_'")
    return prefix + sha256_value(value)
