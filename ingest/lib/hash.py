"""Deterministic hashes for idempotency."""
import hashlib
import json
from typing import Any


def sha256_json(obj: Any) -> str:
    """Canonical JSON → SHA256. Stable across Python versions and key order."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def content_hash(*parts: Any) -> str:
    """Hash multiple parts (each canonicalized) into one sha256."""
    h = hashlib.sha256()
    for p in parts:
        h.update(sha256_json(p).encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()