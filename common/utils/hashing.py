"""Hashing utilities shared across AEGIS modules."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Iterable


def _coerce_bytes(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Return the hexadecimal SHA-256 digest of *data*."""
    return hashlib.sha256(_coerce_bytes(data)).hexdigest()


def hmac_sha256_hex(key: bytes | str, message: bytes | str) -> str:
    """Compute an HMAC-SHA256 signature."""
    return hmac.new(_coerce_bytes(key), _coerce_bytes(message), hashlib.sha256).hexdigest()


def derive_hmac_key(seed: bytes | str | None = None) -> bytes:
    """
    Produce a deterministic key suitable for HMAC signing.

    The function prefers the provided *seed*. If absent, it falls back to
    the environment variable ``AEGIS_HMAC_KEY``, generating a random key as a
    last resort to keep the sandbox operational even in demo setups.
    """
    if seed is not None:
        return _coerce_bytes(seed)

    env_key = os.getenv("AEGIS_HMAC_KEY")
    if env_key:
        return _coerce_bytes(env_key)

    return os.urandom(32)


def rolling_hash(parts: Iterable[bytes | str]) -> str:
    """Combine a sequence of payloads into a single digest."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(_coerce_bytes(part))
    return digest.hexdigest()

