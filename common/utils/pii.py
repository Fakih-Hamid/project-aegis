"""PII detection and redaction helpers shared across modules."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from re import Pattern


@dataclass(frozen=True, slots=True)
class PiiPattern:
    label: str
    pattern: Pattern[str]
    replacement: str


DEFAULT_PATTERNS: Sequence[PiiPattern] = (
    PiiPattern(
        label="email",
        pattern=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        replacement="<redacted-email>",
    ),
    PiiPattern(
        label="api_key",
        pattern=re.compile(r"(?:sk|pk|key)_[A-Za-z0-9]{16,}"),
        replacement="<redacted-api-key>",
    ),
    PiiPattern(
        label="phone",
        pattern=re.compile(r"\+?\d[\d\s\-]{7,}\d"),
        replacement="<redacted-phone>",
    ),
    PiiPattern(
        label="credit_card",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        replacement="<redacted-cc>",
    ),
    PiiPattern(
        label="secret",
        pattern=re.compile(r"secret=([A-Za-z0-9+/=]{8,})", re.I),
        replacement="secret=<redacted>",
    ),
)


def detect_pii(text: str, patterns: Iterable[PiiPattern] | None = None) -> list[str]:
    """Return the labels of all PII patterns discovered in *text*."""
    result: list[str] = []
    for pii in patterns or DEFAULT_PATTERNS:
        if pii.pattern.search(text):
            result.append(pii.label)
    return result


def redact_text(text: str, patterns: Iterable[PiiPattern] | None = None) -> str:
    """Replace all PII instances in *text* with their configured replacements."""
    redacted = text
    for pii in patterns or DEFAULT_PATTERNS:
        redacted = pii.pattern.sub(pii.replacement, redacted)
    return redacted


def contains_pii(text: str, patterns: Iterable[PiiPattern] | None = None) -> bool:
    """Convenience boolean wrapper for :func:`detect_pii`."""
    return bool(detect_pii(text, patterns=patterns))

