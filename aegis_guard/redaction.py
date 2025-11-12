"\"\"\"Redaction utilities for the sandbox.\"\"\""

from __future__ import annotations

from dataclasses import dataclass

from common.utils.pii import detect_pii, redact_text

from .memory import UserMemory


@dataclass
class RedactionResult:
    text: str
    redacted: list[str]
    pii: list[str]


def redact_sensitive(text: str, memory: UserMemory) -> RedactionResult:
    redacted = redact_text(text)
    pii_hits = detect_pii(text)
    replaced_tokens: list[str] = []

    for token in memory.sensitive_tokens():
        if token and token.lower() in redacted.lower():
            redacted = redacted.replace(token, "<redacted-secret>")
            replaced_tokens.append(token)

    return RedactionResult(text=redacted, redacted=replaced_tokens, pii=pii_hits)

