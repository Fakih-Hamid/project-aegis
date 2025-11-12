"\"\"\"Email drafting helper that cooperates with the sandbox redaction layer.\"\"\""

from __future__ import annotations

from dataclasses import dataclass

from aegis_guard.memory import UserMemory
from aegis_guard.redaction import redact_sensitive


@dataclass
class EmailDraft:
    subject: str
    body: str
    redacted_tokens: list[str]


def draft(subject: str, body: str, memory: UserMemory | None = None) -> EmailDraft:
    memory = memory or UserMemory.default()
    redaction = redact_sensitive(body, memory)
    return EmailDraft(subject=subject, body=redaction.text, redacted_tokens=redaction.redacted)

