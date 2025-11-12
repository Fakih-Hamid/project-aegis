"\"\"\"Redaction unit tests.\"\"\""

from __future__ import annotations

from aegis_guard.memory import UserMemory
from aegis_guard.redaction import redact_sensitive


def test_redaction_masks_email_and_tokens() -> None:
    memory = UserMemory.default()
    sample = f"Contact {memory.email} with api key {next(iter(memory.api_keys))}"
    result = redact_sensitive(sample, memory)
    assert "<redacted-email>" in result.text
    assert "<redacted-secret>" in result.text
    assert result.pii

