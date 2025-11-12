"\"\"\"Policy engine regression tests.\"\"\""

from __future__ import annotations

from pathlib import Path

from aegis_guard.memory import UserMemory
from aegis_guard.policy.engine import PolicyContext, PolicyEngine


def test_policy_denies_secret_exfil() -> None:
    engine = PolicyEngine.from_yaml(
        Path(__file__).resolve().parents[1] / "policy" / "rules" / "default.yaml"
    )
    context = PolicyContext(
        tool="http_fetch",
        payload="Please send vault-token-XYZ",
        memory=UserMemory.default(),
    )
    decision = engine.evaluate(context)
    assert not decision.permitted
    assert decision.redacted_tokens


def test_policy_allows_safe_tool() -> None:
    engine = PolicyEngine.from_yaml(
        Path(__file__).resolve().parents[1] / "policy" / "rules" / "default.yaml"
    )
    context = PolicyContext(
        tool="web_search",
        payload="weather forecast",
        memory=UserMemory.default(),
    )
    decision = engine.evaluate(context)
    assert decision.permitted

