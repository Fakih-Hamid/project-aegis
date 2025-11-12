"\"\"\"Policy evaluation engine for the AEGIS guard.\"\"\""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

import yaml

from common.utils.pii import contains_pii

from aegis_guard.memory import UserMemory
from aegis_guard.redaction import RedactionResult, redact_sensitive


ActionType = Literal["allow", "deny", "redact"]


@dataclass(slots=True)
class PolicyRule:
    id: str
    action: ActionType
    match: Mapping[str, Any]


@dataclass(slots=True)
class PolicyDecision:
    permitted: bool
    rule_id: str | None
    reason: str
    redacted_text: str
    redacted_tokens: Sequence[str]
    pii_hits: Sequence[str]


@dataclass(slots=True)
class PolicyContext:
    tool: str
    payload: str
    memory: UserMemory


class PolicyEngine:
    def __init__(self, rules: Sequence[PolicyRule]) -> None:
        self.rules = list(rules)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        rules = [
            PolicyRule(id=item["id"], action=item["action"], match=item.get("match", {}))
            for item in data.get("rules", [])
        ]
        return cls(rules=rules)

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        redaction = redact_sensitive(context.payload, context.memory)
        for rule in self.rules:
            if self._matches(rule.match, context, redaction):
                if rule.action == "deny":
                    return PolicyDecision(
                        permitted=False,
                        rule_id=rule.id,
                        reason="Rule denied payload",
                        redacted_text=redaction.text,
                        redacted_tokens=redaction.redacted,
                        pii_hits=redaction.pii,
                    )
                if rule.action == "redact":
                    return PolicyDecision(
                        permitted=True,
                        rule_id=rule.id,
                        reason="Payload redacted per policy",
                        redacted_text=redaction.text,
                        redacted_tokens=redaction.redacted,
                        pii_hits=redaction.pii,
                    )
                if rule.action == "allow":
                    return PolicyDecision(
                        permitted=True,
                        rule_id=rule.id,
                        reason="Explicit allow rule matched",
                        redacted_text=redaction.text,
                        redacted_tokens=redaction.redacted,
                        pii_hits=redaction.pii,
                    )

        # default deny if secrets detected
        if context.memory.contains_sensitive(context.payload):
            return PolicyDecision(
                permitted=False,
                rule_id=None,
                reason="Implicit deny due to sensitive token",
                redacted_text=redaction.text,
                redacted_tokens=redaction.redacted,
                pii_hits=redaction.pii,
            )

        return PolicyDecision(
            permitted=True,
            rule_id=None,
            reason="No policy matched (default allow)",
            redacted_text=redaction.text,
            redacted_tokens=redaction.redacted,
            pii_hits=redaction.pii,
        )

    def _matches(self, match: Mapping[str, Any], context: PolicyContext, redaction: RedactionResult) -> bool:
        if not match:
            return True

        payload = context.payload

        if "tool" in match:
            tools = match["tool"]
            if isinstance(tools, str):
                tools = [tools]
            if context.tool not in tools:
                return False

        if match.get("contains_secret") and not context.memory.contains_sensitive(payload):
            return False

        if match.get("contains_pii") and not redaction.pii:
            return False

        if "contains" in match:
            needles = match["contains"]
            if isinstance(needles, str):
                needles = [needles]
            if not any(needle.lower() in payload.lower() for needle in needles):
                return False

        if "payload_regex" in match:
            pattern = re.compile(match["payload_regex"], re.I)
            if not pattern.search(payload):
                return False

        if "max_length" in match and len(payload) > int(match["max_length"]):
            return False

        return True

