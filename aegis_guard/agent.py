"\"\"\"Sandboxed agent orchestrating tool invocations under policy control.\"\"\""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_guard.audit import AuditLogger
from aegis_guard.memory import UserMemory
from aegis_guard.policy.engine import PolicyContext, PolicyDecision, PolicyEngine
from aegis_guard.tools import db_query, email_draft, http_fetch, payment_stub, web_search

ToolFunc = Callable[..., Any]


TOOL_REGISTRY: dict[str, ToolFunc] = {
    "http_fetch": lambda **kwargs: http_fetch.fetch(kwargs["url"]),
    "web_search": lambda **kwargs: web_search.search(kwargs["query"]),
    "db_query": lambda **kwargs: db_query.query(
        kwargs.get("table", "config"),
        kwargs.get("limit", 5),
    ),
    "email_draft": lambda **kwargs: email_draft.draft(
        kwargs["subject"],
        kwargs["body"],
        kwargs.get("memory"),
    ),
    "payment_stub": lambda **kwargs: payment_stub.charge(kwargs["amount"]),
}


@dataclass
class AgentResponse:
    content: Any
    decision: PolicyDecision


class SandboxedAgent:
    def __init__(
        self,
        *,
        policy_path: str | None = None,
        memory: UserMemory | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.memory = memory or UserMemory.default()
        if policy_path:
            policy_file = Path(policy_path)
        else:
            policy_file = Path(__file__).resolve().parent / "policy" / "rules" / "default.yaml"
        self.policy = PolicyEngine.from_yaml(policy_file)
        self.audit = audit_logger or AuditLogger()

    def chat(self, prompt: str) -> AgentResponse:
        decision = self.policy.evaluate(
            PolicyContext(tool="chat", payload=prompt, memory=self.memory)
        )
        if not decision.permitted:
            self.audit.log("chat", "deny", prompt, "blocked", reason=decision.reason)
            raise PermissionError(decision.reason)

        reply = f"Redacted response: {decision.redacted_text}"
        self.audit.log("chat", "allow", prompt, "reply", redacted=decision.redacted_text)
        return AgentResponse(content=reply, decision=decision)

    def call_tool(self, tool_name: str, **kwargs: Any) -> AgentResponse:
        if tool_name not in TOOL_REGISTRY:
            raise KeyError(f"Unknown tool: {tool_name}")

        payload_components = " ".join(str(value) for value in kwargs.values())
        decision = self.policy.evaluate(
            PolicyContext(tool=tool_name, payload=payload_components, memory=self.memory)
        )

        if not decision.permitted:
            self.audit.log(tool_name, "deny", payload_components, "blocked", reason=decision.reason)
            raise PermissionError(decision.reason)

        adjusted_kwargs = dict(kwargs)
        if "body" in adjusted_kwargs:
            adjusted_kwargs["body"] = decision.redacted_text
        if tool_name == "email_draft":
            adjusted_kwargs["memory"] = self.memory

        result = TOOL_REGISTRY[tool_name](**adjusted_kwargs)
        self.audit.log(
            tool_name,
            "allow",
            payload_components,
            "ok",
            redacted=decision.redacted_text,
        )
        return AgentResponse(content=result, decision=decision)

