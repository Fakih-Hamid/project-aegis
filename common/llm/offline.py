"""
Offline-usable LLM shim.

The objective is to provide deterministic, dependency-free guidance that mimics
an LLM without requiring network connectivity. The implementation uses simple
pattern matching and a rule-driven knowledge base to derive suggestions.
"""

from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .base import BaseLLM, LLMRequest, LLMResponse


DEFAULT_PAYLOAD_HINTS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1\" --",
    "{{7*7}}",
    "${7*7}",
    "'; DROP TABLE users; --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "admin' --",
]

DEFAULT_OBSERVATION_PATTERNS = {
    "sql": re.compile(r"sql|database|query|select|where", re.I),
    "template": re.compile(r"template|jinja|render|{{", re.I),
    "auth": re.compile(r"auth|login|token", re.I),
    "file": re.compile(r"file|path|read|config", re.I),
}


@dataclass(slots=True)
class OfflineLLMConfig:
    """Configuration knobs for the deterministic LLM."""

    max_tokens: int = 128
    latency_range: tuple[float, float] = (0.01, 0.05)
    seed: int = 1337
    payload_hints: Iterable[str] = field(default_factory=lambda: DEFAULT_PAYLOAD_HINTS)
    observation_patterns: Mapping[str, re.Pattern[str]] = field(
        default_factory=lambda: DEFAULT_OBSERVATION_PATTERNS
    )


class OfflineLLM(BaseLLM):
    """Rule-based pseudo-LLM used for both fuzzing and sandbox demos."""

    def __init__(self, config: OfflineLLMConfig | None = None) -> None:
        self._config = config or OfflineLLMConfig()
        self._random = random.Random(self._config.seed)
        self._payloads = list(self._config.payload_hints)
        if not self._payloads:
            raise ValueError("OfflineLLM requires at least one payload hint")

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Produce a deterministic, context-aware suggestion."""
        await asyncio.sleep(self._random.uniform(*self._config.latency_range))

        prompt = request.prompt.lower()
        history = "\n".join(request.history or [])
        clue_space = f"{prompt}\n{history}"

        selected = self._suggest_payload(clue_space)
        advice = self._build_advice(selected, clue_space)

        text = f"{selected}\n\n{advice}"
        usage_tokens = min(len(text.split()), self._config.max_tokens)
        return LLMResponse(text=text.strip(), usage_tokens=usage_tokens, metadata={"mode": "offline"})

    # Internal helpers -----------------------------------------------------
    def _suggest_payload(self, clue_space: str) -> str:
        matches: list[str] = []
        for payload in self._payloads:
            if payload.lower() in clue_space:
                matches.append(payload)

        if matches:
            return self._random.choice(matches)

        # rank based on observation heuristics
        for label, pattern in self._config.observation_patterns.items():
            if pattern.search(clue_space):
                seeded = [p for p in self._payloads if label in self._classify_payload(p)]
                if seeded:
                    return self._random.choice(seeded)

        return self._random.choice(self._payloads)

    def _classify_payload(self, payload: str) -> str:
        if any(token in payload.lower() for token in ("'", "\"", "select", "union")):
            return "sql"
        if "{{" in payload or "}}" in payload:
            return "template"
        if "<script" in payload.lower():
            return "xss"
        if "../" in payload:
            return "file"
        return "generic"

    def _build_advice(self, payload: str, clue_space: str) -> str:
        observations: list[str] = []
        for label, pattern in self._config.observation_patterns.items():
            if pattern.search(clue_space):
                observations.append(label)

        if not observations:
            return "Focus on forcing error responses and increasing coverage."

        advice_bits = [f"Observation: {label}" for label in observations]
        advice_bits.append(f"Consider mutating around payload `{payload}`.")
        return " ".join(advice_bits)

