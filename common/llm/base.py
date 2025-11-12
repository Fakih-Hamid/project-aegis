"""
Common LLM interface abstractions used by the AEGIS components.

These classes are intentionally lightweight so that alternative offline models
can be swapped in without touching the higher-level business logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """Container describing a generation request."""

    prompt: str
    history: Sequence[str] | None = None
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Standard response wrapper for LLM generations."""

    text: str
    usage_tokens: int = 0
    metadata: Mapping[str, Any] | None = None


class BaseLLM(ABC):
    """Minimal interface required by the guided mutator and sandbox agent."""

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Produce a response for the provided prompt."""

    async def simple_completion(self, prompt: str) -> str:
        """Helper around :meth:`generate` returning only the generated text."""
        response = await self.generate(LLMRequest(prompt=prompt))
        return response.text.strip()

