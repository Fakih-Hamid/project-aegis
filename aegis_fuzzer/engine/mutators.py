"""Payload mutators for the AEGIS fuzzer."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from common.llm.offline import OfflineLLM
from common.llm.base import BaseLLM


SEED_PAYLOADS: Sequence[str] = (
    "",
    "admin",
    "test",
    "1",
    "../etc/passwd",
    "' OR 1=1--",
    "{{7*7}}",
)

DEFAULT_ALPHABET = string.ascii_letters + string.digits + string.punctuation


@dataclass(slots=True)
class MutationContext:
    """Holds the latest execution feedback consumed by the mutators."""

    status_code: int
    response_length: int
    findings: Sequence[str]
    new_coverage: bool


class Mutator:
    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random(1337)

    def choose_seed(self, corpus: Sequence[str]) -> str:
        if not corpus:
            return self._rng.choice(SEED_PAYLOADS)
        return self._rng.choice(corpus)


class ClassicMutator(Mutator):
    """Classic mutation strategies: bit flips, dictionary injections, casing."""

    def __init__(self, dictionary: Iterable[str] | None = None, rng: random.Random | None = None) -> None:
        super().__init__(rng=rng)
        self.dictionary = list(dictionary or [])
        if not self.dictionary:
            self.dictionary = [
                "' OR '1'='1",
                "\" OR \"1\"=\"1\" --",
                "<script>alert(1)</script>",
                "../../etc/passwd",
                "{{ config.items() }}",
            ]

    def mutate(self, seed: str, context: MutationContext) -> list[str]:
        payloads = set[str]()
        payloads.add(seed[::-1])
        payloads.add(seed.upper())
        payloads.add(seed.lower())
        payloads.add(self._bitflip(seed))

        for word in self.dictionary:
            payloads.add(word)
            payloads.add(f"{seed}{word}")
            payloads.add(f"{word}{seed}")

        if context.new_coverage or context.status_code >= 500:
            payloads.add(seed + "'\"")

        return [p for p in payloads if p]

    def _bitflip(self, value: str) -> str:
        if not value:
            return self._rng.choice(self.dictionary)
        index = self._rng.randrange(len(value))
        flipped_char = self._rng.choice(DEFAULT_ALPHABET)
        return value[:index] + flipped_char + value[index + 1 :]


class LLMGuidedMutator(Mutator):
    """Leverages the offline LLM to generate informed payloads."""

    def __init__(self, llm: BaseLLM | None = None, rng: random.Random | None = None) -> None:
        super().__init__(rng=rng)
        self.llm: BaseLLM = llm or OfflineLLM()

    async def mutate(self, seed: str, context: MutationContext) -> list[str]:
        feedback = "; ".join(context.findings) if context.findings else "No findings yet."
        prompt = (
            "You are assisting a security fuzzer. "
            f"Current seed: {seed!r}. "
            f"HTTP status: {context.status_code}. "
            f"Response length: {context.response_length}. "
            f"New coverage: {context.new_coverage}. "
            f"Prior findings: {feedback}. "
            "Suggest 3 concise payloads separated by newline characters."
        )
        completion = await self.llm.simple_completion(prompt)
        candidates = [line.strip() for line in completion.splitlines() if line.strip()]

        if len(candidates) < 3:
            # Fall back to random perturbations around the seed.
            candidates.extend(self._neighbourhood(seed))

        return list(dict.fromkeys(candidates))  # Preserve order while deduplicating.

    def _neighbourhood(self, seed: str) -> list[str]:
        neighbours = []
        for _ in range(3):
            neighbours.append(seed + self._rng.choice(self.dictionary_fallback()))
        return neighbours

    def dictionary_fallback(self) -> Sequence[str]:
        return [
            "'; DROP TABLE users; --",
            "{{ self.__class__.__mro__ }}",
            "${7*7}",
        ]

