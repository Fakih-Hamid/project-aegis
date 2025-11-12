"\"\"\"Unit tests for fuzzer mutators.\"\"\""

from __future__ import annotations

import pytest

from aegis_fuzzer.engine.mutators import ClassicMutator, LLMGuidedMutator, MutationContext
from common.llm.base import BaseLLM, LLMRequest, LLMResponse


class DummyLLM(BaseLLM):
    async def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text="payload_one\npayload_two\npayload_three",
            usage_tokens=3,
        )


def test_classic_mutator_generates_variations() -> None:
    mutator = ClassicMutator(dictionary=["foo", "bar"])
    context = MutationContext(
        status_code=200,
        response_length=10,
        findings=[],
        new_coverage=False,
    )
    results = mutator.mutate("seed", context)
    assert "foo" in results
    assert any(result != "seed" for result in results)


@pytest.mark.asyncio
async def test_llm_mutator_uses_llm_output() -> None:
    mutator = LLMGuidedMutator(llm=DummyLLM())
    context = MutationContext(
        status_code=500,
        response_length=100,
        findings=["error"],
        new_coverage=True,
    )
    results = await mutator.mutate("seed", context)
    assert len(results) >= 3
    assert "payload_one" in results

