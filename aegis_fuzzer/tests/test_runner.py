"\"\"\"Tests for the main fuzzing runner.\"\"\""

from __future__ import annotations

from types import TracebackType

import pytest

from aegis_fuzzer.engine.coverage import CoverageMap
from aegis_fuzzer.engine.detectors import Detection
from aegis_fuzzer.engine.harness import FuzzResponse
from aegis_fuzzer.engine.runner import FuzzRunner


class DummyHarness:
    def __init__(self, base_url: str, *, coverage: CoverageMap | None = None, **_: object) -> None:
        self.coverage = coverage or CoverageMap()
        self.payloads: list[str] = []

    async def __aenter__(self) -> DummyHarness:
        if len(self.coverage) == 0:
            self.coverage.register(path="/warmup", status=200, length=0)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    async def warmup(self) -> None:
        return None

    async def execute(self, payload: str) -> FuzzResponse:
        self.payloads.append(payload)
        coverage_entry = self.coverage.register(path="/search", status=500, length=42)
        detections = [
            Detection(
                rule_id="AEGIS500",
                title="Server error response",
                severity="medium",
                description="Simulated server error",
                evidence="Simulated stack trace",
            )
        ]
        return FuzzResponse(
            payload=payload,
            status_code=500,
            elapsed_ms=10.0,
            response_length=42,
            body="Simulated stack trace",
            url="http://example/search",
            coverage=coverage_entry,
            detections=detections,
        )


@pytest.mark.asyncio
async def test_runner_collects_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aegis_fuzzer.engine.runner.TargetHarness", DummyHarness)
    runner = FuzzRunner(target_url="http://dummy", time_budget=0.1)
    result = await runner.run()
    assert result.findings, "Expected runner to aggregate findings"
    assert result.coverage_count >= 1
    assert result.iterations > 0

