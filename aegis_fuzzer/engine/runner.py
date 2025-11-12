"\"\"\"Main fuzzing loop implementation.\"\"\""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from common.utils.logging import setup_logging

from .coverage import CoverageMap
from .harness import FuzzResponse, TargetHarness
from .mutators import ClassicMutator, LLMGuidedMutator, MutationContext


@dataclass(slots=True)
class FuzzFinding:
    rule_id: str
    title: str
    severity: str
    description: str
    payload: str
    evidence: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence,
            "url": self.url,
        }


@dataclass(slots=True)
class FuzzCase:
    payload: str
    status_code: int
    elapsed_ms: float
    response_length: int
    url: str
    new_coverage: bool
    findings: Sequence[FuzzFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "payload": self.payload,
            "status_code": self.status_code,
            "elapsed_ms": self.elapsed_ms,
            "response_length": self.response_length,
            "url": self.url,
            "new_coverage": self.new_coverage,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass
class FuzzRunResult:
    target: str
    duration_seconds: float
    iterations: int
    coverage_count: int
    cases: list[FuzzCase] = field(default_factory=list)
    findings: list[FuzzFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "iterations": self.iterations,
            "coverage_count": self.coverage_count,
            "cases": [case.to_dict() for case in self.cases],
            "findings": [finding.to_dict() for finding in self.findings],
        }


class FuzzRunner:
    def __init__(
        self,
        target_url: str,
        *,
        time_budget: float = 180.0,
        classic_mutator: ClassicMutator | None = None,
        llm_mutator: LLMGuidedMutator | None = None,
    ) -> None:
        setup_logging()
        self.target_url = target_url
        self.time_budget = time_budget
        self.coverage = CoverageMap()
        self.classic_mutator = classic_mutator or ClassicMutator()
        self.llm_mutator = llm_mutator or LLMGuidedMutator()
        self.corpus: list[str] = []
        self._unique_findings: dict[tuple[str, str], FuzzFinding] = {}

    async def run(self) -> FuzzRunResult:
        start = time.time()
        iterations = 0
        result = FuzzRunResult(
            target=self.target_url,
            duration_seconds=0.0,
            iterations=0,
            coverage_count=0,
        )

        async with TargetHarness(self.target_url, coverage=self.coverage) as harness:
            await harness.warmup()

            while time.time() - start < self.time_budget:
                context = MutationContext(
                    status_code=200 if not result.cases else result.cases[-1].status_code,
                    response_length=0 if not result.cases else result.cases[-1].response_length,
                    findings=[finding.title for finding in result.findings],
                    new_coverage=False,
                )

                seed = self.classic_mutator.choose_seed(self.corpus)
                classic_payloads = self.classic_mutator.mutate(seed, context)
                llm_payloads = await self.llm_mutator.mutate(seed, context)
                payloads = list(dict.fromkeys([seed, *classic_payloads, *llm_payloads]))

                for payload in payloads:
                    response = await harness.execute(payload)
                    iterations += 1
                    case = self._build_case(response)
                    result.cases.append(case)
                    if case.new_coverage:
                        self.corpus.append(payload)
                    for finding in case.findings:
                        self._unique_findings[(finding.rule_id, finding.payload)] = finding

                await asyncio.sleep(0)

        result.duration_seconds = time.time() - start
        result.iterations = iterations
        result.coverage_count = len(self.coverage)
        result.findings = list(self._unique_findings.values())
        return result

    # Internal helpers -------------------------------------------------
    def _build_case(self, response: FuzzResponse) -> FuzzCase:
        findings = [
            FuzzFinding(
                rule_id=detection.rule_id,
                title=detection.title,
                severity=detection.severity,
                description=detection.description,
                payload=response.payload,
                evidence=detection.evidence,
                url=response.url,
            )
            for detection in response.detections
        ]
        return FuzzCase(
            payload=response.payload,
            status_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
            response_length=response.response_length,
            url=response.url,
            new_coverage=response.coverage is not None,
            findings=findings,
        )

