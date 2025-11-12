"\"\"\"Pydantic models for the fuzzer API.\"\"\""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class FindingModel(BaseModel):
    rule_id: str
    title: str
    severity: str
    description: str
    payload: str
    evidence: str
    url: str


class CaseModel(BaseModel):
    payload: str
    status_code: int
    elapsed_ms: float
    response_length: int
    url: str
    new_coverage: bool
    findings: List[FindingModel] = Field(default_factory=list)


class RunSummary(BaseModel):
    target: str
    duration_seconds: float
    iterations: int
    coverage_count: int
    cases: List[CaseModel]
    findings: List[FindingModel]


class RunListEntry(BaseModel):
    path: str
    created_at: datetime


class FuzzRequest(BaseModel):
    target_url: str
    budget_seconds: float = Field(default=60.0, gt=0, le=900)

