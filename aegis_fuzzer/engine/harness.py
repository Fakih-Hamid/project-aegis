"""HTTP harness around the vulnerable target application."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .coverage import CoverageEntry, CoverageMap
from .detectors import Detection, analyze_response


@dataclass(slots=True)
class FuzzResponse:
    payload: str
    status_code: int
    elapsed_ms: float
    response_length: int
    body: str
    url: str
    coverage: CoverageEntry | None
    detections: list[Detection]


class TargetHarness:
    """Wraps the HTTP interactions with the vulnerable Flask application."""

    def __init__(self, base_url: str, *, timeout: float = 5.0, coverage: CoverageMap | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.coverage = coverage or CoverageMap()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "TargetHarness":
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        if self._client is not None:
            await self._client.aclose()
        self._client = None

    async def warmup(self) -> None:
        """Ensure the target is reachable before fuzzing."""
        client = await self._ensure_client()
        try:
            await client.get("/health")
        except Exception as exc:  # pragma: no cover - defensive logging
            raise RuntimeError("Failed to reach target health endpoint") from exc

    async def execute(self, payload: str) -> FuzzResponse:
        client = await self._ensure_client()
        start = time.perf_counter()
        response = await client.get("/search", params={"q": payload})
        elapsed_ms = (time.perf_counter() - start) * 1000

        body = response.text
        coverage_entry = self.coverage.register(path="/search", status=response.status_code, length=len(body))
        detections = analyze_response(payload=payload, status=response.status_code, body=body, elapsed_ms=elapsed_ms)
        return FuzzResponse(
            payload=payload,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            response_length=len(body),
            body=body[:10_000],
            url=str(response.request.url),
            coverage=coverage_entry,
            detections=detections,
        )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return self._client

