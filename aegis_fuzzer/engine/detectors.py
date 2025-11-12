"\"\"\"Response heuristics to flag interesting behaviour during fuzzing.\"\"\""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List


ERROR_PATTERNS: dict[str, re.Pattern[str]] = {
    "sql": re.compile(r"(sql syntax|sqlite|psql|mysql|error.*near|sqlstate)", re.I),
    "template": re.compile(r"(jinja|template rendering|{{|}}|undefinedError)", re.I),
    "stack": re.compile(r"(traceback|stack trace|exception in)", re.I),
    "xss": re.compile(r"<script>.*?</script>", re.I),
    "path": re.compile(r"(etc/passwd|system32|c:\\\\)", re.I),
}


@dataclass(slots=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str


def analyze_response(
    payload: str,
    status: int,
    body: str,
    elapsed_ms: float,
) -> list[Detection]:
    """Scan an HTTP response for quick vulnerability signals."""
    findings: list[Detection] = []

    if status >= 500:
        findings.append(
            Detection(
                rule_id="AEGIS500",
                title="Server error response",
                severity="medium",
                description="Target returned a 5xx response which often indicates an unhandled exception.",
                evidence=f"Status {status} with payload {payload[:120]!r}",
            )
        )

    for label, pattern in ERROR_PATTERNS.items():
        if pattern.search(body):
            findings.append(
                Detection(
                    rule_id=f"AEGIS-{label.upper()}",
                    title=f"Potential {label} vulnerability",
                    severity="high" if label in {"sql", "template"} else "medium",
                    description=f"Response body contains indicators of {label} exploitation.",
                    evidence=pattern.search(body).group(0)[:200],  # type: ignore[union-attr]
                )
            )

    if elapsed_ms > 1_500:
        findings.append(
            Detection(
                rule_id="AEGIS-LATE",
                title="High latency response",
                severity="low",
                description="Response latency exceeded 1.5 seconds which may indicate heavy processing.",
                evidence=f"Latency {elapsed_ms:.2f}ms for payload {payload[:60]!r}",
            )
        )

    return findings

