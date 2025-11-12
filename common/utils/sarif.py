"""
Minimal SARIF report helpers for the fuzzing engine.

The goal is to avoid pulling heavy dependencies while still producing valid
SARIF v2.1.0 payloads that can be consumed by code scanning tools.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

SARIF_VERSION = "2.1.0"


@dataclass(slots=True)
class SarifLocation:
    uri: str
    message: str
    line: int | None = None


@dataclass(slots=True)
class SarifResult:
    rule_id: str
    message: str
    level: Literal["none", "note", "warning", "error"] = "warning"
    locations: Sequence[SarifLocation] = field(default_factory=list)
    properties: Mapping[str, Any] | None = None


@dataclass(slots=True)
class SarifRule:
    rule_id: str
    name: str
    short_description: str
    full_description: str
    help_uri: str | None = None
    properties: Mapping[str, Any] | None = None


@dataclass(slots=True)
class SarifRun:
    tool_name: str
    tool_version: str
    information_uri: str | None = None
    rules: Sequence[SarifRule] = field(default_factory=list)
    results: Sequence[SarifResult] = field(default_factory=list)
    artifacts: Sequence[str] = field(default_factory=list)


def _rule_to_dict(rule: SarifRule) -> dict[str, Any]:
    rule_dict = {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.short_description},
        "fullDescription": {"text": rule.full_description},
    }
    if rule.help_uri:
        rule_dict["helpUri"] = rule.help_uri
    if rule.properties:
        rule_dict["properties"] = dict(rule.properties)
    return rule_dict


def _location_to_dict(location: SarifLocation) -> dict[str, Any]:
    physical_location: dict[str, Any] = {"artifactLocation": {"uri": location.uri}}
    if location.line is not None:
        physical_location["region"] = {"startLine": location.line}
    return {
        "physicalLocation": physical_location,
        "message": {"text": location.message},
    }


def _result_to_dict(result: SarifResult) -> dict[str, Any]:
    payload = {
        "ruleId": result.rule_id,
        "level": result.level,
        "message": {"text": result.message},
    }
    if result.locations:
        payload["locations"] = [_location_to_dict(loc) for loc in result.locations]
    if result.properties:
        payload["properties"] = dict(result.properties)
    return payload


def run_to_sarif(run: SarifRun) -> dict[str, Any]:
    """Convert a :class:`SarifRun` object into a SARIF v2.1.0 dict."""
    artifact_entries: list[dict[str, Any]] = [
        {"location": {"uri": artifact}} for artifact in run.artifacts
    ]

    return {
        "version": SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": run.tool_name,
                        "version": run.tool_version,
                        **({"informationUri": run.information_uri} if run.information_uri else {}),
                        "rules": [_rule_to_dict(rule) for rule in run.rules],
                    }
                },
                "results": [_result_to_dict(result) for result in run.results],
                "artifacts": artifact_entries,
            }
        ],
    }


def write_sarif(run: SarifRun, output_path: str | Path) -> Path:
    """Serialize *run* into a SARIF file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sarif_payload = run_to_sarif(run)
    path.write_text(json.dumps(sarif_payload, indent=2), encoding="utf-8")
    return path

