"\"\"\"Reporting utilities for the AEGIS fuzzer.\"\"\""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable, Tuple

from jinja2 import Template

from common.utils.sarif import SarifLocation, SarifResult, SarifRule, SarifRun, write_sarif

from .runner import FuzzFinding, FuzzRunResult


SARIF_RULES = [
    SarifRule(
        rule_id="AEGIS500",
        name="Server error response",
        short_description="Unhandled server error encountered while fuzzing.",
        full_description="The target returned a 5xx response code indicating a potential vulnerability.",
    ),
    SarifRule(
        rule_id="AEGIS-SQL",
        name="SQL injection indicator",
        short_description="Evidence of SQL query manipulation detected.",
        full_description="Response body matched patterns commonly produced by SQL injection attempts.",
    ),
    SarifRule(
        rule_id="AEGIS-TEMPLATE",
        name="Template injection indicator",
        short_description="Template rendering artifacts were identified.",
        full_description="Response contains template syntax which suggests server-side template injection.",
    ),
]

HTML_TEMPLATE = Template(
    """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>AEGIS Fuzzer Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; background: #0b0c10; color: #c5c6c7; }
    h1, h2 { color: #66fcf1; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
    th, td { border: 1px solid #45a29e; padding: 0.5rem; }
    th { background: #1f2833; }
    tr:nth-child(even) { background: #1b1e23; }
    code { color: #66fcf1; }
  </style>
</head>
<body>
  <h1>AEGIS Fuzzer Report</h1>
  <p><strong>Target:</strong> {{ run.target }}</p>
  <p><strong>Duration:</strong> {{ run.duration_seconds | round(2) }}s</p>
  <p><strong>Iterations:</strong> {{ run.iterations }}</p>
  <p><strong>Coverage entries:</strong> {{ run.coverage_count }}</p>

  <h2>Findings</h2>
  {% if run.findings %}
  <table>
    <thead>
      <tr><th>Rule</th><th>Title</th><th>Severity</th><th>Evidence</th><th>Payload</th></tr>
    </thead>
    <tbody>
    {% for finding in run.findings %}
      <tr>
        <td>{{ finding.rule_id }}</td>
        <td>{{ finding.title }}</td>
        <td>{{ finding.severity }}</td>
        <td><code>{{ finding.evidence }}</code></td>
        <td><code>{{ finding.payload }}</code></td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No high-confidence findings were recorded.</p>
  {% endif %}

  <h2>Sample Cases</h2>
  <table>
    <thead>
      <tr><th>Status</th><th>Latency (ms)</th><th>Coverage</th><th>Payload</th></tr>
    </thead>
    <tbody>
    {% for case in run.cases[:25] %}
      <tr>
        <td>{{ case.status_code }}</td>
        <td>{{ case.elapsed_ms | round(2) }}</td>
        <td>{{ "Yes" if case.new_coverage else "No" }}</td>
        <td><code>{{ case.payload }}</code></td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""
)


def generate_reports(run: FuzzRunResult, output_dir: str | Path) -> tuple[Path, Path]:
    """Generate SARIF and HTML reports and return their paths."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    sarif_path = output_path / f"aegis-fuzzer-{timestamp}.sarif"
    html_path = output_path / f"aegis-fuzzer-{timestamp}.html"

    sarif_run = _build_sarif_run(run)
    write_sarif(sarif_run, sarif_path)

    html_path.write_text(HTML_TEMPLATE.render(run=run), encoding="utf-8")
    return sarif_path, html_path


def _build_sarif_run(run: FuzzRunResult) -> SarifRun:
    results = [
        SarifResult(
            rule_id=finding.rule_id,
            message=finding.description,
            level=_severity_to_level(finding.severity),
            locations=[
                SarifLocation(
                    uri=finding.url,
                    message=f"Payload: {finding.payload}",
                )
            ],
            properties={"evidence": finding.evidence},
        )
        for finding in run.findings
    ]
    return SarifRun(
        tool_name="AEGIS Fuzzer",
        tool_version="0.1.0",
        information_uri="https://example.local/aegis",
        rules=SARIF_RULES,
        results=results,
        artifacts=[],
    )


def _severity_to_level(severity: str) -> str:
    mapping = {
        "low": "note",
        "medium": "warning",
        "high": "error",
    }
    return mapping.get(severity.lower(), "warning")

