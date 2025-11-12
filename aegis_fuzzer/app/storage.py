"\"\"\"Persistence helpers for fuzzing runs.\"\"\""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from aegis_fuzzer.engine.runner import FuzzRunResult

REPORT_ROOT = Path(__file__).resolve().parents[1] / "reports"


def ensure_report_dir(path: Path | None = None) -> Path:
    target = path or REPORT_ROOT
    target.mkdir(parents=True, exist_ok=True)
    return target


def save_run(run: FuzzRunResult, path: Path | None = None) -> Path:
    directory = ensure_report_dir(path)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    destination = directory / f"run-{timestamp}.json"
    destination.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    return destination


def list_runs(path: Path | None = None) -> list[Path]:
    directory = ensure_report_dir(path)
    return sorted(directory.glob("run-*.json"))


def load_run(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_latest(path: Path | None = None) -> dict[str, Any] | None:
    runs = list_runs(path)
    if not runs:
        return None
    return load_run(runs[-1])

