"\"\"\"FastAPI application exposing the fuzzer as a service.\"\"\""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException

from aegis_fuzzer.engine.report import generate_reports
from aegis_fuzzer.engine.runner import FuzzRunner

from .models import FuzzRequest, RunListEntry, RunSummary
from .storage import ensure_report_dir, list_runs, load_latest, load_run, save_run

app = FastAPI(title="AEGIS Fuzzer", version="0.1.0")


@app.get("/runs", response_model=list[RunListEntry])
def get_runs() -> list[RunListEntry]:
    runs = []
    for path in list_runs():
        timestamp = path.stem.replace("run-", "")
        created = datetime.strptime(timestamp, "%Y%m%d-%H%M%S")
        runs.append(RunListEntry(path=str(path), created_at=created))
    return runs


@app.get("/runs/latest", response_model=RunSummary | None)
def get_latest_run() -> RunSummary | None:
    latest = load_latest()
    if latest is None:
        return None
    return RunSummary.model_validate(latest)


@app.post("/fuzz", response_model=RunSummary)
async def trigger_fuzz(request: FuzzRequest) -> RunSummary:
    runner = FuzzRunner(target_url=request.target_url, time_budget=request.budget_seconds)
    run = await runner.run()
    save_run(run)
    generate_reports(run, ensure_report_dir())
    return RunSummary.model_validate(run.to_dict())


def run() -> None:
    """Entry point used by the console script."""
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9000)

