"\"\"\"Command-line interface for the AEGIS fuzzer.\"\"\""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from aegis_fuzzer.app.storage import ensure_report_dir, save_run
from aegis_fuzzer.engine.report import generate_reports
from aegis_fuzzer.engine.runner import FuzzRunner


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AEGIS guided fuzzer.")
    parser.add_argument("--target", required=True, help="Target base URL, e.g. http://localhost:5001")
    parser.add_argument("--budget", type=float, default=180.0, help="Time budget in seconds")
    parser.add_argument(
        "--reports",
        type=Path,
        default=None,
        help="Directory used to write reports",
    )
    return parser.parse_args(argv)


async def _run_async(args: argparse.Namespace) -> int:
    runner = FuzzRunner(target_url=args.target, time_budget=args.budget)
    run = await runner.run()
    report_dir = ensure_report_dir(args.reports)
    save_run(run, report_dir)
    sarif_path, html_path = generate_reports(run, report_dir)
    print(f"[+] Fuzzing complete. SARIF: {sarif_path}, HTML: {html_path}")
    print(f"[+] Findings: {len(run.findings)} | Coverage entries: {run.coverage_count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return asyncio.run(_run_async(args))
    except KeyboardInterrupt:
        print("[-] Fuzzing interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())

