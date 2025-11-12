# Project AEGIS

**An Offline AI Security Lab combining an Autonomous Fuzzer and an Exfiltration-Resistant Policy Sandbox. Because the best defense is understanding your offense.**

## Overview

Project AEGIS is a mono-repo that ships two complementary demonstrators:

- `aegis-fuzzer/` — an AI-assisted vulnerability discovery pipeline that combines classical fuzzing strategies with offline large-language-model guidance.
- `aegis-guard/` — a privacy-preserving sandbox that enforces strict data-loss-prevention policies whenever an AI agent invokes external tools.

Both modules share reusable utilities under `common/` and can run fully offline.


## Quick Start

```bash
# Setup local environment
uv sync --extra dev

# Launch the vulnerable target used by the fuzzer
make up

# Run a short fuzzing session (3 minutes by default)
make fuzz-demo

# Review generated SARIF and HTML reports
make report

# Start the sandbox demo API (FastAPI)
make sandbox

# Run static checks and tests
make lint
make test
```

All commands are designed to operate without external network access once dependencies are installed.

## Repository Layout

- `common/`: shared offline LLM abstractions, logging, hashing, PII detection, and SARIF helpers.
- `aegis-fuzzer/`: fuzzing engine, CLI entrypoint, vulnerable targets, and tests.
- `aegis-guard/`: sandbox policies, tool wrappers, FastAPI demo app, and tests.
- `.github/`: CI workflows (ruff, mypy, pytest, SARIF artifact export).
- `docker-compose.yml`: orchestration for vulnerable targets used by the fuzzer.

## Licensing

This project is released under the MIT License.

