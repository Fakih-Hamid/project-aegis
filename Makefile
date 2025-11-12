PYTHON ?= uv run
PROJECT_ROOT := $(CURDIR)
REPORT_DIR := $(PROJECT_ROOT)/aegis-fuzzer/reports

.PHONY: install
install:
	uv sync

.PHONY: lint
lint:
	uv run ruff check .
	uv run mypy .

.PHONY: test
test:
	uv run pytest

.PHONY: up
up:
	docker compose up --build -d vulnerable_flask

.PHONY: down
down:
	docker compose down

.PHONY: fuzz-demo
fuzz-demo:
	uv run python -m aegis_fuzzer.cli --target http://localhost:5001 --budget 180

.PHONY: report
report:
	uv run python -m aegis_fuzzer.engine.report --output $(REPORT_DIR)

.PHONY: sandbox
sandbox:
	uv run uvicorn aegis_guard.app.main:app --reload --port 8000

