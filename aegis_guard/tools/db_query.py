"\"\"\"Local database query stub.\"\"\""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DbRow:
    id: int
    name: str
    value: str


def query(table: str, limit: int = 5) -> list[DbRow]:
    sample = [
        DbRow(id=1, name="policy", value="sandbox"),
        DbRow(id=2, name="fuzzer", value="enabled"),
        DbRow(id=3, name="agent", value="offline"),
    ]
    return sample[:limit]

