"""Coverage tracking utilities for the AEGIS fuzzer."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from common.utils.hashing import sha256_hex


@dataclass(slots=True)
class CoverageEntry:
    path: str
    status: int
    length: int
    digest: str
    first_seen: float


@dataclass
class CoverageMap:
    """Very small coverage map based on response metadata."""

    entries: dict[str, CoverageEntry] = field(default_factory=dict)

    def _hash(self, path: str, status: int, length: int) -> str:
        return sha256_hex(f"{path}|{status}|{length}")

    def register(self, path: str, status: int, length: int) -> CoverageEntry | None:
        """Register an observation; return the :class:`CoverageEntry` if new."""
        digest = self._hash(path, status, length)
        if digest in self.entries:
            return None

        entry = CoverageEntry(
            path=path,
            status=status,
            length=length,
            digest=digest,
            first_seen=time.time(),
        )
        self.entries[digest] = entry
        return entry

    def seen(self, path: str, status: int, length: int) -> bool:
        return self._hash(path, status, length) in self.entries

    def digests(self) -> set[str]:
        return set(self.entries.keys())

    def __len__(self) -> int:
        return len(self.entries)

    def serialize(self) -> Iterable[dict[str, str | int | float]]:
        for entry in self.entries.values():
            yield {
                "path": entry.path,
                "status": entry.status,
                "length": entry.length,
                "digest": entry.digest,
                "first_seen": entry.first_seen,
            }

