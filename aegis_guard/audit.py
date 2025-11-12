"\"\"\"Audit logging with HMAC signatures.\"\"\""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.utils.hashing import derive_hmac_key, hmac_sha256_hex


@dataclass(slots=True)
class AuditRecord:
    timestamp: float
    tool: str
    action: str
    payload: str
    decision: str
    signature: str
    metadata: dict[str, Any]


class AuditLogger:
    def __init__(self, key: bytes | str | None = None) -> None:
        self._key = derive_hmac_key(key)
        self._records: list[AuditRecord] = []

    def log(
        self,
        tool: str,
        action: str,
        payload: str,
        decision: str,
        **metadata: Any,
    ) -> AuditRecord:
        timestamp = time.time()
        data = {
            "timestamp": timestamp,
            "tool": tool,
            "action": action,
            "payload": payload,
            "decision": decision,
            "metadata": metadata,
        }
        serialized = json.dumps(data, sort_keys=True)
        signature = hmac_sha256_hex(self._key, serialized)
        record = AuditRecord(
            timestamp=timestamp,
            tool=tool,
            action=action,
            payload=payload,
            decision=decision,
            signature=signature,
            metadata=metadata,
        )
        self._records.append(record)
        return record

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def export(self, path: Path) -> None:
        data = [
            {
                "timestamp": record.timestamp,
                "tool": record.tool,
                "action": record.action,
                "payload": record.payload,
                "decision": record.decision,
                "signature": record.signature,
                "metadata": record.metadata,
            }
            for record in self._records
        ]
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

