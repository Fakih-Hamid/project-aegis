"\"\"\"Payment processing stub that never hits external services.\"\"\""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4


@dataclass
class PaymentResult:
    reference: str
    status: str
    amount: float


def charge(amount: float) -> PaymentResult:
    return PaymentResult(reference=f"PAY-{uuid4().hex[:8]}", status="approved", amount=amount)

