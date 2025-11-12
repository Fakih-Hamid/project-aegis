"\"\"\"Offline HTTP fetch stub for the sandbox.\"\"\""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class HttpResponse:
    url: str
    status_code: int
    body: str


def fetch(url: str) -> HttpResponse:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return HttpResponse(url=url, status_code=400, body="Unsupported scheme")
    if parsed.netloc and parsed.netloc.endswith("example.com"):
        return HttpResponse(url=url, status_code=200, body="Example domain placeholder response.")
    return HttpResponse(url=url, status_code=200, body="Offline fetch placeholder.")

