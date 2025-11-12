"\"\"\"Offline web search tool stub.\"\"\""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SearchResult:
    title: str
    url: str
    summary: str


def search(query: str) -> list[SearchResult]:
    return [
        SearchResult(
            title="Project AEGIS Knowledge Base",
            url="https://aegis.local/docs",
            summary=f"Offline documentation entry for query: {query}",
        ),
        SearchResult(
            title="Security Hardening Guide",
            url="https://aegis.local/hardening",
            summary="Checklist for securing AI-assisted systems.",
        ),
    ]

