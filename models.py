from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ParsedRequest:
    method: str
    scheme: str
    host: str
    port: int | None
    path: str
    headers: dict[str, str]
    cookies: dict[str, str]
    query_params: dict[str, str]
    body: bytes
    content_type: str | None = None
    json_body: Any | None = None
    mutation_points: list[str] = field(default_factory=list)

    def is_json(self) -> bool:
        return bool(self.content_type and "application/json" in self.content_type.lower())

    def full_url(self) -> str:
        if self.port in (80, 443, None):
            return f"{self.scheme}://{self.host}{self.path}"
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


@dataclass(slots=True)
class ReplayResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    text: str
    elapsed_ms: int
    error: str | None = None


@dataclass(slots=True)
class TestCase:
    test_id: str
    name: str
    category: str
    severity: str
    description: str
    payloads: list[str] = field(default_factory=list)
    turns: list[dict[str, str]] = field(default_factory=list)
    success_indicators: list[str] = field(default_factory=list)
    failure_indicators: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    finding_id: str
    test_id: str
    title: str
    severity: str
    confidence: str
    reason: str
    evidence_snippet: str | None = None
    matched_indicators: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RunArtifact:
    run_id: str
    test_id: str
    parsed_request: ParsedRequest
    mutated_request: ParsedRequest | None
    response: ReplayResponse
    finding: Finding | None
    timestamp: str