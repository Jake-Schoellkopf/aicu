"""Shared utilities used across multiple modules."""
from __future__ import annotations

import copy
import json

from .models import ParsedRequest


def clone_request(request: ParsedRequest) -> ParsedRequest:
    """Deep-copy a ParsedRequest."""
    return ParsedRequest(
        method=request.method,
        scheme=request.scheme,
        host=request.host,
        port=request.port,
        path=request.path,
        headers=copy.deepcopy(request.headers),
        cookies=copy.deepcopy(request.cookies),
        query_params=copy.deepcopy(request.query_params),
        body=bytes(request.body),
        content_type=request.content_type,
        json_body=copy.deepcopy(request.json_body),
        mutation_points=copy.deepcopy(request.mutation_points),
    )


def rebuild_json_request(request: ParsedRequest) -> None:
    """Rebuild request.body from request.json_body."""
    if request.json_body is None:
        raise ValueError("Cannot rebuild JSON request: json_body is None")

    body_text = json.dumps(request.json_body, ensure_ascii=False)
    request.body = body_text.encode("utf-8")

    if not request.content_type:
        request.content_type = "application/json"

    request.headers["Content-Type"] = request.content_type


def serialize_mutation_result(mutation, response, diagnostics, evaluation) -> dict:
    """Serialize a single-turn mutation result to a JSON-safe dict."""
    return {
        "test_type": "single_turn",
        "test_id": mutation.test_id,
        "name": mutation.name,
        "family": mutation.family,
        "variant_id": mutation.variant_id,
        "transformation_type": mutation.transformation_type,
        "mutation_point": mutation.mutation_point,
        "mode": mutation.mode,
        "response": {
            "status_code": response.status_code,
            "elapsed_ms": response.elapsed_ms,
            "body_preview": response.text[:2000],
            "error": response.error,
        },
        "diagnostics": {
            "auth_issue": diagnostics.auth_issue,
            "csrf_issue": diagnostics.csrf_issue,
            "cookie_issue": diagnostics.cookie_issue,
            "likely_causes": diagnostics.likely_causes,
        },
        "evaluation": {
            "outcome": evaluation.outcome,
            "title": evaluation.title,
            "confidence": evaluation.confidence,
            "reason": evaluation.reason,
            "evidence": evaluation.evidence,
        },
    }


def serialize_multi_turn_result(result) -> dict:
    """Serialize a multi-turn result to a JSON-safe dict."""
    return {
        "test_type": "multi_turn",
        "test_id": result.test_id,
        "name": result.name,
        "steps": [
            {
                "step_number": step.step_number,
                "prompt": step.prompt,
                "response": {
                    "status_code": step.response.status_code,
                    "elapsed_ms": step.response.elapsed_ms,
                    "body_preview": step.response.text[:2000],
                    "error": step.response.error,
                },
                "diagnostics": {
                    "auth_issue": step.diagnostics.auth_issue,
                    "csrf_issue": step.diagnostics.csrf_issue,
                    "cookie_issue": step.diagnostics.cookie_issue,
                    "likely_causes": step.diagnostics.likely_causes,
                },
            }
            for step in result.steps
        ],
        "final_evaluation": {
            "outcome": result.final_evaluation.outcome if result.final_evaluation else "none",
            "title": result.final_evaluation.title if result.final_evaluation else "",
            "confidence": result.final_evaluation.confidence if result.final_evaluation else "low",
            "reason": result.final_evaluation.reason if result.final_evaluation else "",
            "evidence": result.final_evaluation.evidence if result.final_evaluation else [],
        },
    }
