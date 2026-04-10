from __future__ import annotations

from dataclasses import dataclass

from evaluator import evaluate_response
from file_generators import GeneratedTestFile, generate_all_test_files
from models import ParsedRequest, ReplayResponse
from multipart import replace_uploaded_file
from replay import ReplayDiagnostics, replay_request


@dataclass(slots=True)
class IndirectInjectionResult:
    test_id: str
    name: str
    file_type: str
    injected_filename: str
    response: ReplayResponse
    diagnostics: ReplayDiagnostics
    evaluation_outcome: str
    evaluation_title: str
    evaluation_confidence: str
    evaluation_reason: str
    evaluation_evidence: list[str]


def guess_content_type(file_type: str) -> str:
    """
    Map generated file types to content types.
    """
    mapping = {
        "txt": "text/plain",
        "md": "text/markdown",
        "json": "application/json",
        "py": "text/x-python",
        "js": "application/javascript",
    }
    return mapping.get(file_type, "application/octet-stream")


def run_indirect_file_test(
    base_request: ParsedRequest,
    baseline_response: ReplayResponse,
    generated_file: GeneratedTestFile,
) -> IndirectInjectionResult:
    """
    Replace the uploaded file in a multipart request with a generated test file,
    replay the request, and strictly evaluate the response.
    """
    file_bytes = generated_file.file_path.read_bytes()
    content_type = guess_content_type(generated_file.file_type)

    mutated_request = replace_uploaded_file(
        request=base_request,
        file_bytes=file_bytes,
        new_filename=generated_file.file_path.name,
        content_type=content_type,
    )

    response, diagnostics = replay_request(mutated_request)

    evaluation = evaluate_response(
        baseline_response=baseline_response,
        mutated_response=response,
        diagnostics=diagnostics,
    )

    return IndirectInjectionResult(
        test_id=generated_file.test_id,
        name=generated_file.name,
        file_type=generated_file.file_type,
        injected_filename=generated_file.file_path.name,
        response=response,
        diagnostics=diagnostics,
        evaluation_outcome=evaluation.outcome,
        evaluation_title=evaluation.title,
        evaluation_confidence=evaluation.confidence,
        evaluation_reason=evaluation.reason,
        evaluation_evidence=evaluation.evidence,
    )


def run_all_indirect_file_tests(
    base_request: ParsedRequest,
    baseline_response: ReplayResponse,
    output_dir: str = "generated_files",
) -> list[IndirectInjectionResult]:
    """
    Generate all indirect prompt injection test files and replay the multipart
    upload request once per generated file.
    """
    generated_files = generate_all_test_files(output_dir)
    results: list[IndirectInjectionResult] = []

    for generated_file in generated_files:
        results.append(
            run_indirect_file_test(
                base_request=base_request,
                baseline_response=baseline_response,
                generated_file=generated_file,
            )
        )

    return results


def serialize_indirect_result(result: IndirectInjectionResult) -> dict:
    """
    Convert an indirect injection result to a JSON-safe dictionary.
    """
    return {
        "test_type": "indirect_file",
        "test_id": result.test_id,
        "name": result.name,
        "file_type": result.file_type,
        "injected_filename": result.injected_filename,
        "response": {
            "status_code": result.response.status_code,
            "elapsed_ms": result.response.elapsed_ms,
            "body_preview": result.response.text[:2000],
            "error": result.response.error,
        },
        "diagnostics": {
            "auth_issue": result.diagnostics.auth_issue,
            "csrf_issue": result.diagnostics.csrf_issue,
            "cookie_issue": result.diagnostics.cookie_issue,
            "likely_causes": result.diagnostics.likely_causes,
        },
        "evaluation": {
            "outcome": result.evaluation_outcome,
            "title": result.evaluation_title,
            "confidence": result.evaluation_confidence,
            "reason": result.evaluation_reason,
            "evidence": result.evaluation_evidence,
        },
    }