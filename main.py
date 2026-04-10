#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from baseline import run_baseline
from evaluator import evaluate_response
from indirect_injection import run_all_indirect_file_tests, serialize_indirect_result
from multi_turn import run_all_multi_turn_tests
from mutations import generate_mutations
from parsing import parse_raw_request_file
from replay import replay_request
from runner import run_scan


def serialize_mutation_result(mutation, response, diagnostics, evaluation) -> dict:
    return {
        "test_type": "single_turn",
        "test_id": mutation.test_id,
        "name": mutation.name,
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


def command_baseline(args: argparse.Namespace) -> None:
    run_baseline(args.request)


def command_scan(args: argparse.Namespace) -> None:
    run_scan(args.request)


def command_single_turn(args: argparse.Namespace) -> None:
    parsed = parse_raw_request_file(args.request)

    if not parsed.is_json():
        raise ValueError("single-turn command requires a JSON request.")

    baseline_response, baseline_diag = replay_request(parsed)
    mutations = generate_mutations(parsed)

    results: list[dict] = []

    for mutation in mutations:
        response, diagnostics = replay_request(mutation.mutated_request)
        evaluation = evaluate_response(
            baseline_response=baseline_response,
            mutated_response=response,
            diagnostics=diagnostics,
        )
        results.append(
            serialize_mutation_result(
                mutation,
                response,
                diagnostics,
                evaluation,
            )
        )

    print(json.dumps(results, indent=2))


def command_multi_turn(args: argparse.Namespace) -> None:
    parsed = parse_raw_request_file(args.request)

    if not parsed.is_json():
        raise ValueError("multi-turn command requires a JSON request.")

    baseline_response, baseline_diag = replay_request(parsed)
    results = run_all_multi_turn_tests(parsed, baseline_response)
    serialized = [serialize_multi_turn_result(result) for result in results]

    print(json.dumps(serialized, indent=2))


def command_indirect(args: argparse.Namespace) -> None:
    parsed = parse_raw_request_file(args.request)

    is_multipart = bool(
        parsed.content_type and "multipart/form-data" in parsed.content_type.lower()
    )
    if not is_multipart:
        raise ValueError("indirect command requires a multipart/form-data request.")

    baseline_response, baseline_diag = replay_request(parsed)
    results = run_all_indirect_file_tests(
        base_request=parsed,
        baseline_response=baseline_response,
        output_dir=args.output_dir,
    )
    serialized = [serialize_indirect_result(result) for result in results]

    print(json.dumps(serialized, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AICU - LLM and agent security testing framework"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Run a baseline request and save the result",
    )
    baseline_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw HTTP request file",
    )
    baseline_parser.set_defaults(func=command_baseline)

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run full scan workflow",
    )
    scan_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw HTTP request file",
    )
    scan_parser.set_defaults(func=command_scan)

    # single-turn
    single_turn_parser = subparsers.add_parser(
        "single-turn",
        help="Run automated single-turn JSON mutations",
    )
    single_turn_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw HTTP request file",
    )
    single_turn_parser.set_defaults(func=command_single_turn)

    # multi-turn
    multi_turn_parser = subparsers.add_parser(
        "multi-turn",
        help="Run automated multi-turn JSON sequences",
    )
    multi_turn_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw HTTP request file",
    )
    multi_turn_parser.set_defaults(func=command_multi_turn)

    # indirect
    indirect_parser = subparsers.add_parser(
        "indirect",
        help="Run indirect file injection tests against a multipart request",
    )
    indirect_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw multipart HTTP request file",
    )
    indirect_parser.add_argument(
        "--output-dir",
        default="generated_files",
        help="Directory for generated test files",
    )
    indirect_parser.set_defaults(func=command_indirect)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()