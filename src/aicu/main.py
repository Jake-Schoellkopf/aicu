#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .baseline import run_baseline
from .evaluator import evaluate_response
from .indirect_injection import run_all_indirect_file_tests, serialize_indirect_result
from .multi_turn import run_all_multi_turn_tests
from .mutations import generate_mutations
from .parsing import parse_raw_request_file
from .replay import replay_request
from .runner import run_scan
from .safety_bypass import run_all_safety_tests, serialize_safety_result
from .shared import serialize_mutation_result, serialize_multi_turn_result
from .target_profile import get_profile, apply_profile_to_request

# Exit codes for CI integration
EXIT_CLEAN = 0
EXIT_CONFIRMED = 1
EXIT_SUSPICIOUS = 2


def _apply_profile(parsed, args):
    """Apply target profile to request if specified."""
    if hasattr(args, "profile") and args.profile:
        profile = get_profile(args.profile)
        return apply_profile_to_request(parsed, profile)
    return parsed


def command_baseline(args: argparse.Namespace) -> None:
    run_baseline(args.request)


def command_scan(args: argparse.Namespace) -> int:
    run_path = run_scan(args.request)

    # Determine exit code from results
    results_file = run_path / "results.json"
    mt_file = run_path / "multi_turn_results.json"
    indirect_file = run_path / "indirect_results.json"

    has_confirmed = False
    has_suspicious = False

    for filepath in (results_file, mt_file, indirect_file):
        if not filepath.exists():
            continue
        data = json.loads(filepath.read_text(encoding="utf-8"))
        for result in data:
            outcome = result.get("evaluation", result.get("final_evaluation", {})).get("outcome", "none")
            if outcome == "confirmed":
                has_confirmed = True
            elif outcome == "suspicious":
                has_suspicious = True

    if has_confirmed:
        print(f"\n[!] EXIT CODE {EXIT_CONFIRMED}: Confirmed findings detected.")
        return EXIT_CONFIRMED
    if has_suspicious:
        print(f"\n[*] EXIT CODE {EXIT_SUSPICIOUS}: Suspicious findings only (no confirmed).")
        return EXIT_SUSPICIOUS

    print(f"\n[+] EXIT CODE {EXIT_CLEAN}: No findings.")
    return EXIT_CLEAN


def command_single_turn(args: argparse.Namespace) -> None:
    parsed = parse_raw_request_file(args.request)
    parsed = _apply_profile(parsed, args)

    if not parsed.is_json():
        raise ValueError("single-turn command requires a JSON request.")

    baseline_response, baseline_diag = replay_request(parsed)
    mutations = generate_mutations(parsed, best_of_n=args.best_of_n)

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
    parsed = _apply_profile(parsed, args)

    if not parsed.is_json():
        raise ValueError("multi-turn command requires a JSON request.")

    baseline_response, baseline_diag = replay_request(parsed)
    results = run_all_multi_turn_tests(parsed, baseline_response)
    serialized = [serialize_multi_turn_result(result) for result in results]

    print(json.dumps(serialized, indent=2))


def command_safety(args: argparse.Namespace) -> None:
    parsed = parse_raw_request_file(args.request)
    parsed = _apply_profile(parsed, args)

    if not parsed.is_json():
        raise ValueError("safety command requires a JSON request.")

    categories = None
    if args.category:
        categories = [args.category]

    results = run_all_safety_tests(parsed, categories=categories)
    serialized = [serialize_safety_result(result) for result in results]

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


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add common arguments shared across subcommands."""
    parser.add_argument(
        "--profile",
        default=None,
        help="Target profile (preset name or path to YAML). Presets: openai, anthropic, azure_openai, generic",
    )


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
    single_turn_parser.add_argument(
        "--best-of-n",
        type=int,
        default=5,
        help="Number of best-of-N repetitions per seed payload (default: 5)",
    )
    _add_common_args(single_turn_parser)
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
    _add_common_args(multi_turn_parser)
    multi_turn_parser.set_defaults(func=command_multi_turn)

    # safety
    safety_parser = subparsers.add_parser(
        "safety",
        help="Run safety bypass, harmful content, and unauthorized action tests",
    )
    safety_parser.add_argument(
        "--request",
        required=True,
        help="Path to raw HTTP request file",
    )
    safety_parser.add_argument(
        "--category",
        choices=["safety_bypass", "harmful_content", "unauthorized_action"],
        default=None,
        help="Run only a specific test category (default: all)",
    )
    _add_common_args(safety_parser)
    safety_parser.set_defaults(func=command_safety)

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
    result = args.func(args)
    if isinstance(result, int):
        sys.exit(result)


if __name__ == "__main__":
    main()