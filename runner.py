from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from baseline import create_run_directory, generate_run_id
from evaluator import evaluate_response
from evidence import (
    save_all_evidence,
    save_all_multi_turn_evidence,
    save_all_indirect_evidence,
)
from html_reporter import generate_html_report
from indirect_injection import (
    run_all_indirect_file_tests,
    serialize_indirect_result,
)
from multi_turn import run_all_multi_turn_tests
from mutations import generate_mutations
from parsing import parse_raw_request_file
from replay import replay_request
from reporter import generate_markdown_report
from shared import serialize_mutation_result, serialize_multi_turn_result


def run_scan(request_file: str) -> Path:
    print(f"[+] Loading request: {request_file}")

    parsed = parse_raw_request_file(request_file)

    run_id = generate_run_id()
    run_path = create_run_directory(run_id)

    print(f"[+] Run ID: {run_id}")
    print(f"[+] Target: {parsed.full_url()}")

    print("[+] Running baseline...")
    baseline_response, baseline_diag = replay_request(parsed)

    baseline_data = {
        "timestamp": datetime.now().isoformat(),
        "status_code": baseline_response.status_code,
        "body_preview": baseline_response.text[:2000],
        "diagnostics": baseline_diag.likely_causes,
    }
    (run_path / "baseline.json").write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")

    single_turn_results: list[dict] = []
    if parsed.is_json():
        print("[+] Generating single-turn mutations...")
        mutations = generate_mutations(parsed)
        print(f"[+] Total single-turn mutations: {len(mutations)}")

        for i, mutation in enumerate(mutations, start=1):
            print(f"[+] [ST {i}/{len(mutations)}] Running: {mutation.variant_id} - {mutation.name}")

            response, diagnostics = replay_request(mutation.mutated_request)
            evaluation = evaluate_response(
                baseline_response=baseline_response,
                mutated_response=response,
                diagnostics=diagnostics,
            )

            result = serialize_mutation_result(
                mutation,
                response,
                diagnostics,
                evaluation,
            )
            single_turn_results.append(result)
    else:
        print("[*] Skipping single-turn tests (request is not JSON).")

    multi_turn_results: list[dict] = []
    if parsed.is_json():
        print("[+] Running multi-turn sequences...")
        multi_turn_runs = run_all_multi_turn_tests(parsed, baseline_response)
        print(f"[+] Total multi-turn sequences: {len(multi_turn_runs)}")
        multi_turn_results = [serialize_multi_turn_result(result) for result in multi_turn_runs]
    else:
        print("[*] Skipping multi-turn tests (request is not JSON).")

    indirect_results: list[dict] = []
    is_multipart = bool(
        parsed.content_type and "multipart/form-data" in parsed.content_type.lower()
    )
    if is_multipart:
        print("[+] Running indirect file injection tests...")
        indirect_runs = run_all_indirect_file_tests(parsed, baseline_response)
        indirect_results = [serialize_indirect_result(result) for result in indirect_runs]
        print(f"[+] Total indirect file tests: {len(indirect_results)}")
    else:
        print("[*] Skipping indirect file tests (request is not multipart/form-data).")

    single_turn_file = run_path / "results.json"
    multi_turn_file = run_path / "multi_turn_results.json"
    indirect_file = run_path / "indirect_results.json"

    single_turn_file.write_text(json.dumps(single_turn_results, indent=2), encoding="utf-8")
    multi_turn_file.write_text(json.dumps(multi_turn_results, indent=2), encoding="utf-8")
    indirect_file.write_text(json.dumps(indirect_results, indent=2), encoding="utf-8")

    save_all_evidence(run_path, single_turn_results)
    save_all_multi_turn_evidence(run_path, multi_turn_results)
    save_all_indirect_evidence(run_path, indirect_results)

    report_path = generate_markdown_report(
        run_path=run_path,
        single_turn_results=single_turn_results,
        multi_turn_results=multi_turn_results,
        indirect_results=indirect_results,
    )

    html_report_path = generate_html_report(
        run_path=run_path,
        single_turn_results=single_turn_results,
        multi_turn_results=multi_turn_results,
        indirect_results=indirect_results,
    )

    print(f"[+] Single-turn results saved to: {single_turn_file}")
    print(f"[+] Multi-turn results saved to: {multi_turn_file}")
    print(f"[+] Indirect results saved to: {indirect_file}")
    print(f"[+] Report generated: {report_path}")
    print(f"[+] HTML report generated: {html_report_path}")

    return run_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AICU Scanner")
    parser.add_argument("--request", required=True, help="Path to raw HTTP request")

    args = parser.parse_args()

    run_scan(args.request)