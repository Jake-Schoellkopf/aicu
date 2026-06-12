from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .baseline import create_run_directory, generate_run_id
from .dynamic_payloads import generate_dynamic_payloads
from .evaluator import evaluate_response, extract_model_output
from .live_dashboard import emit_event, start_dashboard, stop_dashboard
from .llm_judge import judge_evaluation
from .evidence import (
    save_all_evidence,
    save_all_multi_turn_evidence,
    save_all_indirect_evidence,
)
from .html_reporter import generate_html_report
from .indirect_injection import (
    run_all_indirect_file_tests,
    serialize_indirect_result,
)
from .multi_turn import run_all_multi_turn_tests
from .mutations import generate_mutations
from .parsing import parse_raw_request_file
from .replay import replay_request
from .reporter import generate_markdown_report
from .shared import serialize_mutation_result, serialize_multi_turn_result


def run_scan(request_file: str, canary: str | None = None, llm_judge: bool = False, judge_model: str = "gpt-4o-mini", live: bool = False) -> Path:
    dashboard_server = None
    if live:
        print("[+] Starting live dashboard at http://localhost:4171")
        dashboard_server = start_dashboard()

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

        # Dynamic payload generation if LLM judge is enabled
        if llm_judge:
            print("[+] Generating dynamic LLM-crafted payloads...")
            baseline_text = extract_model_output(baseline_response.text) if baseline_response.text else ""
            dynamic_defs = generate_dynamic_payloads(baseline_text, count=15, model=judge_model)
            if dynamic_defs:
                from .mutations import mutate_request, MutationResult
                for pdef in dynamic_defs:
                    for point in parsed.mutation_points:
                        try:
                            mutated_req = mutate_request(parsed, pdef["content"], point, "replace")
                            mutations.append(MutationResult(
                                test_id=pdef["id"],
                                name=pdef["name"],
                                family=pdef["family"],
                                variant_id=pdef["variant_id"],
                                transformation_type=pdef["transformation_type"],
                                mutation_point=point,
                                mode="replace",
                                mutated_request=mutated_req,
                            ))
                        except Exception:
                            continue
                print(f"[+] Dynamic payloads added: {len(dynamic_defs)}")

        print(f"[+] Total single-turn mutations: {len(mutations)}")
        if live:
            emit_event({"type": "scan_start", "total_mutations": len(mutations)})

        for i, mutation in enumerate(mutations, start=1):
            response, diagnostics = replay_request(mutation.mutated_request)
            evaluation = evaluate_response(
                baseline_response=baseline_response,
                mutated_response=response,
                diagnostics=diagnostics,
            )

            # Canary detection — override to confirmed if canary found in response
            if canary and response.text and canary in response.text:
                evaluation = type(evaluation)(
                    outcome="confirmed",
                    title="CANARY EXTRACTED — secret leaked in response",
                    confidence="high",
                    reason=f"The planted canary '{canary}' was found in the model's response. This proves the system prompt can be extracted.",
                    evidence=[f"Canary value '{canary}' present in response"],
                )

            # LLM Judge — second-pass on suspicious findings
            if llm_judge and evaluation.outcome == "suspicious":
                from .mutations import get_value_at_path
                _payload = ""
                if mutation.mutated_request.json_body:
                    _val = get_value_at_path(mutation.mutated_request.json_body, mutation.mutation_point)
                    if isinstance(_val, str):
                        _payload = _val
                _resp_text = extract_model_output(response.text) if response.text else ""
                _base_text = extract_model_output(baseline_response.text) if baseline_response.text else ""
                evaluation = judge_evaluation(evaluation, _payload, _resp_text, _base_text, model=judge_model)

            result = serialize_mutation_result(
                mutation,
                response,
                diagnostics,
                evaluation,
            )
            single_turn_results.append(result)

            # Live output with evidence
            outcome = evaluation.outcome
            tag = "CONFIRMED" if outcome == "confirmed" else "SUSPICIOUS" if outcome == "suspicious" else "CLEAN"
            print(f"[+] [{i}/{len(mutations)}] {mutation.variant_id} {mutation.name}")
            print(f"    [{tag}] {evaluation.title} (confidence: {evaluation.confidence})")
            if mutation.mutated_request.json_body:
                from .mutations import get_value_at_path
                payload_text = get_value_at_path(mutation.mutated_request.json_body, mutation.mutation_point)
                if isinstance(payload_text, str) and len(payload_text) > 0:
                    preview = payload_text[:80] + ("..." if len(payload_text) > 80 else "")
                    print(f"    Payload:  \"{preview}\"")
            if response.text and not response.error:
                model_output = extract_model_output(response.text)
                resp_preview = model_output[:200].replace("\n", " ")
                print(f"    Response: \"{resp_preview}\"")
            if evaluation.reason and outcome != "none":
                print(f"    Reason:   {evaluation.reason[:120]}")
            # Show leaked secrets/canary for confirmed findings
            if outcome == "confirmed" and response.text:
                _model_out = extract_model_output(response.text)
                if canary and canary in _model_out:
                    print(f"    \033[91m*** CANARY LEAKED: \"{canary}\" found in response ***\033[0m")
            # Emit live dashboard event
            if live:
                from .mutations import get_value_at_path
                _p = ""
                if mutation.mutated_request.json_body:
                    _v = get_value_at_path(mutation.mutated_request.json_body, mutation.mutation_point)
                    if isinstance(_v, str):
                        _p = _v
                _r = extract_model_output(response.text) if response.text and not response.error else ""
                emit_event({
                    "type": "result",
                    "index": i,
                    "variant_id": mutation.variant_id,
                    "name": mutation.name,
                    "transformation_type": mutation.transformation_type,
                    "outcome": outcome,
                    "confidence": evaluation.confidence,
                    "payload": _p,
                    "payload_preview": _p[:120],
                    "response": _r,
                    "reason": evaluation.reason or "",
                    "canary_leaked": bool(canary and response.text and canary in extract_model_output(response.text)),
                })
            print()
    else:
        print("[*] Skipping single-turn tests (request is not JSON).")

    multi_turn_results: list[dict] = []
    if parsed.is_json():
        print("[+] Running multi-turn sequences...")
        if live:
            emit_event({"type": "phase", "message": "Running multi-turn sequences..."})
        multi_turn_runs = run_all_multi_turn_tests(parsed, baseline_response)
        print(f"[+] Total multi-turn sequences: {len(multi_turn_runs)}")
        for result in multi_turn_runs:
            # LLM Judge for multi-turn suspicious findings
            if llm_judge and result.final_evaluation and result.final_evaluation.outcome == "suspicious":
                last_step = result.steps[-1] if result.steps else None
                _resp_text = extract_model_output(last_step.response.text) if last_step and last_step.response.text else ""
                _base_text = extract_model_output(baseline_response.text) if baseline_response.text else ""
                _payload = last_step.prompt if last_step else ""
                result.final_evaluation = judge_evaluation(result.final_evaluation, _payload, _resp_text, _base_text, model=judge_model)

            serialized = serialize_multi_turn_result(result)
            multi_turn_results.append(serialized)
            outcome = serialized["final_evaluation"]["outcome"]
            tag = "CONFIRMED" if outcome == "confirmed" else "SUSPICIOUS" if outcome == "suspicious" else "CLEAN"
            print(f"    [MT] {result.name}")
            print(f"         [{tag}] {serialized['final_evaluation']['title']} (confidence: {serialized['final_evaluation']['confidence']})")
            if serialized["final_evaluation"]["reason"] and outcome != "none":
                print(f"         Reason: {serialized['final_evaluation']['reason'][:120]}")
            # Show last turn response
            if serialized.get("steps"):
                last_step = serialized["steps"][-1]
                if last_step.get("response_text"):
                    resp_preview = last_step["response_text"][:200].replace("\n", " ")
                    print(f"         Response: \"{resp_preview}\"")
            print()
    else:
        print("[*] Skipping multi-turn tests (request is not JSON).")

    # TAP (Tree of Attacks with Pruning) — only when LLM judge is enabled
    tap_results: list[dict] = []
    if parsed.is_json() and llm_judge:
        from .tap import run_tap
        print("[+] Running TAP (Tree of Attacks with Pruning)...")
        tap_result = run_tap(base_request=parsed, baseline_response=baseline_response, model=judge_model)
        print(f"    [TAP] Depth: {tap_result.max_depth_reached}, Queries: {tap_result.total_queries}, Best score: {tap_result.best_score}/10")
        if tap_result.evaluation:
            tag = "CONFIRMED" if tap_result.evaluation.outcome == "confirmed" else "SUSPICIOUS"
            print(f"    [{tag}] {tap_result.evaluation.title}")
            if tap_result.successful_prompt:
                print(f"    Winning prompt: \"{tap_result.successful_prompt[:100]}\"")
            if tap_result.successful_response:
                print(f"    Response: \"{tap_result.successful_response[:200]}\"")
            tap_results.append({
                "test_type": "tap",
                "test_id": "TAP-001",
                "name": "tree_of_attacks",
                "objective": tap_result.objective,
                "best_score": tap_result.best_score,
                "total_queries": tap_result.total_queries,
                "max_depth_reached": tap_result.max_depth_reached,
                "successful_prompt": tap_result.successful_prompt,
                "evaluation": {
                    "outcome": tap_result.evaluation.outcome,
                    "title": tap_result.evaluation.title,
                    "confidence": tap_result.evaluation.confidence,
                    "reason": tap_result.evaluation.reason,
                    "evidence": tap_result.evaluation.evidence,
                },
            })
        else:
            print("    [CLEAN] TAP did not achieve objective.")
        print()

    # PAIR (Prompt Automatic Iterative Refinement)
    if parsed.is_json() and llm_judge:
        from .pair import run_pair
        print("[+] Running PAIR (Prompt Automatic Iterative Refinement)...")
        pair_result = run_pair(base_request=parsed, baseline_response=baseline_response, max_iterations=20, model=judge_model)
        print(f"    [PAIR] Iterations: {pair_result.iterations}, Queries: {pair_result.total_queries}, Best score: {pair_result.best_score}/10")
        if pair_result.evaluation:
            tag = "CONFIRMED" if pair_result.evaluation.outcome == "confirmed" else "SUSPICIOUS"
            print(f"    [{tag}] {pair_result.evaluation.title}")
            if pair_result.winning_prompt:
                print(f"    Winning prompt: \"{pair_result.winning_prompt[:100]}\"")
            tap_results.append({
                "test_type": "pair",
                "test_id": "PAIR-001",
                "name": "pair_iterative_refinement",
                "best_score": pair_result.best_score,
                "total_queries": pair_result.total_queries,
                "iterations": pair_result.iterations,
                "successful_prompt": pair_result.winning_prompt,
                "evaluation": {
                    "outcome": pair_result.evaluation.outcome,
                    "title": pair_result.evaluation.title,
                    "confidence": pair_result.evaluation.confidence,
                    "reason": pair_result.evaluation.reason,
                    "evidence": pair_result.evaluation.evidence,
                },
            })
        else:
            print("    [CLEAN] PAIR did not achieve objective.")
        print()

    # Crescendo (progressive multi-turn escalation)
    if parsed.is_json() and llm_judge:
        from .crescendo import run_crescendo
        print("[+] Running Crescendo (progressive multi-turn escalation)...")
        crescendo_result = run_crescendo(base_request=parsed, baseline_response=baseline_response, max_turns=12, model=judge_model)
        print(f"    [CRESCENDO] Turns: {crescendo_result.turns_used}, Queries: {crescendo_result.total_queries}, Success: {crescendo_result.success}")
        if crescendo_result.evaluation:
            tag = "CONFIRMED" if crescendo_result.evaluation.outcome == "confirmed" else "SUSPICIOUS"
            print(f"    [{tag}] {crescendo_result.evaluation.title}")
            if crescendo_result.final_response:
                print(f"    Response: \"{crescendo_result.final_response[:200]}\"")
            tap_results.append({
                "test_type": "crescendo",
                "test_id": "CRESC-001",
                "name": "crescendo_escalation",
                "turns_used": crescendo_result.turns_used,
                "total_queries": crescendo_result.total_queries,
                "success": crescendo_result.success,
                "evaluation": {
                    "outcome": crescendo_result.evaluation.outcome,
                    "title": crescendo_result.evaluation.title,
                    "confidence": crescendo_result.evaluation.confidence,
                    "reason": crescendo_result.evaluation.reason,
                    "evidence": crescendo_result.evaluation.evidence,
                },
            })
        else:
            print("    [CLEAN] Crescendo did not achieve objective.")
        print()

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

    print(f"[+] Reports saved to: {run_path}")

    # Print summary
    all_results = single_turn_results + multi_turn_results + indirect_results + tap_results
    confirmed_results = [r for r in all_results if r.get("evaluation", r.get("final_evaluation", {})).get("outcome") == "confirmed"]
    suspicious_count = sum(1 for r in all_results if r.get("evaluation", r.get("final_evaluation", {})).get("outcome") == "suspicious")
    clean = len(all_results) - len(confirmed_results) - suspicious_count
    print()
    print("=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print()
    print(f"  Confirmed:  {len(confirmed_results)}")
    print(f"  Suspicious: {suspicious_count}")
    print(f"  Clean:      {clean}")
    print()

    # Real findings breakdown — show what was actually leaked
    if confirmed_results:
        print("-" * 60)
        print("  CONFIRMED FINDINGS DETAIL")
        print("-" * 60)
        print()
        for r in confirmed_results:
            eval_data = r.get("evaluation", r.get("final_evaluation", {}))
            name = r.get("name", r.get("test_id", "unknown"))
            variant = r.get("variant_id", "")
            technique = r.get("transformation_type", r.get("test_type", ""))
            resp_text = r.get("response_text", "")
            if not resp_text and r.get("response", {}).get("body_preview"):
                resp_text = r["response"]["body_preview"]

            print(f"  [{variant}] {name}")
            print(f"    Technique: {technique}")
            print(f"    Title:     {eval_data.get('title', '')}")
            if canary and canary.lower() in resp_text.lower():
                print(f"    \033[91m*** CANARY \"{canary}\" EXTRACTED ***\033[0m")
            if eval_data.get("reason"):
                print(f"    Reason:    {eval_data['reason'][:150]}")
            print()

    print(f"  Evidence saved: {run_path / 'evidence'}")
    print(f"  HTML report:    {run_path / 'report.html'}")
    print(f"  JSON results:   {single_turn_file}")
    print()

    if live:
        emit_event({"type": "scan_complete", "confirmed": len(confirmed_results), "suspicious": suspicious_count, "clean": clean})
        print("[+] Live dashboard remains open. Press Ctrl+C to exit.")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            if dashboard_server:
                stop_dashboard(dashboard_server)

    return run_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AICU Scanner")
    parser.add_argument("--request", required=True, help="Path to raw HTTP request")

    args = parser.parse_args()

    run_scan(args.request)