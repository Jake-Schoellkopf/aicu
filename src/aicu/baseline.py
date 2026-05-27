from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .parsing import parse_raw_request_file
from .replay import replay_request


RUNS_DIR = Path("runs")


def generate_run_id() -> str:
    """Generate a timestamp-based run ID."""
    return datetime.now().strftime("run_%Y-%m-%d_%H-%M-%S")


def create_run_directory(run_id: str) -> Path:
    """Create a directory for the run."""
    run_path = RUNS_DIR / run_id
    run_path.mkdir(parents=True, exist_ok=True)
    return run_path


def serialize_parsed_request(parsed) -> dict:
    """Convert ParsedRequest into JSON-safe dict."""
    return {
        "method": parsed.method,
        "url": parsed.full_url(),
        "headers": parsed.headers,
        "cookies": parsed.cookies,
        "query_params": parsed.query_params,
        "content_type": parsed.content_type,
        "json_body": parsed.json_body,
        "mutation_points": parsed.mutation_points,
    }


def serialize_response(response) -> dict:
    """Convert ReplayResponse into JSON-safe dict."""
    return {
        "status_code": response.status_code,
        "headers": response.headers,
        "body_preview": response.text[:2000],  # limit size
        "elapsed_ms": response.elapsed_ms,
        "error": response.error,
    }


def serialize_diagnostics(diagnostics) -> dict:
    """Convert ReplayDiagnostics into dict."""
    return {
        "auth_issue": diagnostics.auth_issue,
        "csrf_issue": diagnostics.csrf_issue,
        "cookie_issue": diagnostics.cookie_issue,
        "likely_causes": diagnostics.likely_causes,
    }


def run_baseline(request_file: str) -> Path:
    """
    Execute baseline run:
    - parse request
    - replay it
    - save results
    """
    print(f"[+] Loading request from: {request_file}")

    parsed = parse_raw_request_file(request_file)

    print(f"[+] Target: {parsed.full_url()}")
    print(f"[+] Method: {parsed.method}")

    print("[+] Replaying baseline request...")
    response, diagnostics = replay_request(parsed)

    print(f"[+] Status: {response.status_code}")
    print(f"[+] Time: {response.elapsed_ms} ms")

    if diagnostics.likely_causes:
        print("[!] Diagnostics:")
        for cause in diagnostics.likely_causes:
            print(f"   - {cause}")

    run_id = generate_run_id()
    run_path = create_run_directory(run_id)

    baseline_data = {
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "request": serialize_parsed_request(parsed),
        "response": serialize_response(response),
        "diagnostics": serialize_diagnostics(diagnostics),
    }

    output_file = run_path / "baseline.json"
    output_file.write_text(json.dumps(baseline_data, indent=2))

    print(f"[+] Baseline saved to: {output_file}")

    return run_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AICU Baseline Runner")
    parser.add_argument("--request", required=True, help="Path to raw HTTP request file")

    args = parser.parse_args()

    run_baseline(args.request)