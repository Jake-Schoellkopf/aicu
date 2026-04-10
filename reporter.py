from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path


def classify_single_turn_findings(results: list[dict]) -> dict[str, list[dict]]:
    confirmed: list[dict] = []
    suspicious: list[dict] = []
    none: list[dict] = []

    for result in results:
        outcome = result["evaluation"]["outcome"]

        if outcome == "confirmed":
            confirmed.append(result)
        elif outcome == "suspicious":
            suspicious.append(result)
        else:
            none.append(result)

    return {
        "confirmed": confirmed,
        "suspicious": suspicious,
        "none": none,
    }


def classify_multi_turn_findings(results: list[dict]) -> dict[str, list[dict]]:
    confirmed: list[dict] = []
    suspicious: list[dict] = []
    none: list[dict] = []

    for result in results:
        outcome = result["final_evaluation"]["outcome"]

        if outcome == "confirmed":
            confirmed.append(result)
        elif outcome == "suspicious":
            suspicious.append(result)
        else:
            none.append(result)

    return {
        "confirmed": confirmed,
        "suspicious": suspicious,
        "none": none,
    }


def classify_indirect_findings(results: list[dict]) -> dict[str, list[dict]]:
    confirmed: list[dict] = []
    suspicious: list[dict] = []
    none: list[dict] = []

    for result in results:
        outcome = result["evaluation"]["outcome"]

        if outcome == "confirmed":
            confirmed.append(result)
        elif outcome == "suspicious":
            suspicious.append(result)
        else:
            none.append(result)

    return {
        "confirmed": confirmed,
        "suspicious": suspicious,
        "none": none,
    }


def summarize_single_turn_families(results: list[dict]) -> list[str]:
    counter = Counter()
    for result in results:
        family = result.get("family", "unknown")
        outcome = result["evaluation"]["outcome"]
        counter[f"{family}:{outcome}"] += 1

    lines: list[str] = []
    for key, count in sorted(counter.items()):
        lines.append(f"- {key} = {count}")
    return lines


def generate_markdown_report(
    run_path: Path,
    single_turn_results: list[dict],
    multi_turn_results: list[dict],
    indirect_results: list[dict],
) -> Path:
    st = classify_single_turn_findings(single_turn_results)
    mt = classify_multi_turn_findings(multi_turn_results)
    ind = classify_indirect_findings(indirect_results)

    total_confirmed = len(st["confirmed"]) + len(mt["confirmed"]) + len(ind["confirmed"])
    total_suspicious = len(st["suspicious"]) + len(mt["suspicious"]) + len(ind["suspicious"])
    total_tests = len(single_turn_results) + len(multi_turn_results) + len(indirect_results)

    lines: list[str] = []

    lines.append("# AICU Scan Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Total tests: {total_tests}")
    lines.append(f"- Confirmed findings: {total_confirmed}")
    lines.append(f"- Suspicious findings: {total_suspicious}")
    lines.append(f"- Single-turn tests: {len(single_turn_results)}")
    lines.append(f"- Multi-turn tests: {len(multi_turn_results)}")
    lines.append(f"- Indirect file tests: {len(indirect_results)}")
    lines.append("")

    if single_turn_results:
        lines.append("## Single-Turn Family Summary")
        lines.extend(summarize_single_turn_families(single_turn_results))
        lines.append("")

    if st["confirmed"]:
        lines.append("## Confirmed Findings — Single-Turn")
        lines.append("")

        for finding in st["confirmed"]:
            evaluation = finding["evaluation"]

            lines.append(f"### [HIGH] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Variant ID: `{finding.get('variant_id', '')}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Family: `{finding.get('family', 'unknown')}`")
            lines.append(f"Transformation: `{finding.get('transformation_type', 'unknown')}`")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Evidence:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

    if mt["confirmed"]:
        lines.append("## Confirmed Findings — Multi-Turn")
        lines.append("")

        for finding in mt["confirmed"]:
            evaluation = finding["final_evaluation"]

            lines.append(f"### [HIGH] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Evidence:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

            lines.append("Turn Sequence:")
            for step in finding["steps"]:
                lines.append(f"- Step {step['step_number']}: {step['prompt']}")
            lines.append("")

    if ind["confirmed"]:
        lines.append("## Confirmed Findings — Indirect File Injection")
        lines.append("")

        for finding in ind["confirmed"]:
            evaluation = finding["evaluation"]

            lines.append(f"### [HIGH] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Injected File: `{finding['injected_filename']}`")
            lines.append(f"File Type: `{finding['file_type']}`")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Evidence:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

    if st["suspicious"]:
        lines.append("## Suspicious Findings — Single-Turn")
        lines.append("")

        for finding in st["suspicious"]:
            evaluation = finding["evaluation"]

            lines.append(f"### [MEDIUM] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Variant ID: `{finding.get('variant_id', '')}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Family: `{finding.get('family', 'unknown')}`")
            lines.append(f"Transformation: `{finding.get('transformation_type', 'unknown')}`")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Indicators:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

    if mt["suspicious"]:
        lines.append("## Suspicious Findings — Multi-Turn")
        lines.append("")

        for finding in mt["suspicious"]:
            evaluation = finding["final_evaluation"]

            lines.append(f"### [MEDIUM] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Indicators:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

            lines.append("Turn Sequence:")
            for step in finding["steps"]:
                lines.append(f"- Step {step['step_number']}: {step['prompt']}")
            lines.append("")

    if ind["suspicious"]:
        lines.append("## Suspicious Findings — Indirect File Injection")
        lines.append("")

        for finding in ind["suspicious"]:
            evaluation = finding["evaluation"]

            lines.append(f"### [MEDIUM] {evaluation['title']}")
            lines.append(f"Test ID: `{finding['test_id']}`")
            lines.append(f"Scenario: {finding['name']}")
            lines.append(f"Injected File: `{finding['injected_filename']}`")
            lines.append(f"File Type: `{finding['file_type']}`")
            lines.append(f"Confidence: {evaluation['confidence']}")
            lines.append("")
            lines.append(f"Reason: {evaluation['reason']}")
            lines.append("")

            if evaluation["evidence"]:
                lines.append("Indicators:")
                for item in evaluation["evidence"]:
                    lines.append(f"- `{item}`")
                lines.append("")

    if total_confirmed == 0 and total_suspicious == 0:
        lines.append("## No Findings")
        lines.append("No confirmed or suspicious issues detected.")
        lines.append("")

    report_path = run_path / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    return report_path