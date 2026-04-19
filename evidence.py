from __future__ import annotations

import json
from pathlib import Path


def save_evidence(
    run_path: Path,
    mutation_index: int,
    mutation_result: dict,
) -> Path:
    """
    Save a single single-turn mutation result as an evidence file.
    """
    evidence_dir = run_path / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    test_id = mutation_result.get("test_id", "unknown")
    filename = f"{test_id}_{mutation_index}.json"

    file_path = evidence_dir / filename
    file_path.write_text(json.dumps(mutation_result, indent=2), encoding="utf-8")

    return file_path


def save_all_evidence(run_path: Path, results: list[dict]) -> None:
    """
    Save all single-turn mutation results as individual evidence files.
    """
    for i, result in enumerate(results, start=1):
        save_evidence(run_path, i, result)


def save_multi_turn_evidence(
    run_path: Path,
    run_index: int,
    multi_turn_result: dict,
) -> Path:
    """
    Save one multi-turn run result as an evidence file.
    """
    evidence_dir = run_path / "multi_turn_evidence"
    evidence_dir.mkdir(exist_ok=True)

    test_id = multi_turn_result.get("test_id", "unknown")
    filename = f"{test_id}_{run_index}.json"

    file_path = evidence_dir / filename
    file_path.write_text(json.dumps(multi_turn_result, indent=2), encoding="utf-8")

    return file_path


def save_all_multi_turn_evidence(run_path: Path, results: list[dict]) -> None:
    """
    Save all multi-turn results as individual evidence files.
    """
    for i, result in enumerate(results, start=1):
        save_multi_turn_evidence(run_path, i, result)


def save_indirect_evidence(
    run_path: Path,
    run_index: int,
    indirect_result: dict,
) -> Path:
    """
    Save one indirect file injection result as an evidence file.
    """
    evidence_dir = run_path / "indirect_evidence"
    evidence_dir.mkdir(exist_ok=True)

    test_id = indirect_result.get("test_id", "unknown")
    filename = f"{test_id}_{run_index}.json"

    file_path = evidence_dir / filename
    file_path.write_text(json.dumps(indirect_result, indent=2), encoding="utf-8")

    return file_path


def save_all_indirect_evidence(run_path: Path, results: list[dict]) -> None:
    """
    Save all indirect file injection results as individual evidence files.
    """
    for i, result in enumerate(results, start=1):
        save_indirect_evidence(run_path, i, result)