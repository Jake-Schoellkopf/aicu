from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"YAML file {file_path} must contain a top-level mapping/object.")

    return data


def load_single_turn_payloads(path: str | Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    payload_sets = data.get("payload_sets", {})

    if not isinstance(payload_sets, dict):
        raise ValueError("single_turn.yaml must contain a 'payload_sets' mapping.")

    payloads: list[dict[str, Any]] = []

    for family_name, group_items in payload_sets.items():
        if not isinstance(group_items, list):
            raise ValueError(f"Payload group {family_name!r} must be a list.")

        for item in group_items:
            if not isinstance(item, dict):
                raise ValueError(f"Payload entry in group {family_name!r} must be an object.")

            normalized = dict(item)
            normalized.setdefault("family", family_name)
            payloads.append(normalized)

    return payloads


def load_multi_turn_payloads(path: str | Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    tests = data.get("multi_turn_tests", [])

    if not isinstance(tests, list):
        raise ValueError("multi_turn.yaml must contain a 'multi_turn_tests' list.")

    for item in tests:
        if not isinstance(item, dict):
            raise ValueError("Each multi-turn test must be an object.")

    return tests


def load_file_payloads(path: str | Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    payloads = data.get("file_payloads", [])

    if not isinstance(payloads, list):
        raise ValueError("file_payloads.yaml must contain a 'file_payloads' list.")

    for item in payloads:
        if not isinstance(item, dict):
            raise ValueError("Each file payload must be an object.")

    return payloads