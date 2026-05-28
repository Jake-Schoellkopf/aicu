from __future__ import annotations

import copy
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path

from .models import ParsedRequest
from .payload_loader import load_single_turn_payloads
from .shared import clone_request, rebuild_json_request


_PATH_TOKEN_RE = re.compile(
    r"""
    ([^.\[\]]+)
    |
    \[(\d+)\]
    """,
    re.VERBOSE,
)

from aicu import PAYLOADS_DIR

DEFAULT_SINGLE_TURN_PAYLOADS_PATH = PAYLOADS_DIR / "single_turn.yaml"
DEFAULT_BEST_OF_N = 5


@dataclass(slots=True)
class MutationResult:
    test_id: str
    name: str
    family: str
    variant_id: str
    transformation_type: str
    mutation_point: str
    mode: str
    mutated_request: ParsedRequest


def parse_path_tokens(path: str) -> list[str | int]:
    tokens: list[str | int] = []

    for match in _PATH_TOKEN_RE.finditer(path):
        key, index = match.groups()
        if key is not None:
            tokens.append(key)
        elif index is not None:
            tokens.append(int(index))

    if not tokens:
        raise ValueError(f"Invalid mutation path: {path!r}")

    return tokens


def get_value_at_path(data: object, path: str) -> object:
    current = data

    for token in parse_path_tokens(path):
        if isinstance(token, int):
            if not isinstance(current, list):
                raise TypeError(f"Expected list while resolving index {token} in {path!r}")
            current = current[token]
        else:
            if not isinstance(current, dict):
                raise TypeError(f"Expected dict while resolving key {token!r} in {path!r}")
            current = current[token]

    return current


def set_value_at_path(data: object, path: str, new_value: object) -> None:
    tokens = parse_path_tokens(path)
    current = data

    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(current, list):
                raise TypeError(f"Expected list while resolving index {token} in {path!r}")
            current = current[token]
        else:
            if not isinstance(current, dict):
                raise TypeError(f"Expected dict while resolving key {token!r} in {path!r}")
            current = current[token]

    last = tokens[-1]

    if isinstance(last, int):
        if not isinstance(current, list):
            raise TypeError(f"Expected list while setting index {last} in {path!r}")
        current[last] = new_value
    else:
        if not isinstance(current, dict):
            raise TypeError(f"Expected dict while setting key {last!r} in {path!r}")
        current[last] = new_value


def mutate_request(
    request: ParsedRequest,
    payload: str,
    mutation_point: str,
    mode: str,
) -> ParsedRequest:
    mutated = clone_request(request)

    if mutated.json_body is None:
        raise ValueError("Request content-type is JSON but json_body is missing")

    current_value = get_value_at_path(mutated.json_body, mutation_point)

    if not isinstance(current_value, str):
        raise TypeError(f"Mutation target is not a string at {mutation_point!r}")

    if mode == "replace":
        new_value = payload
    elif mode == "append":
        new_value = f"{current_value}\n{payload}"
    else:
        raise ValueError(f"Invalid mode: {mode!r}")

    set_value_at_path(mutated.json_body, mutation_point, new_value)
    rebuild_json_request(mutated)

    return mutated


def build_best_of_n_payloads(
    payload_defs: list[dict],
    best_of_n: int,
) -> list[dict]:
    """
    Expand the best_of_n_seed family into repeated safe variants.
    """
    expanded: list[dict] = []

    for payload_def in payload_defs:
        family = str(payload_def.get("family", "unknown"))
        if family != "best_of_n_seed_set":
            expanded.append(payload_def)
            continue

        for index in range(1, best_of_n + 1):
            variant = dict(payload_def)
            variant["variant_id"] = f"{payload_def.get('variant_id', 'BON')}-R{index}"
            variant["name"] = f"{payload_def.get('name', 'best_of_n_seed')}_r{index}"
            expanded.append(variant)

    random.shuffle(expanded)
    return expanded


def generate_mutations(
    request: ParsedRequest,
    payloads_path: str | Path = DEFAULT_SINGLE_TURN_PAYLOADS_PATH,
    best_of_n: int = DEFAULT_BEST_OF_N,
) -> list[MutationResult]:
    """
    Fully automated mutation generator using YAML payloads.
    """
    if not request.is_json():
        raise ValueError("Only JSON requests supported in V1")

    if request.json_body is None:
        raise ValueError("JSON request is missing parsed json_body")

    if not request.mutation_points:
        raise ValueError("No mutation points detected in request")

    payload_defs = load_single_turn_payloads(payloads_path)
    payload_defs = build_best_of_n_payloads(payload_defs, best_of_n)

    results: list[MutationResult] = []

    for point in request.mutation_points:
        for payload_def in payload_defs:
            payload_text = str(payload_def["content"])
            payload_mode = str(payload_def["mode"])
            payload_id = str(payload_def["id"])
            payload_name = str(payload_def["name"])
            family = str(payload_def.get("family", "unknown"))
            variant_id = str(payload_def.get("variant_id", payload_id))
            transformation_type = str(payload_def.get("transformation_type", "unknown"))

            try:
                mutated = mutate_request(
                    request=request,
                    payload=payload_text,
                    mutation_point=point,
                    mode=payload_mode,
                )

                results.append(
                    MutationResult(
                        test_id=payload_id,
                        name=payload_name,
                        family=family,
                        variant_id=variant_id,
                        transformation_type=transformation_type,
                        mutation_point=point,
                        mode=payload_mode,
                        mutated_request=mutated,
                    )
                )
            except Exception:
                continue

    return results