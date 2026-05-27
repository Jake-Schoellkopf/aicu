"""
Custom target profile system.
Handles response format extraction, auth refresh, and conversation ID threading.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from .models import ParsedRequest, ReplayResponse


@dataclass
class TargetProfile:
    """Configuration for a specific target API."""
    name: str = "generic"

    # Response extraction: JSON path to the model's actual output
    # e.g., "choices[0].message.content" for OpenAI
    response_path: str = ""

    # Conversation ID: field name in response that contains thread/conversation ID
    conversation_id_field: str = ""
    # Where to inject conversation ID in subsequent requests (JSON path in request body)
    conversation_id_inject: str = ""

    # Auth refresh configuration
    auth_refresh_url: str = ""
    auth_refresh_method: str = "POST"
    auth_refresh_body: str = ""
    auth_refresh_token_path: str = ""  # JSON path in refresh response to extract new token
    auth_header_format: str = "Bearer {token}"  # How to format the Authorization header

    # Rate limiting
    request_delay_ms: int = 0  # Delay between requests in milliseconds
    max_retries: int = 3

    # Request customization
    extra_headers: dict[str, str] = field(default_factory=dict)


# --- Built-in presets ---

PRESETS: dict[str, TargetProfile] = {
    "openai": TargetProfile(
        name="openai",
        response_path="choices[0].message.content",
        request_delay_ms=100,
    ),
    "anthropic": TargetProfile(
        name="anthropic",
        response_path="content[0].text",
        extra_headers={"anthropic-version": "2023-06-01"},
        request_delay_ms=100,
    ),
    "azure_openai": TargetProfile(
        name="azure_openai",
        response_path="choices[0].message.content",
        request_delay_ms=200,
    ),
    "generic": TargetProfile(
        name="generic",
        response_path="",
    ),
}


def load_profile(path: str | Path) -> TargetProfile:
    """Load a target profile from a YAML file."""
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Profile file {path} must contain a YAML mapping.")

    # Check if it references a preset
    preset_name = data.get("preset")
    if preset_name and preset_name in PRESETS:
        profile = PRESETS[preset_name]
    else:
        profile = TargetProfile()

    # Override with any specified fields
    for field_name in (
        "name", "response_path", "conversation_id_field",
        "conversation_id_inject", "auth_refresh_url", "auth_refresh_method",
        "auth_refresh_body", "auth_refresh_token_path", "auth_header_format",
        "request_delay_ms", "max_retries",
    ):
        if field_name in data:
            setattr(profile, field_name, data[field_name])

    if "extra_headers" in data and isinstance(data["extra_headers"], dict):
        profile.extra_headers = data["extra_headers"]

    return profile


def get_profile(name_or_path: str) -> TargetProfile:
    """Get a profile by preset name or file path."""
    if name_or_path in PRESETS:
        return PRESETS[name_or_path]

    path = Path(name_or_path)
    if path.exists():
        return load_profile(path)

    raise ValueError(f"Unknown profile: {name_or_path}. Available presets: {list(PRESETS.keys())}")


def _resolve_json_path(data: object, path: str) -> object | None:
    """Resolve a dot/bracket notation path against a JSON object."""
    if not path:
        return None

    import re
    tokens = re.findall(r'([^.\[\]]+)|\[(\d+)\]', path)
    current = data

    for key, index in tokens:
        if current is None:
            return None
        if index:
            if not isinstance(current, list):
                return None
            idx = int(index)
            if idx >= len(current):
                return None
            current = current[idx]
        elif key:
            if not isinstance(current, dict):
                return None
            current = current.get(key)

    return current


def _set_json_path(data: object, path: str, value: object) -> None:
    """Set a value at a dot/bracket notation path in a JSON object."""
    import re
    tokens = re.findall(r'([^.\[\]]+)|\[(\d+)\]', path)
    current = data

    for key, index in tokens[:-1]:
        if index:
            current = current[int(index)]
        elif key:
            if key not in current:
                current[key] = {}
            current = current[key]

    last_key, last_index = tokens[-1]
    if last_index:
        current[int(last_index)] = value
    elif last_key:
        current[last_key] = value


def extract_response_content(response: ReplayResponse, profile: TargetProfile) -> str:
    """Extract model output from response using the profile's response_path."""
    if not profile.response_path:
        return response.text

    try:
        parsed = json.loads(response.text)
    except json.JSONDecodeError:
        return response.text

    result = _resolve_json_path(parsed, profile.response_path)
    if result is None:
        return response.text

    return str(result)


def extract_conversation_id(response: ReplayResponse, profile: TargetProfile) -> str | None:
    """Extract conversation/thread ID from a response."""
    if not profile.conversation_id_field:
        return None

    try:
        parsed = json.loads(response.text)
    except json.JSONDecodeError:
        return None

    result = _resolve_json_path(parsed, profile.conversation_id_field)
    return str(result) if result else None


def inject_conversation_id(request: ParsedRequest, conversation_id: str, profile: TargetProfile) -> ParsedRequest:
    """Inject a conversation ID into a request based on the profile config."""
    if not profile.conversation_id_inject or not conversation_id:
        return request

    from .shared import clone_request, rebuild_json_request

    mutated = clone_request(request)
    if mutated.json_body is None:
        return request

    _set_json_path(mutated.json_body, profile.conversation_id_inject, conversation_id)
    rebuild_json_request(mutated)
    return mutated


def refresh_auth(request: ParsedRequest, profile: TargetProfile) -> ParsedRequest:
    """Refresh authentication token using the profile's auth refresh config."""
    if not profile.auth_refresh_url:
        return request

    from .shared import clone_request

    headers = {"Content-Type": "application/json"}
    body = profile.auth_refresh_body.encode("utf-8") if profile.auth_refresh_body else None

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.request(
                method=profile.auth_refresh_method,
                url=profile.auth_refresh_url,
                headers=headers,
                content=body,
            )
            resp.raise_for_status()

        data = resp.json()
        token = _resolve_json_path(data, profile.auth_refresh_token_path)

        if not token:
            print("[!] Auth refresh: could not extract token from response.")
            return request

        mutated = clone_request(request)
        mutated.headers["Authorization"] = profile.auth_header_format.format(token=token)
        return mutated

    except Exception as exc:
        print(f"[!] Auth refresh failed: {exc}")
        return request


def apply_profile_to_request(request: ParsedRequest, profile: TargetProfile) -> ParsedRequest:
    """Apply profile's extra headers and settings to a request."""
    if not profile.extra_headers:
        return request

    from .shared import clone_request

    mutated = clone_request(request)
    for key, value in profile.extra_headers.items():
        mutated.headers[key] = value
    return mutated
