from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from models import ParsedRequest


COMMON_MUTATION_KEYS = {
    "prompt",
    "input",
    "message",
    "content",
    "text",
    "query",
}


def load_raw_request(file_path: str | Path) -> str:
    """Load a raw HTTP request from disk as text, preserving CRLF."""
    return Path(file_path).read_bytes().decode("utf-8")


def split_raw_request(raw_request: str) -> tuple[str, str]:
    """
    Split a raw HTTP request into head and body.

    Returns:
        tuple[str, str]: (head, body)
    """
    if "\r\n\r\n" in raw_request:
        return raw_request.split("\r\n\r\n", 1)
    if "\n\n" in raw_request:
        return raw_request.split("\n\n", 1)
    return raw_request, ""


def parse_request_line(request_line: str) -> tuple[str, str]:
    """
    Parse the first line of a raw HTTP request.

    Example:
        POST /api/chat HTTP/1.1
    """
    parts = request_line.strip().split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line!r}")

    method = parts[0].upper()
    path = parts[1]
    return method, path


def parse_headers(header_lines: list[str]) -> dict[str, str]:
    """Parse raw HTTP header lines into a dictionary."""
    headers: dict[str, str] = {}

    for line in header_lines:
        if not line.strip():
            continue
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    return headers


def parse_cookies(cookie_header: str | None) -> dict[str, str]:
    """Parse a Cookie header into a dictionary."""
    if not cookie_header:
        return {}

    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()

    return cookies


def infer_scheme_and_port(host_header: str | None) -> tuple[str, str, int | None]:
    """
    Infer scheme, host, and port from Host header.

    For V1:
    - default scheme = https
    - localhost/127.x = http
    - default port = 443
    """
    if not host_header:
        raise ValueError("Missing Host header")

    scheme = "https"

    if ":" in host_header:
        host, port_str = host_header.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host = host_header
            port = 443
    else:
        host = host_header
        port = 443

    # Use HTTP for localhost or common non-TLS ports
    if host in ("localhost", "127.0.0.1", "0.0.0.0") or host.startswith("127."):
        scheme = "http"
    elif port in (80, 8080, 8888, 8899):
        scheme = "http"

    return scheme, host, port


def parse_query_params(path: str) -> tuple[str, dict[str, str]]:
    """Split query parameters from the path."""
    parsed = urlsplit(path)
    clean_path = parsed.path or "/"
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return clean_path, query_params


def try_parse_json(body_text: str, content_type: str | None) -> object | None:
    """Parse JSON body if content type indicates JSON."""
    if not content_type:
        return None

    if "application/json" not in content_type.lower():
        return None

    if not body_text.strip():
        return None

    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return None


def find_mutation_points(data: object, prefix: str = "") -> list[str]:
    """
    Recursively identify likely mutation points in a JSON structure.

    Examples of returned paths:
    - prompt
    - message
    - messages[0].content
    """
    points: list[str] = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{prefix}.{key}" if prefix else key

            if key in COMMON_MUTATION_KEYS and isinstance(value, str):
                points.append(current_path)

            if key == "messages" and isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        role = item.get("role")
                        content = item.get("content")
                        if role == "user" and isinstance(content, str):
                            points.append(f"{current_path}[{index}].content")

            points.extend(find_mutation_points(value, current_path))

    elif isinstance(data, list):
        for index, item in enumerate(data):
            current_path = f"{prefix}[{index}]"
            points.extend(find_mutation_points(item, current_path))

    return list(dict.fromkeys(points))


def parse_raw_request(raw_request: str) -> ParsedRequest:
    """Parse a raw HTTP request into a ParsedRequest object."""
    head, body_text = split_raw_request(raw_request)

    header_block = head.replace("\r\n", "\n")
    lines = header_block.split("\n")

    if not lines or not lines[0].strip():
        raise ValueError("Raw request is missing a request line")

    request_line = lines[0]
    header_lines = lines[1:]

    method, raw_path = parse_request_line(request_line)
    headers = parse_headers(header_lines)

    scheme, host, port = infer_scheme_and_port(headers.get("Host"))
    path, query_params = parse_query_params(raw_path)

    cookies = parse_cookies(headers.get("Cookie"))
    content_type = headers.get("Content-Type")
    json_body = try_parse_json(body_text, content_type)

    mutation_points: list[str] = []
    if json_body is not None:
        mutation_points = find_mutation_points(json_body)

    return ParsedRequest(
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        headers=headers,
        cookies=cookies,
        query_params=query_params,
        body=body_text.encode("utf-8"),
        content_type=content_type,
        json_body=json_body,
        mutation_points=mutation_points,
    )


def parse_raw_request_file(file_path: str | Path) -> ParsedRequest:
    """Load and parse a raw HTTP request from disk."""
    raw_request = load_raw_request(file_path)
    return parse_raw_request(raw_request)