from __future__ import annotations

import re
from dataclasses import dataclass

from .models import ParsedRequest
from .shared import clone_request


_BOUNDARY_RE = re.compile(r'boundary=("?)([^";]+)\1', re.IGNORECASE)
_FILENAME_RE = re.compile(r'filename="([^"]*)"')
_NAME_RE = re.compile(r'name="([^"]*)"')


@dataclass(slots=True)
class MultipartPart:
    headers: dict[str, str]
    body: bytes


def extract_boundary(content_type: str | None) -> str:
    if not content_type:
        raise ValueError("Missing Content-Type header for multipart request.")

    match = _BOUNDARY_RE.search(content_type)
    if not match:
        raise ValueError("Could not extract multipart boundary.")

    return match.group(2)


def parse_part_headers(header_blob: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    text = header_blob.decode("utf-8", errors="replace")

    for line in text.split("\r\n"):
        if not line.strip():
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    return headers


def split_multipart_body(body: bytes, boundary: str) -> list[MultipartPart]:
    delimiter = f"--{boundary}".encode("utf-8")
    raw_parts = body.split(delimiter)

    parts: list[MultipartPart] = []

    for raw_part in raw_parts:
        raw_part = raw_part.strip(b"\r\n")
        if not raw_part or raw_part == b"--":
            continue

        if b"\r\n\r\n" not in raw_part:
            continue

        header_blob, part_body = raw_part.split(b"\r\n\r\n", 1)
        headers = parse_part_headers(header_blob)
        parts.append(MultipartPart(headers=headers, body=part_body))

    return parts


def build_content_disposition(
    original_value: str,
    new_filename: str,
) -> str:
    filename_match = _FILENAME_RE.search(original_value)

    if filename_match:
        return _FILENAME_RE.sub(f'filename="{new_filename}"', original_value)

    return f'{original_value}; filename="{new_filename}"'


def find_file_part_index(parts: list[MultipartPart]) -> int:
    for index, part in enumerate(parts):
        disposition = part.headers.get("Content-Disposition", "")
        if 'filename="' in disposition:
            return index

    raise ValueError("No file part found in multipart request.")


def rebuild_multipart_body(parts: list[MultipartPart], boundary: str) -> bytes:
    chunks: list[bytes] = []

    for part in parts:
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))

        for key, value in part.headers.items():
            chunks.append(f"{key}: {value}\r\n".encode("utf-8"))

        chunks.append(b"\r\n")
        chunks.append(part.body)
        chunks.append(b"\r\n")

    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))

    return b"".join(chunks)


def replace_uploaded_file(
    request: ParsedRequest,
    file_bytes: bytes,
    new_filename: str,
    content_type: str = "text/plain",
) -> ParsedRequest:
    """
    Replace the first detected file part in a multipart/form-data request.
    """
    if not request.content_type or "multipart/form-data" not in request.content_type.lower():
        raise ValueError("Request is not multipart/form-data.")

    mutated = clone_request(request)

    boundary = extract_boundary(mutated.content_type)
    parts = split_multipart_body(mutated.body, boundary)

    file_index = find_file_part_index(parts)
    file_part = parts[file_index]

    disposition = file_part.headers.get("Content-Disposition", "")
    file_part.headers["Content-Disposition"] = build_content_disposition(
        disposition,
        new_filename,
    )
    file_part.headers["Content-Type"] = content_type
    file_part.body = file_bytes

    mutated.body = rebuild_multipart_body(parts, boundary)

    if "Content-Length" in mutated.headers:
        mutated.headers.pop("Content-Length", None)

    return mutated