from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from models import ParsedRequest, ReplayResponse


@dataclass(slots=True)
class ReplayDiagnostics:
    auth_issue: bool = False
    csrf_issue: bool = False
    cookie_issue: bool = False
    likely_causes: list[str] | None = None


def build_url(request: ParsedRequest) -> str:
    """Construct full URL including query parameters."""
    base = request.full_url()

    if not request.query_params:
        return base

    query_string = "&".join(
        f"{key}={value}" for key, value in request.query_params.items()
    )
    return f"{base}?{query_string}"


def prepare_headers(request: ParsedRequest) -> dict[str, str]:
    """
    Prepare headers for outbound request.

    Removes headers that should not be forwarded directly.
    """
    headers = dict(request.headers)
    headers.pop("Content-Length", None)
    headers.pop("Host", None)
    return headers


def detect_auth_header(headers: dict[str, str]) -> bool:
    """Check whether an Authorization header is present."""
    return any(header.lower() == "authorization" for header in headers)


def detect_csrf_header(headers: dict[str, str]) -> bool:
    """Detect common CSRF-related headers."""
    csrf_names = {
        "x-csrf-token",
        "x-xsrf-token",
        "csrf-token",
        "x-requested-with",
    }
    return any(header.lower() in csrf_names for header in headers)


def analyze_response_issues(
    request: ParsedRequest,
    response: ReplayResponse,
) -> ReplayDiagnostics:
    """
    Analyze likely replay issues such as:
    - expired auth
    - missing CSRF
    - missing cookies/session
    """
    likely_causes: list[str] = []
    headers_lower = {k.lower(): v for k, v in request.headers.items()}
    response_text = response.text.lower()

    auth_present = detect_auth_header(request.headers)
    csrf_present = detect_csrf_header(request.headers)
    cookies_present = bool(request.cookies)

    auth_issue = False
    csrf_issue = False
    cookie_issue = False

    if response.status_code in {401, 403}:
        if auth_present:
            auth_issue = True
            likely_causes.append(
                "Authorization may be expired, invalid, or tied to an old session. Recapture a fresh authenticated request."
            )

        if not cookies_present:
            cookie_issue = True
            likely_causes.append(
                "No cookies were present. The application may require a live session cookie."
            )

        if not csrf_present and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            csrf_issue = True
            likely_causes.append(
                "No CSRF header was detected. The target may require a valid anti-CSRF token."
            )

    if "csrf" in response_text or "xsrf" in response_text:
        csrf_issue = True
        if (
            "Response appears to reference CSRF/XSRF validation failure."
            not in likely_causes
        ):
            likely_causes.append(
                "Response appears to reference CSRF/XSRF validation failure."
            )

    if "unauthorized" in response_text or "invalid token" in response_text:
        auth_issue = True
        if (
            "Response suggests an authentication or token issue."
            not in likely_causes
        ):
            likely_causes.append(
                "Response suggests an authentication or token issue."
            )

    if "session expired" in response_text or "login" in response_text:
        cookie_issue = True
        if (
            "Response suggests the request may require a valid live session."
            not in likely_causes
        ):
            likely_causes.append(
                "Response suggests the request may require a valid live session."
            )

    return ReplayDiagnostics(
        auth_issue=auth_issue,
        csrf_issue=csrf_issue,
        cookie_issue=cookie_issue,
        likely_causes=likely_causes,
    )


def replay_request(
    request: ParsedRequest,
    timeout: float = 30.0,
    max_retries: int = 3,
    base_delay: float = 1.0,
    request_delay: float = 0.0,
) -> tuple[ReplayResponse, ReplayDiagnostics]:
    """
    Replay a ParsedRequest and return:
    - ReplayResponse
    - ReplayDiagnostics

    Includes exponential backoff on 429/5xx responses and optional inter-request delay.
    """
    if request_delay > 0:
        time.sleep(request_delay)

    url = build_url(request)
    headers = prepare_headers(request)

    for attempt in range(max_retries + 1):
        start = time.time()

        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                response = client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=request.body,
                )

            elapsed_ms = int((time.time() - start) * 1000)

            # Retry on 429 or 5xx with backoff
            if response.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
                continue

            replay_response = ReplayResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
                text=response.text,
                elapsed_ms=elapsed_ms,
                error=None,
            )

            diagnostics = analyze_response_issues(request, replay_response)
            return replay_response, diagnostics

        except Exception as exc:
            elapsed_ms = int((time.time() - start) * 1000)

            if attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
                continue

            replay_response = ReplayResponse(
                status_code=0,
                headers={},
                body=b"",
                text="",
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )

            diagnostics = ReplayDiagnostics(
                likely_causes=[f"Transport or connection error: {exc}"]
            )

            return replay_response, diagnostics

    # Should not reach here, but satisfy type checker
    return ReplayResponse(
        status_code=0, headers={}, body=b"", text="", elapsed_ms=0, error="Max retries exceeded"
    ), ReplayDiagnostics(likely_causes=["Max retries exceeded"])