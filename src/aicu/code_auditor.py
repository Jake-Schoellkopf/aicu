"""
AI Code Review Auditor

Scans AI-generated code for planted vulnerabilities that look correct
but contain subtle security flaws. Detects patterns that AI models
commonly introduce when compromised or poorly prompted.

Checks for:
- Hardcoded credentials/backdoor URLs
- Weak cryptography (MD5, SHA1 for passwords, ECB mode, small keys)
- SQL injection vulnerabilities (string concatenation in queries)
- Command injection (unsanitized input to os.system/subprocess)
- SSRF-able URLs (user input in HTTP requests without validation)
- Insecure deserialization (pickle.loads, yaml.load without SafeLoader)
- Path traversal (user input in file paths without sanitization)
- Disabled security features (verify=False, CSRF exempt, no auth)

Usage:
    python code_auditor.py --path /path/to/generated/code
    python code_auditor.py --file generated_module.py
    python code_auditor.py --path . --severity high

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


@dataclass(slots=True)
class CodeFinding:
    severity: str
    category: str
    file: str
    line: int
    code: str
    reason: str
    fix: str


# ============================================================
# DETECTION RULES
# ============================================================

RULES: list[dict] = [
    # Hardcoded credentials
    {
        "id": "CRED-001",
        "severity": "critical",
        "category": "hardcoded_credential",
        "pattern": re.compile(r"""(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*['"]((?!(?:os\.environ|getenv|config|settings|None|''|"")).{8,}?)['"]""", re.IGNORECASE),
        "reason": "Hardcoded credential in source code",
        "fix": "Use environment variables or a secrets manager",
        "extensions": None,
    },
    {
        "id": "CRED-002",
        "severity": "critical",
        "category": "backdoor_url",
        "pattern": re.compile(r"""https?://(?!(?:localhost|127\.0\.0\.1|example\.com|placeholder))[a-z0-9\-]+\.[a-z]{2,}[^\s'"]*(?:callback|hook|collect|exfil|steal|log)""", re.IGNORECASE),
        "reason": "Suspicious external URL that may be a backdoor/exfiltration endpoint",
        "fix": "Verify all external URLs are legitimate and expected",
        "extensions": None,
    },
    # Weak cryptography
    {
        "id": "CRYPTO-001",
        "severity": "high",
        "category": "weak_crypto",
        "pattern": re.compile(r"""(?:hashlib\.md5|hashlib\.sha1|MD5|SHA1)\s*\("""),
        "reason": "Weak hash algorithm used (MD5/SHA1) — vulnerable to collision attacks",
        "fix": "Use SHA-256 or bcrypt/argon2 for passwords",
        "extensions": {".py"},
    },
    {
        "id": "CRYPTO-002",
        "severity": "high",
        "category": "weak_crypto",
        "pattern": re.compile(r"""(?:AES\.new|Cipher).*(?:ECB|MODE_ECB)"""),
        "reason": "ECB mode encryption — patterns in plaintext are visible in ciphertext",
        "fix": "Use GCM or CBC mode with proper IV",
        "extensions": {".py"},
    },
    {
        "id": "CRYPTO-003",
        "severity": "medium",
        "category": "weak_crypto",
        "pattern": re.compile(r"""(?:key_size|bits)\s*=\s*(?:64|128|256)\b"""),
        "reason": "Potentially weak key size — verify it meets requirements",
        "fix": "Use minimum 256-bit keys for symmetric encryption",
        "extensions": None,
    },
    # SQL injection
    {
        "id": "SQLI-001",
        "severity": "critical",
        "category": "sql_injection",
        "pattern": re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*f?['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{.*\}""", re.IGNORECASE),
        "reason": "SQL query built with string formatting — vulnerable to SQL injection",
        "fix": "Use parameterized queries (cursor.execute(sql, params))",
        "extensions": {".py"},
    },
    {
        "id": "SQLI-002",
        "severity": "critical",
        "category": "sql_injection",
        "pattern": re.compile(r"""(?:execute|query)\s*\(\s*['"].*['"]\s*\+\s*"""),
        "reason": "SQL query built with string concatenation — vulnerable to SQL injection",
        "fix": "Use parameterized queries",
        "extensions": None,
    },
    # Command injection
    {
        "id": "CMDI-001",
        "severity": "critical",
        "category": "command_injection",
        "pattern": re.compile(r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*f?['"].*\{"""),
        "reason": "User input in shell command — vulnerable to command injection",
        "fix": "Use subprocess with shell=False and pass args as list",
        "extensions": {".py"},
    },
    {
        "id": "CMDI-002",
        "severity": "critical",
        "category": "command_injection",
        "pattern": re.compile(r"""(?:exec|eval)\s*\(\s*(?:request|input|user|data|params)""", re.IGNORECASE),
        "reason": "Dynamic code execution with user input",
        "fix": "Never use eval/exec with user-supplied data",
        "extensions": None,
    },
    # SSRF
    {
        "id": "SSRF-001",
        "severity": "high",
        "category": "ssrf",
        "pattern": re.compile(r"""(?:requests\.get|requests\.post|httpx\.|fetch|urllib)\s*\(\s*(?:url|endpoint|target|user_url|input)""", re.IGNORECASE),
        "reason": "HTTP request with user-controlled URL — vulnerable to SSRF",
        "fix": "Validate and allowlist URLs before making requests",
        "extensions": None,
    },
    # Insecure deserialization
    {
        "id": "DESER-001",
        "severity": "critical",
        "category": "insecure_deserialization",
        "pattern": re.compile(r"""pickle\.loads?\s*\("""),
        "reason": "Pickle deserialization — can execute arbitrary code",
        "fix": "Use JSON or a safe serialization format",
        "extensions": {".py"},
    },
    {
        "id": "DESER-002",
        "severity": "high",
        "category": "insecure_deserialization",
        "pattern": re.compile(r"""yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)"""),
        "reason": "YAML load without SafeLoader — can execute arbitrary code",
        "fix": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        "extensions": {".py"},
    },
    # Path traversal
    {
        "id": "PATH-001",
        "severity": "high",
        "category": "path_traversal",
        "pattern": re.compile(r"""(?:open|Path)\s*\(\s*(?:f?['"].*\{|.*\+\s*(?:request|input|user|filename|path))""", re.IGNORECASE),
        "reason": "File path constructed from user input — vulnerable to path traversal",
        "fix": "Validate path is within expected directory (use Path.resolve() and check prefix)",
        "extensions": None,
    },
    # Disabled security
    {
        "id": "SEC-001",
        "severity": "medium",
        "category": "disabled_security",
        "pattern": re.compile(r"""verify\s*=\s*False"""),
        "reason": "SSL verification disabled — vulnerable to MITM attacks",
        "fix": "Enable SSL verification (verify=True) or use proper CA bundle",
        "extensions": None,
    },
    {
        "id": "SEC-002",
        "severity": "medium",
        "category": "disabled_security",
        "pattern": re.compile(r"""@csrf_exempt|csrf_protect\s*=\s*False"""),
        "reason": "CSRF protection disabled",
        "fix": "Enable CSRF protection for state-changing endpoints",
        "extensions": None,
    },
    {
        "id": "SEC-003",
        "severity": "medium",
        "category": "disabled_security",
        "pattern": re.compile(r"""(?:CORS|cors).*(?:\*|allow_all|any)""", re.IGNORECASE),
        "reason": "Overly permissive CORS configuration",
        "fix": "Restrict CORS to specific trusted origins",
        "extensions": None,
    },
]


def scan_file(filepath: Path, min_severity: str = "low") -> list[CodeFinding]:
    """Scan a single file for vulnerability patterns."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_level = severity_order.get(min_severity, 3)

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return []

    findings: list[CodeFinding] = []
    ext = filepath.suffix.lower()

    for rule in RULES:
        if severity_order.get(rule["severity"], 3) > min_level:
            continue
        if rule["extensions"] and ext not in rule["extensions"]:
            continue

        for i, line in enumerate(content.split("\n"), 1):
            if rule["pattern"].search(line):
                findings.append(CodeFinding(
                    severity=rule["severity"],
                    category=rule["category"],
                    file=str(filepath),
                    line=i,
                    code=line.strip()[:120],
                    reason=rule["reason"],
                    fix=rule["fix"],
                ))

    return findings


def scan_path(path: str, min_severity: str = "low") -> list[CodeFinding]:
    """Scan a directory or file."""
    target = Path(path)
    all_findings: list[CodeFinding] = []

    if target.is_file():
        return scan_file(target, min_severity)

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.suffix.lower() in SCAN_EXTENSIONS:
                all_findings.extend(scan_file(filepath, min_severity))

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AI Code Review Auditor — detect planted vulnerabilities")
    parser.add_argument("--path", default=".", help="Path to scan (file or directory)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Minimum severity to report")
    args = parser.parse_args()

    print("=" * 60)
    print("  AI CODE REVIEW AUDITOR")
    print("  Detecting planted vulnerabilities in AI-generated code")
    print("=" * 60)
    print(f"  Target: {args.path}")
    print(f"  Min severity: {args.severity}")

    findings = scan_path(args.path, args.severity)

    if findings:
        print(f"\n  FINDINGS: {len(findings)}")
        print("  " + "-" * 50)
        for f in findings:
            icon = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f535"}.get(f.severity, "?")
            print(f"\n  {icon} [{f.severity.upper()}] {f.category}")
            print(f"     File: {f.file}:{f.line}")
            print(f"     Code: {f.code}")
            print(f"     Issue: {f.reason}")
            print(f"     Fix: {f.fix}")
    else:
        print("\n  No vulnerabilities detected.")

    print(f"\n  {'═' * 50}")
    crits = sum(1 for f in findings if f.severity == "critical")
    highs = sum(1 for f in findings if f.severity == "high")
    print(f"  Critical: {crits} | High: {highs} | Total: {len(findings)}")
    print(f"  {'═' * 50}")

    return 1 if crits or highs else 0


if __name__ == "__main__":
    sys.exit(main())
