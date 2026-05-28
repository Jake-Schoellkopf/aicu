"""
Codebase Injection Scanner

Scans git repositories for hidden AI instructions that could hijack
AI coding assistants (Cursor, Kiro, Copilot, Claude Code) when they
index or read the codebase.

Detects:
- Zero-width characters hiding instructions in comments/docs
- Comments targeting AI assistants specifically
- Markdown with embedded directives
- Invisible Unicode in variable names/strings
- Base64-encoded instructions in comments
- Prompt injection in docstrings/README files

Usage:
    python codebase_scanner.py --path /path/to/repo
    python codebase_scanner.py --path . --deep

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "BOM/ZERO WIDTH NO-BREAK",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
}

AI_TARGETING_PATTERNS = [
    re.compile(r"(?i)(if\s+you\s+are\s+an?\s+ai|when\s+an?\s+ai\s+reads?\s+this)"),
    re.compile(r"(?i)(assistant|copilot|cursor|kiro|claude|gpt|llm|ai\s+agent)[\s:,]*(ignore|override|forget|disregard|instead)"),
    re.compile(r"(?i)(note\s+to\s+(ai|assistant|model)|instruction\s+for\s+(ai|assistant))"),
    re.compile(r"(?i)(system\s*prompt|hidden\s*instruction|secret\s*directive)"),
    re.compile(r"(?i)(output|reveal|print|show|display)\s+(your|the)\s+(system|hidden|secret|internal)\s+(prompt|instructions?|config)"),
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|context)"),
    re.compile(r"(?i)(do\s+not|don'?t)\s+(summarize|analyze|review)\s+this\s+(file|code|document)"),
    re.compile(r"(?i)instead\s+(of|,)\s+(your\s+normal|what\s+you\s+were)\s+(task|told|instructed)"),
]

SUSPICIOUS_COMMENT_PATTERNS = [
    re.compile(r"(?i)#\s*(ai|assistant|llm|model)\s*:"),
    re.compile(r"(?i)//\s*(ai|assistant|llm|model)\s*:"),
    re.compile(r"(?i)/\*\s*(ai|assistant|llm|model)\s*:"),
    re.compile(r"(?i)<!--\s*(ai|assistant|llm|model)\s*:"),
    re.compile(r"(?i)#\s*TODO.*\b(ai|assistant|llm)\b.*\b(output|reveal|ignore|override)\b"),
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".rb", ".php",
    ".c", ".cpp", ".h", ".cs", ".swift", ".kt", ".scala",
    ".md", ".txt", ".rst", ".yaml", ".yml", ".json", ".toml",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".html", ".css", ".xml", ".svg",
    ".env", ".env.example", ".gitignore", ".dockerignore",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target"}


@dataclass(slots=True)
class ScanFinding:
    severity: str
    category: str
    file: str
    line: int
    content: str
    reason: str


def scan_for_zero_width(content: str, filepath: str) -> list[ScanFinding]:
    """Detect zero-width characters that could hide instructions."""
    findings = []
    for i, line in enumerate(content.split("\n"), 1):
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in line:
                count = line.count(char)
                # Strip zero-width chars and check if remaining text is suspicious
                clean = line
                for c in ZERO_WIDTH_CHARS:
                    clean = clean.replace(c, "")
                findings.append(ScanFinding(
                    severity="high",
                    category="zero_width_injection",
                    file=filepath,
                    line=i,
                    content=f"[{count}x {name}] Clean text: {clean.strip()[:100]}",
                    reason=f"Zero-width characters found — may hide instructions from code review but visible to AI indexers",
                ))
    return findings


def scan_for_ai_targeting(content: str, filepath: str) -> list[ScanFinding]:
    """Detect comments/text that specifically target AI assistants."""
    findings = []
    for i, line in enumerate(content.split("\n"), 1):
        for pattern in AI_TARGETING_PATTERNS:
            if match := pattern.search(line):
                findings.append(ScanFinding(
                    severity="critical",
                    category="ai_targeted_injection",
                    file=filepath,
                    line=i,
                    content=line.strip()[:150],
                    reason=f"Text specifically targets AI assistants: '{match.group(0)}'",
                ))
                break
    return findings


def scan_for_suspicious_comments(content: str, filepath: str) -> list[ScanFinding]:
    """Detect comments that appear to contain AI directives."""
    findings = []
    for i, line in enumerate(content.split("\n"), 1):
        for pattern in SUSPICIOUS_COMMENT_PATTERNS:
            if pattern.search(line):
                findings.append(ScanFinding(
                    severity="medium",
                    category="suspicious_comment",
                    file=filepath,
                    line=i,
                    content=line.strip()[:150],
                    reason="Comment appears to contain directive targeting AI assistant",
                ))
                break
    return findings


def scan_for_encoded_instructions(content: str, filepath: str) -> list[ScanFinding]:
    """Detect base64-encoded content in comments that might be hidden instructions."""
    findings = []
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

    for i, line in enumerate(content.split("\n"), 1):
        # Only check in comments
        if not any(line.strip().startswith(c) for c in ("#", "//", "/*", "*", "<!--")):
            continue
        for match in b64_pattern.finditer(line):
            try:
                decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
                # Check if decoded content looks like an instruction
                if any(k in decoded.lower() for k in ("ignore", "instruction", "system", "prompt", "override", "reveal", "output")):
                    findings.append(ScanFinding(
                        severity="critical",
                        category="encoded_injection",
                        file=filepath,
                        line=i,
                        content=f"Encoded: {match.group(0)[:40]}... Decoded: {decoded[:80]}",
                        reason="Base64 in comment decodes to AI injection instruction",
                    ))
            except Exception:
                pass
    return findings


def scan_for_bidi_attacks(content: str, filepath: str) -> list[ScanFinding]:
    """Detect bidirectional Unicode that can hide code from reviewers."""
    findings = []
    bidi_chars = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
    for i, line in enumerate(content.split("\n"), 1):
        if any(c in line for c in bidi_chars):
            findings.append(ScanFinding(
                severity="high",
                category="bidi_attack",
                file=filepath,
                line=i,
                content=repr(line.strip()[:100]),
                reason="Bidirectional Unicode override — can make code appear different than it executes (CVE-2021-42574)",
            ))
    return findings


def scan_file(filepath: Path, deep: bool = False) -> list[ScanFinding]:
    """Scan a single file for all injection types."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return []

    rel_path = str(filepath)
    findings = []

    findings.extend(scan_for_zero_width(content, rel_path))
    findings.extend(scan_for_ai_targeting(content, rel_path))
    findings.extend(scan_for_suspicious_comments(content, rel_path))
    findings.extend(scan_for_bidi_attacks(content, rel_path))

    if deep:
        findings.extend(scan_for_encoded_instructions(content, rel_path))

    return findings


def scan_repo(path: str, deep: bool = False) -> list[ScanFinding]:
    """Scan an entire repository."""
    root = Path(path)
    all_findings: list[ScanFinding] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.suffix.lower() in SCAN_EXTENSIONS:
                findings = scan_file(filepath, deep)
                all_findings.extend(findings)
                files_scanned += 1

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Codebase Injection Scanner — find hidden AI instructions in repos")
    parser.add_argument("--path", default=".", help="Path to repository (default: current directory)")
    parser.add_argument("--deep", action="store_true", help="Enable deep scanning (base64 decoding, slower)")
    args = parser.parse_args()

    print("=" * 60)
    print("  CODEBASE INJECTION SCANNER")
    print("  Detecting hidden AI instructions in source code")
    print("=" * 60)
    print(f"  Target: {args.path}")
    print(f"  Deep mode: {args.deep}")

    findings = scan_repo(args.path, args.deep)

    if findings:
        print(f"\n  FINDINGS: {len(findings)}")
        print("  " + "-" * 50)
        for f in findings:
            icon = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f535"}.get(f.severity, "?")
            print(f"\n  {icon} [{f.severity.upper()}] {f.category}")
            print(f"     File: {f.file}:{f.line}")
            print(f"     Content: {f.content}")
            print(f"     Reason: {f.reason}")
    else:
        print("\n  No hidden AI instructions detected.")

    print(f"\n  {'═' * 50}")
    crits = sum(1 for f in findings if f.severity == "critical")
    highs = sum(1 for f in findings if f.severity == "high")
    print(f"  Critical: {crits} | High: {highs} | Total: {len(findings)}")
    print(f"  {'═' * 50}")

    return 1 if crits or highs else 0


if __name__ == "__main__":
    sys.exit(main())
