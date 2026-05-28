"""AICU - Black-box security scanner for LLM applications."""
from pathlib import Path


def _resolve_payloads_dir():
    """Resolve payloads directory - works both installed and from source."""
    installed = Path(__file__).parent / "payloads"
    if installed.exists():
        return installed
    source = Path(__file__).parent.parent.parent / "payloads"
    if source.exists():
        return source
    return installed

PAYLOADS_DIR = _resolve_payloads_dir()
