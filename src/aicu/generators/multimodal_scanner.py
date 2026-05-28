"""Multimodal payload scanner - generates and delivers adversarial multimodal payloads.

Orchestrates all multimodal generators (vision, audio, documents) and delivers
payloads to target endpoints via the existing HTTP replay mechanism.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .multimodal import MultimodalPayload, OUTPUT_DIR
from .multimodal import stego_lsb, opacity_overlay, exif_injection, split_payload
from .multimodal import whisper_underlay, universal_mute, frequency_hiding
from .multimodal import font_remap, white_on_white, docx_hidden_xml, zero_width


ALL_GENERATORS = {
    "vision/stego_lsb": stego_lsb,
    "vision/opacity_overlay": opacity_overlay,
    "vision/exif_injection": exif_injection,
    "vision/split_payload": split_payload,
    "audio/whisper_underlay": whisper_underlay,
    "audio/universal_mute": universal_mute,
    "audio/frequency_hiding": frequency_hiding,
    "documents/font_remap": font_remap,
    "documents/white_on_white": white_on_white,
    "documents/docx_hidden_xml": docx_hidden_xml,
    "documents/zero_width": zero_width,
}


def generate_all_payloads(categories: list[str] | None = None) -> list[MultimodalPayload]:
    """Generate payloads from all (or selected) generators."""
    payloads: list[MultimodalPayload] = []

    for name, module in ALL_GENERATORS.items():
        if categories:
            cat = name.split("/")[0]
            if cat not in categories and name not in categories:
                continue
        payloads.extend(module.generate())

    return payloads


def save_payloads(payloads: list[MultimodalPayload], output_dir: Path | None = None) -> Path:
    """Save generated payloads to disk organized by category/technique."""
    out = output_dir or OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, Any]] = []

    for p in payloads:
        technique_dir = out / p.category / p.technique
        technique_dir.mkdir(parents=True, exist_ok=True)

        filepath = technique_dir / p.filename
        filepath.write_bytes(p.content)

        manifest.append({
            "payload_id": p.payload_id,
            "category": p.category,
            "technique": p.technique,
            "filename": p.filename,
            "path": str(filepath),
            "mime_type": p.mime_type,
            "description": p.description,
            "metadata": p.metadata,
            "size_bytes": len(p.content),
        })

    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return out


def build_vision_api_payload(payload: MultimodalPayload, user_prompt: str = "What is in this image?") -> dict:
    """Build an OpenAI-compatible vision API request body with the payload image."""
    b64 = base64.b64encode(payload.content).decode()
    data_uri = f"data:{payload.mime_type};base64,{b64}"

    return {
        "messages": [{
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": data_uri}},
                {"type": "text", "text": user_prompt},
            ],
        }]
    }


def build_audio_api_payload(payload: MultimodalPayload) -> dict:
    """Build a Whisper-compatible transcription request structure."""
    b64 = base64.b64encode(payload.content).decode()
    return {
        "file_base64": b64,
        "model": "whisper-1",
        "response_format": "text",
    }


def build_document_api_payload(payload: MultimodalPayload, user_prompt: str = "Summarize this document.") -> dict:
    """Build a document upload payload for LLM endpoints that accept file attachments."""
    b64 = base64.b64encode(payload.content).decode()
    return {
        "messages": [{
            "role": "user",
            "content": user_prompt,
        }],
        "attachments": [{
            "file_name": payload.filename,
            "file_type": payload.mime_type,
            "file_data": b64,
            "extracted_content": payload.metadata.get("hidden_text", ""),
        }],
    }


def run_multimodal_scan(
    request_file: str,
    categories: list[str] | None = None,
    output_dir: str | None = None,
    save_artifacts: bool = True,
) -> dict[str, Any]:
    """Run a full multimodal payload scan.

    Generates payloads, optionally saves them, and returns a summary.
    """
    start = datetime.now()

    payloads = generate_all_payloads(categories)

    run_dir = Path(output_dir) if output_dir else Path("runs") / f"multimodal_{start.strftime('%Y%m%d_%H%M%S')}"

    if save_artifacts:
        save_payloads(payloads, run_dir / "payloads")

    # Group by category/technique for reporting
    summary: dict[str, Any] = {
        "run_id": f"multimodal_{start.strftime('%Y%m%d_%H%M%S')}",
        "timestamp": start.isoformat(),
        "total_payloads": len(payloads),
        "categories": {},
        "output_dir": str(run_dir),
    }

    for p in payloads:
        key = f"{p.category}/{p.technique}"
        if key not in summary["categories"]:
            summary["categories"][key] = {"count": 0, "payloads": []}
        summary["categories"][key]["count"] += 1
        summary["categories"][key]["payloads"].append({
            "id": p.payload_id,
            "filename": p.filename,
            "description": p.description,
            "size_bytes": len(p.content),
        })

    # Save summary
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "multimodal_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary
