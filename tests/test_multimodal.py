"""Tests for multimodal payload generators."""
from __future__ import annotations

import json
import struct
import zipfile
from io import BytesIO

import pytest

from aicu.generators.multimodal import MultimodalPayload, INJECTION_COMMANDS, EXFIL_URLS
from aicu.generators.multimodal import (
    stego_lsb,
    opacity_overlay,
    exif_injection,
    split_payload,
    whisper_underlay,
    universal_mute,
    frequency_hiding,
    font_remap,
    white_on_white,
    docx_hidden_xml,
    zero_width,
)
from aicu.generators.multimodal_scanner import (
    generate_all_payloads,
    build_vision_api_payload,
    build_audio_api_payload,
    build_document_api_payload,
)


class TestStegoLSB:
    def test_generates_payloads(self):
        payloads = stego_lsb.generate()
        assert len(payloads) > 0
        assert all(isinstance(p, MultimodalPayload) for p in payloads)

    def test_produces_valid_png(self):
        payloads = stego_lsb.generate()
        for p in payloads:
            assert p.content[:8] == b"\x89PNG\r\n\x1a\n"
            assert p.mime_type == "image/png"

    def test_metadata_contains_hidden_text(self):
        payloads = stego_lsb.generate()
        assert all("hidden_text" in p.metadata for p in payloads)


class TestOpacityOverlay:
    def test_generates_payloads(self):
        payloads = opacity_overlay.generate()
        assert len(payloads) > 0

    def test_valid_png_with_alpha(self):
        payloads = opacity_overlay.generate()
        for p in payloads:
            assert p.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_alpha_levels_are_low(self):
        payloads = opacity_overlay.generate()
        for p in payloads:
            assert p.metadata.get("alpha_level", 255) <= 12


class TestExifInjection:
    def test_generates_payloads(self):
        payloads = exif_injection.generate()
        assert len(payloads) > 0

    def test_produces_valid_jpeg(self):
        payloads = exif_injection.generate()
        for p in payloads:
            assert p.content[:2] == b"\xFF\xD8"
            assert p.mime_type == "image/jpeg"


class TestSplitPayload:
    def test_generates_payloads(self):
        payloads = split_payload.generate()
        assert len(payloads) > 0

    def test_has_group_metadata(self):
        payloads = split_payload.generate()
        for p in payloads:
            assert "group_id" in p.metadata
            assert "part" in p.metadata


class TestWhisperUnderlay:
    def test_generates_payloads(self):
        payloads = whisper_underlay.generate()
        assert len(payloads) > 0

    def test_produces_valid_wav(self):
        payloads = whisper_underlay.generate()
        for p in payloads:
            assert p.content[:4] == b"RIFF"
            assert p.content[8:12] == b"WAVE"
            assert p.mime_type == "audio/wav"


class TestUniversalMute:
    def test_generates_payloads(self):
        payloads = universal_mute.generate()
        assert len(payloads) > 0

    def test_valid_wav(self):
        payloads = universal_mute.generate()
        for p in payloads:
            assert p.content[:4] == b"RIFF"


class TestFrequencyHiding:
    def test_generates_payloads(self):
        payloads = frequency_hiding.generate()
        assert len(payloads) > 0

    def test_valid_wav(self):
        payloads = frequency_hiding.generate()
        for p in payloads:
            assert p.content[:4] == b"RIFF"


class TestFontRemap:
    def test_generates_payloads(self):
        payloads = font_remap.generate()
        assert len(payloads) > 0

    def test_produces_valid_pdf(self):
        payloads = font_remap.generate()
        for p in payloads:
            assert p.content[:5] == b"%PDF-"
            assert p.mime_type == "application/pdf"


class TestWhiteOnWhite:
    def test_generates_payloads(self):
        payloads = white_on_white.generate()
        assert len(payloads) > 0

    def test_valid_pdf(self):
        payloads = white_on_white.generate()
        for p in payloads:
            assert p.content[:5] == b"%PDF-"


class TestDocxHiddenXml:
    def test_generates_payloads(self):
        payloads = docx_hidden_xml.generate()
        assert len(payloads) > 0

    def test_produces_valid_docx(self):
        payloads = docx_hidden_xml.generate()
        for p in payloads:
            # DOCX is a ZIP file
            buf = BytesIO(p.content)
            with zipfile.ZipFile(buf) as zf:
                assert "word/document.xml" in zf.namelist()
                assert "[Content_Types].xml" in zf.namelist()


class TestZeroWidth:
    def test_generates_payloads(self):
        payloads = zero_width.generate()
        assert len(payloads) > 0

    def test_contains_zero_width_chars(self):
        payloads = zero_width.generate()
        zw_chars = {"\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF"}
        for p in payloads:
            text = p.content.decode("utf-8")
            assert any(c in text for c in zw_chars)


class TestMultimodalScanner:
    def test_generate_all(self):
        payloads = generate_all_payloads()
        assert len(payloads) >= 151

    def test_filter_by_category(self):
        vision = generate_all_payloads(categories=["vision"])
        audio = generate_all_payloads(categories=["audio"])
        docs = generate_all_payloads(categories=["documents"])
        assert all(p.category == "vision" for p in vision)
        assert all(p.category == "audio" for p in audio)
        assert all(p.category == "documents" for p in docs)
        assert len(vision) + len(audio) + len(docs) >= 151

    def test_build_vision_payload(self):
        payloads = stego_lsb.generate()
        body = build_vision_api_payload(payloads[0])
        assert "messages" in body
        content = body["messages"][0]["content"]
        assert any(c["type"] == "image_url" for c in content)

    def test_build_audio_payload(self):
        payloads = whisper_underlay.generate()
        body = build_audio_api_payload(payloads[0])
        assert "file_base64" in body

    def test_build_document_payload(self):
        payloads = docx_hidden_xml.generate()
        body = build_document_api_payload(payloads[0])
        assert "attachments" in body
        assert body["attachments"][0]["file_name"].endswith(".docx")
