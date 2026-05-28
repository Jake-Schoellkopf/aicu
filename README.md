# AICU

[![CI](https://github.com/Jake-Schoellkopf/aicu/actions/workflows/ci.yml/badge.svg)](https://github.com/Jake-Schoellkopf/aicu/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Black-box security scanner for LLM applications.** Point it at any chat endpoint, get a report of what leaks.

<p align="center">
  <img src="demo.svg" alt="AICU demo" width="800">
</p>

AICU replays captured HTTP requests with adversarial payloads and evaluates whether the target discloses system prompts, internal tools, credentials, or responds to safety bypass attempts — no API keys or model access required.

## Quick Start (2 minutes)

```bash
# Install
git clone https://github.com/Jake-Schoellkopf/aicu.git && cd aicu
pip install -e .

# Start the built-in vulnerable demo target
python demo_server.py &

# Run a full scan
aicu scan --request examples/demo_request.txt
```

## What It Finds

| Category | Examples |
|----------|----------|
| **Prompt Disclosure** | System prompt leakage via translation, repetition, reframing |
| **Capability Leakage** | Tool names, API schemas, internal function exposure |
| **Safety Bypass** | Roleplay, hypothetical, academic, completion tricks |
| **Credential Exposure** | API keys, tokens, internal URLs leaked in responses |
| **Multi-turn Escalation** | Crescendo-style attacks that build trust over turns |
| **Indirect Injection** | Malicious payloads embedded in uploaded files |
| **Harmful Content** | Phishing, malware generation, disinformation |
| **Unauthorized Actions** | Privilege escalation, data exfiltration prompts |
| **Multimodal Attacks** | Steganographic images, adversarial audio, hidden document layers |

## Multimodal Attack Engine

AICU generates 151 advanced adversarial payloads across vision, audio, and document modalities — no model access required.

### Vision (48 payloads)

| Technique | Description |
|-----------|-------------|
| **LSB Steganography** | Instructions encoded in least-significant bits of pixel data |
| **Opacity Overlay** | Text composited at 2-5% alpha (invisible to humans, detected by VLMs) |
| **EXIF/XMP Injection** | Payloads in image metadata fields parsed by LLM pipelines |
| **Split Payload** | Instructions distributed across multiple images that reassemble in context |

### Audio (36 payloads)

| Technique | Description |
|-----------|-------------|
| **Whisper Underlay** | Commands whispered at -30 to -40dB beneath foreground speech |
| **Universal Mute** | Adversarial segments that suppress or hijack ASR transcription |
| **Frequency Hiding** | FSK/spread-spectrum encoding in near-ultrasonic 15-20kHz band |

### Documents (67 payloads)

| Technique | Description |
|-----------|-------------|
| **Font Remap** | PDF ToUnicode CMap manipulation — displays benign text, extracts as injection |
| **White on White** | Invisible PDF layers: white text, 0.1pt font, off-page, zero-opacity |
| **DOCX Hidden XML** | Vanish property, deleted revisions, hidden bookmarks, SDT controls, comments |
| **Zero-Width Unicode** | Binary/4-bit encoding using invisible unicode characters in text |

```bash
# Generate all multimodal payloads
aicu multimodal

# Vision only
aicu multimodal --category vision

# Audio only
aicu multimodal --category audio

# Documents only
aicu multimodal --category documents

# Custom output directory
aicu multimodal --output-dir ./payloads_out
```

## How It Works

1. **Capture** a request to your LLM endpoint (Burp Suite, browser dev tools, curl)
2. **Save** it as a raw HTTP file
3. **Run** `aicu scan --request req.txt`
4. **Read** the HTML/JSON/Markdown report with findings and evidence

AICU establishes a baseline response, then fires YAML-driven payloads (single-turn, multi-turn, file-based) and uses a strict multi-layer evaluator to classify results with minimal false positives.

## Usage

```bash
# Full scan (recommended)
aicu scan --request req.txt

# Individual modes
aicu single-turn --request req.txt --best-of-n 10
aicu multi-turn --request req.txt
aicu safety --request req.txt --category safety_bypass
aicu indirect --request upload_req.txt
aicu multimodal --category vision

# With target profile
aicu scan --request req.txt --profile openai
```

## Burp Suite Integration

1. Capture a request in Burp (Proxy → HTTP history)
2. Right-click → Copy to file → save as `req.txt`
3. `aicu scan --request req.txt`

## CI/CD

```yaml
- name: LLM Security Scan
  run: aicu scan --request req.txt
  # Exit 0 = clean, 1 = confirmed findings, 2 = suspicious only
```

## Target Profiles

Built-in: `openai`, `anthropic`, `azure_openai`, `generic`

Custom via YAML:
```yaml
preset: openai
name: my_chatbot
response_path: choices[0].message.content
request_delay_ms: 200
```

## False Positive Reduction

No external LLM needed for evaluation. AICU uses:
- Payload echo detection
- Baseline similarity comparison
- Reflection/httpbin filtering
- Entropy analysis
- Refusal detection
- Tiered confidence scoring

## Output

Reports land in `runs/run_<timestamp>/`:
- `report.html` — interactive HTML report
- `results.json` — structured findings
- `report.md` — markdown summary
- `evidence/` — raw response captures

Multimodal payloads land in `runs/multimodal_<timestamp>/`:
- `payloads/` — organized by `category/technique/`
- `manifest.json` — full payload inventory with metadata
- `multimodal_summary.json` — generation summary

## Companion Tool

| Tool | Tests |
|------|-------|
| **AICU** | LLM applications (prompt injection, multimodal attacks, safety bypass) |
| [**AICU Agent**](https://github.com/Jake-Schoellkopf/aicu-agent) | MCP infrastructure (server probing, credential extraction, protocol attacks) |

## Install

```bash
pip install aicu-scanner    # from PyPI
# or
pip install -e .            # editable install from source
pip install -e ".[dev]"     # with test/lint tools
```

## Run Tests

```bash
pytest -v
```

## License

MIT
