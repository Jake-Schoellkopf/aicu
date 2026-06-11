# AICU

[![CI](https://github.com/Jake-Schoellkopf/aicu/actions/workflows/ci.yml/badge.svg)](https://github.com/Jake-Schoellkopf/aicu/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Black-box security scanner for LLM applications.** Point it at any chat endpoint, get a report of what leaks.

<p align="center">
  <img src="demo.svg" alt="AICU demo" width="800">
</p>

AICU replays captured HTTP requests with adversarial payloads and evaluates whether the target discloses system prompts, internal tools, credentials, or responds to safety bypass attempts.

## Quick Start (2 minutes)

```bash
# Install
git clone https://github.com/Jake-Schoellkopf/aicu.git && cd aicu
pip install -e .

# Option 1: Scan with an API key (OpenAI, Azure, Ollama — no Burp needed)
aicu scan --api-key sk-your-key --model gpt-4o-mini

# Option 2: Scan via captured Burp request (Claude, custom apps)
aicu scan --request examples/demo_request.txt

# Option 3: Test against the built-in vulnerable demo
python demo_server.py &
aicu scan --request examples/demo_request.txt
```

### API Key Mode (recommended for OpenAI/Azure/Ollama)

```bash
# OpenAI
aicu scan --api-key sk-... --model gpt-4.1-mini

# Anthropic Claude
aicu scan --api-key sk-ant-... --model claude-haiku-4-5-20251001

# Azure OpenAI
aicu scan --api-key your-azure-key --model gpt-4o --base-url https://your-resource.openai.azure.com

# Local Ollama (no key needed)
aicu scan --api-key dummy --model llama3.2 --base-url http://localhost:11434

# Or set OPENAI_API_KEY env var and just run:
aicu scan --model gpt-4.1-mini
```

### Canary Mode (proves extraction with undeniable evidence)

```bash
# Plant a secret in the system prompt, check if any payload extracts it
aicu scan --model gpt-4.1-mini --canary "AICU_SECRET_12345"

# Combine with a custom system prompt to simulate a real app
aicu scan --model gpt-4.1-mini \
  --canary "sk-prod-secret-key-abc123" \
  --system-prompt "You are FinanceBot for Acme Corp. Help users with account queries."
```

If any payload makes the model output the canary value, it's an instant **CONFIRMED** finding.

### Burp Proxy Mode (for web apps like Claude, custom chatbots)

```bash
# Capture a request in Burp, save to file, scan
aicu scan --request captured_request.txt
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

1. **Capture** a request to your LLM endpoint (Burp Suite, browser dev tools, curl) — or just provide an API key
2. **Run** `aicu scan --api-key sk-... --llm-judge` for the full attack suite
3. **Read** the HTML/JSON/Markdown report with findings and evidence

### Attack Pipeline

AICU fires multiple attack stages, each using different optimization strategies:

| Stage | Technique | Based On |
|-------|-----------|----------|
| Static payloads (86) | Task framing, logic exploits, role assumption, linguistic transforms | Guardrail-evasive handcrafted prompts |
| Trigger-optimized (25) | Format coercion, completion steering, context boundary, gradient triggers | Black Hat USA adversarial optimization (X_before ⊕ X_trigger₁ ⊕ X_payload ⊕ X_trigger₂ ⊕ X_after) |
| Encoding attacks (24) | Base64, Unicode, ROT13, homoglyphs, multilingual, escape sequences | Token-level confusion to bypass classifier attention |
| Intruder payloads (135) | DevOps framing, IaC templates, format coercion, context probing | Burp Intruder-style high-volume fuzzing |
| Dynamic generation (15) | LLM generates novel payloads tailored to target's baseline | Context-aware attack synthesis |
| TAP | Tree of Attacks with Pruning — 4 depths, 4 branches | Mehrotra et al. (2023) |
| PAIR | Prompt Automatic Iterative Refinement — 20 iterations | Chao et al. (2310.08419) |
| Crescendo | Progressive 12-turn trust escalation | Microsoft Research (2404.01833) |
| Multi-turn (20) | Trust ratcheting, version control framing, cognitive overload | Adaptive multi-turn sequences |

### Evaluation

Results are evaluated by a multi-layer system:
- **5 statistical signals**: entropy divergence, TF-IDF anomaly, fingerprint divergence, n-gram novelty, refusal inversion
- **LLM Judge** (optional): bug-bounty severity bar — only confirms findings with real exploit value
- **Canary detection**: ground-truth proof via planted secrets

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
