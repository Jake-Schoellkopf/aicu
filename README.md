# AICU — AI Capability & Vulnerability Scanner

AICU is a modular security testing framework designed to evaluate Large Language Model (LLM) applications and agents for prompt injection, policy disclosure, capability leakage, safety bypass, and indirect injection vulnerabilities.

It supports single-turn, multi-turn, file-based, and safety bypass attack patterns with a strict evaluation engine to reduce false positives.

**Requires Python 3.10+**

---

## Features

- 🔹 Single-turn prompt injection testing
- 🔹 Multi-turn (Crescendo-style) escalation testing with assistant response threading
- 🔹 Indirect file-based prompt injection
- 🔹 Safety bypass, harmful content, and unauthorized action testing
- 🔹 YAML-driven payload system (no hardcoding)
- 🔹 Best-of-N variant testing
- 🔹 Contextual reframing & paraphrase attacks
- 🔹 Strict evaluator with multi-layer false positive reduction
- 🔹 Target profiles (OpenAI, Anthropic, Azure, custom)
- 🔹 Structured JSON + Markdown + Interactive HTML reporting
- 🔹 CI/CD exit codes for pipeline gating
- 🔹 Evidence extraction for findings
- 🔹 Exponential backoff and rate limiting

---

## What AICU Tests For

- Hidden system prompt disclosure
- Internal policy or developer instruction leakage
- Tool / API / capability exposure
- Multi-turn escalation weaknesses
- Indirect prompt injection via file uploads
- Safety bypass (roleplay, hypothetical, academic, translation, completion)
- Harmful content generation (phishing, malware, disinformation)
- Unauthorized actions (privilege escalation, data exfiltration, instruction override)
- Boundary slippage and excessive agency indicators

---

## 📦 Installation

```bash
git clone https://github.com/Jake-Schoellkopf/aicu.git
cd aicu
python -m pip install -r requirements.txt
```

**Requirements:** Python 3.10 or higher (uses `dataclass(slots=True)` and modern type hints).

---

## 🛠️ How to Use

### Baseline test
```bash
python main.py baseline --request req.txt
```

### Single-turn testing
```bash
python main.py single-turn --request req.txt
python main.py single-turn --request req.txt --best-of-n 10
```

### Multi-turn testing
```bash
python main.py multi-turn --request req.txt
```

### Safety bypass testing
```bash
python main.py safety --request req.txt
python main.py safety --request req.txt --category safety_bypass
python main.py safety --request req.txt --category harmful_content
python main.py safety --request req.txt --category unauthorized_action
```

### Indirect file testing
```bash
python main.py indirect --request upload_req.txt
```

### Full scan (recommended)
```bash
python main.py scan --request req.txt
```

### With a target profile
```bash
python main.py single-turn --request req.txt --profile openai
python main.py multi-turn --request req.txt --profile anthropic
python main.py safety --request req.txt --profile profiles/example.yaml
```

---

## 🔌 Burp Suite Integration

1. Capture a request in Burp (Proxy → HTTP history)
2. Right-click → Copy to file → save as `req.txt`
3. Run AICU against it:
```bash
python main.py scan --request req.txt
```

For file upload endpoints, capture the multipart request and use:
```bash
python main.py indirect --request upload_req.txt
```

---

## 📁 Payload System

```text
payloads/
  single_turn.yaml    # Direct, contextual, paraphrase, best-of-N, encoded
  multi_turn.yaml     # Escalation sequences
  file_payloads.yaml  # Indirect injection via file uploads
```

Each payload includes:
- family
- variant_id
- transformation_type

---

## 🎯 Target Profiles

Built-in presets: `openai`, `anthropic`, `azure_openai`, `generic`

Custom profiles via YAML:
```yaml
preset: openai
name: my_internal_chatbot
response_path: choices[0].message.content
conversation_id_field: id
conversation_id_inject: conversation_id
request_delay_ms: 200
max_retries: 3
```

See `profiles/example.yaml` for full documentation.

---

## 🚦 CI/CD Integration

AICU returns exit codes for pipeline gating:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Clean — no findings |
| `1` | Confirmed findings detected |
| `2` | Suspicious findings only |

```yaml
# GitHub Actions example
- name: Run AICU security scan
  run: python main.py scan --request req.txt
```

---

## 📊 Output

```text
runs/
  run_<timestamp>/
    baseline.json
    results.json
    multi_turn_results.json
    indirect_results.json
    report.md
    report.html          # Interactive HTML report
    evidence/
    multi_turn_evidence/
    indirect_evidence/
```

---

## 🛡️ False Positive Reduction

AICU uses multiple layers to minimize false positives without requiring an external LLM:

1. **Payload echo detection** — filters responses that just repeat the injected payload
2. **Baseline similarity** — filters responses that didn't materially change from normal behavior
3. **Reflection filtering** — detects echo endpoints (httpbin-style) that reflect request data
4. **Entropy analysis** — validates that flagged responses have higher information density than baseline
5. **Refusal detection** — distinguishes refusals that mention sensitive terms from actual leaks
6. **Tiered confidence** — requires strong evidence for "confirmed", downgrades weak signals

---

## 🏗️ Architecture

```text
main.py               → CLI entry point
runner.py             → Orchestrates full scan
parsing.py            → Parses raw HTTP requests
replay.py             → Replays requests with backoff/retry
baseline.py           → Establishes normal response
mutations.py          → Generates single-turn attacks
multi_turn.py         → Runs multi-turn escalation sequences
safety_bypass.py      → Safety bypass / harmful content / unauthorized action tests
file_generators.py    → Creates malicious test files
multipart.py          → Injects files into upload requests
indirect_injection.py → Executes file-based attacks
patterns.py           → Detects indicators in responses
evaluator.py          → Strict classification with FP reduction
structured_evaluator.py → JSON/XML/tool call evaluation
target_profile.py     → Target API configuration
reporter.py           → Generates Markdown report
html_reporter.py      → Generates interactive HTML report
payload_loader.py     → Loads YAML payloads
perturbation.py       → Adversarial mutation engine
shared.py             → Shared utilities
evidence.py           → Evidence storage
web_ui.py             → Web dashboard (port 8080)
codebase_scanner.py   → Scan repos for hidden AI instructions (NEW)
code_auditor.py       → Detect planted vulns in AI-generated code (NEW)
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## 🔐 Important Notes

- Only test systems you are authorized to assess
- Do not use against production systems without permission
- This tool is intended for security research and defensive testing

---

## 🤖 Companion Tool: AICU Agent

For MCP (Model Context Protocol) server security testing, see [**aicu-agent**](https://github.com/Jake-Schoellkopf/aicu-agent) — adaptive MCP server probing, exploit chaining, LLM-based extraction, and honeypot detection.

| Tool | What it tests |
|------|--------------|
| **AICU** | LLM applications (prompt injection, file upload, safety bypass) |
| **AICU Agent** | MCP infrastructure (server probing, credential extraction, protocol attacks) |

---

## 📜 License

MIT License
