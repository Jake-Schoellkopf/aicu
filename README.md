# AICU — AI Capability & Vulnerability Scanner

AICU is a modular security testing framework designed to evaluate Large Language Model (LLM) applications and agents for prompt injection, policy disclosure, capability leakage, and indirect injection vulnerabilities.

It supports single-turn, multi-turn, and file-based attack patterns with a strict evaluation engine to reduce false positives.

---

## Features

- 🔹 Single-turn prompt injection testing
- 🔹 Multi-turn (Crescendo-style) escalation testing
- 🔹 Indirect file-based prompt injection
- 🔹 YAML-driven payload system (no hardcoding)
- 🔹 Best-of-N variant testing
- 🔹 Contextual reframing & paraphrase attacks
- 🔹 Strict evaluator with reflection filtering
- 🔹 Structured JSON + Markdown reporting
- 🔹 Evidence extraction for findings

---

## What AICU Tests For

- Hidden system prompt disclosure
- Internal policy or developer instruction leakage
- Tool / API / capability exposure
- Multi-turn escalation weaknesses
- Indirect prompt injection via file uploads
- Boundary slippage and excessive agency indicators

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/aicu.git
cd aicu
python -m pip install -r requirements.txt
```

---

## 🛠️ How to Use

### Baseline test
```bash
python main.py baseline --request req.txt
```

### Single-turn testing
```bash
python main.py single-turn --request req.txt
```

### Multi-turn testing
```bash
python main.py multi-turn --request req.txt
```

### Indirect file testing
```bash
python main.py indirect --request upload_req.txt
```

### Full scan (recommended)
```bash
python main.py scan --request req.txt
```

### Increase test intensity (Best-of-N)
```bash
python main.py single-turn --request req.txt --best-of-n 10
```

### Install dependencies
```bash
python -m pip install -r requirements.txt
```

### Validate code
```bash
python -m py_compile *.py
```

### Example workflow
```bash
python main.py baseline --request req.txt
python main.py scan --request req.txt
```

---

## 📁 Payload System

```text
payloads/
  single_turn.yaml
  multi_turn.yaml
  file_payloads.yaml
```

Each payload includes:
- family
- variant_id
- transformation_type

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
```

---

## 🏗️ Architecture

```text
parsing.py        → Parses raw HTTP request
replay.py         → Replays requests to target
baseline.py       → Establishes normal response
mutations.py      → Generates single-turn attacks
multi_turn.py     → Runs multi-turn escalation sequences
file_generators.py→ Creates malicious test files
multipart.py      → Injects files into upload requests
indirect_injection.py → Executes file-based attacks
patterns.py       → Detects indicators in responses
evaluator.py      → Strict classification (no FP-heavy results)
runner.py         → Orchestrates full scan
reporter.py       → Generates Markdown report
payload_loader.py → Loads YAML payloads
```

---

## 🔐 Important Notes

- Only test systems you are authorized to assess  
- Do not use against production systems without permission  
- This tool is intended for security research and defensive testing  

---

## 📜 License

MIT License