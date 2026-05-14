# Usage Guide

## Workflow Overview

1. **Capture** a request in Burp Suite (or write one manually)
2. **Save** it as a raw HTTP request file (e.g., `req.txt`)
3. **Run** AICU against it
4. **Review** findings in the HTML report

## Capturing Requests

### From Burp Suite
1. Proxy → HTTP history → find the LLM chat request
2. Right-click → Copy to file → save as `req.txt`

### Manual Request File
```
POST /api/chat HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer sk-...

{"messages":[{"role":"user","content":"hello"}]}
```

## Running Scans

### Full Scan (recommended)
```bash
python main.py scan --request req.txt
```

### Individual Test Types
```bash
python main.py baseline --request req.txt
python main.py single-turn --request req.txt
python main.py multi-turn --request req.txt
python main.py safety --request req.txt
python main.py indirect --request req.txt  # multipart only
```

### Options
```bash
# Increase best-of-N repetitions
python main.py single-turn --request req.txt --best-of-n 10

# Use a target profile
python main.py scan --request req.txt --profile openai

# Filter safety tests by category
python main.py safety --request req.txt --category safety_bypass
python main.py safety --request req.txt --category harmful_content
python main.py safety --request req.txt --category unauthorized_action
```

## Generating Attack Files

For file upload testing:

```bash
# Generate all attack files (72 base files)
python generate_attack_files.py

# Specific type only
python generate_attack_files.py --type phantom
python generate_attack_files.py --type indirect
python generate_attack_files.py --type exfil

# With adversarial triggers (1300+ files)
python generate_attack_files.py --adversarial

# Control perturbation count
python generate_attack_files.py --adversarial --perturbations 10
```

## Target Profiles

### Built-in Presets
```bash
python main.py scan --request req.txt --profile openai
python main.py scan --request req.txt --profile anthropic
python main.py scan --request req.txt --profile azure_openai
```

### Custom Profile
Create a YAML file (see `profiles/example.yaml`):
```yaml
preset: openai
name: my_chatbot
response_path: choices[0].message.content
request_delay_ms: 200
```

Then use it:
```bash
python main.py scan --request req.txt --profile my_profile.yaml
```

## Viewing Results

### Output Directory
```
runs/run_<timestamp>/
├── baseline.json          # Baseline response
├── results.json           # Single-turn results
├── multi_turn_results.json
├── indirect_results.json
├── report.md              # Markdown report
├── report.html            # Interactive HTML report
├── evidence/              # Individual finding evidence
├── multi_turn_evidence/
└── indirect_evidence/
```

### HTML Report
Open `runs/run_<timestamp>/report.html` in a browser. Features:
- Summary statistics
- Filter by test type
- Color-coded severity
- Evidence display

### Web Dashboard
```bash
python web_ui.py
# Open http://127.0.0.1:8080
```

## CI/CD Integration

AICU returns exit codes:
| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | Confirmed findings |
| 2 | Suspicious only |

```yaml
# GitHub Actions
- run: python main.py scan --request req.txt
```

## Tips

- **Session expiry**: If you get 401/403 errors, recapture a fresh request from Burp
- **Rate limiting**: AICU has built-in exponential backoff (3 retries)
- **Large scans**: Use `--best-of-n 1` for faster initial sweeps
- **Multipart targets**: The `indirect` command requires a multipart/form-data request
- **Streaming responses**: AICU handles SSE (Server-Sent Events) responses automatically
