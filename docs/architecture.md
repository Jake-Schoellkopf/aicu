# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        AICU                                   │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│   Input     │   Engine     │  Evaluation  │    Output       │
├─────────────┼──────────────┼──────────────┼─────────────────┤
│ parsing.py  │ mutations.py │ evaluator.py │ reporter.py     │
│ replay.py   │ multi_turn.py│ patterns.py  │ html_reporter.py│
│ payload_    │ safety_      │ perturbation │ evidence.py     │
│  loader.py  │  bypass.py   │  .py         │                 │
│             │ generators/  │              │                 │
├─────────────┴──────────────┴──────────────┴─────────────────┤
│                    Orchestration                              │
│              main.py / runner.py / web_ui.py                 │
├──────────────────────────────────────────────────────────────┤
│                    Configuration                             │
│         payloads/*.yaml / profiles/*.yaml                    │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Raw HTTP Request (req.txt)
    │
    ▼
parsing.py ──► ParsedRequest (method, headers, body, mutation_points)
    │
    ▼
baseline.py ──► Baseline response (normal behavior)
    │
    ├──► mutations.py ──► Mutated requests (payload injected)
    ├──► multi_turn.py ──► Multi-turn sequences
    ├──► safety_bypass.py ──► Safety test payloads
    │
    ▼
replay.py ──► Send to target (with backoff/retry)
    │
    ▼
evaluator.py ──► EvaluationResult (none/suspicious/confirmed)
    │   ├── Payload echo detection
    │   ├── Baseline similarity check
    │   ├── Pattern analysis (patterns.py)
    │   ├── Reflection filtering
    │   └── Entropy analysis
    │
    ▼
reporter.py / html_reporter.py ──► Reports (MD + HTML)
```

## Module Responsibilities

### Input Layer
| Module | Purpose |
|--------|---------|
| `parsing.py` | Parse raw HTTP requests, detect mutation points |
| `replay.py` | Send requests to target with retry/backoff |
| `payload_loader.py` | Load YAML payload definitions |
| `target_profile.py` | Target API configuration (response paths, auth refresh) |

### Engine Layer
| Module | Purpose |
|--------|---------|
| `mutations.py` | Generate single-turn payload mutations |
| `multi_turn.py` | Multi-turn escalation with assistant response threading |
| `safety_bypass.py` | Safety bypass, harmful content, unauthorized action tests |
| `perturbation.py` | Token-level mutation engine (10 strategies) |
| `generators/` | File upload attack generators (indirect, phantom, exfil) |
| `multipart.py` | Multipart form-data manipulation |
| `file_generators.py` | Original file payload generator |

### Evaluation Layer
| Module | Purpose |
|--------|---------|
| `evaluator.py` | Main evaluation logic with FP reduction |
| `patterns.py` | Regex + structural + entropy pattern detection |

### Output Layer
| Module | Purpose |
|--------|---------|
| `reporter.py` | Markdown report generation |
| `html_reporter.py` | Interactive HTML report |
| `evidence.py` | Individual finding evidence storage |

### Orchestration
| Module | Purpose |
|--------|---------|
| `main.py` | CLI entry point, argument parsing |
| `runner.py` | Full scan orchestration |
| `web_ui.py` | Web dashboard (port 8080) |
| `generate_attack_files.py` | File attack generation CLI |
| `shared.py` | Shared utilities (clone_request, serializers) |

## Key Design Decisions

1. **Raw HTTP input** — Works with any HTTP endpoint, not just SDK-based APIs
2. **YAML-driven payloads** — Extensible without code changes
3. **Tiered evaluation** — Strong/medium/weak indicators prevent false positives
4. **Modular architecture** — Each module is independently testable
5. **No external LLM dependency** — All evaluation is local (regex + heuristics)
6. **Optional adversarial enhancement** — Can be applied to any payload family
7. **Profile system** — Adapts to different API response formats

## False Positive Reduction Pipeline

```
Response received
    │
    ├── 1. Payload echo? (>50% n-gram overlap → FP)
    ├── 2. Baseline similar? (>85% Jaccard → FP)
    ├── 3. Reflection endpoint? (httpbin-style → FP)
    ├── 4. Refusal with mention? (mentions but refuses → downgrade)
    └── 5. Entropy check (supports/weakens confidence)
    │
    ▼
Final classification: none / suspicious / confirmed
```
