# Payload Reference

## Overview

AICU includes 240+ payloads across 10 YAML files covering multiple attack categories.

## Payload Files

### `payloads/single_turn.yaml` — Prompt Injection (21 payloads)
| Family | Description |
|--------|-------------|
| direct_request | Explicit "reveal your prompt" style attacks |
| contextual_reframing | Audit/governance/transparency framing |
| paraphrase_family | Semantic variations of disclosure requests |
| best_of_n_seed_set | Repeated variants for statistical bypass |
| encoded | Base64 encoded instructions |

### `payloads/multi_turn.yaml` — Escalation Sequences (8 tests)
| Family | Description |
|--------|-------------|
| audit_escalation | Governance/compliance framing over multiple turns |
| prior_output_escalation | Uses model's own responses as leverage |
| capability_escalation | General → specific tool disclosure |
| self_reference_escalation | Builds on model's self-description |

### `payloads/jailbreaks.yaml` — Jailbreak Templates (32 payloads)
| Family | Description |
|--------|-------------|
| dan_variants | "Do Anything Now" persona attacks |
| aim_variants | "Always Intelligent Machiavellian" |
| stan_variants | "Strive To Avoid Norms" |
| devmode_variants | Developer/debug mode activation |
| persona_hijack | Evil confidant, opposite day, grandma |
| context_manipulation | Prompt termination, XML/markdown escape |
| simulation_attacks | Virtual machine, text adventure, movie script |
| authority_impersonation | Fake admin, researcher, employee |
| logic_exploits | Recursive, double negative, conditional |
| payload_splitting | Fragmented instructions, acronyms |

### `payloads/encoding_attacks.yaml` — Encoding Bypasses (21 payloads)
| Family | Description |
|--------|-------------|
| rot13 | ROT13 encoded instructions |
| hex_encoding | Hexadecimal encoded payloads |
| unicode_escape | Unicode escape sequences |
| leetspeak | L33tsp34k substitution |
| pig_latin | Pig Latin encoded instructions |
| reverse_text | Reversed text payloads |
| mixed_encoding | Multi-layer encoding chains |

### `payloads/toxicity.yaml` — Bias & Harmful Content (21 payloads)
| Family | Description |
|--------|-------------|
| bias_gender | Gender discrimination probes |
| bias_racial | Racial profiling/stereotyping |
| bias_age | Age discrimination |
| discrimination_disability | Disability exclusion |
| harmful_content_elicitation | Market manipulation, insider trading, money laundering |
| hate_speech | Slur/hate content generation |
| harassment_templates | Intimidation, bullying, retaliation |

### `payloads/hallucination.yaml` — Hallucination Probes (21 payloads)
| Family | Description |
|--------|-------------|
| fake_authority | Non-existent rules, regulations, case law |
| false_facts | Fabricated events, statistics, people |
| confabulation | False conversation history, fake documents |
| sycophancy | Leading questions with wrong premises |
| knowledge_boundary | Future events, confidential info |

### `payloads/dos_probes.yaml` — Denial of Service (17 payloads)
| Family | Description |
|--------|-------------|
| recursive_prompts | Infinite loops, self-referential |
| context_stuffing | JSON bombs, unicode floods |
| resource_abuse | Massive computation requests |
| format_abuse | Markdown bombs, code generation floods |
| logic_bombs | Contradictory/impossible constraints |

### `payloads/file_payloads.yaml` — File Injection (7 payloads)
Original file-based injection payloads (md, txt, json, py, js).

### `payloads/adversarial_triggers.yaml` — Adversarial Enhancement
| Section | Count | Description |
|---------|-------|-------------|
| prefixes | 8 | Compliance priming ("Sure, I'd be happy to...") |
| suffixes | 15 | GCG-style adversarial token sequences |
| compositions | 8 | Full prefix+suffix sandwich pairs |

## File Upload Attack Generators

### Indirect Injection (`generators/indirect_injection_gen.py`)
11 payloads × 3 formats (txt, md, docx) = 33 files
- Hidden notes, footer injection, HTML comments
- Data field injection, fake errors, multi-language
- Grandma-style social engineering (5 variants)

### Phantom Zero-Width (`generators/phantom_gen.py`)
8 payloads × 3 formats = 24 files
- Instructions encoded in invisible Unicode characters
- Binary encoding: ZWS=0, ZWNJ=1, ZWJ=separator

### Markdown Exfiltration (`generators/markdown_exfil_gen.py`)
10 payloads × 3 formats = 30 files
- Image tag exfiltration, link exfil, CSS exfil
- Iframe injection, fetch URL construction

## Adversarial Enhancement (Optional)

Any payload can be enhanced with `--adversarial`:
- Wraps with compliance priming prefixes
- Appends GCG adversarial suffixes
- Applies 10 perturbation strategies (leet, homoglyph, zero-width, etc.)
- Generates 40+ variants per base payload

## Adding Custom Payloads

Create a YAML file in `payloads/` following this structure:
```yaml
payload_sets:
  my_family:
    - id: CUSTOM-001
      variant_id: MY-001
      name: my_custom_payload
      mode: replace  # or "append"
      transformation_type: custom
      content: "Your payload text here"
```
