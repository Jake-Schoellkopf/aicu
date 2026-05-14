# Contributing

## Adding New Payloads

The easiest way to contribute is adding new payloads:

1. Create or edit a YAML file in `payloads/`
2. Follow the existing structure:
```yaml
payload_sets:
  family_name:
    - id: PREFIX-001
      variant_id: VARIANT-001
      name: descriptive_name
      mode: replace  # or "append"
      transformation_type: category_name
      content: "Your payload text"
```
3. Test it: `python main.py single-turn --request req.txt`

## Adding New Test Categories

1. Create a new module (e.g., `my_tests.py`)
2. Follow the pattern in `safety_bypass.py`:
   - Define test cases as dataclasses
   - Create an evaluator function
   - Create a runner function
3. Add a CLI command in `main.py`
4. Add tests in `tests/test_aicu.py`

## Adding File Upload Generators

1. Create a new generator in `generators/`
2. Follow the pattern in `generators/phantom_gen.py`:
   - Define payloads as a list of dicts
   - Create a `generate_*_files()` function returning `list[GeneratedFile]`
3. Register it in `generate_attack_files.py`

## Adding Perturbation Strategies

1. Open `perturbation.py`
2. Add a new function following the signature: `def my_strategy(text: str) -> str`
3. Add it to the `STRATEGIES` list

## Code Style

- Use `from __future__ import annotations` in every file
- Type hints on all function signatures
- `@dataclass(slots=True)` for data classes
- No external dependencies beyond requirements.txt

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
aicu/
├── main.py                 # CLI entry point
├── runner.py               # Scan orchestration
├── web_ui.py               # Web dashboard
├── generate_attack_files.py # File generator CLI
├── evaluator.py            # Evaluation engine
├── patterns.py             # Pattern detection
├── perturbation.py         # Mutation engine
├── mutations.py            # Single-turn mutations
├── multi_turn.py           # Multi-turn tests
├── safety_bypass.py        # Safety tests
├── parsing.py              # HTTP request parsing
├── replay.py               # Request replay
├── multipart.py            # Multipart handling
├── shared.py               # Shared utilities
├── models.py               # Data models
├── target_profile.py       # Target configuration
├── payload_loader.py       # YAML loader
├── reporter.py             # Markdown reports
├── html_reporter.py        # HTML reports
├── evidence.py             # Evidence storage
├── baseline.py             # Baseline capture
├── file_generators.py      # Original file gen
├── payloads/               # YAML payload definitions
├── generators/             # File upload generators
├── profiles/               # Target profile configs
├── tests/                  # Unit tests
└── docs/                   # Documentation
```
