# Installation Guide

## Requirements

- **Python 3.10+** (uses `dataclass(slots=True)` and modern type hints)
- **pip** for dependency management

## Quick Install

```bash
git clone https://github.com/Jake-Schoellkopf/aicu.git
cd aicu
python -m pip install -r requirements.txt
```

## Dependencies

| Package | Purpose |
|---------|---------|
| httpx | HTTP client for replaying requests |
| PyYAML | Loading payload definitions |
| rich | Terminal formatting |
| python-multipart | Multipart form parsing |
| pytest | Running unit tests |

## Verify Installation

```bash
python -m py_compile main.py
python main.py --help
```

## Optional: Web Dashboard

```bash
python web_ui.py
# Open http://127.0.0.1:8080
```

## Platform Notes

### Windows
- Works with Python from python.org, Microsoft Store, or scoop
- Ensure Python is on PATH

### Linux/macOS
```bash
python3 -m pip install -r requirements.txt
python3 main.py --help
```

## Upgrading

```bash
cd aicu
git pull origin main
python -m pip install -r requirements.txt --upgrade
```
