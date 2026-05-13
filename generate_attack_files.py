#!/usr/bin/env python3
"""
AICU File Attack Generator

Generates all attack files for file upload testing:
- Indirect prompt injection (txt, md, docx)
- Phantom zero-width character attacks (txt, md, docx)
- Markdown exfiltration (md, txt, docx)

Usage:
    python generate_attack_files.py [--output-dir DIR] [--type TYPE]

Examples:
    python generate_attack_files.py
    python generate_attack_files.py --output-dir ./my_attacks
    python generate_attack_files.py --type phantom
    python generate_attack_files.py --type indirect
    python generate_attack_files.py --type exfil
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from generators.indirect_injection_gen import generate_all_indirect_injection_files
from generators.phantom_gen import generate_phantom_files
from generators.markdown_exfil_gen import generate_exfil_files


def main():
    parser = argparse.ArgumentParser(description="AICU File Attack Generator")
    parser.add_argument(
        "--output-dir",
        default="attack_files",
        help="Base output directory (default: attack_files)",
    )
    parser.add_argument(
        "--type",
        choices=["all", "indirect", "phantom", "exfil"],
        default="all",
        help="Type of attack files to generate (default: all)",
    )
    args = parser.parse_args()

    base = Path(args.output_dir)
    total = 0

    if args.type in ("all", "indirect"):
        print("[+] Generating indirect prompt injection files...")
        files = generate_all_indirect_injection_files(base / "indirect_injection")
        print(f"    Generated {len(files)} files in {base / 'indirect_injection'}")
        total += len(files)

    if args.type in ("all", "phantom"):
        print("[+] Generating phantom zero-width character files...")
        files = generate_phantom_files(base / "phantom")
        print(f"    Generated {len(files)} files in {base / 'phantom'}")
        total += len(files)

    if args.type in ("all", "exfil"):
        print("[+] Generating markdown exfiltration files...")
        files = generate_exfil_files(base / "markdown_exfil")
        print(f"    Generated {len(files)} files in {base / 'markdown_exfil'}")
        total += len(files)

    print(f"\n[+] Total: {total} attack files generated in {base}/")
    print("\nUsage:")
    print("  1. Upload these files to the target application")
    print("  2. Ask the AI to analyze/summarize the uploaded document")
    print("  3. Observe whether the hidden instructions are followed")
    print(f"\nNote: For exfil tests, replace 'attacker.example.com' with your callback server.")


if __name__ == "__main__":
    main()
