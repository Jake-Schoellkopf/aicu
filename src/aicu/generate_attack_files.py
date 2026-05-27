#!/usr/bin/env python3
"""
AICU File Attack Generator

Generates all attack files for file upload testing:
- Indirect prompt injection (txt, md, docx)
- Phantom zero-width character attacks (txt, md, docx)
- Markdown exfiltration (md, txt, docx)

Optional:
- --adversarial: Wrap all payloads with GCG triggers and perturbations

Usage:
    python generate_attack_files.py [--output-dir DIR] [--type TYPE] [--adversarial]

Examples:
    python generate_attack_files.py
    python generate_attack_files.py --type phantom
    python generate_attack_files.py --type indirect --adversarial
    python generate_attack_files.py --adversarial --perturbations 10
"""
from __future__ import annotations

import argparse
from pathlib import Path


from .generators.indirect_injection_gen import generate_all_indirect_injection_files, INJECTION_PAYLOADS
from .generators.phantom_gen import generate_phantom_files, PHANTOM_PAYLOADS
from .generators.markdown_exfil_gen import generate_exfil_files, EXFIL_PAYLOADS
from .perturbation import generate_adversarial_variants


def generate_adversarial_files(output_dir: Path, n_perturbations: int = 5) -> int:
    """Generate adversarial variants of all payload types."""
    out = output_dir / "adversarial"
    out.mkdir(parents=True, exist_ok=True)

    count = 0

    # Collect all payload texts from all generators
    all_payloads = []
    for p in INJECTION_PAYLOADS:
        all_payloads.append({"id": p["id"], "name": p["name"], "text": p["text"]})
    for p in PHANTOM_PAYLOADS:
        all_payloads.append({"id": p["id"], "name": p["name"], "text": p["visible_text"]})
    for p in EXFIL_PAYLOADS:
        all_payloads.append({"id": p["id"], "name": p["name"], "text": p["text"]})

    for payload in all_payloads:
        variants = generate_adversarial_variants(
            payload["text"],
            n_perturbations=n_perturbations,
            include_triggers=True,
            include_perturbations=True,
        )

        for i, variant in enumerate(variants):
            filename = f"{payload['id']}_{payload['name']}_adv_{i:03d}.txt"
            (out / filename).write_text(variant, encoding="utf-8")
            count += 1

    return count


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
    parser.add_argument(
        "--adversarial",
        action="store_true",
        help="Also generate adversarial variants with GCG triggers and perturbations",
    )
    parser.add_argument(
        "--perturbations",
        type=int,
        default=5,
        help="Number of perturbation variants per payload (default: 5, used with --adversarial)",
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

    if args.adversarial:
        print(f"[+] Generating adversarial variants (perturbations={args.perturbations})...")
        adv_count = generate_adversarial_files(base, n_perturbations=args.perturbations)
        print(f"    Generated {adv_count} adversarial variant files in {base / 'adversarial'}")
        total += adv_count

    print(f"\n[+] Total: {total} attack files generated in {base}/")
    print("\nUsage:")
    print("  1. Upload these files to the target application")
    print("  2. Ask the AI to analyze/summarize the uploaded document")
    print("  3. Observe whether the hidden instructions are followed")
    if not args.adversarial:
        print("\nTip: Add --adversarial to also generate GCG trigger + perturbation variants")


if __name__ == "__main__":
    main()
