from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .payload_loader import load_file_payloads


from aicu import PAYLOADS_DIR

DEFAULT_FILE_PAYLOADS_PATH = PAYLOADS_DIR / "file_payloads.yaml"


@dataclass(slots=True)
class GeneratedTestFile:
    test_id: str
    name: str
    family: str
    transformation_type: str
    file_type: str
    file_path: Path
    prompt_text: str


def ensure_output_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate_test_file(
    payload: dict,
    output_dir: str | Path,
) -> GeneratedTestFile:
    output_path = ensure_output_dir(output_dir)

    file_type = str(payload["type"])
    file_name = f"{payload['id']}.{file_type}"
    file_path = output_path / file_name

    rendered = str(payload["content"])
    file_path.write_text(rendered, encoding="utf-8")

    return GeneratedTestFile(
        test_id=str(payload["id"]),
        name=str(payload["name"]),
        family=str(payload.get("family", "unknown")),
        transformation_type=str(payload.get("transformation_type", "unknown")),
        file_type=file_type,
        file_path=file_path,
        prompt_text=rendered,
    )


def generate_all_test_files(
    output_dir: str | Path,
    payloads_path: str | Path = DEFAULT_FILE_PAYLOADS_PATH,
) -> list[GeneratedTestFile]:
    payloads = load_file_payloads(payloads_path)
    generated: list[GeneratedTestFile] = []

    for payload in payloads:
        generated.append(generate_test_file(payload, output_dir))

    return generated