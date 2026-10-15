import importlib.util
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "gen_checklist_check", ROOT / "scripts" / "gen_checklist_check.py"
)
assert _spec and _spec.loader
gcc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gcc)


def test_checklist_validates() -> None:
    assert gcc.validate(ROOT) == []


def test_markdown_matches_yaml() -> None:
    md = (ROOT / gcc.CHECKLIST_MD).read_text(encoding="utf-8")
    assert md == gcc.render(ROOT), "run: uv run python scripts/gen_checklist_check.py --write"


def test_every_control_is_rendered() -> None:
    data = yaml.safe_load((ROOT / gcc.CHECKLIST_YAML).read_text(encoding="utf-8"))
    md = gcc.render(ROOT)
    assert 20 <= len(data["controls"]) <= 30
    for c in data["controls"]:
        assert f"### {c['id']} {c['title']}" in md


def _copy_tree(tmp: Path) -> Path:
    for rel in ("rules", "taxonomy"):
        shutil.copytree(ROOT / rel, tmp / rel)
    for rel in ("matrix/rubric.yaml", str(gcc.CHECKLIST_YAML), str(gcc.RQ3_JSON)):
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp / rel)
    return tmp


def _mutate(root: Path, fn) -> list[str]:  # type: ignore[no-untyped-def]
    path = root / gcc.CHECKLIST_YAML
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(data["controls"][0])
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return gcc.validate(root, check_commands=False)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda c: c["verify"]["rules"].append("HG-NOPE-999"), "HG-NOPE-999"),
        (
            lambda c: c["mappings"]["mas_airm"]["airmkit_controls"].append("AIRM-9.9-INVENTED"),
            "AIRM-9.9-INVENTED",
        ),
        (lambda c: c["mappings"]["mitre_atlas"].append("AML.T9999"), "AML.T9999"),
        (lambda c: c["mappings"]["owasp_agentic"].append("ASI99"), "ASI99"),
        (lambda c: c["mappings"]["owasp_llm_2025"].append("LLM99"), "LLM99"),
        # exists in the taxonomy, but not under any threat class GC-01 cites
        (lambda c: c["mappings"]["mitre_atlas"].append("AML.T0051.001"), "not supported"),
        (lambda c: c.update(statement="The organisation should do things."), "shall"),
        (lambda c: c["threats"].append("T99"), "T99"),
    ],
)
def test_validation_catches_bad_references(tmp_path: Path, mutation, expected: str) -> None:  # type: ignore[no-untyped-def]
    errors = _mutate(_copy_tree(tmp_path), mutation)
    assert any(expected in e for e in errors), errors


def test_command_check_rejects_unknown_subcommand_and_option() -> None:
    tree = gcc._command_tree()
    assert gcc.check_command("harnesswatch audit ci . -f sarif -o ci.sarif", tree) == []
    assert gcc.check_command("harnesswatch audit nope .", tree)
    assert gcc.check_command("harnesswatch audit ci . --bogus", tree)
    assert gcc.check_command("kubectl get pods", tree)
