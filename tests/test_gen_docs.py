import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "scripts" / "gen_docs.py")
assert _spec and _spec.loader
gen_docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_docs)

SCEN = [("control", "No injection | baseline", "-")]


def test_generated_pages_cover_sources() -> None:
    pages = {p.name: c for p, c in gen_docs.generate(ROOT, SCEN).items()}
    assert set(pages) == {"rules.md", "profiles.md", "taxonomy.md", "bench-scenarios.md"}
    rule_ids = [p.stem for p in (ROOT / "rules").glob("HG-*.yaml")]
    assert rule_ids and all(f"## {rid}" in pages["rules.md"] for rid in rule_ids)
    profile_ids = [p.stem for p in (ROOT / "rules" / "harness_profiles").glob("*.yaml")]
    assert all(f"`{pid}`" in pages["profiles.md"] for pid in profile_ids)
    assert "### T01" in pages["taxonomy.md"]
    assert "No injection \\| baseline" in pages["bench-scenarios.md"]


def test_generation_is_deterministic() -> None:
    assert gen_docs.generate(ROOT, SCEN) == gen_docs.generate(ROOT, SCEN)


def test_cell_escapes_pipes_and_empty() -> None:
    assert gen_docs._cell("a|b\nc") == "a\\|b c"
    assert gen_docs._cell(None) == "-"
