from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _test_rules_dir(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Point the CLI at test fixtures unless a test opts into the real rule pack."""
    if "real_rules" not in request.keywords:
        monkeypatch.setenv("HARNESSWATCH_RULES_DIR", str(DATA / "rules"))
