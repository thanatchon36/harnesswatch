# Phase 7 — Release preparation

Date: 2026-10-15 · Spend: $0.00

## Done (local, reversible)
- Version 0.1.0 (`pyproject.toml`, `__version__`), with a CHANGELOG entry in Keep a Changelog format.
- README: badges (live once the public repo, CI, Codecov and docs exist), quickstart, command table, research summary, demo cast (`docs/demo.cast`, generated from real runs).
- `CITATION.cff`, `SECURITY.md`, `LICENSE` (Apache-2.0).
- CI and docs workflows pinned by SHA; `release.yml` publishes to PyPI with Trusted Publishing.
- `brief/announcement.md`: LinkedIn draft, not posted.
- **Clean-clone `make all` passes in 81 s.** The chain is lint → types → 352 tests (93% coverage) → docs → experiments regenerated → paper → wheel and sdist. Every results JSON, table and macro is byte-identical to the committed ones; only PDF timestamps differ.
  - It found and fixed: an undeclared `requests` import in E4, and over-broad `.gitignore` patterns that hid a test fixture and 8 E6 corpus files.
- Clean-container `pip install` of the wheel, then `inventory && audit config .`: 3.5 s cold, 0.8 s warm.

## Left for the author (irreversible or public): see RELEASE_CHECKLIST.md
Create the public GitHub repo and push; set up Pages and Codecov; add the PyPI trusted publisher; push the signed `v0.1.0` tag (which triggers the PyPI publish); create the GitHub release; submit to arXiv; post the announcement. Report the 2 pending disclosure items first.
