# RELEASE_CHECKLIST.md: steps only the author can take

Everything below is prepared and committed. Each step is an irreversible or public action (MISSION hard blocker 2),
so it is left to you. Run the commands in order from a clean clone of this repository.

## 0. Pre-flight (local, safe)
```bash
git status                      # clean
make all                        # lint -> types -> tests (>=85% cov) -> docs -> experiments -> paper -> build
ls dist/                        # harnesswatch-0.1.0-py3-none-any.whl, harnesswatch-0.1.0.tar.gz
```
- Read `reports/REVIEW.md`. It holds the hostile-review and code-review resolutions.
- Disclosure first: see §6. Nothing in the paper or repo describes the pending items.

## 1. Create the public GitHub repository
```bash
gh repo create thanatchon36/harnesswatch --public \
  --description "Security audit toolkit and research on AI coding-agent harnesses" --source . --remote origin
git push -u origin main
```
Then in repository settings:
- Pages: Source = GitHub Actions (the `docs.yml` workflow deploys the MkDocs site).
- Code security: enable private vulnerability reporting, which SECURITY.md points to.
- Add the secret `CODECOV_TOKEN` from codecov.io after adding the repository there; it drives the Codecov badge.
- Branch protection for `main`: require the `ci` checks.

Check that CI is green on ubuntu and macOS × Python 3.12 and 3.13, that the docs deploy, and that the badges in README.md resolve.

## 2. PyPI Trusted Publishing (one-time)
On https://pypi.org/manage/account/publishing/ add a pending publisher:
- project name: `harnesswatch`; owner: `thanatchon36`; repository: `harnesswatch`;
- workflow: `release.yml`; environment: `pypi`.

Create a GitHub environment named `pypi`, adding yourself as a required reviewer if you like.

## 2b. Zenodo (one-time, before step 3)
Zenodo archives a GitHub *release* and mints a DOI. It only sees releases published after the switch is on.
1. Log in at https://zenodo.org/account/settings/github/ (the same GitHub account as for cbtone).
2. Click **Sync now**, then turn on the switch next to `thanatchon36/harnesswatch`.
3. After step 3 creates the GitHub release, Zenodo reads `.zenodo.json` (title, description, keywords, link to the paper)
   and publishes the record. Copy the **concept DOI** (all versions) into `CITATION.cff` (`doi:`) and add the badge to README:
   `[![DOI](https://zenodo.org/badge/DOI/<concept-doi>.svg)](https://doi.org/<concept-doi>)`.

## 3. Signed release tag → PyPI publish
```bash
git tag -s v0.1.0 -m "harnesswatch 0.1.0"     # needs your GPG/SSH signing key
git tag -v v0.1.0
git push origin v0.1.0                          # triggers .github/workflows/release.yml -> PyPI
gh release create v0.1.0 dist/* paper/main.pdf brief/executive-brief.pdf \
  --title "harnesswatch 0.1.0" --notes-file <(sed -n '/## \[0.1.0\]/,/## \[/p' CHANGELOG.md | head -n -1)
```
Verify on a clean machine:
```bash
python3 -m venv /tmp/hw && /tmp/hw/bin/pip install harnesswatch==0.1.0
/tmp/hw/bin/harnesswatch inventory && /tmp/hw/bin/harnesswatch audit config .
```
The local clean-container check was 3.5 s cold and 0.8 s warm (PHASE_3).

## 4. arXiv
- Upload `paper/main.tex`, `paper/sections/`, `paper/tables/`, `paper/figures/*.pdf`, `paper/numbers.tex` and
  `paper/refs.bib` (or the compiled `.bbl`). Category: cs.CR. License: CC BY 4.0, or your choice.
- After you get the arXiv id, add it to `CITATION.cff` (`preferred-citation`) and to the README.

## 5. Announcement
`brief/announcement.md` is a LinkedIn draft. Fill in the links after steps 1–4. Nothing has been posted.

## 6. Coordinated disclosure: before or alongside publication
`private/DISCLOSURE_DRAFT.md` (gitignored, never pushed) holds 2 open items plus 1 closed:
1. Item 1 (a Tier-A harness, source reading; untested): see the private draft.
2. ~~Cline CLI workspace plugins~~: CLOSED, vendor-documented behaviour (A27). No report needed.
3. Item 3 (a Tier-B harness, local observation): did not reproduce in headless mode; interactive mode is untested. See the private draft.

For each: reproduce in a sandbox, then report through the vendor's channel (Continue: GitHub security advisory; Cline:
GitHub security advisory; Anthropic: HackerOne / security@anthropic.com). Public write-ups only after a fix or 90 days.

## 7. N/A harnesses (no access, recorded honestly)
These are `N/A (no access)` in ACCESS.md, VERSIONS.md and the matrix. If you obtain accounts later, `observe` and `bench`
adapters can be added. **Never put personal credentials into containers** (A05/A16).
- Antigravity (Google login; no local-model path; terms).
- Cursor CLI, Kiro CLI, Amp, Augment/Auggie, Jules, Windsurf/Devin Desktop.
- Factory Droid, Qoder: login is still enforced even with BYOK.
- Bench second model (llama3.1:8b): cancelled to free the shared GPU (A25). Run `bash bench/run_all.sh` once the GPU is free.
