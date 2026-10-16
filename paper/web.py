"""Build the web reader docs/paper/ from paper/main.tex (same text as the PDF).

A standalone page built by pandoc with paper/reader.html: masthead, abstract, a results strip whose
numbers come from paper/numbers.tex (generated from experiments/results/*.json), contents,
numbered sections, [n] citations linked to the references. The PDF and the PNG figures are copied
next to it, and mkdocs serves the folder at /paper/. Requires pandoc on PATH. Usage:
python3 web.py
"""

from __future__ import annotations

import html
import re
import shutil
import subprocess
import sys
from pathlib import Path

from md_mirror import flatten, title_author

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "docs" / "paper"
REPO_URL = "https://github.com/thanatchon36/harnesswatch"
PAPER_URL = "https://thanatchon36.github.io/harnesswatch/paper/"

# (research question, finding, detail) with \macro placeholders from numbers.tex.
RESULTS = [
    (
        "RQ2",
        r"\nHarnesses harnesses scored on 15 security-control dimensions",
        r"\nCellsScored evidence-linked cells; second rater quadratic κ = \kappaEOne",
    ),
    (
        "RQ3",
        r"\nIncCounted harness-level advisories and incidents, 2025" "\u2013" "2026",
        "each one re-checked against NVD or the GitHub advisory database",
    ),
    (
        "RQ4",
        r"\eTwoStratCiTwo of agent CI workflows grant write-scoped tokens",
        r"\eTwoStratMcpFive of agent config files declare repository MCP servers; "
        r"\eTwoReposAudited public repositories",
    ),
    (
        "RQ4",
        r"Auditor precision \eSixPrecision",
        r"95% CI \eSixPrecisionLo" "\u2013" r"\eSixPrecisionHi on a held-out labelled corpus",
    ),
    (
        "RQ5",
        r"Injection followed in \benchFollowAutoK/\benchFollowAutoN (auto) vs "
        r"\benchFollowDefaultK/\benchFollowDefaultN (default)",
        r"\nBenchRuns inert canary runs, \nBenchHarnesses harnesses, one small local model",
    ),
    (
        "RQ5",
        r"A gitignored secret reached the Claude Code transcript in "
        r"\benchClaudeImportK/\benchClaudeImportN runs",
        "through the documented @-import, not through model action",
    ),
    (
        "RQ5",
        r"Secret copied into harness state in \nResidueWithCopy of \nResidueHarnesses harnesses",
        r"readable by other local users in \nResidueReachable",
    ),
    (
        "RQ7",
        r"\nClaimsMatch of \nClaimsTested tested vendor claims matched",
        r"\nClaims documented claims; \nClaimsMismatch contradicted by observation",
    ),
]


def macros() -> dict[str, str]:
    text = (HERE / "numbers.tex").read_text(encoding="utf-8")
    return {
        m.group(1): m.group(2).replace("\\%", "%")
        for m in re.finditer(r"\\newcommand\{\\(\w+)\}\{([^}]*)\}", text)
    }


def expand(text: str, values: dict[str, str]) -> str:
    return re.sub(r"\\(\w+)", lambda m: values[m.group(1)], text)  # a missing macro fails


def pandoc(tex: str, args: list[str]) -> str:
    tmp = HERE / ".web.tex"
    tmp.write_text(tex, encoding="utf-8")
    try:
        return subprocess.run(
            ["pandoc", tmp.name, "--from=latex", "--to=html5", "--mathml", "--wrap=none", *args],
            cwd=HERE,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    main_tex = (HERE / "main.tex").read_text(encoding="utf-8")
    title, author = title_author(main_tex)
    preamble = main_tex.split("\\begin{document}")[0]
    abstract = (HERE / "sections" / "abstract.tex").read_text(encoding="utf-8")
    abstract = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", abstract, re.S)
    if abstract is None:
        raise SystemExit("no abstract in sections/abstract.tex")
    abstract_html = pandoc(
        preamble + "\\begin{document}\n" + abstract.group(1) + "\n\\end{document}\n", []
    )
    body = flatten(main_tex.replace("\\input{sections/abstract}", "").replace("\\maketitle", ""))
    page = pandoc(
        body,
        [
            f"--template={HERE / 'reader.html'}",
            "--standalone",
            "--citeproc",
            "--bibliography=refs.bib",
            "--resource-path=.:sections",
            "--number-sections",
            "--toc",
            "--toc-depth=1",
            f"--metadata=title:{title}",
            f"--metadata=author:{author}",
            "--metadata=pagetitle:harnesswatch: paper",
        ],
    )
    page = re.sub(
        r'<embed src="figures/([\w-]+)\.pdf"[^>]*/>', r'<img src="figures/\1.png" alt="" />', page
    )
    values = macros()
    items = "\n".join(
        f'<li class="r r-ref"><span class="r-id">{rq}</span>'
        f'<span class="r-text">{html.escape(expand(text, values))}'
        f"<small>{html.escape(expand(detail, values))}</small></span></li>"
        for rq, text, detail in RESULTS
    )
    version = re.search(
        r'^__version__ = "([^"]+)"',
        (ROOT / "src" / "harnesswatch" / "__init__.py").read_text(encoding="utf-8"),
        re.M,
    )
    if version is None:
        raise SystemExit("no __version__ in src/harnesswatch/__init__.py")
    meta = (
        f"<b>harnesswatch v{version.group(1)}</b> · {values['nHarnesses']} harnesses · "
        f"{values['nIncCounted']} incidents · {values['eTwoReposAudited']} public repositories · "
        f"{values['nBenchRuns']} benchmark runs · evidence labels [T] test, [D] docs, "
        "[3P] third party"
    )
    actions = (
        '<li><a href="paper.pdf">Download PDF</a></li>'
        f'<li><a href="{REPO_URL}">Source code</a></li>'
        '<li><a href="../">Documentation</a></li>'
        f'<li><a href="{REPO_URL}/blob/main/brief/executive-brief.pdf">Executive brief</a></li>'
        f'<li><a href="{REPO_URL}/blob/main/brief/governance-checklist.md">Governance checklist</a></li>'
    )
    bib = (
        "@misc{chongmankhong2026harness,\n"
        "  author = {Chongmankhong, Thanatchon},\n"
        f"  title  = {{{title.replace('\u2013', '--')}}},\n"
        "  year   = {2026},\n"
        "  note   = {Preprint},\n"
        "  doi    = {10.5281/zenodo.23407630},\n"
        f"  url    = {{{PAPER_URL}}}\n"
        "}"
    )
    cite = f"<h2>How to cite</h2><pre><code>{html.escape(bib)}</code></pre>"
    colophon = (
        "<p>Toolkit, experiments and manuscript draft by Claude (Anthropic) under the author's "
        "specification; the author is responsible for the content. Defensive research: inert "
        "canaries, synthetic secrets, public data only; no individual repository is named.</p>"
        "<p>Rendered from <code>paper/main.tex</code> by <code>make paper</code>. Every number "
        "comes from <code>experiments/results/*.json</code> through <code>paper/numbers.tex</code>; "
        "the PDF is authoritative.</p>"
    )
    for marker, value in (
        ("<!--ABSTRACT-->", abstract_html),
        ("<!--META-->", meta),
        ("<!--ACTIONS-->", actions),
        ("<!--RESULTS-NOTE-->", "Headline numbers, generated from the results files."),
        ("<!--RESULTS-->", items),
        ("<!--CITE-->", cite),
        ("<!--COLOPHON-->", colophon),
    ):
        if marker not in page:
            raise SystemExit(f"reader.html lacks {marker}")
        page = page.replace(marker, value)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "index.html").write_text(page, encoding="utf-8")
    shutil.copyfile(HERE / "main.pdf", OUT / "paper.pdf")
    (OUT / "figures").mkdir(exist_ok=True)
    for name in sorted(set(re.findall(r'src="figures/([\w.-]+)"', page))):
        shutil.copyfile(HERE / "figures" / name, OUT / "figures" / name)
    print(f"wrote {OUT / 'index.html'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
