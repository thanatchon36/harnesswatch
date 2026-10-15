"""E5 table (offline): experiments/results/e5_residue.json -> paper/tables/e5_residue.tex|md."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rows() -> list[list[str]]:
    data = json.loads((ROOT / "experiments" / "results" / "e5_residue.json").read_text())
    out = []
    for harness, kinds in sorted(data.items()):
        content, key = kinds.get("content", {}), kinds.get("key", {})
        residue = content.get("residue", [])
        cats = sorted({r["category"] for r in residue})
        modes = sorted({r["mode"].replace("0o", "") for r in residue})
        reach = sum(1 for r in residue if r.get("world_reachable"))
        out.append(
            [
                harness,
                str(content.get("residue_files", "--")),
                "/".join(cats) or "--",
                "/".join(modes) or "--",
                str(reach),
                "n/a" if "na" in key else str(key.get("residue_files", "--")),
                f"{content.get('other_user_readable_state_files', '--')}/{content.get('state_files_written', '--')}",
            ]
        )
    return out


HEADER = [
    "Harness",
    "Files w/ secret",
    "Kind",
    "Mode",
    "Reach.",
    "Cred.",
    "o+r state",
]


def main() -> None:
    body = rows()
    md = ["| " + " | ".join(HEADER) + " |", "|" + "---|" * len(HEADER)]
    md += ["| " + " | ".join(r) + " |" for r in body]
    tex = ["\\begin{tabular}{lrllrrr}", "\\toprule", " & ".join(HEADER) + " \\\\", "\\midrule"]
    tex += [" & ".join(c.replace("_", "\\_") for c in r) + " \\\\" for r in body]
    tex += ["\\bottomrule", "\\end{tabular}"]
    out = ROOT / "paper" / "tables"
    out.mkdir(parents=True, exist_ok=True)
    (out / "e5_residue.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / "e5_residue.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    print(f"{len(body)} harnesses -> {out / 'e5_residue.tex'}")


if __name__ == "__main__":
    main()
