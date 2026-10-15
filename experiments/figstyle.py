"""Shared matplotlib style for the paper figures (IEEEtran conference, two columns, 8 pt captions).

Figures are drawn at their final printed size (one column = 3.5 in) in a Times-compatible serif
(STIX, bundled with matplotlib), so figure text matches the body text and is never scaled by
LaTeX. Fonts are embedded as Type 42 (TrueType) rather than Type 3, which IEEE PDF eXpress and
arXiv accept without complaint. Call `apply()` before importing pyplot; `save()` writes a
timestamp-free PDF for LaTeX and a PNG for the web reader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

COLUMN_IN = 3.5  # \columnwidth of IEEEtran conference = 252 pt
TEXT_IN = 7.16  # \textwidth = 516 pt

# Single-hue sequential ramp for ordinal scores 0-3 (light -> dark); N/A is a hatched neutral.
RAMP = ["#e6eef8", "#a9c4e4", "#4a7fbf", "#163d6b"]
INK_ON_RAMP = ["#1a1a1a", "#1a1a1a", "#ffffff", "#ffffff"]
NEUTRAL = "#f2f2f2"
NEUTRAL_EDGE = "#b8b8b8"
BLUE = "#2f5f9e"
LIGHT_BLUE = "#a9c4e4"
ACCENT = "#b2182b"
GRID = "#dcdcdc"
TEXT = "#333333"


def apply() -> None:
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["STIXGeneral", "Times New Roman", "Nimbus Roman", "DejaVu Serif"],
            "mathtext.fontset": "stix",
            "font.size": 7,
            "axes.titlesize": 7.5,
            "axes.labelsize": 7,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.5,
            "legend.fontsize": 6.5,
            "axes.linewidth": 0.5,
            "axes.edgecolor": TEXT,
            "axes.labelcolor": TEXT,
            "xtick.color": TEXT,
            "ytick.color": TEXT,
            "xtick.major.width": 0.5,
            "ytick.major.width": 0.5,
            "xtick.major.size": 2,
            "ytick.major.size": 2,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "legend.frameon": False,
            "hatch.linewidth": 0.4,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.hashsalt": "harnesswatch",
        }
    )


def save(fig: Any, out_dir: Path, stem: str) -> None:
    """PDF without timestamps (rebuilds are byte-stable) and a 300 dpi PNG for the web reader."""
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / f"{stem}.pdf", metadata={"CreationDate": None, "ModDate": None})
    fig.savefig(out_dir / f"{stem}.png", dpi=300, metadata={"Software": None})
