"""Record docs/demo.cast (asciinema v2) from real CLI runs on the bundled demo repository.

No asciinema binary is needed: each command runs for real and its output is written as timed events.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = [
    "harnesswatch version",
    "harnesswatch audit repo tests/data/repo_demo",
    "harnesswatch audit repo tests/data/repo_demo -f sarif -o /tmp/hw-demo.sarif",
    "harnesswatch bench list",
]


def main() -> None:
    env = {**os.environ, "COLUMNS": "110", "TERM": "xterm-256color", "FORCE_COLOR": "1"}
    events: list[list[object]] = []
    t = 0.5
    for cmd in COMMANDS:
        events.append([round(t, 2), "o", f"\x1b[32m$\x1b[0m {cmd}\r\n"])
        t += 0.8
        proc = subprocess.run(
            ["uv", "run", *cmd.split()],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        for line in (proc.stdout + proc.stderr).splitlines():
            events.append([round(t, 2), "o", line + "\r\n"])
            t += 0.03
        t += 1.2
    header = {"version": 2, "width": 110, "height": 32, "title": "harnesswatch demo"}
    out = ROOT / "docs" / "demo.cast"
    out.write_text("\n".join([json.dumps(header), *(json.dumps(e) for e in events)]) + "\n")
    print(f"{len(events)} events -> {out}")


if __name__ == "__main__":
    main()
