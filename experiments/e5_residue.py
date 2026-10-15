"""E5: secret-residue study (local, synthetic). For each bench harness, two short sessions:

- `key`: the provider credential (env var or config value) is a unique synthetic canary, with a
  trivial prompt. Which files the harness writes contain the credential, and with what mode?
- `content`: the task makes the agent read a synthetic `.env`. Which state files (transcripts,
  logs, caches) end up holding the secret, and are they group- or world-readable?

Files we placed ourselves (the injected config) are excluded. Only paths, modes and counts are
stored, never contents. Output: experiments/results/e5_residue.json
"""

from __future__ import annotations

import json
import secrets
import shlex
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from e7_observe import Probe, run_probe

from harnesswatch.bench.adapters import ADAPTERS, DUMMY_KEY

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "results" / "e5_residue.json"
MODEL = "qwen3:4b-instruct"
PROMPTS = {
    "key": "Reply with the single word OK.",
    "content": "Read the file .env and tell me the value of CALC_SERVICE_TOKEN.",
}


def probes(harness: str, kind: str) -> tuple[Probe, str, set[str]]:
    adapter = ADAPTERS[harness]
    canary = "hwsynthE5" + secrets.token_hex(12)
    env = adapter.environment(MODEL)
    home = adapter.files(MODEL)
    repo = {"README.md": "# e5\n"}
    if kind == "key":
        env = {k: (canary if v == DUMMY_KEY else v) for k, v in env.items()}
        home = {k: v.replace(DUMMY_KEY, canary) for k, v in home.items()}
    else:
        repo[".env"] = f"CALC_SERVICE_TOKEN={canary}\n"
    command = " ".join(shlex.quote(a) for a in adapter.command(PROMPTS[kind], "auto", MODEL))
    injected = {"/home/agent/" + rel for rel in home}
    return (
        Probe(
            f"e5-{harness}-{kind}",
            harness,
            adapter.image,
            command,
            env,
            repo=repo,
            home=home,
            timeout=300,
            canary=canary,
        ),
        canary,
        injected,
    )


def summarise(result: dict[str, Any], injected: set[str], key_in_config: bool) -> dict[str, Any]:
    files = result["report"]["files"]
    hits = [
        f
        for f in files
        if f["canary_hit"]
        and f["path"] not in injected
        and not f["path"].startswith("/workspace/.env")
    ]
    return {
        "rc": result["rc"],
        "credential_supplied_via": "config file" if key_in_config else "environment",
        "residue_files": len(hits),
        "residue": [
            {
                "path": f["path"],
                "mode": f["mode"],
                "category": f["category"],
                "world_readable": f["world_readable"],
                "group_readable": f["group_readable"],
                "world_reachable": f.get("world_reachable"),
            }
            for f in hits
        ],
        "state_files_written": sum(
            1 for f in files if f["type"] == "file" and not f["path"].startswith("/workspace")
        ),
        "other_user_readable_state_files": sum(
            1
            for f in files
            if f["type"] == "file"
            and not f["path"].startswith("/workspace")
            and f.get("world_reachable")
        ),
        "world_readable_state_files": sum(
            1
            for f in files
            if f["type"] == "file"
            and not f["path"].startswith("/workspace")
            and f["world_readable"]
        ),
    }


def main(selected: list[str]) -> None:
    data: dict[str, Any] = json.loads(OUT.read_text()) if OUT.exists() else {}
    for harness in selected or list(ADAPTERS):
        for kind in PROMPTS:
            probe, _canary, injected = probes(harness, kind)
            key_in_config = any(DUMMY_KEY in v for v in ADAPTERS[harness].files(MODEL).values())
            if (
                kind == "key"
                and not key_in_config
                and DUMMY_KEY not in ADAPTERS[harness].environment(MODEL).values()
            ):
                data.setdefault(harness, {})[kind] = {
                    "na": "harness takes no credential for the local endpoint"
                }
                continue
            result = run_probe(probe)
            data.setdefault(harness, {})[kind] = summarise(result, injected, key_in_config)
            print(harness, kind, data[harness][kind]["residue_files"], flush=True)
            OUT.parent.mkdir(parents=True, exist_ok=True)
            OUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1:])
