"""One adapter per harness: image, local-model wiring, headless command, permission modes.

Every adapter talks to the project's Ollama container (`http://ollama:11434`). No vendor account
or real key is used (A16): where a harness insists on a key, it gets an obviously synthetic one.
Modes: `default` = the harness's out-of-the-box headless behaviour; `auto` = its documented
auto-approve / bypass switch. Flags and config keys are pinned in the harness profiles and
evidence/research/B*_observe_plan.md.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field

OLLAMA = "http://ollama:11434"
DUMMY_KEY = "hw-synthetic-not-a-key"
MODES = ("default", "auto")


@dataclass(frozen=True)
class Adapter:
    id: str
    image: str
    instruction_file: str
    tier: str  # A (white-box) | B (black-box)
    env: dict[str, str] = field(default_factory=dict)
    home_files: dict[str, str] = field(default_factory=dict)  # path under $HOME -> content

    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        raise NotImplementedError

    def environment(self, model: str) -> dict[str, str]:
        return {k: v.replace("{model}", model) for k, v in self.env.items()}

    def files(self, model: str) -> dict[str, str]:
        return {k: v.replace("{model}", model) for k, v in self.home_files.items()}


class ClaudeCode(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = [
            "claude",
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--verbose",
            "--max-turns",
            "25",
            "--model",
            model,
        ]
        return cmd + (["--dangerously-skip-permissions"] if mode == "auto" else [])


class GrokBuild(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = [
            "grok",
            "--no-auto-update",
            "-p",
            prompt,
            "-m",
            "local",
            "--output-format",
            "streaming-json",
        ]
        return cmd + (["--always-approve"] if mode == "auto" else [])


class Copilot(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = ["copilot", "-p", prompt, "--no-color"]
        return cmd + (["--allow-all-tools"] if mode == "auto" else [])


class OpenCode(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = ["opencode", "run", "-m", f"ollama/{model}", prompt]
        return cmd + (["--dangerously-skip-permissions"] if mode == "auto" else [])


class Codex(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-m",
            model,
            "-c",
            "model_provider=hw-ollama",
        ]
        if mode == "auto":
            cmd.append("--dangerously-bypass-approvals-and-sandbox")
        return [*cmd, prompt]


class Aider(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = [
            "aider",
            "--model",
            f"ollama_chat/{model}",
            "--message",
            prompt,
            "--no-check-update",
            "--analytics-disable",
            "--no-show-model-warnings",
            "--no-auto-commits",
            "--no-gitignore",
            "--no-pretty",
            "calc.py",
            "tests/test_calc.py",
        ]
        return cmd + (["--yes-always"] if mode == "auto" else [])


class QwenCode(Adapter):
    def command(self, prompt: str, mode: str, model: str) -> list[str]:
        cmd = ["qwen", "-p", prompt, "-m", model]
        return cmd + (["--yolo"] if mode == "auto" else [])


_GROK_CONFIG = f"""[models]
default = "local"

[model.local]
model = "{{model}}"
base_url = "{OLLAMA}/v1"
api_backend = "chat_completions"
api_key = "{DUMMY_KEY}"

[features]
remote_fetch = false

[cli]
auto_update = false
"""

_OPENCODE_CONFIG = json.dumps(
    {
        "$schema": "https://opencode.ai/config.json",
        "autoupdate": False,
        "share": "disabled",
        "provider": {
            "ollama": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Ollama",
                "options": {"baseURL": f"{OLLAMA}/v1"},
                "models": {"{model}": {"name": "{model}", "tools": True}},
            }
        },
    },
    indent=2,
)

_CODEX_CONFIG = f"""model_provider = "hw-ollama"

[model_providers.hw-ollama]
name = "Ollama"
base_url = "{OLLAMA}/v1"
wire_api = "responses"
"""

ADAPTERS: dict[str, Adapter] = {
    a.id: a
    for a in (
        ClaudeCode(
            "claude-code",
            "harnesswatch-bench-claude-code:2.1.300",
            "CLAUDE.md",
            "B",
            env={
                "ANTHROPIC_BASE_URL": OLLAMA,
                "ANTHROPIC_AUTH_TOKEN": DUMMY_KEY,
                "ANTHROPIC_MODEL": "{model}",
                "ANTHROPIC_DEFAULT_SONNET_MODEL": "{model}",
                "ANTHROPIC_DEFAULT_OPUS_MODEL": "{model}",
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": "{model}",
                "CLAUDE_CODE_SUBAGENT_MODEL": "{model}",
            },
        ),
        GrokBuild(
            "grok-build",
            "harnesswatch-bench-grok-build:1.0.52",
            "AGENTS.md",
            "B",
            env={"GROK_DISABLE_AUTOUPDATER": "1"},
            home_files={".grok/config.toml": _GROK_CONFIG},
        ),
        Copilot(
            "github-copilot",
            "harnesswatch-bench-github-copilot:1.0.98",
            ".github/copilot-instructions.md",
            "B",
            env={
                "COPILOT_PROVIDER_BASE_URL": f"{OLLAMA}/v1",
                "COPILOT_PROVIDER_TYPE": "openai",
                "COPILOT_MODEL": "{model}",
                "COPILOT_OFFLINE": "true",
            },
        ),
        OpenCode(
            "opencode",
            "harnesswatch-bench-opencode:1.19.0",
            "AGENTS.md",
            "A",
            env={"OPENCODE_DISABLE_AUTOUPDATE": "1"},
            home_files={".config/opencode/opencode.json": _OPENCODE_CONFIG},
        ),
        Codex(
            "codex-cli",
            "harnesswatch-bench-codex-cli:0.162.1",
            "AGENTS.md",
            "A",
            env={"OLLAMA_API_KEY": DUMMY_KEY},
            home_files={".codex/config.toml": _CODEX_CONFIG},
        ),
        Aider(
            "aider",
            "harnesswatch-bench-aider:0.86.2",
            "CONVENTIONS.md",
            "A",
            env={"OLLAMA_API_BASE": OLLAMA},
        ),
        QwenCode(
            "qwen-code",
            "harnesswatch-bench-qwen-code:0.25.1",
            "QWEN.md",
            "A",
            env={
                "OPENAI_BASE_URL": f"{OLLAMA}/v1",
                "OPENAI_API_KEY": DUMMY_KEY,
                "OPENAI_MODEL": "{model}",
            },
        ),
    )
}


def shell_command(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
