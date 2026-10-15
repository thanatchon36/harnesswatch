"""Command-line interface."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from harnesswatch import __version__
from harnesswatch import audits as audits_mod
from harnesswatch.audits import AUDITS, REPO_AUDITS, AuditOptions, AuditResult, supply
from harnesswatch.inventory import run_inventory
from harnesswatch.models import Severity
from harnesswatch.report import (
    apply_baseline,
    load_json,
    load_report,
    plain,
    print_rich,
    to_json,
    to_markdown,
    to_sarif,
)
from harnesswatch.resources import load_profiles
from harnesswatch.rules_engine import at_or_above, load_rules


class OutputFormat(StrEnum):
    rich = "rich"
    json = "json"
    markdown = "markdown"
    sarif = "sarif"


class SafeGroup(TyperGroup):
    """Keep the exit-code contract (0 clean, 1 findings, 2 error) for unexpected exceptions.

    Without this a crash exits 1, which CI wrappers read as "findings found".
    """

    def invoke(self, ctx: Any) -> Any:  # typer.Context (vendored click)
        try:
            return super().invoke(ctx)
        except (typer.TyperException, typer.Exit, typer.Abort):  # usage errors, exits
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}".splitlines()[0][:300]
            typer.echo(f"error: {message}", err=True)
            raise typer.Exit(2) from exc


app = typer.Typer(
    cls=SafeGroup,
    no_args_is_help=True,
    help="Security audit toolkit for AI coding-agent harnesses.",
)
console = Console()


@app.callback()
def main() -> None:
    """harnesswatch: audit AI coding-agent harness configuration and behaviour."""


@app.command()
def version() -> None:
    """Print the harnesswatch version."""
    typer.echo(__version__)


@app.command()
def inventory(
    repo: Annotated[Path, typer.Argument(help="Repository to scan for harness files.")] = Path(),
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    exec_version: Annotated[
        bool, typer.Option(help="Run `<binary> --version` when no static version is found.")
    ] = False,
) -> None:
    """Detect installed harnesses (PATH, state dirs, login state) and harness files in REPO."""
    items = run_inventory(load_profiles(), repo.resolve(), run_versions=exec_version)
    if as_json:
        typer.echo(json.dumps([i.model_dump() for i in items], indent=2))
        return
    table = Table(title="Harness inventory")
    for column in ("harness", "binary", "version", "install", "state dirs", "login", "repo files"):
        table.add_column(column)
    for item in items:
        binary = item.binaries[0] if item.binaries else None
        state = ", ".join(
            f"{d.path} ({d.mode}{' world-readable' if d.world_readable else ''})"
            for d in item.state_dirs
        )
        table.add_row(
            item.name,
            binary.path if binary else "-",
            (binary.version or "?") if binary else "-",
            binary.install_method if binary else "-",
            state or "-",
            "credentials present" if item.credential_files else "-",
            ", ".join(item.repo_files) or "-",
        )
    console.print(table)


# ---------------------------------------------------------------- audits

audit_app = typer.Typer(
    no_args_is_help=True, help="Run static audits (read-only, offline by default)."
)
app.add_typer(audit_app, name="audit")

FormatOpt = Annotated[
    OutputFormat, typer.Option("--format", "-f", help="Output format.", case_sensitive=False)
]
OutputOpt = Annotated[
    Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
]
FailOnOpt = Annotated[
    Severity, typer.Option("--fail-on", help="Exit 1 if any finding is at or above this severity.")
]
BaselineOpt = Annotated[
    Path | None, typer.Option("--baseline", help="JSON report whose findings are suppressed.")
]
UserOpt = Annotated[
    bool, typer.Option("--user/--no-user", help="Include user-level (home) config.")
]
PathArg = Annotated[Path, typer.Argument(help="Repository / directory to audit.")]


def _git_prefix(path: Path | None) -> str:
    """`path` relative to its git root, as a SARIF URI prefix ("" at the root or outside git)."""
    if path is None:
        return ""
    for parent in [path, *path.parents]:
        if (parent / ".git").exists():
            rel = path.relative_to(parent).as_posix()
            return "" if rel == "." else rel + "/"
    return ""


def _emit(
    result: AuditResult,
    fmt: OutputFormat,
    output: Path | None,
    fail_on: Severity,
    baseline: Path | None,
    scanned_path: Path | None = None,
) -> None:
    findings = result.findings
    if baseline is not None:
        findings = apply_baseline(findings, load_json(baseline))
    if fmt is OutputFormat.rich and output is None:
        print_rich(findings, console, result.scanned)
        for path, message in result.errors:
            console.print("[yellow]warning[/yellow]", plain(f"{path}: {message}"))
    else:
        if fmt is OutputFormat.json:
            text = to_json(findings, result.errors, result.scanned)
        elif fmt is OutputFormat.sarif:
            sarif = to_sarif(findings, load_rules(), result.errors, _git_prefix(scanned_path))
            text = json.dumps(sarif, indent=2) + "\n"
        else:
            text = to_markdown(findings, errors=result.errors)
        if output is None:
            typer.echo(text, nl=False)
        else:
            output.write_text(text, encoding="utf-8")
            console.print(f"Wrote {len(findings)} finding(s) to {output}")
    if at_or_above(findings, fail_on):
        raise typer.Exit(1)


def _run(audits: tuple[str, ...], options: AuditOptions) -> AuditResult:
    if options.repo is not None and not options.repo.is_dir():
        # A typo in a CI `path:` input must not pass as "No findings".
        console.print(
            f"[red]error:[/red] {plain(str(options.repo))} does not exist or is not a directory"
        )
        raise typer.Exit(2)
    try:
        return audits_mod.run(audits, load_profiles(), options)
    except (OSError, ValueError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc


@audit_app.command("config")
def audit_config(
    path: PathArg = Path(),
    user: UserOpt = True,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Permission modes, allowlists, hooks, network, telemetry and credentials in harness configs."""
    _emit(
        _run(("config",), AuditOptions(repo=path.resolve(), include_user=user)),
        fmt,
        output,
        fail_on,
        baseline,
        path.resolve(),
    )


@audit_app.command("mcp")
def audit_mcp(
    path: PathArg = Path(),
    user: UserOpt = True,
    tools_json: Annotated[
        list[Path] | None,
        typer.Option("--tools-json", help="Saved MCP `tools/list` result to scan."),
    ] = None,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """MCP server declarations: pinning, transport/auth, inline secrets, tool poisoning."""
    options = AuditOptions(repo=path.resolve(), include_user=user, tool_manifests=tools_json or [])
    _emit(_run(("mcp",), options), fmt, output, fail_on, baseline, path.resolve())


@audit_app.command("instructions")
def audit_instructions(
    path: PathArg = Path(),
    user: Annotated[
        bool, typer.Option("--user/--no-user", help="Include user-level files.")
    ] = False,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Injection indicators in instruction, rules and skill files."""
    _emit(
        _run(("instructions",), AuditOptions(repo=path.resolve(), include_user=user)),
        fmt,
        output,
        fail_on,
        baseline,
        path.resolve(),
    )


@audit_app.command("secrets")
def audit_secrets(
    max_file_mb: Annotated[int, typer.Option(help="Read at most this many MB per file.")] = 50,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Secret residue in harness logs/transcripts/memory and loose file permissions (redacted)."""
    _emit(_run(("secrets",), AuditOptions(max_file_mb=max_file_mb)), fmt, output, fail_on, baseline)


@audit_app.command("supply")
def audit_supply(
    online: Annotated[
        bool, typer.Option(help="Query OSV (sends package name + version only).")
    ] = False,
    sbom: Annotated[
        Path | None, typer.Option(help="Write a CycloneDX SBOM of installed harnesses.")
    ] = None,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Installed harness packages: installer verification, known vulnerabilities, SBOM."""
    result = _run(("supply",), AuditOptions(online=online))
    if sbom is not None:
        profiles = load_profiles()
        subject = supply.SupplySubject(run_inventory(profiles, None), {p.id: p for p in profiles})
        supply.write_sbom(subject, sbom)
    _emit(result, fmt, output, fail_on, baseline)


@audit_app.command("ci")
def audit_ci(
    path: PathArg = Path(),
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Headless agents in CI workflows triggered by untrusted input ("pwn request")."""
    _emit(
        _run(("ci",), AuditOptions(repo=path.resolve(), include_user=False)),
        fmt,
        output,
        fail_on,
        baseline,
        path.resolve(),
    )


@audit_app.command("repo")
def audit_repo(
    path: PathArg = Path(),
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """All repository audits (config, mcp, instructions, ci) without reading the home directory."""
    options = AuditOptions(repo=path.resolve(), include_user=False)
    _emit(_run(REPO_AUDITS, options), fmt, output, fail_on, baseline, path.resolve())


@audit_app.command("all")
def audit_all(
    path: PathArg = Path(),
    online: Annotated[bool, typer.Option(help="Allow OSV lookups.")] = False,
    fmt: FormatOpt = OutputFormat.rich,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.HIGH,
    baseline: BaselineOpt = None,
) -> None:
    """Every audit: repository plus this machine's user-level harness state."""
    _emit(
        _run(AUDITS, AuditOptions(repo=path.resolve(), online=online)),
        fmt,
        output,
        fail_on,
        baseline,
        path.resolve(),
    )


@app.command()
def report(
    inputs: Annotated[list[Path], typer.Argument(help="JSON reports to merge.")],
    fmt: FormatOpt = OutputFormat.markdown,
    output: OutputOpt = None,
    fail_on: FailOnOpt = Severity.CRITICAL,
    baseline: BaselineOpt = None,
) -> None:
    """Merge JSON reports into Markdown/SARIF/JSON, optionally diffing against a baseline."""
    loaded = [load_report(p) for p in inputs]
    findings = audits_mod.dedupe([f for found, _ in loaded for f in found])
    errors = list(dict.fromkeys(e for _, errs in loaded for e in errs))
    _emit(AuditResult(findings=findings, errors=errors), fmt, output, fail_on, baseline)


@app.command()
def observe(
    harness: Annotated[str, typer.Argument(help="Harness id (label for the report).")],
    command: Annotated[
        list[str], typer.Argument(help="Command to run in the container, after --.")
    ],
    image: Annotated[str, typer.Option(help="Container image that has the harness installed.")],
    repo: Annotated[
        Path | None, typer.Option(help="Synthetic repository to copy into /workspace.")
    ] = None,
    env: Annotated[
        list[str] | None,
        typer.Option("--env", "-e", help="KEY=VALUE for the target (synthetic values only)."),
    ] = None,
    allow: Annotated[
        list[str] | None,
        typer.Option(help="host:port the egress proxy lets through (default ollama:11434)."),
    ] = None,
    network: Annotated[str, typer.Option(help="Internal Docker network.")] = "hw-bench-net",
    timeout: Annotated[float, typer.Option(help="Seconds before the target is killed.")] = 300.0,
    canary: Annotated[
        str | None,
        typer.Option(help="Synthetic canary string: count written files that contain it."),
    ] = None,
    keep: Annotated[bool, typer.Option(help="Keep the containers for inspection.")] = False,
    output: OutputOpt = None,
) -> None:
    """Black-box probe: run COMMAND in a sandbox, record hosts, files, sandboxing and prompts."""
    from harnesswatch.observe import ObserveError, ObserveSpec
    from harnesswatch.observe import run as observe_run

    pairs = [item.partition("=") for item in env or []]
    spec = ObserveSpec(
        harness=harness,
        image=image,
        command=command,
        repo=repo,
        env={k: v for k, _, v in pairs},
        allow=allow or ["ollama:11434"],
        network=network,
        timeout=timeout,
        canary=canary,
        keep=keep,
    )
    try:
        result = observe_run(spec)
    except ObserveError as exc:
        console.print(f"[red]observe failed:[/] {exc}")
        raise typer.Exit(2) from exc
    text = result.model_dump_json(indent=2)
    if output:
        output.write_text(text + "\n", encoding="utf-8")
    else:
        typer.echo(text)


bench_app = typer.Typer(
    no_args_is_help=True, help="Canary-bench: inert prompt-injection benchmark."
)
app.add_typer(bench_app, name="bench")


@bench_app.command("list")
def bench_list() -> None:
    """List harness adapters and scenarios."""
    from harnesswatch.bench.adapters import ADAPTERS
    from harnesswatch.bench.scenarios import SCENARIOS

    for adapter in ADAPTERS.values():
        typer.echo(f"harness  {adapter.id:16} tier {adapter.tier}  {adapter.image}")
    for scenario in SCENARIOS.values():
        typer.echo(f"scenario {scenario.id:16} {scenario.taxonomy:8} {scenario.title}")


@bench_app.command("run")
def bench_run(
    out: Annotated[
        Path, typer.Option(help="Results directory (runs.jsonl is appended, resumable).")
    ],
    harness: Annotated[
        list[str] | None, typer.Option(help="Adapter id (repeatable; default all).")
    ] = None,
    scenario: Annotated[
        list[str] | None, typer.Option(help="Scenario id (repeatable; default all).")
    ] = None,
    mode: Annotated[list[str] | None, typer.Option(help="default and/or auto.")] = None,
    model: Annotated[list[str] | None, typer.Option(help="Ollama model tag (repeatable).")] = None,
    runs: Annotated[
        int, typer.Option("-n", help="Repetitions per cell (>= 3, MISSION asks 5).")
    ] = 5,
    parallel: Annotated[int, typer.Option(help="Concurrent runs.")] = 1,
    max_usd: Annotated[
        float,
        typer.Option(
            help="Stop once tracked spend exceeds this many USD. Cost is only tracked for priced "
            "(API) adapters; local Ollama models cost $0, so the cap never triggers for them."
        ),
    ] = 25.0,
    timeout: Annotated[int, typer.Option(help="Per-run harness timeout in seconds.")] = 600,
    raw: Annotated[
        Path | None, typer.Option(help="Keep full transcripts here (debug; never committed).")
    ] = None,
) -> None:
    """Run the bench grid in disposable containers (needs Docker and the bench images)."""
    from harnesswatch.bench.adapters import ADAPTERS, MODES
    from harnesswatch.bench.runner import BudgetExceeded, RunResult, run_grid
    from harnesswatch.bench.scenarios import SCENARIOS

    if runs < 3:
        raise typer.BadParameter("at least 3 runs per cell")
    for name, values, known in (
        ("--harness", harness, ADAPTERS),
        ("--scenario", scenario, SCENARIOS),
        ("--mode", mode, MODES),
    ):
        unknown = [v for v in values or [] if v not in known]
        if unknown:
            raise typer.BadParameter(
                f"unknown value(s) {', '.join(unknown)}; choose from {', '.join(known)}",
                param_hint=name,
            )
    # Model tags are substituted into generated TOML/JSON harness configs.
    bad_models = [m for m in model or [] if not re.fullmatch(r"[A-Za-z0-9._:/\-]+", m)]
    if bad_models:
        raise typer.BadParameter(
            f"invalid model tag(s) {', '.join(bad_models)}", param_hint="--model"
        )
    adapters = [ADAPTERS[h] for h in harness or ADAPTERS]
    scenarios = [SCENARIOS[s] for s in scenario or SCENARIOS]
    cells = [
        (a, s, m, mdl)
        for a in adapters
        for s in scenarios
        for m in mode or MODES
        for mdl in model or ["qwen3:4b-instruct"]
        if a.instruction_file or s.id not in {"instructions", "hidden_unicode"}
    ]

    def show(r: RunResult) -> None:
        console.print(
            r.model_dump_json(
                include={
                    "harness",
                    "scenario",
                    "mode",
                    "rep",
                    "duration_s",
                    "injection_followed",
                    "task_completed",
                    "error",
                }
            )
        )

    try:
        run_grid(
            cells,
            runs,
            out,
            parallel=parallel,
            max_usd=max_usd,
            timeout=timeout,
            on_result=show,
            raw_dir=raw,
        )
    except BudgetExceeded as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from exc


@bench_app.command("report")
def bench_report(
    results: Annotated[Path, typer.Argument(help="Results directory containing runs.jsonl.")],
) -> None:
    """Aggregate runs.jsonl into summary.json (per-cell rates with Wilson 95% CIs)."""
    from harnesswatch.bench.runner import completed_runs
    from harnesswatch.bench.stats import aggregate

    rows = aggregate(completed_runs(results / "runs.jsonl"))
    (results / "summary.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"{len(rows)} cells -> {results / 'summary.json'}")
