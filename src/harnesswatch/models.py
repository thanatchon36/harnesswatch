"""Pydantic models shared by every module: findings, harness profiles, the common config schema."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Scope(StrEnum):
    USER = "user"
    PROJECT = "project"
    PROJECT_LOCAL = "project-local"
    MANAGED = "managed"
    ENV = "env"


class Location(BaseModel):
    path: str
    line: int | None = None


class Finding(BaseModel):
    """One rule hit. `evidence` is always redacted before it is stored here."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    message: str
    location: Location
    harness: str | None = None
    taxonomy: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    evidence: str | None = None
    key: str = ""  # hashed stable subject (server, hook, job...) supplied by the check

    @property
    def fingerprint(self) -> str:
        """Stable identity used for baselines and SARIF partialFingerprints.

        Built from the rule, the path and the check's subject key, never from the line or the
        message, so inserting a line above a finding or a growing count keeps it baselined.
        """
        key = f"{self.rule_id}|{self.location.path}|{self.key}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


def stable_key(subject: str) -> str:
    """Hash a check's subject key; without one, the message with every number removed."""
    return hashlib.sha256(subject.encode()).hexdigest()[:12]


def message_key(message: str) -> str:
    return re.sub(r"\d+", "#", message)


class ConfigFileSpec(BaseModel):
    model_config = ConfigDict(extra="allow")

    path: str
    scope: Scope
    format: str
    kind: str


class McpSpec(BaseModel):
    model_config = ConfigDict(extra="allow")

    files: list[str] = Field(default_factory=list)
    servers_key: str | None = "mcpServers"  # None: harness has no MCP config file
    server_fields: dict[str, Any] = Field(default_factory=dict)


class AutoApproveValue(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str
    value: Any


class PermissionSpec(BaseModel):
    model_config = ConfigDict(extra="allow")

    config_keys: dict[str, Any] = Field(default_factory=dict)
    default_mode: str | None = None
    auto_approve_values: list[AutoApproveValue] = Field(default_factory=list)
    cli_flags_auto_approve: list[Any] = Field(default_factory=list)
    overbroad_patterns: list[str] = Field(default_factory=list)

    def key(self, name: str) -> str | None:
        value = self.config_keys.get(name)
        return value if isinstance(value, str) else None


class HooksSpec(BaseModel):
    model_config = ConfigDict(extra="allow")

    supported: bool | None = False
    config_key: str | None = None
    repo_scoped_allowed: bool | None = None
    command_field: str | None = "command"


class HarnessProfile(BaseModel):
    """Data describing where a harness keeps its config and how risky settings are spelled."""

    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    vendor: str | None = None
    tier: str | None = None
    status: str = "analysed"
    version_analysed: str | None = None
    binaries: list[str] = Field(default_factory=list)
    packages: list[dict[str, Any]] = Field(default_factory=list)
    state_dirs: list[str] = Field(default_factory=list)
    credential_files: list[str] = Field(default_factory=list)
    log_paths: list[str] = Field(default_factory=list)
    memory_paths: list[str] = Field(default_factory=list)
    config_files: list[ConfigFileSpec] = Field(default_factory=list)
    instruction_files: list[str] = Field(default_factory=list)
    skills_paths: list[str] = Field(default_factory=list)
    mcp: McpSpec | None = None
    permissions: PermissionSpec | None = None
    hooks: HooksSpec | None = None


class McpServer(BaseModel):
    """An MCP server declaration normalised across harness formats.

    `env` and `headers` keep raw values in memory so rules can test them; they are never
    serialised into findings or reports.
    """

    name: str
    harness: str
    source: Location
    scope: Scope
    transport: str = "stdio"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict, exclude=True)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict, exclude=True)
    tool_descriptions: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True


class Hook(BaseModel):
    event: str
    command: str
    harness: str
    source: Location
    scope: Scope


class HarnessConfig(BaseModel):
    """Common schema every parser produces (one per harness per config file)."""

    harness: str
    source: Location
    scope: Scope
    kind: str = "settings"  # profile config-file kind: settings | mcp | hooks | agents
    permission_mode: str | None = None
    auto_approve_matches: list[str] = Field(default_factory=list)  # "key=value" hits
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    hooks: list[Hook] = Field(default_factory=list)
    mcp_servers: list[McpServer] = Field(default_factory=list)
    instruction_files: list[str] = Field(default_factory=list)
    trust: dict[str, Any] = Field(default_factory=dict)
    telemetry: bool | None = None
    auto_update: bool | None = None
    sandbox_enabled: bool | None = None
    network_allowlist: list[str] | None = None
    web_fetch_enabled: bool | None = None
    memory_enabled: bool | None = None
    subagent_inherits_bypass: bool | None = None
    plaintext_credentials: list[str] = Field(default_factory=list, exclude=True)
