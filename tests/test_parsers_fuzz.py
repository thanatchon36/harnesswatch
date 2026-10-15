"""Property tests: parsers and scanners never crash on arbitrary input and keep invariants."""

import contextlib
import json

import httpx
from hypothesis import given, settings
from hypothesis import strategies as st

from harnesswatch import textscan
from harnesswatch.audits import supply
from harnesswatch.inventory import BinaryInfo, InventoryItem
from harnesswatch.models import HarnessProfile
from harnesswatch.parsers.loaders import (
    ConfigParseError,
    get_all,
    get_dotted,
    parse_text,
    strip_jsonc,
)
from harnesswatch.secrets import find_secrets, is_secret_value, redact

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=20,
)


@given(json_values)
def test_strip_jsonc_preserves_plain_json(value: object) -> None:
    text = json.dumps(value)
    assert json.loads(strip_jsonc(text)) == value


@given(json_values)
def test_jsonc_comments_and_trailing_commas(value: object) -> None:
    text = "// header\n" + json.dumps(value, indent=1).replace("\n", " /* c */\n", 1)
    assert parse_text(text, "jsonc") == value


@settings(max_examples=200)
@given(st.text(max_size=300), st.sampled_from(["json", "jsonc", "toml", "yaml", "markdown"]))
def test_parse_text_only_raises_parse_error(text: str, fmt: str) -> None:
    with contextlib.suppress(ConfigParseError):
        parse_text(text, fmt)


@given(json_values, st.text(alphabet="ab.*", max_size=8))
def test_dotted_lookups_never_crash(value: object, key: str) -> None:
    get_dotted(value, key)
    assert isinstance(get_all(value, key), list)


def test_get_all_wildcards() -> None:
    data = {"mcpServers": {"a": {"trust": True}, "b": {"trust": False}}, "x.y": {"z": 1}}
    assert get_all(data, "mcpServers.<name>.trust") == [True, False]
    assert get_all(data, "x.y.z") == [1]
    assert get_all({"projects": {"/a.b": {"t": 1}}}, 'projects."/a.b".t') == [1]


@settings(max_examples=200)
@given(st.text(max_size=500))
def test_text_scanners_total(text: str) -> None:
    indicators = textscan.hidden_unicode(text) + textscan.phrase_indicators(text)
    indicators += textscan.remote_imports(text) + textscan.endpoints(text)
    assert textscan.score(indicators) >= 0
    for match in find_secrets(text):
        assert text[match.start : match.end] not in match.redacted or match.end - match.start < 4


@given(st.text(min_size=1, max_size=80))
def test_redaction_never_reveals_more_than_prefix(value: str) -> None:
    out = redact(value)
    assert str(len(value)) in out
    assert value[4:] not in out or len(value) <= 8


def test_secret_value_examples() -> None:
    assert not is_secret_value("${GITHUB_TOKEN}")
    assert not is_secret_value("your-api-key-here")
    assert is_secret_value("AKIA" + "Q" * 16)


def test_osv_query_with_mock_transport() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-test"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    comps = [
        supply.Component("claude-code", "npm", "@anthropic-ai/claude-code", "1.0.0"),
        supply.Component("aider", "pypi", "aider-chat", None),
    ]
    result = supply.query_osv(comps, client)
    assert result == {"pkg:npm/%40anthropic-ai/claude-code@1.0.0": [{"id": "GHSA-test"}]}
    assert seen == [
        {"package": {"name": "@anthropic-ai/claude-code", "ecosystem": "npm"}, "version": "1.0.0"}
    ]


def test_sbom_components() -> None:
    profile = HarnessProfile(
        id="aider", name="Aider", packages=[{"ecosystem": "pypi", "name": "aider-chat"}]
    )
    item = InventoryItem(
        harness="aider",
        name="Aider",
        binaries=[
            BinaryInfo(
                name="aider", path="/x", resolved="/x", install_method="pip", version="0.86.0"
            )
        ],
    )
    subject = supply.SupplySubject([item], {"aider": profile})
    bom = supply.cyclonedx(subject)
    assert bom["components"][0]["purl"] == "pkg:pypi/aider-chat@0.86.0"
