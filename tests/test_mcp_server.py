"""The MCP server, with most of the weight on its three runtime guardrails.

The MCP surface differs from the CLI in blast radius. The hook sees one file
the model just wrote; `scan(path)` can be pointed at a whole tree the model has
never read. So the tests that matter here are not "does it find things" — the
engine is tested elsewhere — but "can an agent use it to reach or reveal
something it was not given".
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="MCP SDK is an optional extra")

from valca import mcp_server  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

UNSAFE_COMPOSE = 'services:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n'
SECRET_FILE = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


@pytest.fixture
def rooted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the server at a temp tree and return it."""
    monkeypatch.setenv(mcp_server._ROOT_ENV, str(tmp_path))
    return tmp_path


# ── Guardrail 1: the scan root is a boundary ─────────────────────────────────


@pytest.mark.parametrize(
    "escape",
    ["..", "../..", "../secrets", "/etc", "/etc/passwd", "~/.ssh", "../../../../etc/hosts"],
)
def test_scan_refuses_to_leave_the_root(rooted: Path, escape: str) -> None:
    result = mcp_server.scan(escape)
    assert result["findings"] == []
    assert "outside the scan root" in result.get("error", ""), (
        f"{escape!r} was not refused: {result.get('error')!r}"
    )


def test_symlink_cannot_walk_out_of_the_root(rooted: Path, tmp_path_factory) -> None:
    """Resolution happens before the boundary check, so a symlink is not an escape."""
    outside = tmp_path_factory.mktemp("outside")
    (outside / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    (rooted / "link").symlink_to(outside)

    result = mcp_server.scan("link")
    assert "outside the scan root" in result.get("error", ""), (
        "a symlink pointing out of the root was followed"
    )


def test_scan_accepts_paths_inside_the_root(rooted: Path) -> None:
    (rooted / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    result = mcp_server.scan(".")
    assert result.get("error") is None
    assert result["count"] >= 1, "the fixture should produce a finding, or this proves nothing"


# ── Guardrail 2: no absolute paths in output ─────────────────────────────────


def test_findings_never_carry_an_absolute_path(rooted: Path) -> None:
    """An absolute path leaks the username and the directory layout."""
    (rooted / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    result = mcp_server.scan(".")

    assert result["findings"], "no findings to check"
    for finding in result["findings"]:
        assert not finding["file"].startswith("/"), f"absolute path leaked: {finding['file']}"
        assert str(rooted) not in finding["file"], f"root path leaked: {finding['file']}"


# ── Guardrail 3: snippets are never returned ─────────────────────────────────


def test_secret_value_is_never_returned(rooted: Path) -> None:
    """For the secret rules the snippet is the line holding the secret."""
    (rooted / "config.py").write_text(SECRET_FILE)
    result = mcp_server.scan(".")

    assert result["findings"], "the secret fixture produced no finding"
    blob = repr(result)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "the matched secret was returned to the agent"
    for finding in result["findings"]:
        assert "snippet" not in finding, "snippet field present; it must be omitted entirely"


def test_no_finding_carries_a_snippet_key_for_any_rule(rooted: Path) -> None:
    """Fails closed: a new rule cannot reintroduce the field by being forgotten."""
    (rooted / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    (rooted / "Dockerfile").write_text("FROM python:latest\n")
    (rooted / "config.py").write_text(SECRET_FILE)

    for finding in mcp_server.scan(".")["findings"]:
        assert set(finding) == {"rule", "severity", "message", "file", "line", "fix"}, (
            f"unexpected field in MCP output: {sorted(finding)}"
        )


# ── Guardrail 4: telemetry stays out of it ───────────────────────────────────


def test_scan_writes_no_telemetry(rooted: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A scan the agent asked for is not the user's own scan."""
    from valca import telemetry

    store = rooted / "events.jsonl"
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", store)
    monkeypatch.delenv("VALCA_NO_TELEMETRY", raising=False)
    monkeypatch.delenv("VIGIL_NO_TELEMETRY", raising=False)

    (rooted / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    assert mcp_server.scan(".")["count"] >= 1
    assert not store.exists(), "the MCP path wrote telemetry"


# ── Read-only surface ────────────────────────────────────────────────────────


def test_no_tool_can_write() -> None:
    """The absence of a fix tool is the design, so assert it rather than trust it."""
    exported = {n for n in dir(mcp_server) if not n.startswith("_")}
    forbidden = {"fix", "apply", "write", "edit", "patch", "remediate", "autofix"}
    assert not (exported & forbidden), f"a mutating tool appeared: {exported & forbidden}"


def test_tools_declare_read_only_to_the_protocol() -> None:
    assert mcp_server._READ_ONLY.read_only_hint is True
    assert mcp_server._READ_ONLY.destructive_hint is False


def test_module_imports_no_subprocess() -> None:
    """VGL-MCP003 catches shell execution in an MCP handler. Do not be the example."""
    source = (REPO / "src" / "valca" / "mcp_server.py").read_text()
    for banned in ("import subprocess", "from subprocess", "os.system", "os.popen"):
        assert banned not in source, f"{banned!r} in the MCP server"


# ── Catalogue ────────────────────────────────────────────────────────────────


def test_list_rules_matches_the_engine() -> None:
    from valca.rules import DEFAULT_RULES

    catalogue = mcp_server.list_rules()
    assert catalogue["count"] == len(DEFAULT_RULES)
    assert {r["id"] for r in catalogue["rules"]} == {r.id for r in DEFAULT_RULES}
    assert all(r["catches"] for r in catalogue["rules"]), "a rule reached MCP with no description"


# ── Packaging ────────────────────────────────────────────────────────────────


def test_mcp_is_an_extra_and_the_core_stays_dependency_free() -> None:
    """Installing a scanner must not pull a dependency tree into the scanned env."""
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == [], (
        f"core gained a runtime dependency: {project['dependencies']}"
    )
    extras = project.get("optional-dependencies", {})
    assert "mcp" in extras, "mcp extra is not declared"
    assert any(d.startswith("mcp") for d in extras["mcp"])
    assert project["scripts"]["valca-mcp"] == "valca.mcp_server:main"


# ── Config is honoured, as on the CLI path ───────────────────────────────────


def test_disabled_rules_in_config_are_honoured(rooted: Path) -> None:
    (rooted / "docker-compose.yml").write_text(UNSAFE_COMPOSE)
    before = mcp_server.scan(".")
    fired = {f["rule"] for f in before["findings"]}
    assert "VGL-D001" in fired, f"expected VGL-D001 in {fired}"

    (rooted / ".valcarc").write_text('disabled_rules = ["VGL-D001"]\n')
    after = mcp_server.scan(".")
    assert "VGL-D001" not in {f["rule"] for f in after["findings"]}, (
        ".valcarc disabled_rules was ignored on the MCP path"
    )
