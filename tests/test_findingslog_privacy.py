"""The findings log must honour the opt-out and stay owner-only.

Both properties were absent from the shipped package until 2026-09-24. The
findings log is the more sensitive of the two local stores — events.jsonl holds
rule ids and file extensions, this holds absolute paths, so it reveals the
username, the directory layout and every project name — and it was the one
created world-readable and written regardless of the opt-out.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valca import findingslog
from valca.engine import Engine

UNSAFE_COMPOSE = 'services:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n'


@pytest.fixture
def log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the findings log into a temp file and clear both opt-out vars."""
    target = tmp_path / "findings.jsonl"
    monkeypatch.setenv("VIGIL_LOG_PATH", str(target))
    monkeypatch.delenv("VALCA_NO_TELEMETRY", raising=False)
    monkeypatch.delenv("VIGIL_NO_TELEMETRY", raising=False)
    return target


@pytest.fixture
def unsafe(tmp_path: Path) -> Path:
    target = tmp_path / "docker-compose.yml"
    target.write_text(UNSAFE_COMPOSE)
    return target


# ── E1: the opt-out is honoured ──────────────────────────────────────────────


def test_config_optout_silences_the_findings_log(log: Path, unsafe: Path) -> None:
    """`telemetry = false` must stop this store too, not only events.jsonl."""
    findings = Engine(telemetry_enabled=False).scan(unsafe)
    assert findings, "fixture produced no finding, so this proves nothing"
    assert not log.exists(), "findings were logged despite telemetry being disabled"


@pytest.mark.parametrize("env_name", ["VALCA_NO_TELEMETRY", "VIGIL_NO_TELEMETRY"])
def test_env_optout_silences_the_findings_log(
    log: Path, unsafe: Path, monkeypatch: pytest.MonkeyPatch, env_name: str
) -> None:
    monkeypatch.setenv(env_name, "1")
    findings = Engine().scan(unsafe)
    assert findings, "fixture produced no finding, so this proves nothing"
    assert not log.exists(), f"{env_name}=1 did not stop the findings log"


def test_log_is_written_when_not_opted_out(log: Path, unsafe: Path) -> None:
    """The control. Without it the tests above pass on a store that never writes."""
    assert Engine().scan(unsafe)
    assert log.exists(), "nothing was logged even though telemetry is enabled"
    record = json.loads(log.read_text().splitlines()[0])
    assert record["rule"] == "VGL-D001"


# ── E2: owner-only permissions ───────────────────────────────────────────────


def test_new_log_is_owner_only(log: Path, unsafe: Path) -> None:
    Engine().scan(unsafe)
    assert log.exists()
    mode = log.stat().st_mode & 0o777
    assert mode == 0o600, f"findings log created with mode {oct(mode)}, expected 0o600"


def test_existing_world_readable_log_is_repaired(log: Path, unsafe: Path) -> None:
    """Installs that predate this rule hold a 0644 file; the next write fixes it.

    Tightening only at creation would leave every existing store exposed
    indefinitely, which is the population that actually matters.
    """
    log.write_text("")
    log.chmod(0o644)

    Engine().scan(unsafe)

    mode = log.stat().st_mode & 0o777
    assert mode == 0o600, f"pre-existing log left at {oct(mode)}; it was not repaired"


def test_log_never_contains_a_code_snippet(log: Path, unsafe: Path) -> None:
    """Paths are unavoidable here; matched source lines are not."""
    Engine().scan(unsafe)
    for line in log.read_text().splitlines():
        assert set(json.loads(line)) <= {
            "ts",
            "file",
            "rule",
            "severity",
            "title",
            "detail",
            "session_id",
        }, f"unexpected field in the findings log: {sorted(json.loads(line))}"
