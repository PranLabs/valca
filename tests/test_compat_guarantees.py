"""Every old-name/new-name guarantee the 0.4.0 CHANGELOG makes, asserted.

Those guarantees were published to PyPI and then quietly stopped being true:
the fixes were written into the public tree, and `vigil_promote.py` copies
`src/valca` private -> public, so the private tree's older files overwrote all
of them. Four of the five rows were false in 0.4.0, 0.4.1 and 0.5.0 — including
`VALCA_NO_TELEMETRY`, which meant a user who followed the documented opt-out was
still recorded.

One test per row. A promise in published documentation with no test behind it is
a promise that reverts without anyone noticing.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from valca import telemetry
from valca.config import load_config
from valca.engine import _SUPPRESS_MARKERS

REPO = Path(__file__).resolve().parent.parent


# ── Row 1: both console scripts installed ────────────────────────────────────


def test_both_commands_are_installed() -> None:
    scripts = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]
    assert {"valca", "vigil"} <= set(scripts), f"missing console script: {scripts}"
    assert scripts["valca"] == scripts["vigil"], "the two commands must share an entry point"


@pytest.mark.parametrize("invoked_as", ["valca", "vigil"])
def test_help_names_the_command_the_user_typed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], invoked_as: str
) -> None:
    """`valca --help` must not answer "usage: vigil".

    prog was hardcoded to "vigil", so the tool announced the pre-rename name to
    every user of the documented one.
    """
    import contextlib

    from valca import cli

    monkeypatch.setattr("sys.argv", [invoked_as, "--help"])
    with contextlib.suppress(SystemExit):
        cli.main()
    usage = capsys.readouterr().out
    assert usage.startswith(f"usage: {invoked_as}"), (
        f"invoked as {invoked_as!r}, help says: {usage.splitlines()[0]!r}"
    )


# ── Row 2: both suppression markers honoured ─────────────────────────────────


@pytest.mark.parametrize("marker", ["# valca: ignore", "# vigil: ignore"])
def test_both_suppression_markers_are_honoured(marker: str) -> None:
    assert marker in _SUPPRESS_MARKERS


def test_suppression_marker_actually_suppresses(tmp_path: Path) -> None:
    """Assert the behaviour, not just the constant."""
    from valca.engine import Engine

    target = tmp_path / "docker-compose.yml"
    target.write_text('services:\n  db:\n    ports:\n      - "5432:5432"  # valca: ignore\n')
    findings = Engine(telemetry_enabled=False).scan(target)
    assert not findings, f"'# valca: ignore' did not suppress: {[f.rule_id for f in findings]}"


# ── Row 3: both config filenames read, .valcarc wins ─────────────────────────


@pytest.mark.parametrize("name", [".valcarc", ".vigilrc"])
def test_both_config_filenames_are_read(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text('disabled_rules = ["VGL-D001"]\n')
    assert load_config(tmp_path).disabled_rules == ["VGL-D001"], f"{name} was ignored"


def test_valcarc_takes_precedence_over_vigilrc(tmp_path: Path) -> None:
    (tmp_path / ".valcarc").write_text('disabled_rules = ["FROM-VALCARC"]\n')
    (tmp_path / ".vigilrc").write_text('disabled_rules = ["FROM-VIGILRC"]\n')
    assert load_config(tmp_path).disabled_rules == ["FROM-VALCARC"]


# ── Row 4: both telemetry opt-out variables honoured ─────────────────────────


@pytest.mark.parametrize("env_name", ["VALCA_NO_TELEMETRY", "VIGIL_NO_TELEMETRY"])
def test_both_optout_env_vars_are_honoured(monkeypatch: pytest.MonkeyPatch, env_name: str) -> None:
    monkeypatch.delenv("VALCA_NO_TELEMETRY", raising=False)
    monkeypatch.delenv("VIGIL_NO_TELEMETRY", raising=False)
    assert not telemetry._is_opted_out(True), "unexpectedly opted out with no variable set"
    monkeypatch.setenv(env_name, "1")
    assert telemetry._is_opted_out(True), f"{env_name}=1 did not opt out"


def test_optout_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The guarantee that matters: opted out means nothing lands on disk."""
    from valca.engine import Engine

    store = tmp_path / "events.jsonl"
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", store)
    monkeypatch.setenv("VALCA_NO_TELEMETRY", "1")

    target = tmp_path / "docker-compose.yml"
    target.write_text('services:\n  db:\n    ports:\n      - "5432:5432"\n')
    findings = Engine().scan(target)

    assert findings, "fixture should produce a finding, or this proves nothing"
    assert not store.exists(), "telemetry was written despite VALCA_NO_TELEMETRY=1"


# ── Row 5: legacy event history migrates ─────────────────────────────────────


def test_legacy_store_migrates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    new = tmp_path / ".valca" / "events.jsonl"
    legacy = tmp_path / ".vigil" / "events.jsonl"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"rule_id": "VGL-D001"}\n')

    monkeypatch.setattr(telemetry, "_DEFAULT_EVENTS_FILE", new)
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", new)
    monkeypatch.setattr(telemetry, "_LEGACY_EVENTS_FILE", legacy)

    telemetry._migrate_legacy_store()

    assert new.is_file(), "history was not migrated"
    assert '"VGL-D001"' in new.read_text(), "migrated file lost its contents"
    assert not legacy.exists(), "legacy file should be moved, not copied"
    assert new.stat().st_mode & 0o777 == 0o600, "migrated store must stay owner-only"


def test_migration_never_clobbers_an_existing_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    new = tmp_path / ".valca" / "events.jsonl"
    legacy = tmp_path / ".vigil" / "events.jsonl"
    new.parent.mkdir(parents=True)
    legacy.parent.mkdir(parents=True)
    new.write_text('{"keep": "me"}\n')
    legacy.write_text('{"old": "data"}\n')

    monkeypatch.setattr(telemetry, "_DEFAULT_EVENTS_FILE", new)
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", new)
    monkeypatch.setattr(telemetry, "_LEGACY_EVENTS_FILE", legacy)

    telemetry._migrate_legacy_store()

    assert new.read_text() == '{"keep": "me"}\n', "existing history was overwritten"


def test_migration_is_skipped_when_the_path_is_patched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Guards the developer's real ~/.vigil history against the test suite.

    If migration ran while _EVENTS_FILE points at a temp directory, a test run
    would move real scan history somewhere pytest deletes on exit.
    """
    legacy = tmp_path / ".vigil" / "events.jsonl"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"rule_id": "VGL-D001"}\n')

    monkeypatch.setattr(telemetry, "_DEFAULT_EVENTS_FILE", tmp_path / "real" / "events.jsonl")
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", tmp_path / "patched" / "events.jsonl")
    monkeypatch.setattr(telemetry, "_LEGACY_EVENTS_FILE", legacy)

    telemetry._migrate_legacy_store()

    assert legacy.is_file(), "migration ran under a patched path and moved real history"
