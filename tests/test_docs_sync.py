"""Documentation must match the shipped engine.

These tests exist because the published listings advertised 36 rules while the
engine shipped 102 — a 66-rule understatement that sat on PyPI and the VS Code
Marketplace because the catalogue was maintained by hand.

Anything a user reads before installing is checked here: the rule count, the
rule catalogue, and the CLI command list. A release that documents something
the engine does not do — or omits something it does — fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path

from valca.rules import DEFAULT_RULES

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
VSCODE_README = REPO / "vigil-vscode" / "README.md"
MANIFEST = REPO / "plugin" / "manifest.json"

# Rule IDs emitted by a parent rule class rather than registered separately.
# Keep in sync with the class that raises them; the test below proves they are real.
SUB_RULE_IDS = {"VGL-PKG002", "VGL-PKG003", "VGL-PKG004"}

# Commands intentionally omitted from the README (none today).
UNDOCUMENTED_COMMANDS: set[str] = set()


def engine_rule_ids() -> set[str]:
    """Every rule ID a user can actually see in output."""
    return {r.id for r in DEFAULT_RULES} | SUB_RULE_IDS


def documented_rule_ids() -> set[str]:
    return set(re.findall(r"\|\s*(VGL-[A-Z]+\d+)\s*\|", README.read_text()))


def test_sub_rule_ids_are_real() -> None:
    """SUB_RULE_IDS must appear in the source, or this file is lying to the others."""
    source = "\n".join(p.read_text() for p in (REPO / "src" / "valca" / "rules").glob("*.py"))
    for rule_id in SUB_RULE_IDS:
        assert rule_id in source, f"{rule_id} is declared a sub-rule but appears nowhere in the source"


def test_readme_rule_count_matches_engine() -> None:
    """The headline number is the first thing a prospective user reads."""
    match = re.search(r"\*\*(\d+) rules across (\d+) categories\.?\*\*", README.read_text())
    assert match, "README must state '**N rules across M categories**'"
    documented_total = int(match.group(1))
    assert documented_total == len(engine_rule_ids()), (
        f"README advertises {documented_total} rules, engine emits {len(engine_rule_ids())}. "
        "Regenerate the catalogue before releasing."
    )


def test_every_engine_rule_is_documented() -> None:
    missing = sorted(engine_rule_ids() - documented_rule_ids())
    assert not missing, f"Rules shipped but undocumented: {missing}"


def test_no_documented_rule_is_missing_from_engine() -> None:
    """Documenting a rule that does not exist is worse than omitting one."""
    undocumented_in_engine = sorted(documented_rule_ids() - engine_rule_ids())
    assert not undocumented_in_engine, (
        f"README documents rules the engine does not emit: {undocumented_in_engine}"
    )


def test_every_cli_command_is_documented() -> None:
    from valca import cli

    commands = set(getattr(cli, "COMMANDS", ())) or _commands_from_parser()
    undocumented = sorted(
        c for c in commands - UNDOCUMENTED_COMMANDS if not _mentions_command(README.read_text(), c)
    )
    assert not undocumented, f"CLI commands missing from README: {undocumented}"


def test_vscode_listing_rule_count_matches_engine() -> None:
    """The Marketplace listing is a separate public surface and drifts independently."""
    if not VSCODE_README.exists():
        return
    match = re.search(r"What It Catches \((\d+) rules?\)", VSCODE_README.read_text())
    assert match, "VS Code README must state 'What It Catches (N rules)'"
    assert int(match.group(1)) == len(engine_rule_ids()), (
        f"VS Code listing advertises {match.group(1)} rules, engine emits {len(engine_rule_ids())}"
    )


def _commands_from_parser() -> set[str]:
    """Read subcommands straight out of the argparse parser."""
    import contextlib
    import io

    from valca import cli

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        import sys

        original, sys.argv = sys.argv, ["valca", "--help"]
        try:
            cli.main()
        finally:
            sys.argv = original
    match = re.search(r"\{([a-z,]+)\}", buf.getvalue())
    assert match, "could not read subcommands from the CLI parser"
    return set(match.group(1).split(","))


def _mentions_command(text: str, command: str) -> bool:
    return bool(re.search(rf"\b(valca|vigil)\s+{re.escape(command)}\b", text))


def test_every_rule_has_a_description() -> None:
    """A catalogue row with an empty description is worse than no row.

    Thirteen rules — the whole AI-agent, MCP and prompt-injection set — shipped
    with an empty `name`, so the published catalogue rendered blank cells for
    exactly the rules the product is differentiated on.
    """
    unnamed = sorted(r.id for r in DEFAULT_RULES if not getattr(r, "name", "").strip())
    assert not unnamed, f"Rules with no description: {unnamed}"


def test_catalogue_has_no_empty_cells() -> None:
    """Guard the rendered table, not just the source objects."""
    blank = re.findall(r"^\| (VGL-[A-Z]+\d+) \| [A-Z]+ \|\s*\|$", README.read_text(), re.M)
    assert not blank, f"Catalogue rows with an empty 'What it catches' column: {blank}"


# ── Plugin manifest ──────────────────────────────────────────────────────────
# The manifest is a published surface that no test read until 2026-09-13, by
# which point it named the wrong licence (MIT — actually the BUSL Change
# License, four years out), the wrong version (0.1.0 against a shipped 0.5.0),
# the old product name, and told users to `pip install vigil` — a package on
# PyPI that belongs to somebody else entirely.


def _manifest() -> dict:
    import json

    return json.loads(MANIFEST.read_text())


def _pyproject() -> dict:
    import tomllib

    return tomllib.loads((REPO / "pyproject.toml").read_text())["project"]


def test_manifest_identity_matches_packaging() -> None:
    """Name and version are the same facts pyproject.toml already states."""
    manifest, project = _manifest(), _pyproject()
    assert manifest["name"] == project["name"], (
        f"manifest name {manifest['name']!r} != package name {project['name']!r}"
    )
    assert manifest["version"] == project["version"], (
        f"manifest version {manifest['version']} != package version {project['version']}"
    )


def test_manifest_states_the_current_licence() -> None:
    """BUSL-1.1 names MIT as the Change License. That is not today's licence.

    Publishing 'MIT' on a product with a paid tier gives away the terms the
    paid tier rests on.
    """
    declared = _manifest().get("license", "")
    licence_title = (REPO / "LICENSE").read_text().splitlines()[0].strip()
    assert "Business Source License 1.1" in licence_title, (
        f"LICENSE no longer starts with the BUSL title ({licence_title!r}) — update this test"
    )
    assert declared == "BUSL-1.1", (
        f"manifest declares licence {declared!r}, but LICENSE is {licence_title!r}"
    )


def test_manifest_install_steps_name_the_package_we_publish() -> None:
    """`pip install <name>` must name our package, not a stranger's.

    The manifest said `pip install vigil`. `vigil` is live on PyPI under a
    different author, so anyone following the manifest installed someone
    else's code on the strength of our instructions.
    """
    ours = _pyproject()["name"]
    steps = [s for v in _manifest().get("install", {}).values() for s in v]
    installed = re.findall(r"pip install\s+([A-Za-z0-9._-]+)", " ".join(steps))
    assert installed, "manifest install steps contain no `pip install` line"
    wrong = sorted({p for p in installed if p != ours})
    assert not wrong, f"manifest tells users to install {wrong}, but we publish {ours!r}"


def test_manifest_lists_no_rule_the_engine_does_not_emit() -> None:
    """A manifest rule list is optional; a fictional one is not acceptable."""
    listed = {r["id"] for r in _manifest().get("rules", [])}
    phantom_rules = sorted(listed - engine_rule_ids())
    assert not phantom_rules, f"manifest lists rules the engine does not emit: {phantom_rules}"
