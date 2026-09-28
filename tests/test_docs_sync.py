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
PLUGIN_ROOT = REPO / "plugin"
MANIFEST = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
HOOKS_JSON = PLUGIN_ROOT / "hooks" / "hooks.json"
MCP_JSON = PLUGIN_ROOT / ".mcp.json"

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


def test_vscode_guard_moved_rather_than_vanished() -> None:
    """The Marketplace rule-count check now lives in PranLabs/valca-vscode.

    The extension was split into its own repository on 2026-09-27. The old test
    here read `vigil-vscode/README.md` and began with `if not exists(): return`,
    so the moment that directory left, it would have passed forever while
    checking nothing — the precise way a guard disappears without anyone
    noticing.

    It was replaced by `scripts/check_listing.py` in the extension's repository,
    which is a stronger check: it installs the *published* `valca` package and
    compares the listing against what a user actually receives, rather than
    against source sitting in a sibling directory. The extension's CI runs it on
    every push.

    This test exists so the move is recorded where the old guard used to be,
    instead of leaving a silent hole.
    """
    assert not VSCODE_README.exists(), (
        "vigil-vscode/ is back in this repository. The Marketplace rule-count "
        "guard lives in PranLabs/valca-vscode now; if the extension returns, the "
        "guard has to come back with it or the listing can drift unchecked again."
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


def test_published_install_instructions_name_our_package() -> None:
    """`pip install <name>` must name our package, not a stranger's.

    `vigil` is live on PyPI under a different author, so any instruction saying
    `pip install vigil` sends people to someone else's code on the strength of
    our documentation.

    This check used to read the plugin manifest's invented `install` key. That
    key is not part of the Claude Code plugin spec and is gone — but the same
    wrong instruction was sitting in README_INSTALL.md the whole time, unwatched,
    because only one of the two files was being checked. Every published file
    that carries an install command is checked here now.
    """
    ours = _pyproject()["name"]
    sources = [
        REPO / "plugin" / "README_INSTALL.md",
        REPO / "README.md",
        REPO / "CONTRIBUTING.md",
    ]
    wrong: list[str] = []
    found_any = False
    for path in sources:
        if not path.exists():
            continue
        for pkg in re.findall(r"pip install\s+\"?([A-Za-z0-9._-]+)", path.read_text()):
            found_any = True
            # Flags, not package names: `-r requirements-dev.txt`, `-e .`,
            # `-U pip`. The check is about which *package* is named.
            if pkg in (ours, "-r", "-e", "-U", "--upgrade"):
                continue
            wrong.append(f"{path.name}: pip install {pkg}")

    assert found_any, "no install instructions found in any published file"
    assert not wrong, (
        f"published files tell users to install something other than {ours!r}: {wrong}"
    )


def test_plugin_uses_the_real_claude_code_layout() -> None:
    """The old `plugin/manifest.json` was not a Claude Code plugin at all.

    Verified against the official docs on 2026-09-13: the manifest belongs at
    `.claude-plugin/plugin.json`, hooks go in a separate `hooks/hooks.json`, and
    the `install` and `rules` keys we had invented are not spec fields — Claude
    Code silently ignores them. A plugin in the old shape would have been
    published and quietly done nothing.
    """
    assert MANIFEST.exists(), "plugin/.claude-plugin/plugin.json is missing"
    assert HOOKS_JSON.exists(), "hooks belong in plugin/hooks/hooks.json, not the manifest"
    assert not (PLUGIN_ROOT / "manifest.json").exists(), (
        "plugin/manifest.json is back. That layout is not the Claude Code plugin "
        "spec and is ignored by the loader."
    )

    manifest = _manifest()
    assert "name" in manifest, "`name` is the only required manifest field"
    for invented in ("install", "rules", "hooks"):
        assert invented not in manifest, (
            f"`{invented}` is not a plugin.json field. Hooks go in hooks/hooks.json; "
            f"install steps and rule lists are not part of the spec at all."
        )


def test_hooks_declare_the_posttooluse_gate() -> None:
    """The hook is the enforcement path, so its wiring has to be right.

    PostToolUse is a *list* of matcher groups, each with its own list of hooks.
    The old file had it as a single object, which the loader would not accept.
    """
    import json

    hooks = json.loads(HOOKS_JSON.read_text())["hooks"]
    post = hooks.get("PostToolUse")
    assert isinstance(post, list), "PostToolUse must be a list of matcher groups"

    group = post[0]
    assert group["matcher"] == "Write|Edit|MultiEdit", group["matcher"]
    command = group["hooks"][0]["command"]
    assert "${CLAUDE_PLUGIN_ROOT}" in command, (
        "the hook command must be resolved through ${CLAUDE_PLUGIN_ROOT}; a "
        "relative path breaks wherever the plugin is installed"
    )
    assert command.endswith("hook.sh")
    assert (PLUGIN_ROOT / "hook.sh").exists(), "hooks.json points at a missing hook.sh"


def test_plugin_bundles_the_mcp_server() -> None:
    """Hook plus MCP server in one install is the whole point of this channel.

    No other distribution surface carries both halves of the product at once.
    """
    import json
    import tomllib

    assert _manifest().get("mcpServers") == "./.mcp.json", (
        "plugin.json must point at the .mcp.json that declares the server"
    )
    servers = json.loads(MCP_JSON.read_text())["mcpServers"]
    assert "valca" in servers, servers
    command = servers["valca"]["command"]

    scripts = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]
    assert command in scripts, (
        f".mcp.json runs {command!r}, which is not a console script this package "
        f"installs ({sorted(scripts)}). The plugin would fail at startup."
    )
