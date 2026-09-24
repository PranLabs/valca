"""Valca as an MCP server, so an agent can ask for a scan instead of only being blocked by one.

Two tools, both read-only: `scan` and `list_rules`. There is deliberately no
tool that writes, edits or fixes anything. A scanner that can modify code is a
new attack surface, and it is the surface VGL-MCP003 and VGL-MCP005 exist to
catch. Valca does not ship the thing it warns about.

This does not replace the PostToolUse hook. The hook is push: the harness runs
it on every write, whether or not the model wants it. MCP is pull: the agent
decides whether to call it. Enforcement stays with the hook, because a check an
agent can decline is not enforcement.

Three runtime guardrails, decided before the code was written rather than
patched in afterwards:

* **Paths never leave the root.** The agent chooses the argument to `scan`, so
  without a boundary it could walk to `~/.ssh` or `/` and use the findings to
  map a filesystem it was never given. See `_resolve`.
* **Paths are returned relative to that root.** An absolute path carries the
  username and directory layout.
* **Snippets are never returned.** For the secret-bearing rules the snippet is
  the matched line, which is the line containing the secret. Omitting the field
  outright fails closed; classifying rules one by one would fail open on the
  next rule somebody forgets to classify.

Telemetry is off on this path regardless of configuration: a scan an agent
requested is not the user's own scan, and should not shape their statistics.

Install:  pip install "valca[mcp]"
Run:      valca-mcp
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations
except ImportError as exc:  # pragma: no cover - exercised by a subprocess test
    raise SystemExit(
        "valca-mcp requires the MCP SDK, which ships as an optional extra so that\n"
        "the core package keeps zero runtime dependencies.\n"
        '\n    pip install "valca[mcp]"\n'
    ) from exc

from .config import load_config
from .engine import Engine
from .reporter import dedup_findings
from .rules import DEFAULT_RULES, SEVERITY_ORDER, Finding, Severity

#: Declared to the protocol, not merely in prose, so a client can enforce it.
_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    open_world_hint=False,
)

#: Overrides the scan boundary. Without it the boundary is the working
#: directory the server was started in.
_ROOT_ENV = "VALCA_MCP_ROOT"


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("valca")
    except Exception:  # noqa: BLE001 - version is cosmetic, never fail the server
        return "0.0.0"


server = MCPServer(
    "valca",
    version=_version(),
    description="Read-only security scanner for code, configuration and AI-agent setups.",
)


def _root() -> Path:
    return Path(os.environ.get(_ROOT_ENV) or Path.cwd()).resolve()


def _resolve(path: str) -> Path:
    """Resolve `path` inside the root, or refuse.

    Resolution happens before the check so that `../` and symlinks cannot walk
    out: the comparison is on the real location, not the spelling.

    `~` is expanded first, deliberately. pathlib leaves it literal, so without
    this `~/.ssh` would be read as a directory of that name inside the root and
    refused only because it does not exist — the right answer for the wrong
    reason, and one that breaks the moment somebody adds expanduser() for
    convenience. Expanding it means home-relative paths are judged against the
    boundary like any other.
    """
    root = _root()
    target = Path(path).expanduser()
    target = target if target.is_absolute() else root / target
    target = target.resolve()
    if target != root and root not in target.parents:
        raise ValueError(
            f"{path!r} is outside the scan root. The server scans only within "
            f"the directory it was started in, or {_ROOT_ENV} when set."
        )
    return target


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def _as_dict(finding: Finding, root: Path) -> dict[str, Any]:
    """Serialise a finding. `snippet` is omitted deliberately — see the module docstring."""
    return {
        "rule": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "file": _relative(finding.file_path, root),
        "line": finding.line,
        "fix": finding.fix,
    }


@server.tool(annotations=_READ_ONLY)
def scan(path: str = ".") -> dict[str, Any]:
    """Scan a file or directory for security problems and return the findings.

    Covers hardcoded secrets, insecure Docker and Kubernetes configuration,
    Terraform and IAM policy, dependency vulnerabilities, and the AI-agent
    attack surface: prompt injection, unsafe MCP server configuration, and
    dangerous instructions in agent configuration files.

    `path` is interpreted relative to the scan root and may not leave it.
    Returned file paths are relative to that root. Matched source lines are not
    returned. Project configuration in `.valcarc` or `.vigilrc` is honoured.
    """
    root = _root()
    try:
        target = _resolve(path)
    except ValueError as exc:
        return {"error": str(exc), "findings": [], "count": 0}

    if not target.exists():
        return {"error": f"path not found: {path}", "findings": [], "count": 0}

    config = load_config(target)
    rules = [r for r in DEFAULT_RULES if r.id not in config.disabled_rules]
    engine = Engine(rules=rules, telemetry_enabled=False)

    if target.is_file():
        results = {target: engine.scan(target)}
    else:
        results = engine.scan_dir(target, extra_skip=set(config.exclude_paths))

    findings: list[Finding] = []
    for found in results.values():
        findings.extend(dedup_findings(found))

    if config.min_severity:
        floor = SEVERITY_ORDER[Severity(config.min_severity)]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= floor]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    return {
        "scanned": _relative(target, root) or ".",
        "count": len(findings),
        "by_severity": counts,
        "blocking": Engine.blocking(findings),
        "findings": [_as_dict(f, root) for f in findings],
    }


@server.tool(annotations=_READ_ONLY)
def list_rules() -> dict[str, Any]:
    """Return the rule catalogue: every rule id, its severity, and what it catches."""
    return {
        "count": len(DEFAULT_RULES),
        "rules": [
            {"id": r.id, "severity": r.severity.value, "catches": r.name}
            for r in DEFAULT_RULES
        ],
    }


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
