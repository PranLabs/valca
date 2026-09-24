"""Persistent findings log — append-only JSONL at ~/.vigil/findings.jsonl.

Every scan that produces findings appends one record per finding, giving a local
audit trail across sessions: what was caught, when, and in which file.

Two properties this file gets wrong easily, both fixed here and both regression
tested:

* **It honours the telemetry opt-out.** It did not until 2026-09-24. A user who
  set `telemetry = false` or VALCA_NO_TELEMETRY=1 silenced events.jsonl and kept
  writing every finding here, with full absolute paths. The decision is delegated
  to telemetry so the two stores cannot drift apart again.
* **It is owner-only.** Records carry absolute paths — username, directory
  layout, project names — so the file is more sensitive than events.jsonl, which
  is only rule ids and extensions. It was created at the default umask (0644)
  while events.jsonl was correctly 0600.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Single source of truth for "has the user opted out". Importing the helper is
# deliberate: duplicating the check is how these two stores diverged.
from .telemetry import _is_opted_out
from .rules.base import Finding


def _log_path() -> Path:
    env = os.environ.get("VIGIL_LOG_PATH")
    if env:
        p = Path(env)
        return p if p.suffix == ".jsonl" else p / "findings.jsonl"
    return Path.home() / ".vigil" / "findings.jsonl"


def append(
    findings: list[Finding],
    session_id: str | None = None,
    enabled: bool = True,
) -> None:
    """Append findings to the persistent log.

    No-op when there is nothing to write, or when the user has opted out through
    `telemetry = false` in config or either opt-out environment variable.
    """
    if not findings or _is_opted_out(enabled):
        return
    log = _log_path()
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        is_new = not log.exists()
        with log.open("a") as fh:
            # Tighten on creation, and repair a file that predates this rule:
            # the store shipped at 0644 for months, so self-healing on the next
            # write is what actually protects existing installs.
            if is_new or (log.stat().st_mode & 0o077):
                os.chmod(log, 0o600)
            for f in findings:
                record: dict = {
                    "ts": ts,
                    "file": str(f.file_path),
                    "rule": f.rule_id,
                    "severity": f.severity.value,
                    "title": (f.message or "")[:120],
                    "detail": (f.fix or "")[:120],
                }
                if session_id:
                    record["session_id"] = session_id
                fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # log failures are never fatal


def read(
    project: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Read findings from the log, newest last, with optional filters."""
    log = _log_path()
    if not log.exists():
        return []
    entries: list[dict] = []
    try:
        with log.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if project and project not in e.get("file", ""):
                    continue
                if severity and e.get("severity", "").upper() != severity.upper():
                    continue
                if since and e.get("ts", "") < since:
                    continue
                entries.append(e)
    except OSError:
        return []
    return entries[-limit:]
