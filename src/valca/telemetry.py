"""Anonymous, local-only telemetry for Valca.

Collects only: rule_id, severity, file_ext, timestamp, fp flag.
Never: file path, code snippet, finding message, or any user-identifiable data.

Stored at ~/.valca/events.jsonl (line-delimited JSON), mode 0600. History from
the pre-rename location ~/.vigil/events.jsonl is moved across on first use.

Opt-out: set VALCA_NO_TELEMETRY=1 (or the older VIGIL_NO_TELEMETRY=1), or add
`telemetry = false` to .valcarc. Both variable names are honoured permanently —
an opt-out a user has already set must never quietly stop working.

Events are local-only by default — no network calls are made in this module.
`valca stats` and `valca stats --format json` read events.jsonl for display.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rules.base import Finding

_DEFAULT_EVENTS_FILE = Path.home() / ".valca" / "events.jsonl"
_EVENTS_FILE = _DEFAULT_EVENTS_FILE
_LEGACY_EVENTS_FILE = Path.home() / ".vigil" / "events.jsonl"

#: Any of these set to a non-empty, non-"0" value disables telemetry.
_OPT_OUT_ENVS = ("VALCA_NO_TELEMETRY", "VIGIL_NO_TELEMETRY")


def _is_opted_out(telemetry_config: bool = True) -> bool:
    if not telemetry_config:
        return True
    return any(
        os.environ.get(name, "").strip() not in ("", "0") for name in _OPT_OUT_ENVS
    )


def _migrate_legacy_store() -> None:
    """Move ~/.vigil/events.jsonl to ~/.valca/ once, preserving scan history.

    Guarded to the real default path on purpose. The test suite patches
    _EVENTS_FILE to a temp directory, and migrating under that patch would move
    the developer's actual history into a directory pytest then deletes.
    """
    if _EVENTS_FILE != _DEFAULT_EVENTS_FILE:
        return
    try:
        if _EVENTS_FILE.exists() or not _LEGACY_EVENTS_FILE.is_file():
            return
        _EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        os.replace(_LEGACY_EVENTS_FILE, _EVENTS_FILE)
        os.chmod(_EVENTS_FILE, 0o600)
    except Exception:  # noqa: BLE001 — telemetry must never break a scan
        pass


def record(
    findings: list["Finding"],
    telemetry_enabled: bool = True,
    fp: bool = False,
) -> None:
    """Append one event per finding to ~/.valca/events.jsonl.

    When fp=True the event represents a suppressed finding (false positive):
    the user added '# valca: ignore' or '# pragma: allowlist secret'.

    Silently swallows all errors — telemetry must never break the scan.
    """
    if _is_opted_out(telemetry_enabled) or not findings:
        return
    _migrate_legacy_store()
    try:
        _EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        is_new_file = not _EVENTS_FILE.exists()
        ts = datetime.now(timezone.utc).isoformat()
        with _EVENTS_FILE.open("a") as fh:
            if is_new_file:
                os.chmod(_EVENTS_FILE, 0o600)
            for f in findings:
                ext = f.file_path.suffix if f.file_path else ""
                event: dict = {
                    "ts": ts,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "file_ext": ext,
                }
                if fp:
                    event["fp"] = True
                fh.write(json.dumps(event) + "\n")
    except Exception:  # noqa: BLE001
        pass


def summary() -> dict:
    """Return aggregated stats from local events.jsonl. Returns {} if no data.

    Shape:
    {
        "total_findings": int,          # fired findings (not suppressed)
        "total_fp": int,                # suppressed findings (fp=True events)
        "first_scan": "YYYY-MM-DD",
        "last_scan": "YYYY-MM-DD",
        "by_rule": {
            "VGL-D001": {
                "count": int,
                "fp_count": int,
                "precision": float,     # count / (count + fp_count)
                "first_seen": "YYYY-MM-DD",
                "last_seen": "YYYY-MM-DD",
            }
        },
        "by_severity": {"CRITICAL": int, ...},
        "by_ext": {".yml": int, ...},
    }
    """
    _migrate_legacy_store()
    try:
        if not _EVENTS_FILE.exists():
            return {}

        total = 0
        total_fp = 0
        by_rule_counts: dict[str, int] = {}
        by_rule_fp: dict[str, int] = {}
        by_rule_first: dict[str, str] = {}
        by_rule_last: dict[str, str] = {}
        by_severity: dict[str, int] = {}
        by_ext: dict[str, int] = {}
        all_ts: list[str] = []

        with _EVENTS_FILE.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rule_id = ev.get("rule_id", "unknown")
                is_fp = bool(ev.get("fp", False))
                ts = ev.get("ts", "")
                ts_date = ts[:10] if ts else ""
                sev = ev.get("severity", "?")
                ext = ev.get("file_ext", "") or "no ext"

                if ts_date:
                    all_ts.append(ts_date)
                    cur_first = by_rule_first.get(rule_id)
                    if cur_first is None or ts_date < cur_first:
                        by_rule_first[rule_id] = ts_date
                    cur_last = by_rule_last.get(rule_id)
                    if cur_last is None or ts_date > cur_last:
                        by_rule_last[rule_id] = ts_date

                if is_fp:
                    total_fp += 1
                    by_rule_fp[rule_id] = by_rule_fp.get(rule_id, 0) + 1
                else:
                    total += 1
                    by_rule_counts[rule_id] = by_rule_counts.get(rule_id, 0) + 1
                    by_severity[sev] = by_severity.get(sev, 0) + 1
                    by_ext[ext] = by_ext.get(ext, 0) + 1

        if total == 0 and total_fp == 0:
            return {}

        all_rule_ids = set(by_rule_counts) | set(by_rule_fp)
        by_rule: dict[str, dict] = {}
        for rule_id in all_rule_ids:
            count = by_rule_counts.get(rule_id, 0)
            fp_count = by_rule_fp.get(rule_id, 0)
            denom = count + fp_count
            precision = (count / denom) if denom > 0 else 1.0
            by_rule[rule_id] = {
                "count": count,
                "fp_count": fp_count,
                "precision": round(precision, 3),
                "first_seen": by_rule_first.get(rule_id, ""),
                "last_seen": by_rule_last.get(rule_id, ""),
            }

        all_ts_sorted = sorted(all_ts)
        return {
            "total_findings": total,
            "total_fp": total_fp,
            "first_scan": all_ts_sorted[0] if all_ts_sorted else "",
            "last_scan": all_ts_sorted[-1] if all_ts_sorted else "",
            "by_rule": by_rule,
            "by_severity": by_severity,
            "by_ext": by_ext,
        }
    except Exception:  # noqa: BLE001
        return {}
