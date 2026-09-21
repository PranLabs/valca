"""vigil scan <file|dir> [--format terminal|json|sarif] [--severity CRITICAL|HIGH|...]
vigil init [--global]
vigil feedback

Exit codes (scan):
  0 — no findings
  1 — advisory findings only (MEDIUM/LOW/INFO)
  2 — CRITICAL or HIGH findings present (causes Claude Code to block the write)
"""
import argparse
import json as _json
import sys
import webbrowser
from pathlib import Path

from .config import load_config
from .engine import Engine
from .reporter import report_terminal, report_json, report_sarif, dedup_findings
from .rules import DEFAULT_RULES, Severity, SEVERITY_ORDER


def _find_hook_sh() -> Path | None:
    """Locate plugin/hook.sh relative to this file (works for editable installs)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent.parent / "plugin" / "hook.sh",    # editable: src/valca/ → project root
        Path.home() / ".vigil" / "plugin" / "hook.sh",
        Path("/usr/local/share/vigil/hook.sh"),
    ]
    return next((p for p in candidates if p.exists()), None)


def _run_init(global_install: bool) -> None:
    hook_sh = _find_hook_sh()
    if hook_sh is None:
        print(
            "vigil init: could not locate plugin/hook.sh.\n"
            "Run from the vigil project directory or see plugin/README_INSTALL.md.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Ensure hook.sh is executable — git clones and zip downloads often strip the bit
    if not hook_sh.stat().st_mode & 0o111:
        hook_sh.chmod(hook_sh.stat().st_mode | 0o755)
        print(f"Fixed execute permission on {hook_sh.name}")

    settings_path = (
        Path.home() / ".claude" / "settings.json"
        if global_install
        else Path.cwd() / ".claude" / "settings.json"
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = _json.loads(settings_path.read_text())
        except (_json.JSONDecodeError, OSError):
            settings = {}

    post_tool_use: list = settings.setdefault("hooks", {}).setdefault("PostToolUse", [])
    for entry in post_tool_use:
        for h in entry.get("hooks", []):
            if Path(h.get("command", "")).name == hook_sh.name:
                print(f"Valca hook already installed in {settings_path}")
                return

    post_tool_use.append({
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{"type": "command", "command": str(hook_sh)}],
    })
    settings_path.write_text(_json.dumps(settings, indent=2) + "\n")
    print(f"Valca hook installed → {settings_path}")
    print("Reload Claude Code to activate.")


def _run_stats(fmt: str = "terminal") -> None:
    from . import telemetry as _tel

    data = _tel.summary()

    if not data:
        if fmt == "json":
            print("{}")
        else:
            print("No scan data yet. Run vigil scan on a file to start collecting stats.")
            print("Opt-out: set VIGIL_NO_TELEMETRY=1 or telemetry=false in .vigilrc")
        return

    if fmt == "json":
        print(_json.dumps(data, indent=2))
        return

    total = data.get("total_findings", 0)
    total_fp = data.get("total_fp", 0)
    first_scan = data.get("first_scan", "—") or "—"
    last_scan = data.get("last_scan", "—") or "—"
    by_rule = data.get("by_rule", {})
    by_severity = data.get("by_severity", {})
    by_ext = data.get("by_ext", {})

    _B = "\033[1m"
    _R = "\033[0m"
    _D = "\033[2m"
    _SEV_COLOR = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM": "\033[94m", "LOW": "\033[96m", "INFO": "\033[37m",
    }

    def _sev(s: str) -> str:
        return f"{_SEV_COLOR.get(s, '')}{s}{_R}"

    print(f"\n{_B}Valca — local scan stats{_R}")
    print("─" * 60)
    fp_note = f"  {_D}({total_fp} suppressed via ignore markers){_R}" if total_fp else ""
    print(f"  {_B}Total findings recorded{_R}   {total}{fp_note}")
    print(f"  {_D}First scan{_R}  {first_scan}  {_D}·  Last scan{_R}  {last_scan}")

    # Top rules table: hit count bar + precision + first/last seen
    print(f"\n  {_B}Top rules{_R}  {_D}(precision = findings / (findings + suppressed)){_R}")
    print(f"  {'─' * 58}")
    sorted_rules = sorted(by_rule.items(), key=lambda x: -x[1]["count"])[:10]
    for rule_id, stats in sorted_rules:
        count = stats["count"]
        fp_count = stats.get("fp_count", 0)
        precision = stats.get("precision", 1.0)
        first = stats.get("first_seen", "")[:10] or "—"
        last = stats.get("last_seen", "")[:10] or "—"
        bar = "█" * min(count, 20)
        pct = int(count / total * 100) if total else 0
        prec_str = f"{int(precision * 100):>3}%" if fp_count else "  — "
        prec_col = "\033[91m" if precision < 0.8 else ("\033[93m" if precision < 0.95 else "")
        prec_colored = f"{prec_col}{prec_str}{_R}"
        print(f"  {rule_id:<12}  {bar:<20}  {count:>4} ({pct:>2}%)  prec {prec_colored}  {_D}{first} → {last}{_R}")

    print(f"\n  {_B}By severity{_R}")
    print(f"  {'─' * 42}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        if count:
            pct = int(count / total * 100) if total else 0
            print(f"  {_sev(sev):<22}  {count:>4}  ({pct:>2}%)")

    print(f"\n  {_B}By file type{_R}")
    print(f"  {'─' * 42}")
    for ext, count in sorted(by_ext.items(), key=lambda x: -x[1])[:8]:
        print(f"  {ext:<14}  {count:>4}")

    # Precision warnings: any rule with recorded FPs below 80%
    low_prec = [(rid, s) for rid, s in by_rule.items() if s.get("fp_count", 0) > 0 and s["precision"] < 0.8]
    if low_prec:
        print(f"\n  {_B}⚠  Low-precision rules{_R}  {_D}(< 80% — consider tuning){_R}")
        print(f"  {'─' * 42}")
        for rid, s in sorted(low_prec, key=lambda x: x[1]["precision"]):
            print(f"  {rid:<14}  {int(s['precision']*100)}%  ({s['fp_count']} suppressed / {s['count'] + s['fp_count']} total)")

    print(f"\n{_D}Stats are local-only · stored at ~/.valca/events.jsonl{_R}\n")


def _run_log(args) -> None:
    from . import findingslog
    import json as _json2

    entries = findingslog.read(
        project=args.project,
        severity=args.severity,
        since=args.since,
        limit=args.limit,
    )

    if not entries:
        print("No findings logged yet. Run vigil scan on a file to start.")
        print(f"Log: {findingslog._log_path()}")
        return

    if args.format == "json":
        print(_json2.dumps(entries, indent=2))
        return

    _SEV_COLOR = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM":   "\033[94m", "LOW":  "\033[96m", "INFO": "\033[37m",
    }
    _R = "\033[0m"
    _D = "\033[2m"
    _B = "\033[1m"

    print(f"\n{_B}Valca findings log{_R}  {_D}({len(entries)} shown · {findingslog._log_path()}){_R}\n")
    print(f"  {'DATE':<12}  {'SEV':<8}  {'RULE':<14}  {'FILE':<30}  TITLE")
    print("  " + "─" * 84)

    for e in entries:
        ts = e.get("ts", "")[:10]
        sev = e.get("severity", "?")
        col = _SEV_COLOR.get(sev, "")
        rule = e.get("rule", "?")
        file_str = e.get("file", "?")
        # Show only the last 2 path components for readability
        try:
            from pathlib import Path as _Path
            parts = _Path(file_str).parts
            file_short = "/".join(parts[-2:]) if len(parts) >= 2 else file_str
        except Exception:
            file_short = file_str
        title = e.get("title", "")[:48]
        print(f"  {_D}{ts}{_R}  {col}{sev:<8}{_R}  {rule:<14}  {file_short:<30}  {title}")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        # No prog=: argparse falls back to sys.argv[0], so the tool calls itself
        # whichever name the user invoked. Hardcoding it meant `valca --help`
        # printed "usage: vigil", contradicting the documented primary command.
        description="AI coding security co-pilot — blocks insecure code at generation time.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", type=Path)
    scan_p.add_argument(
        "--format", choices=["terminal", "json", "sarif"], default="terminal",
        help="Output format (default: terminal)",
    )
    scan_p.add_argument(
        "--severity", choices=[s.value for s in Severity], default=None,
        help="Only report findings at this severity level or higher",
    )
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    init_p = sub.add_parser("init", help="Wire the Valca PostToolUse hook into .claude/settings.json")
    init_p.add_argument(
        "--global", dest="global_install", action="store_true",
        help="Install into ~/.claude/settings.json (user-wide) instead of ./.claude/settings.json",
    )

    sub.add_parser("feedback", help="Open the Valca feedback & waitlist page")

    stats_p = sub.add_parser("stats", help="Show local scan statistics from ~/.valca/events.jsonl")
    stats_p.add_argument(
        "--format", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal)",
    )

    log_p = sub.add_parser("log", help="Show persistent findings log (~/.vigil/findings.jsonl)")
    log_p.add_argument("--project", default=None, help="Filter by path prefix (e.g. 'api', 'backend')")
    log_p.add_argument("--severity", choices=[s.value for s in Severity], default=None, help="Filter by severity")
    log_p.add_argument("--since", default=None, metavar="DATE", help="Filter by date, e.g. 2026-06-28")
    log_p.add_argument("--limit", type=int, default=20, help="Max rows to show (default: 20)")
    log_p.add_argument("--format", choices=["terminal", "json"], default="terminal")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "feedback":
        url = "https://github.com/vigilsec-io/cordon/issues"
        print(f"Opening {url}")
        webbrowser.open(url)
        return

    if args.command == "stats":
        _run_stats(fmt=getattr(args, "format", "terminal"))
        return

    if args.command == "log":
        _run_log(args)
        return

    if args.command == "init":
        _run_init(args.global_install)
        return

    path = args.path.resolve()
    config = load_config(path)
    rules = [r for r in DEFAULT_RULES if r.id not in config.disabled_rules]
    engine = Engine(rules=rules, telemetry_enabled=config.telemetry)

    if path.is_file():
        # Honour exclude_paths for single-file scans too (same logic scan_dir uses)
        if config.exclude_paths and any(part in config.exclude_paths for part in path.parts):
            results = {}
        else:
            findings = engine.scan(path)
            results = {path: findings} if findings else {}
    elif path.is_dir():
        results = engine.scan_dir(path, extra_skip=set(config.exclude_paths))
    else:
        print(f"vigil: path not found: {path}", file=sys.stderr)
        sys.exit(1)

    # Dedup: merge native + Trivy findings that share the same root cause category
    results = {p: dedup_findings(fs) for p, fs in results.items()}
    all_findings = [f for fs in results.values() for f in fs]

    # --severity flag takes priority over .vigilrc min_severity
    effective_sev = args.severity or config.min_severity
    if effective_sev:
        min_order = SEVERITY_ORDER[Severity(effective_sev)]
        all_findings = [f for f in all_findings if SEVERITY_ORDER[f.severity] <= min_order]
        results = {
            p: [f for f in fs if SEVERITY_ORDER[f.severity] <= min_order]
            for p, fs in results.items()
        }
        results = {p: fs for p, fs in results.items() if fs}

    if args.format == "json":
        print(report_json(results))
    elif args.format == "sarif":
        print(report_sarif(results))
    else:
        for _path, file_findings in results.items():
            report_terminal(file_findings, use_color=not args.no_color)
        if all_findings:
            _dim = "\033[2m" if not args.no_color else ""
            _rst = "\033[0m" if not args.no_color else ""
            print(
                f"{_dim}── Valca · github.com/vigilsec-io/cordon ──{_rst}",
                file=sys.stderr,
            )

    if engine.blocking(all_findings):
        sys.exit(2)
    if all_findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
