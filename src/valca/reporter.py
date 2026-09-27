import json
import sys
from pathlib import Path
from .rules import Finding, Severity, SEVERITY_ORDER
try:  # optional: ships only in builds licensed for compliance mapping
    from . import compliance as _comp
except ImportError:  # community build — findings carry no compliance tags
    _comp = None


def _compliance_tags(rule_id: str):
    """Compliance mappings, when this build is licensed for them.

    The community build ships without the mapping module; findings are complete
    without it, they simply carry no framework annotations. Routing every lookup
    through here means a new call site cannot forget the guard.
    """
    return _comp.get(rule_id) if _comp is not None else None


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[93m",
    Severity.MEDIUM:   "\033[94m",
    Severity.LOW:      "\033[96m",
    Severity.INFO:     "\033[37m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share the same category on the same file.

    When a native rule and VGL-T001 (Trivy) both catch the same root cause
    (e.g. running as root → VGL-DF001 + Trivy DS-0002), surface one finding
    at the highest severity and annotate it with the corroborating rule ID.
    Findings without a category pass through unchanged.
    """
    from collections import defaultdict

    uncategorized: list[Finding] = []
    by_key: dict[tuple, list[Finding]] = defaultdict(list)

    for f in findings:
        if f.category is None:
            uncategorized.append(f)
        else:
            by_key[(f.file_path, f.category)].append(f)

    merged: list[Finding] = []
    for group in by_key.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # Primary = highest severity; prefer findings with line numbers on ties
        group.sort(key=lambda f: (SEVERITY_ORDER[f.severity], 0 if f.line else 1))
        primary = group[0]
        other_ids = ", ".join(f.rule_id for f in group[1:])
        merged.append(Finding(
            rule_id=primary.rule_id,
            severity=primary.severity,
            message=f"{primary.message} [corroborated by {other_ids}]",
            file_path=primary.file_path,
            line=primary.line,
            snippet=primary.snippet,
            fix=primary.fix,
            category=primary.category,
        ))

    result = merged + uncategorized
    result.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return result


def _c(sev: Severity, text: str, use_color: bool) -> str:
    return f"{_COLORS[sev]}{text}{_RESET}" if use_color else text


def report_terminal(findings: list[Finding], use_color: bool = True) -> None:
    if not findings:
        return
    blocking = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    advisory = [f for f in findings if f.severity not in (Severity.CRITICAL, Severity.HIGH)]

    if blocking:
        label = _c(Severity.CRITICAL, "BLOCKED", use_color)
        print(f"\n{label} — {len(blocking)} CRITICAL/HIGH finding(s):", file=sys.stderr)
        print("─" * 60, file=sys.stderr)

    for f in findings:
        loc = f"{f.file_path.name}:{f.line}" if f.line else f.file_path.name
        sev_label = _c(f.severity, f"[{f.severity.value}]", use_color)
        print(f"{sev_label} {f.rule_id} — {f.message}", file=sys.stderr)
        print(f"  at {loc}", file=sys.stderr)
        if f.snippet:
            print(f"  → {f.snippet[:120]}", file=sys.stderr)
        if f.fix:
            print(f"  fix: {f.fix}", file=sys.stderr)
        print(file=sys.stderr)

    if advisory:
        print(
            f"Advisory: {len(advisory)} MEDIUM/LOW/INFO finding(s) — not blocking.",
            file=sys.stderr,
        )



def _tool_version() -> str:
    """Real package version, so SARIF does not misreport the tool that produced it.

    GitHub code scanning records tool.driver.version against every alert; a
    hardcoded default silently attributes today's findings to an old release.
    """
    try:
        from importlib.metadata import version

        return version("valca")
    except Exception:  # noqa: BLE001
        return "0.0.0"


def report_sarif(results: dict[Path, list[Finding]], tool_version: str | None = None) -> str:
    tool_version = tool_version or _tool_version()
    all_findings = [f for fs in results.values() for f in fs]
    rule_index: dict[str, int] = {}
    for f in all_findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rule_index)

    def _sarif_rule(rid: str) -> dict:
        tags = _compliance_tags(rid)
        rule: dict = {
            "id": rid,
            "name": rid.replace("-", ""),
            "shortDescription": {"text": rid},
        }
        if tags:
            rule["properties"] = {
                "tags": (
                    [f"OWASP:{t}" for t in tags.get("owasp", [])]
                    + [f"NIST-SSDF:{t}" for t in tags.get("nist-ssdf", [])]
                    + tags.get("cwe", [])
                ),
            }
        return rule

    sarif_rules = [_sarif_rule(rid) for rid in rule_index]

    sarif_results = []
    for path, findings in results.items():
        for f in findings:
            sarif_results.append({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": f.line or 1},
                    }
                }],
            })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "valca",
                    "version": tool_version,
                    "informationUri": "https://pypi.org/project/valca",
                    "rules": sarif_rules,
                }
            },
            "results": sarif_results,
        }],
    }, indent=2)


def report_json(results: dict[Path, list[Finding]]) -> str:
    out = []
    for path, findings in results.items():
        for f in findings:
            entry: dict = {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "file": str(path),
                "line": f.line,
                "snippet": f.snippet,
                "fix": f.fix,
            }
            if f.category:
                entry["category"] = f.category
            tags = _compliance_tags(f.rule_id)
            if tags:
                entry["compliance"] = tags
            out.append(entry)
    return json.dumps(out, indent=2)
