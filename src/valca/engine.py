from pathlib import Path
from .rules import DEFAULT_RULES, Finding, Rule, Severity, SEVERITY_ORDER
from . import telemetry as _telemetry
from . import findingslog as _findingslog


#: `# vigil: ignore` is the pre-rename marker and is honoured permanently —
#: suppressions already written into user code must never start firing again.
_SUPPRESS_MARKERS = ("# valca: ignore", "# vigil: ignore", "# pragma: allowlist secret")


class Engine:
    def __init__(self, rules: list[Rule] | None = None, telemetry_enabled: bool = True) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES
        self._telemetry = telemetry_enabled

    def scan(self, path: Path) -> list[Finding]:
        """Scan a single file. Returns findings sorted by severity (CRITICAL first).

        Lines containing '# valca: ignore' (or the older '# vigil: ignore', or
        '# pragma: allowlist secret') are suppressed — same pattern as '# noqa'
        (flake8) and '# nosec' (bandit).
        Suppressed findings are recorded as false-positive events in telemetry so
        per-rule precision can be tracked over time.
        """
        if not path.is_file():
            return []
        try:
            source_lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            source_lines = []

        applicable = [r for r in self.rules if r.applies_to(path)]
        findings: list[Finding] = []
        suppressed: list[Finding] = []
        for rule in applicable:
            for f in rule.check(path):
                if (
                    f.line
                    and f.line <= len(source_lines)
                    and any(m in source_lines[f.line - 1] for m in _SUPPRESS_MARKERS)
                ):
                    suppressed.append(f)
                    continue
                findings.append(f)
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
        _telemetry.record(sorted_findings, telemetry_enabled=self._telemetry)
        if suppressed:
            _telemetry.record(suppressed, telemetry_enabled=self._telemetry, fp=True)
        _findingslog.append(sorted_findings, enabled=self._telemetry)
        return sorted_findings

    def scan_dir(
        self,
        root: Path,
        skip: set[str] | None = None,
        extra_skip: set[str] | None = None,
    ) -> dict[Path, list[Finding]]:
        """Recursively scan all scannable files under root.

        skip: replaces the default skip set when provided.
        extra_skip: merged with the default skip set (use for .vigilrc exclude_paths).
        """
        _default = {".venv", "venv", "node_modules", ".git", "build", "dist", "__pycache__", "Pods"}
        _skip = (skip if skip is not None else _default) | (extra_skip or set())
        results: dict[Path, list[Finding]] = {}
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(s in path.parts for s in _skip):
                continue
            if not any(r.applies_to(path) for r in self.rules):
                continue
            findings = self.scan(path)
            if findings:
                results[path] = findings
        return results

    @staticmethod
    def blocking(findings: list[Finding]) -> bool:
        """True if any finding is CRITICAL or HIGH — should block the AI write."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
