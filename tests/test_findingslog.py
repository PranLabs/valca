"""Tests for persistent findings log: ticket #16."""
import json
import os
from pathlib import Path
import pytest
from valca.rules.base import Finding, Severity


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    """Redirect the findings log to a temp path for each test."""
    p = tmp_path / "findings.jsonl"
    monkeypatch.setenv("VIGIL_LOG_PATH", str(p))
    return p


def _finding(rule_id="VGL-S001", sev=Severity.HIGH, msg="test finding"):
    return Finding(
        rule_id=rule_id, severity=sev, message=msg,
        file_path=Path("/app/main.py"), line=10,
        fix="fix hint",
    )


class TestFindingsLogAppend:

    def test_creates_log_file_on_first_write(self, log_path):
        from valca import findingslog
        findingslog.append([_finding()])
        assert log_path.exists()

    def test_appends_jsonl_record_per_finding(self, log_path):
        from valca import findingslog
        findingslog.append([_finding("VGL-S001"), _finding("VGL-D001")])
        lines = [l for l in log_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2

    def test_record_has_required_fields(self, log_path):
        from valca import findingslog
        findingslog.append([_finding("VGL-S001", Severity.CRITICAL, "bad secret")])
        record = json.loads(log_path.read_text().splitlines()[0])
        assert "ts" in record
        assert record["rule"] == "VGL-S001"
        assert record["severity"] == "CRITICAL"
        assert record["file"] == "/app/main.py"
        assert "bad secret" in record["title"]

    def test_append_is_additive(self, log_path):
        from valca import findingslog
        findingslog.append([_finding("VGL-S001")])
        findingslog.append([_finding("VGL-S002")])
        lines = [l for l in log_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2

    def test_no_op_on_empty_findings(self, log_path):
        from valca import findingslog
        findingslog.append([])
        assert not log_path.exists()

    def test_session_id_included_when_provided(self, log_path):
        from valca import findingslog
        findingslog.append([_finding()], session_id="abc-123")
        record = json.loads(log_path.read_text().splitlines()[0])
        assert record["session_id"] == "abc-123"

    def test_session_id_omitted_when_not_provided(self, log_path):
        from valca import findingslog
        findingslog.append([_finding()])
        record = json.loads(log_path.read_text().splitlines()[0])
        assert "session_id" not in record


class TestFindingsLogRead:

    def _write(self, log_path, entries: list[dict]):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")

    def test_returns_empty_when_no_log(self, log_path):
        from valca import findingslog
        assert findingslog.read() == []

    def test_returns_all_entries_within_limit(self, log_path):
        from valca import findingslog
        self._write(log_path, [
            {"ts": "2026-06-28T10:00:00+00:00", "rule": "VGL-S001", "severity": "HIGH", "file": "a.py", "title": "x", "detail": ""},
            {"ts": "2026-06-28T11:00:00+00:00", "rule": "VGL-D001", "severity": "MEDIUM", "file": "b.py", "title": "y", "detail": ""},
        ])
        result = findingslog.read(limit=20)
        assert len(result) == 2

    def test_limit_respected(self, log_path):
        from valca import findingslog
        entries = [{"ts": "2026-06-28T10:00:00+00:00", "rule": f"VGL-{i}", "severity": "HIGH", "file": "f.py", "title": "", "detail": ""} for i in range(10)]
        self._write(log_path, entries)
        result = findingslog.read(limit=3)
        assert len(result) == 3

    def test_project_filter(self, log_path):
        from valca import findingslog
        self._write(log_path, [
            {"ts": "2026-06-28T10:00:00+00:00", "rule": "VGL-S001", "severity": "HIGH", "file": "/myapp/api.py", "title": "", "detail": ""},
            {"ts": "2026-06-28T10:00:00+00:00", "rule": "VGL-S002", "severity": "HIGH", "file": "/other/main.py", "title": "", "detail": ""},
        ])
        result = findingslog.read(project="myapp")
        assert len(result) == 1
        assert "myapp" in result[0]["file"]

    def test_severity_filter(self, log_path):
        from valca import findingslog
        self._write(log_path, [
            {"ts": "2026-06-28T10:00:00+00:00", "rule": "VGL-S001", "severity": "HIGH", "file": "f.py", "title": "", "detail": ""},
            {"ts": "2026-06-28T10:00:00+00:00", "rule": "VGL-S002", "severity": "MEDIUM", "file": "f.py", "title": "", "detail": ""},
        ])
        result = findingslog.read(severity="HIGH")
        assert all(e["severity"] == "HIGH" for e in result)

    def test_since_filter(self, log_path):
        from valca import findingslog
        self._write(log_path, [
            {"ts": "2026-06-27T10:00:00+00:00", "rule": "VGL-S001", "severity": "HIGH", "file": "f.py", "title": "", "detail": ""},
            {"ts": "2026-06-29T10:00:00+00:00", "rule": "VGL-S002", "severity": "HIGH", "file": "f.py", "title": "", "detail": ""},
        ])
        result = findingslog.read(since="2026-06-28")
        assert len(result) == 1
        assert result[0]["rule"] == "VGL-S002"

    def test_skips_malformed_lines(self, log_path):
        from valca import findingslog
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('not json\n{"ts":"2026-06-28T10:00:00+00:00","rule":"VGL-S001","severity":"HIGH","file":"f.py","title":"","detail":""}\n')
        result = findingslog.read()
        assert len(result) == 1


class TestEngineWritesToLog:
    """Integration: engine.scan() should append findings to the log."""

    def test_engine_scan_appends_findings(self, tmp_path, log_path):
        from valca.engine import Engine
        from valca.rules.base import Rule, Finding, Severity

        class AlwaysFindsRule(Rule):
            id = "VGL-TEST-001"
            name = "test"
            severity = Severity.HIGH
            def applies_to(self, path): return True
            def check(self, path):
                return [Finding(rule_id=self.id, severity=self.severity,
                                message="test finding", file_path=path)]

        f = tmp_path / "code.py"
        f.write_text("x = 1\n")
        # telemetry_enabled stays default here. Since 2026-09-24 the opt-out
        # covers this log too — it records absolute paths, so it is the more
        # sensitive of the two stores, not the lesser. Disabling telemetry and
        # still writing it was the defect, so a test asserting a write must not
        # be opted out. See test_findingslog_privacy.py for the opt-out contract.
        engine = Engine(rules=[AlwaysFindsRule()])
        engine.scan(f)

        from valca import findingslog
        entries = findingslog.read()
        assert len(entries) == 1
        assert entries[0]["rule"] == "VGL-TEST-001"

    def test_engine_scan_no_log_on_clean_file(self, tmp_path, log_path):
        from valca.engine import Engine
        from valca.rules.base import Rule, Severity

        class NeverFindsRule(Rule):
            id = "VGL-TEST-002"
            name = "test"
            severity = Severity.HIGH
            def applies_to(self, path): return True
            def check(self, path): return []

        f = tmp_path / "clean.py"
        f.write_text("x = 1\n")
        engine = Engine(rules=[NeverFindsRule()], telemetry_enabled=False)
        engine.scan(f)
        assert not log_path.exists()
