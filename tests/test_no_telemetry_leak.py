"""Guardrail: the suite must not write into the developer's real local stores.

Two incidents, same shape, different file. In July 2026 thirteen unmocked
Engine() calls polluted real telemetry, making VGL-D001 look like the
most-triggered rule in production when it was mostly test noise. Until
2026-09-24 the findings log was being polluted the same way — a full run wrote
37 records of fixture paths and pytest temp directories into the file
`valca log` reads back.

Isolation is now structural: the autouse `_isolate_local_stores` fixture in
conftest.py redirects both stores for every test, so the failure is prevented
rather than detected. This file checks that the prevention is still in place —
the fixture is the guard, and this is the guard on the guard.
"""
import re
from pathlib import Path

TESTS_DIR = Path(__file__).parent
CONFTEST = TESTS_DIR / "conftest.py"

_ENGINE_CALL = re.compile(r"\bEngine\(")


def test_conftest_isolates_both_local_stores():
    """The autouse fixture is what makes the whole class of leak impossible."""
    text = CONFTEST.read_text()
    assert "autouse=True" in text, "the isolation fixture is no longer autouse"
    assert "_EVENTS_FILE" in text, "conftest no longer redirects the telemetry store"
    assert "VIGIL_LOG_PATH" in text or "VALCA_LOG_PATH" in text, (
        "conftest no longer redirects the findings log"
    )


def test_engine_constructions_are_accounted_for():
    """Every live Engine() should be deliberate.

    The autouse fixture already contains the damage, so this no longer guards
    real data — it keeps the intent visible, so that a test relying on
    telemetry being on says so rather than inheriting it by accident.
    """
    accounted = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name == "test_no_telemetry_leak.py":
            continue
        text = path.read_text()
        redirects_a_store = any(
            marker in text
            for marker in ("_EVENTS_FILE", "VIGIL_LOG_PATH", "VALCA_LOG_PATH", "_log_path")
        )
        for i, line in enumerate(text.splitlines(), 1):
            if _ENGINE_CALL.search(line) and "telemetry_enabled=False" not in line:
                if not redirects_a_store:
                    accounted.append(f"{path.name}:{i}: {line.strip()}")

    assert not accounted, (
        "Engine() constructed with telemetry left on, in a file that redirects "
        "neither local store. The conftest fixture still contains it, but say so "
        "explicitly — pass telemetry_enabled=False, or redirect the store the "
        "test is about:\n" + "\n".join(accounted)
    )
