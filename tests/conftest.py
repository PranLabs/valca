from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_local_stores(tmp_path, monkeypatch):
    """Point both local stores at a temp directory for every test.

    The suite has twice polluted the developer's real data: telemetry in
    July 2026, and the findings log continuously until 2026-09-24 — a full run
    wrote 37 records of test fixtures and pytest temp paths into
    ~/.vigil/findings.jsonl, which is the file `valca log` reads back.

    Both incidents were caught by a static check that looked for unmocked
    Engine() calls. Detection is the weaker tool: it only finds the shapes it
    was taught, and it found neither of these until after the data was dirty.
    Redirecting the stores by default makes the whole class impossible instead.

    A test that needs the real path still wins — its own monkeypatch runs after
    this one.
    """
    from valca import telemetry

    monkeypatch.setenv("VIGIL_LOG_PATH", str(tmp_path / "findings.jsonl"))
    monkeypatch.setattr(telemetry, "_EVENTS_FILE", tmp_path / "events.jsonl")


@pytest.fixture
def safe_compose():
    return FIXTURES / "docker-compose-safe.yml"


@pytest.fixture
def unsafe_compose():
    return FIXTURES / "docker-compose-unsafe.yml"


@pytest.fixture
def safe_dockerfile():
    return FIXTURES / "Dockerfile.safe"


@pytest.fixture
def unsafe_dockerfile():
    return FIXTURES / "Dockerfile.unsafe"
