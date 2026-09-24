"""The package cache must not grow without bound, and must stay owner-only.

`_cache_get` treated an expired entry as a miss but left it in place, and
nothing removed one. The file reached 502 entries and 118 MB of raw OSV
payloads, every one of them expired: each package scan parsed and re-serialised
118 MB to achieve zero cache hits.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from valca.rules import packages


@pytest.fixture
def cache_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "pkg_cache.json"
    monkeypatch.setattr(packages, "_CACHE_PATH", target)
    return target


def _entry(age_seconds: float, value: object = "payload") -> dict:
    return {"v": value, "ts": time.time() - age_seconds}


def test_expired_entries_are_evicted_on_save(cache_file: Path) -> None:
    cache = {
        "fresh": _entry(10),
        "stale": _entry(packages._CACHE_TTL + 60),
        "ancient": _entry(packages._CACHE_TTL * 30),
    }
    packages._save_cache(cache)

    written = json.loads(cache_file.read_text())
    assert set(written) == {"fresh"}, f"expired entries survived: {sorted(written)}"


def test_a_fully_expired_cache_collapses_to_empty(cache_file: Path) -> None:
    """The real-world case: all 502 entries expired, 118 MB of dead payload."""
    cache = {f"vuln:pypi:pkg{i}:1.0": _entry(packages._CACHE_TTL * 2) for i in range(500)}
    packages._save_cache(cache)

    assert json.loads(cache_file.read_text()) == {}
    assert cache_file.stat().st_size < 1_000, (
        f"fully expired cache still occupies {cache_file.stat().st_size} bytes"
    )


def test_fresh_entries_survive_and_stay_readable(cache_file: Path) -> None:
    """Eviction must not break the cache it is pruning."""
    packages._save_cache({"vuln:pypi:requests:2.0": _entry(5, value=["GHSA-xxxx"])})

    reloaded = packages._load_cache()
    assert packages._cache_get(reloaded, "vuln:pypi:requests:2.0") == ["GHSA-xxxx"]


def test_malformed_entries_do_not_break_save(cache_file: Path) -> None:
    """A hand-edited or truncated cache must not crash a scan."""
    packages._save_cache({"good": _entry(5), "bad": "not-a-dict", "worse": None})

    assert set(json.loads(cache_file.read_text())) == {"good"}


def test_cache_is_owner_only(cache_file: Path) -> None:
    """It is a complete inventory of the project's dependencies and versions."""
    packages._save_cache({"fresh": _entry(5)})
    mode = cache_file.stat().st_mode & 0o777
    assert mode == 0o600, f"cache written with mode {oct(mode)}"


def test_existing_world_readable_cache_is_repaired(cache_file: Path) -> None:
    cache_file.write_text("{}")
    cache_file.chmod(0o644)

    packages._save_cache({"fresh": _entry(5)})

    mode = cache_file.stat().st_mode & 0o777
    assert mode == 0o600, f"pre-existing cache left at {oct(mode)}"
