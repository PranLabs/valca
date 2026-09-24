"""
VGL-PKG001  CRITICAL  Pinned package version has a known CVE (OSV.dev)
VGL-PKG002  CRITICAL  Package not found on registry — hallucinated or slopsquatting target
VGL-PKG003  HIGH      Package version significantly behind latest — stale AI training data
VGL-PKG004  HIGH      Package newly registered with few releases — supply chain risk

All checks run inline at generation time via the PostToolUse hook.
Network calls use a 24-hour local cache at ~/.vigil/pkg_cache.json.
Fails open (no findings) if the network is unavailable.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from .base import Finding, Rule, Severity

# Sentinel: registry returned HTTP 404 — package confirmed not to exist
_NOT_FOUND = object()

_CACHE_PATH = Path.home() / ".vigil" / "pkg_cache.json"
_CACHE_TTL = 86_400   # 24 hours
_TIMEOUT = 4          # seconds per HTTP call — hook must stay fast
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_UA = {"User-Agent": "vigilsec/0.1 (https://github.com/vigilsec-io/cordon)"}


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _load_cache() -> dict:
    try:
        if _CACHE_PATH.exists():
            data = json.loads(_CACHE_PATH.read_text())
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_cache(cache: dict) -> None:
    """Persist the cache, dropping anything already expired.

    `_cache_get` treats an expired entry as a miss but left it in the dict, and
    nothing else ever removed one, so the file only grew. By 2026-09-24 it held
    502 entries totalling 118 MB of raw OSV payloads, **all of them expired** —
    every package scan paid a 118 MB parse and re-serialise for zero cache hits.

    Evicting here rather than in `_load_cache` keeps one authority: whatever is
    written is exactly what is still valid.
    """
    now = time.time()
    live = {
        key: entry
        for key, entry in cache.items()
        if isinstance(entry, dict) and now - entry.get("ts", 0) < _CACHE_TTL
    }
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        is_new = not _CACHE_PATH.exists()
        _CACHE_PATH.write_text(json.dumps(live))
        # The cache is a full inventory of the project's dependencies and
        # versions. Owner-only, and repair files created before this rule.
        if is_new or (_CACHE_PATH.stat().st_mode & 0o077):
            os.chmod(_CACHE_PATH, 0o600)
    except OSError:
        pass


def _cache_get(cache: dict, key: str):
    entry = cache.get(key)
    if entry and time.time() - entry.get("ts", 0) < _CACHE_TTL:
        return entry.get("v")
    return None  # miss or expired


def _cache_set(cache: dict, key: str, value) -> None:
    cache[key] = {"v": value, "ts": time.time()}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str):
    """Return parsed JSON, _NOT_FOUND on HTTP 404, or None on other errors (fail-open)."""
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # nosec B310
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return _NOT_FOUND
        return None
    except Exception:
        return None


def _post(url: str, payload: dict) -> dict | None:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={**_UA, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # nosec B310
            return json.loads(r.read())
    except Exception:
        return None


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_requirements(text: str) -> list[tuple[str, str, int]]:
    """Return [(name, version, line_no)] for pinned == entries only."""
    pkgs = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        clean = re.sub(r"\[.*?\]", "", stripped)   # strip extras like [security]
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==([A-Za-z0-9_\-\.]+)", clean)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2), i))
    return pkgs


def _parse_package_json(text: str) -> list[tuple[str, str, None]]:
    """Return [(name, version, None)] for dependencies + devDependencies."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            ver = re.sub(r"^[\^~>=<]+", "", str(ver)).strip()
            if re.match(r"^\d+\.\d+", ver):
                pkgs.append((name.lower(), ver, None))
    return pkgs


# ── Staleness helper ──────────────────────────────────────────────────────────

def _is_stale(current: str, latest: str) -> bool:
    """True if current is more than 1 minor version behind latest."""
    try:
        cur = [int(x) for x in current.split(".")[:3]]
        lat = [int(x) for x in latest.split(".")[:3]]
        while len(cur) < 3: cur.append(0)
        while len(lat) < 3: lat.append(0)
        if lat[0] > cur[0]:
            return True
        if lat[0] == cur[0] and lat[1] > cur[1] + 1:
            return True
    except (ValueError, AttributeError):
        pass
    return False


# ── Rule ──────────────────────────────────────────────────────────────────────

class PackageAuditRule(Rule):
    """
    Checks packages suggested by AI coding assistants against live registries.
    Emits findings with rule IDs VGL-PKG001–PKG004.
    Disable all package checks via: disabled_rules = ["VGL-PKG001"] in .vigilrc
    """
    id = "VGL-PKG001"
    name = "Package audit (CVE · hallucination · staleness · supply chain)"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        name = path.name
        return (
            name == "requirements.txt"
            or (name.startswith("requirements") and name.endswith((".txt", ".in")))
            or (name == "package.json" and "node_modules" not in str(path))
        )

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []

        if path.name == "package.json":
            pkgs = _parse_package_json(text)
            ecosystem = "npm"
        else:
            pkgs = _parse_requirements(text)
            ecosystem = "PyPI"

        if not pkgs:
            return []

        cache = _load_cache()
        findings: list[Finding] = []

        # ── Batch CVE check via OSV.dev (one call for all uncached packages) ──
        uncached_for_osv = [
            (name, ver, lineno)
            for name, ver, lineno in pkgs
            if _cache_get(cache, f"vuln:{ecosystem}:{name}:{ver}") is None
        ]
        if uncached_for_osv:
            queries = [
                {"version": ver, "package": {"name": name, "ecosystem": ecosystem}}
                for name, ver, _ in uncached_for_osv
            ]
            batch_result = _post(_OSV_BATCH, {"queries": queries}) or {}
            results = batch_result.get("results", [])
            for (name, ver, _), result in zip(uncached_for_osv, results):
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                _cache_set(cache, f"vuln:{ecosystem}:{name}:{ver}", vulns)

        # ── Per-package: CVE findings + registry checks ───────────────────────
        for name, ver, lineno in pkgs:
            # PKG001 — known CVE
            vulns = _cache_get(cache, f"vuln:{ecosystem}:{name}:{ver}") or []
            for vuln in vulns:
                vuln_id = vuln.get("id", "unknown")
                summary = (vuln.get("summary") or "")[:100]
                findings.append(Finding(
                    rule_id="VGL-PKG001",
                    severity=Severity.CRITICAL,
                    message=f"{name}=={ver} has known vulnerability {vuln_id}: {summary}",
                    file_path=path,
                    line=lineno,
                    snippet=f"{name}=={ver}",
                    fix=f"Upgrade to a patched version. See https://osv.dev/vulnerability/{vuln_id} for fixed versions.",
                ))

            # Registry checks — fetch once, cache 24h
            cache_key = f"info:{ecosystem}:{name}"
            pkg_info = _cache_get(cache, cache_key)
            if pkg_info is None:
                if ecosystem == "PyPI":
                    raw = _get(f"https://pypi.org/pypi/{name}/json")
                else:
                    raw = _get(f"https://registry.npmjs.org/{name}/latest")
                if raw is _NOT_FOUND:
                    pkg_info = False   # confirmed 404 → cache as not-found
                    _cache_set(cache, cache_key, pkg_info)
                elif raw is None:
                    continue           # network error → fail-open, skip pkg
                else:
                    pkg_info = raw
                    _cache_set(cache, cache_key, pkg_info)

            # PKG002 — package doesn't exist (hallucinated / slopsquatting)
            if pkg_info is False:
                findings.append(Finding(
                    rule_id="VGL-PKG002",
                    severity=Severity.CRITICAL,
                    message=f"'{name}' not found on {ecosystem} registry — possible AI hallucination or slopsquatting target",
                    file_path=path,
                    line=lineno,
                    snippet=f"{name}=={ver}",
                    fix=(
                        f"Verify '{name}' is a real package before installing. "
                        "Attackers register hallucinated package names (slopsquatting). "
                        "Check pypi.org or npmjs.com manually."
                    ),
                ))
                continue

            if not isinstance(pkg_info, dict):
                continue

            # PKG003 — stale version (AI training data gap)
            if ecosystem == "PyPI":
                latest = (pkg_info.get("info") or {}).get("version", "")
            else:
                latest = pkg_info.get("version", "")

            if latest and latest != ver and _is_stale(ver, latest):
                findings.append(Finding(
                    rule_id="VGL-PKG003",
                    severity=Severity.HIGH,
                    message=f"{name}=={ver} is outdated — AI suggested an old version; latest is {latest}",
                    file_path=path,
                    line=lineno,
                    snippet=f"{name}=={ver}",
                    fix=(
                        f"Update to {name}=={latest}. "
                        "AI models have a training cutoff and frequently suggest outdated versions. "
                        "Always verify the latest stable release at pypi.org or npmjs.com."
                    ),
                ))

            # PKG004 — suspicious new package (supply chain / slopsquatting)
            if ecosystem == "PyPI":
                releases = pkg_info.get("releases") or {}
                release_count = len(releases)
                earliest: str | None = None
                for rel_files in releases.values():
                    for f in (rel_files or []):
                        t = f.get("upload_time", "")
                        if t and (earliest is None or t < earliest):
                            earliest = t
                if earliest and release_count <= 2:
                    try:
                        from datetime import datetime
                        age_days = (datetime.now() - datetime.fromisoformat(earliest)).days
                        if age_days < 90:
                            findings.append(Finding(
                                rule_id="VGL-PKG004",
                                severity=Severity.HIGH,
                                message=(
                                    f"'{name}' is newly registered "
                                    f"({age_days}d old, {release_count} release(s)) — "
                                    "possible supply chain attack"
                                ),
                                file_path=path,
                                line=lineno,
                                snippet=f"{name}=={ver}",
                                fix=(
                                    f"Verify '{name}' at pypi.org/{name} before installing. "
                                    "New packages with 1–2 releases are a common supply chain vector."
                                ),
                            ))
                    except Exception:
                        pass

        _save_cache(cache)
        return findings
