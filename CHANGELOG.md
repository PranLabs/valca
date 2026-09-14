# Changelog

## Unreleased

### Fixed

- **The `valca`-named config file, suppression comment and telemetry opt-out now work.**
  Release 0.4.0 documented five compatibility guarantees between the old and new names.
  Four were never implemented, and 0.4.0, 0.4.1 and 0.5.0 all shipped with the
  documentation describing behaviour the code did not have.

| Documented | Actual behaviour until now |
|---|---|
| `.valcarc` is read, and takes precedence over `.vigilrc` | Only `.vigilrc` was read. A project configured through `.valcarc` ran on defaults: disabled rules still fired, `exclude_paths` was ignored, `min_severity` had no effect |
| `# valca: ignore` suppresses a finding | Only `# vigil: ignore` worked |
| `VALCA_NO_TELEMETRY=1` disables telemetry | Only `VIGIL_NO_TELEMETRY` was checked |
| Scan history migrates to `~/.valca/events.jsonl` | No migration ran, and `valca stats` read a path that no longer held the data |

  If you set `VALCA_NO_TELEMETRY` expecting it to apply, it did not. Telemetry has
  always been local-only and makes no network calls, so nothing was transmitted — but
  events were written after you had asked for them not to be. Deleting
  `~/.valca/events.jsonl` clears that history.

  Every row above now has a test in `tests/test_compat_guarantees.py`.

- `valca stats`, `valca log` and `valca init` printed the pre-rename product name.

## 0.5.0

### Added

- **Sixteen rules, covering the agentic attack surface.** These existed in development
  and had never shipped. The engine now carries **116 rules across 27 categories**.

| Family | Rules | Catches |
|---|---|---|
| GitHub Actions — AI agent surface | VGL-GHA011–014 | Untrusted event data reaching an agent prompt; missing `--allowedTools` / `--max-turns`; `contents: write` on agent workflows |
| Prompt injection — application level | VGL-PI005–009 | HTTP, webhook and database data flowing into prompts; LLM output reaching `exec`; vector-store poisoning |
| AI agent configuration files | VGL-AGENT001–002 | Shell execution and exfiltration instructions in `CLAUDE.md` / `copilot-instructions.md` (CVE-2025-59536); credentials exposed through agent exception handlers |
| MCP server | VGL-MCP004–005 | Unpinned packages and plaintext HTTP endpoints in MCP config; SSRF through an agent-controlled URL with no allowlist |

- **`.pre-commit-hooks.yaml`** — the pre-commit integration could not work without it.

### Note on compliance mapping

Rule-to-framework mapping (OWASP Top 10, NIST SSDF, CWE) is a licensed feature and is not
part of this distribution. Findings are complete without it; they simply carry no framework
annotations. Nothing else differs between builds.


## 0.4.1

### Fixed

- **SARIF now identifies the tool correctly.** Output declared
  `tool.driver.name: "vigil"` and `tool.driver.version: "0.1.0"` regardless of the
  installed release, because the version was hardcoded and never passed by the CLI.
  It is now read from package metadata.

  **If you upload Valca's SARIF to GitHub code scanning:** alerts created before
  0.4.1 are recorded against the tool name `vigil`. GitHub groups alerts by tool
  name, so alerts from 0.4.1 onwards appear under `valca` and the older ones will
  not be closed automatically by new runs. Delete the old analyses, or dismiss the
  stale alerts once, and subsequent runs stay consistent.

## 0.4.0

### Changed

- **The project is now Valca.** The package, module and primary command are
  `valca`. The package was previously published as `vigilsec`.

Nothing from the previous name was removed. All of the following still work and
are expected to keep working:

| Previous | Current | Status |
|---|---|---|
| `vigil` command | `valca` | Both installed; `vigil` retained until at least 1.0 |
| `# vigil: ignore` | `# valca: ignore` | Both honoured permanently |
| `.vigilrc` | `.valcarc` | Both read; `.valcarc` takes precedence |
| `VIGIL_NO_TELEMETRY` | `VALCA_NO_TELEMETRY` | Both honoured |
| `~/.vigil/events.jsonl` | `~/.valca/events.jsonl` | Existing history migrated automatically on first run |

Rule IDs keep the `VGL-` prefix. They appear in user configuration, SARIF output
and published references, so renaming them would break suppressions and orphan
citations for no benefit.

### Fixed

- **The hook could silently stop scanning.** It accepted any executable file as
  the scanner. An entry-point script left behind by an earlier install remains
  executable but fails to import, so the hook exited non-zero and the write was
  allowed through. Each candidate must now prove it runs, the current command is
  searched first, and when nothing runnable is found the hook reports that on
  stderr rather than exiting quietly.
- The published hook gained the path-boundary check, file size limit and scan
  timeout that previously existed only in development.
- Running the project's own test suite no longer writes events into the
  developer's telemetry store.

## 0.3.2

### Fixed

- **Corrected the published rule count from 36 to 102.** The listings understated
  the engine by 66 rules across 17 undocumented categories. The rule catalogue is
  now generated from the rule registry and asserted against it, so it cannot drift.
- Documented `valca log` and `valca stats`, which shipped undocumented.
- Documented the three rules that make outbound network requests
  (`api.osv.dev`, `pypi.org`, `registry.npmjs.org`) and how to disable them.

## 0.3.1

### Fixed

- The demo image on the package page used a relative path and did not render.

## 0.3.0

### Changed

- First release under the name `valca`.

### Fixed

- The telemetry event log is now created with owner-only permissions (`0600`).
  It was previously created with the default umask.
