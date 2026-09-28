# Changelog

## 0.6.1

### Changed

- **Listed on the MCP Registry.** The package README now carries an `mcp-name`
  marker, which is how the registry verifies that the publisher of
  `io.github.pranlabs/valca` also owns the `valca` package on PyPI. The marker is
  an HTML comment and does not appear on the rendered page.

  Nothing about the software changed in this release. It exists because the
  registry reads that marker from the live PyPI description, so it has to be in a
  published release before the server can be submitted.

- **The VS Code extension and the GitHub Action now have their own repositories.**
  This repository holds the scanner and nothing else.

  | Moved to | What it is |
  |---|---|
  | [PranLabs/valca-action](https://github.com/PranLabs/valca-action) | The GitHub Action. Marketplace requires `action.yml` at the repository root, so it could not be listed from a subdirectory |
  | [PranLabs/valca-vscode](https://github.com/PranLabs/valca-vscode) | The VS Code extension. A TypeScript toolchain in a Python package's repo meant npm dependency bots filing pull requests against a pytest CI |

  Nothing you install changes. The PyPI package, both the `valca` and `vigil`
  commands, and the extension id `vigilsec.vigil-security` are all the same.

  **If you use the Action**, `PranLabs/valca-action@v1` replaces copying the old
  template. The template also pinned `actions/checkout@v4`, `setup-python@v5` and
  `codeql-action@v3` — three, two and one major versions behind current. The new
  one is on v7, v7 and v4.

### Fixed

- **The Claude Code plugin was not in the plugin format.** `plugin/manifest.json`
  is not a layout the loader recognises: the manifest belongs at
  `.claude-plugin/plugin.json`, hooks belong in `hooks/hooks.json`, and the
  `install` and `rules` keys it carried are not fields at all. Installed as it
  stood, the plugin would have loaded and done nothing.

  The plugin now also ships `.mcp.json`, so a single install gives you both the
  PostToolUse hook that runs on every write and the MCP server the agent can call
  on demand.

- **`plugin/README_INSTALL.md` told users to `pip install vigil`.** That is a
  different author's package on PyPI, so anyone following those instructions
  installed someone else's code. The file also still advertised 15 rules against a
  shipped 116.


## 0.6.0

### Changed

- **The repository moved to [github.com/PranLabs/valca](https://github.com/PranLabs/valca).**
  It was `vigilsec-io/cordon`, which left the project with three different names for one
  thing. GitHub redirects the old paths, so existing clones, links and the images on
  previously published release pages keep working — but new links should use the new URL.

  The PyPI package name (`valca`), the `valca` and `vigil` commands, and the VS Code
  extension id (`vigilsec.vigil-security`) are all **unchanged**. Nothing you have installed
  or configured needs to change.

### Fixed

- **The GitHub Action installed the wrong package.** `vigil-action/action.yml` and the
  workflow template both ran `pip install vigilsec`, which is the pre-rename package, last
  published at 0.2.1 in July 2026. Anyone who adopted the published Action template was
  running a scanner with 100 rules instead of 116 — missing the entire AI-agent set
  (`VGL-GHA011`–`014`, `VGL-PI005`–`009`, `VGL-AGENT001`–`002`, `VGL-MCP004`–`005`) and
  every fix since. Both now install `valca`.

  **If you use the Action, re-copy the template**, or change `pip install vigilsec` to
  `pip install valca` in your workflow.

- **SARIF output linked to the wrong project page.** `tool.driver.informationUri` pointed at
  `pypi.org/project/vigilsec`, so anyone following the link from a GitHub code-scanning
  alert landed on the superseded package.

### Added

- **MCP server.** `pip install "valca[mcp]"` then `valca-mcp` exposes Valca to any
  MCP client. Two tools, both declared read-only to the protocol: `scan(path)` and
  `list_rules()`. There is no tool that edits or fixes anything — a scanner that can
  modify code is the attack surface `VGL-MCP003` and `VGL-MCP005` exist to catch.

  Scanning cannot leave the root directory the server was started in (or
  `VALCA_MCP_ROOT`), returned paths are relative to it, and matched source lines are
  never returned — for the secret rules, that line is the secret. Telemetry is off on
  this path regardless of configuration; `.valcarc` is otherwise honoured in full.

  `mcp` is an optional extra, so the core keeps `dependencies = []`.

  The PostToolUse hook remains the enforcement path. MCP is opt-in by the agent, and
  a check an agent can decline is not enforcement.

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

- **The findings log now honours the telemetry opt-out.** `telemetry = false`, or either
  opt-out environment variable, silenced `events.jsonl` but not `findings.jsonl`, which
  kept recording every finding together with its **absolute path**. It is the more
  revealing of the two stores — `events.jsonl` holds rule ids and file extensions, this
  holds your username, directory layout and project names — and it was the one still
  being written after you asked it to stop. The decision now comes from a single place,
  so the two stores cannot diverge again.

- **The findings log and the package cache are owner-only (`0600`).** Both were created
  at the default umask, so on a shared or multi-user machine any process running as
  another user could read them. Existing files are repaired on the next write rather
  than only new ones, since existing installs are the population that matters.

- **The package cache no longer grows without limit.** Expired entries were treated as
  misses but never removed, so `pkg_cache.json` only ever grew. A real installation
  reached 502 entries and **118 MB** of stored vulnerability payloads with **every entry
  expired**: each dependency scan parsed and rewrote 118 MB for zero cache hits. Expired
  entries are now dropped when the cache is written. The file becomes small again on the
  first scan after upgrading; nothing useful is lost, because expired entries were never
  being used.

- `valca stats`, `valca log` and `valca init` printed the pre-rename product name.
- `valca --help` answered `usage: vigil`. The command now reports whichever name
  it was invoked as.

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
