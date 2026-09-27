# Valca Security

**AI coding security co-pilot — catches insecure code the moment your AI writes it.**

Valca scans every file your AI coding assistant saves and shows security findings inline as squiggles and Problems — before the code ever runs.

---

## The Problem It Solves

AI coding assistants (Copilot, Cursor, Claude Code) reproduce the most common patterns in their training data. The most common patterns are insecure defaults.

The clearest example — this docker-compose port binding exposes your database to the internet, and **Checkov, Trivy, Snyk, and Semgrep all miss it**:

```yaml
ports:
  - "5432:5432"   # binds to 0.0.0.0, bypasses UFW
```

The correct form is `"127.0.0.1:5432:5432"`. Valca catches it instantly on save.

---

## How It Works

1. You (or your AI) save a file
2. Valca runs `valca scan` in the background
3. Findings appear as inline squiggles + Problems panel entries
4. Status bar shows `⊗ Valca: 2 CRITICAL/HIGH` or `✓ Valca` (clean)

---

## Requirements

Install the CLI first:

```bash
pip install valca
```

That's it. The extension auto-detects the `vigil` binary.

---

## What It Catches (116 rules)

- **Docker** — `"PORT:PORT"` bindings that bypass UFW and expose services to the internet
- **Secrets** — hardcoded AWS keys, passwords, JWT secrets, Stripe keys, Slack tokens, PEM keys
- **Dockerfile** — running as root, unpinned `:latest`, secrets baked into image layers
- **Shell scripts** — secrets passed inline to SSH commands (visible in `ps aux`)
- **AI agent patterns** — LLM output piped to shell, `auto_approve = True`, unbounded LLM loops
- **Prompt injection** — user input in system prompts, raw request body passed to LLM
- **MCP server security** — tool poisoning via injected descriptions, shell execution in handlers
- **Kubernetes** — `privileged: true`, host namespace sharing
- **IAM** — wildcard `"Action": "*"` policies
- **Dependencies** — Python CVEs (pip-audit) and npm CVEs on every requirements.txt/package.json save
- **nginx** — missing security headers, deprecated TLS

---

## Configuration

Place a `.vigilrc` file in your project root:

```toml
disabled_rules = ["VGL-T001"]   # skip trivy deep scan
min_severity   = "HIGH"         # only show HIGH and above
exclude_paths  = ["vendor"]
telemetry      = false          # opt out of anonymous local telemetry
```

**Suppress a specific line:**

```python
auto_approve = True  # vigil: ignore
```

**Extension settings** (`Cmd+,` → search "vigil"):

| Setting | Default | Description |
|---|---|---|
| `vigil.enabled` | `true` | Enable/disable scanning |
| `vigil.scanOnSave` | `true` | Scan automatically on save |
| `vigil.executablePath` | auto | Path to vigil binary |
| `vigil.minSeverity` | `HIGH` | Minimum severity to show |

---

## Commands

Open Command Palette (`Cmd+Shift+P`):

- **Valca: Scan Current File** — scan the active file immediately
- **Valca: Scan Workspace** — scan all files in the workspace

---

## License

[BUSL 1.1](https://github.com/PranLabs/valca/blob/main/LICENSE) — free for non-commercial use. Converts to MIT in 2030.

---

[Issues & feedback](https://github.com/PranLabs/valca/issues) · [PyPI](https://pypi.org/project/valca/)
