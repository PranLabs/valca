# Valca — Claude Code plugin

Valca inspects every file Claude Code writes and blocks the write when it finds
a CRITICAL or HIGH security problem. It runs before the file reaches disk, so the
model can correct itself in the same turn rather than leaving something for a
reviewer to catch later.

The plugin carries both halves of the product:

- a **PostToolUse hook** that runs on every write, whether the model wants it or not
- an **MCP server** the agent can call to scan on demand

No other distribution channel installs both at once.

## Install

```bash
pip install "valca[mcp]"
```

Then add the plugin to Claude Code. The hook and the MCP server are wired up
together from `.claude-plugin/plugin.json`.

Installing without the MCP extra is fine — `pip install valca` gives you the
scanner and the hook, and the core keeps zero runtime dependencies. The extra
only adds the MCP SDK.

## Wiring the hook by hand

If you would rather not use the plugin, `valca init` writes the hook into
`.claude/settings.json` for you:

```bash
cd /your/project
valca init            # this project
valca init --global   # every project
```

Reload Claude Code afterwards.

To do it yourself, add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/valca/plugin/hook.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

## What it catches

**116 rules across 27 categories** — secrets and credentials, Docker and
docker-compose, Dockerfiles, Kubernetes, Terraform, IAM policy, nginx, crypto,
deserialization, XSS, SSRF, shell and subprocess use, and the AI-agent attack
surface: prompt injection, unsafe Model Context Protocol configuration, GitHub
Actions agent workflows, and dangerous instructions in agent config files.

The full catalogue is generated from the rule registry and lives in the
[README](https://github.com/PranLabs/valca#rules). It is not duplicated here,
because a hand-copied rule list is a list that goes out of date — an earlier
version of this file advertised 15 rules against a shipped 116.

The one nothing else catches:

```yaml
ports:
  - "5432:5432"     # binds to 0.0.0.0, bypasses UFW, reachable from the internet
```

The correct form is `"127.0.0.1:5432:5432"`. Checkov, Trivy, Snyk and Semgrep all
miss it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Advisory findings only (MEDIUM / LOW / INFO) — the write proceeds |
| `2` | CRITICAL or HIGH — **Claude Code blocks the write** |

## Using the MCP server

Once installed, the agent can ask for a scan rather than only being blocked by
one. Two tools, both read-only:

| Tool | Returns |
|---|---|
| `scan(path)` | Findings: rule, severity, message, file, line, suggested fix |
| `list_rules()` | The full catalogue |

There is deliberately no tool that edits or fixes anything. A scanner that can
modify code is a new attack surface, and it is the one `VGL-MCP003` and
`VGL-MCP005` exist to catch.

Scanning cannot leave the directory the server started in, returned paths are
relative to it, and matched source lines are never returned — for the secret
rules, that line *is* the secret.

## Scanning without Claude Code

```bash
valca scan path/to/file.yml
valca scan path/to/project/ --format json
valca scan path/to/project/ --format sarif    # SARIF 2.1.0, for code scanning
valca log                                      # what has been caught, and when
valca stats                                    # rule frequency and precision
```

The `vigil` command still works everywhere `valca` does. It is retained until at
least 1.0 so existing hooks and scripts keep running.
