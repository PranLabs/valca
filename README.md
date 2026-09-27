# Valca

**AI coding security co-pilot — blocks insecure code at the moment of generation.**

> **Formerly published as `vigilsec`.** The package is now `valca`. Both the `valca` and `vigil`
> commands work, so existing hooks and scripts keep running unchanged.

Valca intercepts every file an AI coding assistant writes and blocks it if CRITICAL or HIGH security findings are detected — before the file hits disk. It's the only tool that operates at generation time rather than post-commit.

```
AI writes file → valca scan → exit 2 → Claude Code blocks the write
```

---

## The Problem

AI coding assistants reproduce the most common patterns in their training data. The most common patterns are insecure defaults.

The clearest example: every existing IaC scanner (Checkov, Trivy, Snyk, Semgrep) misses the docker-compose port binding that exposes your database to the internet:

```yaml
ports:
  - "5432:5432"   # ← binds to 0.0.0.0, bypasses UFW, reachable from anywhere
```

The correct form is `"127.0.0.1:5432:5432"`. Valca catches it. Nothing else does.

---

## Install

```bash
pip install valca
```

**Wire the Claude Code hook (one time):**

```bash
valca init --global     # `valca init --global` also works
```

That's it. Every file Claude Code writes is now scanned before it saves. Reload Claude Code to activate.

---

## Network access

Valca's core scanning is fully offline — the package has **zero runtime dependencies** and the
engine never sends your code, file paths, or findings anywhere.

Three rules do reach the network, because checking whether a dependency is vulnerable or fabricated
is impossible offline. When a manifest (`requirements.txt`, `package.json`, lockfiles) is scanned,
these rules send **package names and version strings only** to:

| Host | Used by | What is sent |
|---|---|---|
| `api.osv.dev` | VGL-PKG001 (known CVE in a pinned version) | package name + version |
| `pypi.org` | VGL-PKG002/003/004 (hallucinated, stale, or suspicious package) | package name |
| `registry.npmjs.org` | VGL-PKG002/003/004 | package name |

Your source code, file contents, file paths, and scan results are never transmitted. If your
dependency inventory is itself sensitive, turn these rules off in `.valcarc` and Valca runs
completely offline:

```ini
disabled_rules = ["VGL-PKG001", "VGL-PKG002", "VGL-PKG003", "VGL-PKG004"]
```

---

## Usage

```bash
# Scan a single file
valca scan docker-compose.yml

# Scan a directory
valca scan ./my-project/

# JSON output (for CI / dashboards)
valca scan ./my-project/ --format json

# SARIF output (for GitHub Advanced Security)
valca scan ./my-project/ --format sarif > results.sarif

# Only report HIGH and above
valca scan ./my-project/ --severity HIGH

# Open feedback & waitlist form
valca feedback
```

**Review what has been caught over time.** Both commands read the local scan
history — nothing leaves your machine.

```bash
# Findings log — what was caught, where, and when
valca log                              # 20 most recent findings
valca log --severity CRITICAL          # only criticals
valca log --project api --since 2026-09-01
valca log --limit 100 --format json    # for dashboards

# Aggregate stats — rule frequency, severity mix, precision per rule
valca stats
valca stats --format json
```

`valca stats` reports how often each rule fires and how often you suppressed it,
so rules with poor precision in *your* codebase are visible rather than guessed at.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings — write proceeds |
| `1` | Advisory findings only (MEDIUM / LOW / INFO) |
| `2` | CRITICAL or HIGH found — **Claude Code blocks the write** |

---

## See It in Action

**Blocking a vulnerable GitHub Actions workflow at write time:**

<!-- GIF: terminal showing claude writing ai-review.yml → vigil hook fires → BLOCKED + VGL-GHA009 CRITICAL → fix applied → clean -->
![Valca blocking a Comment-and-Control attack](https://raw.githubusercontent.com/PranLabs/valca/main/docs/demo-gha.gif)

In April 2026, researchers found that all three major AI coding agents (Claude Code, Gemini CLI, Copilot) could be hijacked to exfiltrate `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` via a hidden HTML comment in a GitHub issue. CVSS 9.4. No special access required.

Valca catches the vulnerable workflow (`issues:` trigger + AI agent + API key in env) before it reaches git — the only tool that does.

→ [Full writeup: The Attack That Steals Your API Keys Through a GitHub Issue Comment](https://medium.com/@rjbdjnf/the-attack-that-steals-your-api-keys-through-a-github-issue-comment-b0301c1906dc)

---

## Rules

**116 rules across 27 categories.** All built-in, stdlib-only, zero runtime dependencies.

This catalogue is generated from the rule registry — it cannot drift from the shipped engine.


### Secrets & Credential Exposure (14 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-I001 | CRITICAL | eval() or exec() — code injection risk |
| VGL-I002 | HIGH | subprocess with shell=True |
| VGL-I003 | HIGH | os.system() call |
| VGL-S001 | CRITICAL | AWS access key hardcoded |
| VGL-S002 | CRITICAL | Hardcoded password |
| VGL-S003 | CRITICAL | Hardcoded API key |
| VGL-S004 | CRITICAL | Hardcoded bearer token |
| VGL-S005 | CRITICAL | Hardcoded JWT secret |
| VGL-S006 | CRITICAL | PEM private key in source |
| VGL-S007 | CRITICAL | Database URL with embedded credentials |
| VGL-S008 | CRITICAL | Stripe live secret key |
| VGL-S009 | CRITICAL | Slack token hardcoded |
| VGL-S010 | CRITICAL | Provider API key hardcoded (OpenAI / GitHub / GitLab / Google) |
| VGL-S012 | HIGH | Insecure placeholder default for security-critical config |


### GitHub Actions — AI Agent Surface (13 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-GHA001 | CRITICAL | Pwn Request — pull_request_target with attacker-controlled checkout ref |
| VGL-GHA002 | CRITICAL | Script injection — user-controlled context expression in run: step |
| VGL-GHA004 | HIGH | Secret directly interpolated in run: step (visible in process table) |
| VGL-GHA005 | MEDIUM | Workflow missing explicit permissions block (implicit GITHUB_TOKEN scope) |
| VGL-GHA006 | HIGH | Cache usage in pull_request workflow (cache poisoning attack vector) |
| VGL-GHA007 | HIGH | Self-hosted runner with pull_request trigger (persistent runner risk) |
| VGL-GHA008 | HIGH | workflow_run trigger without ref/repo validation |
| VGL-GHA009 | CRITICAL | AI agent wired to untrusted-input trigger (issues/pull_request_target) with API key in env |
| VGL-GHA010 | HIGH | AI agent on pull_request_target without fork origin guard |
| VGL-GHA011 | CRITICAL | Untrusted GitHub event data interpolated into AI agent prompt |
| VGL-GHA012 | HIGH | AI agent on untrusted trigger with no --allowedTools restriction |
| VGL-GHA013 | MEDIUM | AI agent on untrusted trigger with no --max-turns limit |
| VGL-GHA014 | HIGH | contents: write permission with AI agent on untrusted trigger |


### AI Agent — Prompt Injection (9 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-PI001 | CRITICAL | User input interpolated into the LLM system prompt |
| VGL-PI002 | HIGH | Raw HTTP request body used as LLM message content |
| VGL-PI003 | HIGH | String formatting used to build prompts with user data |
| VGL-PI004 | MEDIUM | Tool output appended to the conversation without sanitization |
| VGL-PI005 | CRITICAL | HTTP request data flows into an LLM prompt unsanitised |
| VGL-PI006 | CRITICAL | LLM response flows into subprocess, exec or eval |
| VGL-PI007 | HIGH | Webhook payload flows directly into an AI agent |
| VGL-PI008 | HIGH | Database content interpolated into a prompt — second-order injection |
| VGL-PI009 | HIGH | User input written into a vector store — memory poisoning |


### Dockerfile Hardening (8 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-DF001 | HIGH | Dockerfile runs as root — no USER directive |
| VGL-DF002 | MEDIUM | Dockerfile uses unpinned :latest base image |
| VGL-DF003 | HIGH | Dockerfile bakes secret into ENV or ARG layer |
| VGL-DF004 | HIGH | curl|bash or wget|sh pipe in Dockerfile RUN instruction |
| VGL-DF005 | HIGH | TLS verification disabled in Dockerfile RUN fetch |
| VGL-DF006 | MEDIUM | ADD used for local files — use COPY instead |
| VGL-DF007 | HIGH | COPY . without .dockerignore — risks leaking .git, .env, credentials |
| VGL-DF008 | MEDIUM | World-writable permissions set in Dockerfile (chmod 777) |


### Docker Compose (7 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-D001 | CRITICAL | Docker public port binding — bypasses UFW, exposes service to internet |
| VGL-D002 | HIGH | docker-compose environment block contains hardcoded secret |
| VGL-D003 | CRITICAL | Docker container runs in privileged mode |
| VGL-D004 | HIGH | Docker container uses host network mode |
| VGL-D005 | CRITICAL | Docker socket mounted into container — full container escape vector |
| VGL-D006 | HIGH | Sensitive host path mounted into container |
| VGL-D007 | HIGH | AWS credentials directory (~/.aws) mounted into container — exposes all profiles |


### Terraform (7 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-TF001 | CRITICAL | Terraform hardcoded secret value |
| VGL-TF002 | HIGH | Terraform resource with public access enabled |
| VGL-TF003 | HIGH | Terraform encryption explicitly disabled |
| VGL-TF004 | CRITICAL | IMDSv1 enabled on EC2 instance — vulnerable to SSRF metadata theft |
| VGL-TF005 | HIGH | Terraform S3 state backend stored without encryption |
| VGL-TF006 | MEDIUM | Deletion protection disabled on managed resource |
| VGL-TF007 | MEDIUM | Audit logging disabled on Terraform-managed resource |


### Deserialization & Path Traversal (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-DESER001 | CRITICAL | Insecure deserialization — pickle.loads / pickle.load |
| VGL-DESER002 | HIGH | Insecure YAML deserialization — yaml.load() without SafeLoader |
| VGL-DESER003 | HIGH | Insecure deserialization — marshal.loads with untrusted data |
| VGL-PATH001 | HIGH | Path traversal — user input passed to file open or path join without validation |
| VGL-SSTI001 | CRITICAL | Server-Side Template Injection — user input rendered as Jinja2 template |


### MCP Server Security (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-MCP001 | CRITICAL | Prompt injection embedded in MCP tool description |
| VGL-MCP002 | HIGH | MCP tool description built from user-controlled data |
| VGL-MCP003 | HIGH | Shell execution in an MCP tool handler without a sandbox |
| VGL-MCP004 | HIGH | MCP server config uses an unpinned package or plaintext HTTP endpoint |
| VGL-MCP005 | HIGH | MCP fetch tool takes an agent-controlled URL with no allowlist |


### Web Application Security (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-CORS001 | HIGH | CORS wildcard — allow_origins=['*'] |
| VGL-SQL001 | CRITICAL | SQL injection — query built with f-string or string concatenation |
| VGL-SQL002 | CRITICAL | SQL injection — ORM raw query with f-string |
| VGL-SSL001 | HIGH | SSL verification disabled |
| VGL-SSRF001 | CRITICAL | SSRF — HTTP call with user-controlled URL |


### AI Agent — Excessive Agency (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-A001 | CRITICAL | LLM output piped into shell execution |
| VGL-A002 | HIGH | Hardcoded auto-approval disables human-in-the-loop |
| VGL-A003 | HIGH | Unbounded agent loop with no iteration limit |
| VGL-A004 | HIGH | LLM response written to disk without validation |


### Authentication & Session (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-AUTH001 | CRITICAL | JWT algorithm=none — signature verification bypassed |
| VGL-AUTH002 | CRITICAL | JWT verify_signature disabled — any token accepted |
| VGL-AUTH003 | HIGH | Weak or hardcoded web framework secret key |
| VGL-AUTH004 | HIGH | Debug mode enabled in framework code |


### Dependency Integrity (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-PKG001 | CRITICAL | Package audit (CVE · hallucination · staleness · supply chain) |
| VGL-PKG002 | CRITICAL | Package not found on registry — hallucinated or slopsquatting target |
| VGL-PKG003 | HIGH | Package version significantly behind latest — stale AI training data |
| VGL-PKG004 | HIGH | Package newly registered with few releases — supply-chain risk |


### Kubernetes (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-K001 | CRITICAL | Privileged container or host namespace access |
| VGL-K002 | CRITICAL | allowPrivilegeEscalation enabled in Kubernetes securityContext |
| VGL-K003 | HIGH | Dangerous Linux capabilities added in Kubernetes securityContext |
| VGL-K004 | HIGH | Sensitive hostPath volume in Kubernetes manifest |


### Logging & Data Exposure (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-LOG001 | HIGH | Sensitive data written to logs (CWE-532) |
| VGL-LOG002 | HIGH | Error details leaked in HTTP response body (CWE-209) |
| VGL-LOG003 | MEDIUM | Silent exception swallowing in authentication/security context |
| VGL-LOG004 | MEDIUM | CRLF injection risk — user-controlled input logged without newline sanitization |


### Swift / iOS (4 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-SW001 | CRITICAL | Hardcoded secret in Swift string literal |
| VGL-SW002 | HIGH | Plain HTTP URL in Swift networking code |
| VGL-SW003 | HIGH | Sensitive value written to UserDefaults (unencrypted) |
| VGL-SW004 | CRITICAL | SSL certificate validation bypassed in URLSession delegate |


### Dependency CVE Scanners (3 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-DEP001 | HIGH | Vulnerable Python packages (pip-audit) |
| VGL-DEP002 | HIGH | Critical npm vulnerability (npm audit) |
| VGL-DEP003 | HIGH | Vulnerable lockfile package (osv-scanner) |


### GitHub Actions — Workflow Hygiene (3 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-GH001 | HIGH | GitHub Actions secret printed in run step (log exposure) |
| VGL-GH002 | HIGH | GitHub Actions workflow with excessive permissions |
| VGL-GH003 | HIGH | GitHub Actions uses mutable action ref (tag or branch) |


### AI Agent — Configuration Files (2 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-AGENT001 | CRITICAL | Shell execution or exfiltration instructions in an AI agent config file |
| VGL-AGENT002 | HIGH | Credentials exposed through an exception handler in agent code |


### JavaScript / TypeScript (2 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-JS001 | HIGH | process.env secret with hardcoded string fallback |
| VGL-JS004 | HIGH | eval() or new Function() with dynamic argument (CWE-95) |


### Row-Level Security (2 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-RLS001 | CRITICAL | PostgreSQL Row-Level Security explicitly disabled |
| VGL-RLS002 | HIGH | Multi-tenant ORM query missing user/tenant filter |


### Cross-Site Scripting (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-XSS001 | HIGH | Cross-Site Scripting — unsafe HTML injection (CWE-79) |


### Cryptography (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-RAND001 | HIGH | Weak randomness for security-sensitive value (CWE-330) |


### IAM Policies (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-IAM001 | CRITICAL | IAM policy wildcard in Action or Resource |


### Python (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-PY001 | HIGH | Debug bypass without env guard — auth/security conditionally disabled |


### Shell Scripts (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-S011 | HIGH | Secret variable passed inline to subprocess/SSH (ps aux leak) |


### Trivy IaC Deep Scan (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-T001 | HIGH | Trivy IaC deep scan — Dockerfile / Terraform misconfigurations |


### nginx (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-N001 | HIGH | nginx config missing security headers or weak TLS |

---

## Configuration

Place a `.valcarc` file in your project root (or any ancestor directory):

```toml
# .valcarc
disabled_rules = ["VGL-T001"]        # skip trivy scan for this project
min_severity   = "HIGH"              # only report HIGH and above
exclude_paths  = ["vendor", "legacy"]
telemetry      = false               # opt out of anonymous local telemetry
```

Valca walks up the directory tree to find the nearest `.valcarc` (the former `.vigilrc` name is still read). Child config always wins over parent. Monorepos can have per-project overrides alongside a workspace default.

**Inline suppression** — for a specific line you've reviewed and accepted:

```python
auto_approve = True  # vigil: ignore
```

Same pattern as `# noqa` (flake8) and `# nosec` (bandit).

---

## Opt-out

Valca collects anonymous, local-only telemetry: rule ID, severity, and file extension. No file paths, no code, no identifiable data. Stored at `~/.valca/events.jsonl` — never sent anywhere. History from the former `~/.vigil/` location is migrated automatically.

Opt out permanently:

```bash
export VALCA_NO_TELEMETRY=1        # VIGIL_NO_TELEMETRY still works
```

Or in `.valcarc`:

```toml
telemetry = false
```

---

## Adding a Rule

```python
# src/valca/rules/my_category.py
from pathlib import Path
from .base import Finding, Rule, Severity

class MyRule(Rule):
    id = "VGL-X001"
    name = "Descriptive rule name"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".yml"

    def check(self, path: Path) -> list[Finding]:
        findings = []
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if "bad_pattern" in line:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Found bad pattern",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Do this instead.",
                ))
        return findings
```

Then add it to `DEFAULT_RULES` in `src/valca/rules/__init__.py`. Write tests. Done.

---

## GitHub Actions

Add Valca to any CI pipeline — copy `vigil-action/workflow-template.yml` into your project's `.github/workflows/vigil.yml`:

```yaml
- name: Install Valca
  run: pip install valca --quiet

- name: Scan with Valca
  run: valca scan . --no-color

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: valca-results.sarif
```

Findings appear as inline annotations on PR diffs in the GitHub Security tab.

---

## MCP server

The hook blocks an agent. The MCP server lets one ask.

```bash
pip install "valca[mcp]"
valca-mcp
```

Register it with any MCP client — for Claude Code, `claude mcp add valca -- valca-mcp`.
Two tools, both read-only:

| Tool | Returns |
|---|---|
| `scan(path)` | Findings for a file or directory: rule, severity, message, file, line, suggested fix |
| `list_rules()` | The full catalogue — every rule id, severity, and what it catches |

There is no tool that edits, fixes or writes anything. A scanner that can modify
code is a new attack surface, and it is the one `VGL-MCP003` and `VGL-MCP005`
exist to catch.

Three limits are built in rather than configurable:

- **Scanning cannot leave the root.** That root is the directory `valca-mcp`
  started in, or `VALCA_MCP_ROOT` if set. The agent picks the argument to
  `scan`, so without a boundary it could walk to `~/.ssh` and map a filesystem
  it was never given.
- **Paths come back relative to that root.** An absolute path carries your
  username and directory layout.
- **Matched source lines are never returned.** For the secret rules that line
  *is* the secret.

Telemetry is off on this path whatever your configuration says. Your `.valcarc`
is still honoured — `disabled_rules`, `exclude_paths` and `min_severity` all
apply.

`mcp` is an optional extra, so installing Valca normally still pulls no runtime
dependencies at all.

The hook remains the enforcement path. It runs on every write whether the model
wants it or not; MCP is opt-in by the agent, and a check an agent can decline is
not enforcement.

---

## Development

```bash
git clone https://github.com/PranLabs/valca.git
cd vigil
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

[Business Source License 1.1](LICENSE) — free for non-commercial use. Commercial use requires a license agreement. Converts to MIT on 2030-06-26.

---

## Feedback

Found a false positive? Want a rule that doesn't exist yet? Building with AI agents and hitting patterns Valca should catch?

[Open an issue → github.com/PranLabs/valca/issues](https://github.com/PranLabs/valca/issues)

Or: `valca feedback`
