# Contributing to Valca

Thanks for your interest. Valca is a security scanner for AI-agent configurations and
infrastructure-as-code, and contributions — especially new detection rules and false-positive
reports — are genuinely valuable.

Please read the **[licensing note](#licensing-and-contributor-terms)** before opening a pull
request. Valca is source-available under the Business Source License 1.1, not a permissive
open-source licence, and that affects contribution terms.

## Ways to contribute

| Type | Where to start |
|---|---|
| **False positive report** | Open a Bug issue. Include the exact snippet Valca flagged. These are the highest-value reports. |
| **New detection rule** | Open a `[RULE-REQUEST]` issue **first** so the rule ID and scope can be agreed. |
| **Bug fix** | PR directly, with a regression test. |
| **Docs** | PR directly. |

## Development setup

```bash
git clone https://github.com/PranLabs/valca.git
cd cordon
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q                 # full suite must pass before you open a PR
```

## Workflow

Valca uses the standard fork-and-pull-request model. Direct pushes to `main` are blocked.

1. **Fork** the repository to your own account
2. **Branch** from `main` — `fix/<short-description>` or `rule/VGL-XXX000`
3. **Commit** with a sign-off (see below)
4. **Test** — `pytest -q` must be green; add tests covering your change
5. **Open a PR** against `main`, fill in the template, and link the related issue
6. **CI must pass.** The `CI / test` check is required before merge

Keep pull requests focused. One rule, or one fix, per PR.

## Adding a detection rule

Rules live in `src/valca/rules/` grouped by domain (`docker.py`, `gha.py`, `mcp_security.py`,
`prompt_injection.py`, …).

1. **Claim an ID.** Rules follow `VGL-<FAMILY><NNN>` — e.g. `VGL-D001` (Docker), `VGL-GHA011`
   (GitHub Actions), `VGL-MCP004` (MCP), `VGL-PI007` (prompt injection). Agree the ID on the issue
   before writing code so numbering stays stable.
2. **Subclass `Rule`** from `.base`, returning `Finding` objects with an appropriate `Severity`.
3. **Register it** in the `DEFAULT_RULES` list in `src/valca/rules/__init__.py`.
4. **Write tests** in `tests/test_rules_<family>.py` covering *both* a true positive **and** a
   negative case that must not fire.
5. **Document the reasoning.** A rule's docstring should say what the attack is and why existing
   tools miss it — not just what pattern it matches.

### Rule quality bar

A rule is only useful if engineers trust it. Before submitting, check:

- **Low false-positive rate.** A noisy rule gets the whole tool disabled. If you cannot avoid
  false positives, make the rule advisory rather than blocking.
- **Handles the safe idioms.** Real code has legitimate patterns that superficially match. See how
  `docker.py` deliberately excludes variable references (`${VAR}`) and Docker's `_FILE` secret
  convention — those are *more* secure, and flagging them would be wrong.
- **Actionable fix text.** Every finding should tell the reader what to change, concretely.
- **Cites the threat.** Where a rule maps to a known attack class or CWE, reference it.

## Commit messages

Describe what the change does or improves. Keep the subject under ~72 characters.

```
docker: exclude _FILE secret convention from VGL-D002

Docker's FOO_PASSWORD_FILE=/run/secrets/foo pattern is the more secure
approach and must never be flagged as a hardcoded secret. Adds a
regression test for the safe idiom.
```

**Do not include AI-assistant attribution** (`Co-Authored-By: <assistant>`, "Generated with …")
in commit messages or PR descriptions. Contributions are attributed to the human contributor.

### Sign-off (DCO)

Every commit must carry a `Signed-off-by` line certifying you wrote the contribution or have the
right to submit it under this project's licence, per the
[Developer Certificate of Origin](https://developercertificate.org/).

```bash
git commit -s -m "your message"
```

## Reporting security issues

**Do not open a public issue for a vulnerability in Valca.** See [SECURITY.md](SECURITY.md).

## Licensing and contributor terms

Valca is licensed under the **Business Source License 1.1**. It is source-available: you may read,
modify and use it under the terms in [LICENSE](LICENSE), but **commercial use requires a separate
licence agreement**.

By submitting a pull request you agree that your contribution is licensed under the same terms as
the project, and you grant the maintainer the rights necessary to distribute and license the
combined work — including under the commercial terms described in [NOTICE](NOTICE).

If you are contributing on behalf of an employer, make sure you have the authority to do so before
opening the PR. If your organisation requires a signed agreement, say so on the issue and it can be
arranged before you invest time in the work.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
