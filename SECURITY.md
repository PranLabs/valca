# Security Policy

## Reporting a vulnerability in Valca

**Please do not report security vulnerabilities through public GitHub issues.**

Use **[GitHub's private vulnerability reporting](https://github.com/PranLabs/valca/security/advisories/new)**
on this repository. That channel is private, creates a draft advisory, and supports assigning a CVE
once the issue is confirmed.

Please include:

- The type of issue (e.g. arbitrary code execution during a scan, path traversal, prompt injection
  via a scanned file, denial of service on a crafted input)
- Full paths of the source files involved
- A minimal reproducer — ideally a file that Valca scans
- The impact, and how an attacker might exploit it

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 5 business days |
| Initial assessment | within 10 business days |
| Fix or mitigation plan | communicated once assessed |
| Public disclosure | coordinated with you, normally within 90 days |

Credit is given to reporters in the advisory unless you ask otherwise.

## Scope

**In scope** — anything in this repository: the scanner engine, rule implementations, the CLI, the
Claude Code plugin hook, the GitHub Action, and the VS Code extension.

Valca parses untrusted input by design — it scans repositories that may be hostile. Issues where a
crafted input file causes Valca to execute code, escape its scan directory, leak environment
variables, or hang indefinitely are all in scope and are treated seriously.

**Out of scope**

- **False positives and false negatives in detection rules.** These are correctness bugs, not
  vulnerabilities — please open a normal issue. They are still very welcome.
- Vulnerabilities in a project that Valca *scans*. Report those to that project.
- Findings that require a pre-compromised host or a malicious maintainer.

## Supported versions

Valca is pre-1.0. Security fixes are applied to `main` and released from there. Please confirm an
issue reproduces against the current `main` before reporting.

## How Valca handles vulnerabilities it discovers in other projects

Valca is a detection tool, and its rules surface real issues in third-party repositories. When
maintainers of this project report such findings upstream, they follow coordinated disclosure:

1. Report privately to the affected project — via its own security policy, or GitHub private
   vulnerability reporting where available
2. Allow a standard 90-day embargo before public discussion
3. Never exploit a finding against systems we do not own or are not authorised to test; detection is
   static analysis of published code only
4. Request a CVE where the finding warrants one, and credit the affected maintainers' fix

If a Valca rule flagged something in your project and you believe it is a false positive, please open
an issue — that feedback directly improves the rule corpus.
