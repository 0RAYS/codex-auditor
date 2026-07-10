# Code Audit Container

## Environment and Purpose

This is an isolated Linux container for code auditing and related security work. Codex runs as `root` and may execute arbitrary commands inside the container. The primary workspace is `/data/workspace`. Keep target projects, audit artifacts, helper scripts, proof-of-concept harnesses, and final reports under this directory unless the user explicitly requests otherwise.

Use the environment to explore targets, identify exploitable vulnerabilities, validate findings, and produce actionable reports. Treat the target repository as evidence: do not rewrite, delete, or fix its source unless the user asks for implementation changes. Put temporary experiments in `/tmp` or the audit output directory.

## Preinstalled Tools

- Search and inspection: `rg`, `fdfind`, `tree`, `jq`, `batcat`, `less`, `file`, `xxd`, and `vim`.
- Network and web: `curl`, `wget`, `git`, `nc`, `socat`, and `net-tools` utilities.
- Python: Python 3, pip, Requests, Beautiful Soup, Semgrep, and pip-audit.
- Java: the default JRE and CFR 0.152 at `/data/tools/cfr-0.152.jar`.
- JavaScript: Node.js, npm, and the Codex CLI.
- PHP: PHP CLI with cURL, XML, and mbstring support.
- Archives: `tar`, `zip`, `unzip`, `7z`, `xz`, and `bzip2`.
- Services and terminal tools: OpenSSH server, tmux, ttyd, File Browser, and Nginx.

Examples:

```bash
semgrep --config auto .
pip-audit
java -jar /data/tools/cfr-0.152.jar target.jar
```

If a required tool is missing, install it directly.

If no suitable package exists, clone the trusted upstream repository into `/data/tools`, install its build dependencies, and build it from source. pip and npm installations are also allowed. Verify the source and record important tool versions or unusual build steps in the audit notes.

## Security Audits

For code-security reviews, vulnerability research, penetration-test-style source review, or requests to find security bugs, use the `$security-audit` Skill. Follow its six phases in order: reconnaissance, hunting, adversarial validation, reporting, structured output, and independent verification.

The Skill is authoritative for methodology, evidence standards, severity, validation, and report structure. This file overrides only its default artifact location and report language.

## Working Method

1. Establish the target path and requested scope. Unless the user narrows the scope, aim to cover the entire repository: entry points, trust boundaries, authentication and authorization, data flows, configuration, dependencies, client code, background jobs, deployment files, and security-relevant generated interfaces.
2. Explore before hunting. Read project guidance, identify languages and frameworks, determine build and test commands, map entry points and attacker-controlled inputs, and understand the intended deployment and permission model.
3. Use the reconnaissance results and `$security-audit` to create a target-specific plan. Do not substitute a generic checklist for understanding the application.
4. Combine manual review with search tools, Semgrep, dependency auditors, decompilers, parsers, test runners, and focused harnesses. Install additional tools when they materially improve coverage.
5. Validate dynamically whenever safe and practical. Reproduce behavior, run focused payloads, or build minimal harnesses. If required infrastructure is unavailable, mark the issue as requiring deployment testing rather than claiming confirmation.
6. Treat scanner output as leads, not findings. A reported vulnerability needs a concrete attacker, reachable path, reproducible behavior, meaningful impact, and evidence that survives adversarial review. Keep hardening advice separate from exploitable findings.
7. Do not stop after the first result or after automated scans. Review business logic, state transitions, authorization boundaries, implicit trust, and chained attacks that scanners commonly miss.
8. Reconcile every final claim across all outputs. State coverage limitations, untested components, and assumptions clearly.

## Semgrep and Automated Scanning

Use Semgrep as a supplementary tool for broad coverage, targeted patterns, taint analysis, and custom rules. Useful starting commands are:

```bash
semgrep --config auto .
semgrep --config p/security-audit .
semgrep --json --config p/security-audit -o semgrep-results.json .
```

Choose additional rulesets based on the target. Exclude vendored, generated, cached, or otherwise irrelevant content only after confirming it is out of scope. Use local or custom rules when remote rules are unavailable. A clean scan never proves that a repository is secure, and a match must not be reported without manual reachability and impact validation.

## Artifacts and Report Language

Keep every audit run under `/data/workspace`.

Store the standard `$security-audit` artifacts in the run directory:

- `architecture.md`
- `REPORT.md`
- `FINDINGS-DETAIL.md`
- `findings.json`
- Relevant scan output, reproduction scripts, and minimal proof-of-concept files

Write audit reports and explanatory finding content in Simplified Chinese. Keep schema keys, enum values, commands, identifiers, paths, and code snippets in their original technical form. Reports must let the user reproduce confirmed issues and prioritize remediation.
