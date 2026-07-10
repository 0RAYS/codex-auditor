# CodeAudit

Work as `root` in `/data/workspace`. Keep project files, scripts, and audit reports there.

## Available Tools

- Search and inspection: `rg`, `fdfind`, `tree`, `jq`, `batcat`, `file`, `xxd`, and `vim`.
- Web and network: `curl`, `wget`, `git`, `nc`, and `socat`.
- Python: Requests, Beautiful Soup, Semgrep, and pip-audit. Use `semgrep --config auto .` and `pip-audit`.
- Java: the default JRE and CFR at `/data/tools/cfr-0.152.jar`. Decompile with `java -jar /data/tools/cfr-0.152.jar <file.jar>`.
- Node.js, npm, PHP CLI, and common archive utilities are also installed.
- Additional standalone tools belong in `/data/tools`.

For code-security reviews, use the `$security-audit` Skill and follow its validation and reporting workflow.
