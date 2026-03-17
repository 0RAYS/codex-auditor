# Vulnerability Rules Index

> Load individual files on demand during audit. Do not load the entire directory into context at once.

## Critical

| # | Type | File | CWE |
|---|------|------|-----|
| 1 | SQL Injection | sql-injection.md | CWE-89 |
| 2 | Command Injection | command-injection.md | CWE-78 |
| 3 | Code Injection / SSTI | code-injection.md | CWE-94/95 |
| 4 | Insecure Deserialization | insecure-deserialization.md | CWE-502 |
| 5 | Path Traversal / File Inclusion | path-traversal.md | CWE-22 |
| 6 | XSS | xss.md | CWE-79 |
| 7 | XXE | xxe.md | CWE-611 |
| 8 | Hardcoded Secrets | secrets.md | CWE-798 |

## High

| # | Type | File | CWE |
|---|------|------|-----|
| 9 | SSRF | ssrf.md | CWE-918 |
| 10 | JWT Authentication Flaws | authentication-jwt.md | CWE-287/347 |
| 11 | Insecure Cryptography | insecure-crypto.md | CWE-327 |
| 12 | CSRF | csrf.md | CWE-352 |
| 13 | Unsafe Functions | unsafe-functions.md | CWE-676 |

## Medium

| # | Type | File | CWE |
|---|------|------|-----|
| 14 | Race Conditions | race-condition.md | CWE-367 |

## File Structure

Each file follows the same layout:
1. **Quick Search Commands** -- multi-language rg/grep commands to run against the target project
2. **Vulnerability Patterns** -- dangerous vs safe code examples per language
3. **Audit Checklist** -- confirmation steps after finding a suspicious pattern

During the Manual Audit phase of java-audit.md / php-audit.md / python-audit.md,
read the corresponding file when you encounter a specific vulnerability type.
