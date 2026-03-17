# PHP Code Audit Skill

Read this file before starting any PHP code audit task.

---

## Step 0: Project Intake

Identify what you received and prepare the working directory:
```bash
mkdir -p /data/workspace/audit/{report,semgrep}
```

PHP projects are always source code — no decompilation needed. Confirm the root:
```bash
find /data/workspace/audit/ -name "*.php" | head -5
tree /data/workspace/audit/ -L 3 --dirsfirst
```

If a test URL is provided, note it for the report stage. Do not actively probe.

---

## Step 1: Reconnaissance

**Goal: understand the project structure, framework, and entry points before reading business logic.**

### 1a. Framework Identification
```bash
# Check composer dependencies
find . -name "composer.json" -not -path "*/vendor/*" | xargs cat 2>/dev/null

# Common framework indicators
find . -name "*.php" | xargs grep -l "Laravel\|Illuminate" 2>/dev/null | head -3
find . -name "*.php" | xargs grep -l "Symfony\|Kernel" 2>/dev/null | head -3
find . -name "*.php" | xargs grep -l "ThinkPHP\|think\\\\" 2>/dev/null | head -3
find . -name "*.php" | xargs grep -l "Yii\|yii\\\\" 2>/dev/null | head -3
find . -name "*.php" | xargs grep -l "CodeIgniter\|CI_Controller" 2>/dev/null | head -3

# No framework: look for index.php and manual routing
cat index.php 2>/dev/null || cat public/index.php 2>/dev/null
```

Record: framework name and version, PHP version requirement (`composer.json` → `require.php`).

### 1b. Dangerous Dependency Versions

From `composer.json` and `composer.lock`, flag these:

| Component  | Dangerous Versions                                       |
| ---------- | -------------------------------------------------------- |
| Laravel    | < 8.4.3 (debug RCE), < 6.20.12 / 7.30.4 (SQLi)           |
| ThinkPHP   | 5.0.x < 5.0.24, 5.1.x < 5.1.31 (RCE via method override) |
| Yii2       | < 2.0.38 (deserialization)                               |
| Symfony    | Check against CVE list for version range                 |
| GuzzleHTTP | < 7.4.5 (header injection)                               |
| Monolog    | < 1.25.0, < 2.1.1 (RCE via PEAR handler)                 |
| phpmailer  | < 6.5.0                                                  |

### 1c. Configuration Files
```bash
find . -name ".env" -o -name "config.php" -o -name "database.php" \
       -o -name "config.ini" -o -name "settings.php" \
  | grep -v vendor | xargs cat 2>/dev/null
```

Extract and record:
- Database credentials
- `APP_KEY` / `APP_SECRET` (Laravel app key — required to forge signed cookies)
- JWT secrets
- SMTP credentials
- Third-party API keys
- Debug mode status (`APP_DEBUG=true` is itself a finding — enables stack trace disclosure)

**Hardcoded secrets and `APP_DEBUG=true` are findings — record immediately.**

### 1d. Entry Points and Routing
```bash
# Single entry point (modern frameworks)
cat public/index.php

# Multi-entry legacy projects
find . -maxdepth 2 -name "*.php" -not -path "*/vendor/*" \
       -not -path "*/tests/*" | head -30

# Route files
find . -name "routes" -type d
find . -name "web.php" -o -name "api.php" | grep -v vendor
find . -name "*.php" | xargs grep -l "Route::\|@Route\|addRoute" 2>/dev/null \
  | grep -v vendor | head -10

# ThinkPHP: controller directory maps to routes
find . -path "*/controller/*.php" | grep -v vendor

# Legacy: direct file access is a route
find . -maxdepth 3 -name "*.php" -not -path "*/vendor/*" \
       -not -path "*/classes/*" -not -path "*/lib/*"
```

Identify authentication middleware and which routes bypass it:
```bash
# Laravel: check middleware groups in Kernel.php and route files
cat app/Http/Kernel.php 2>/dev/null
grep -r "middleware\|auth\|guest" routes/ 2>/dev/null

# ThinkPHP: middleware.php
cat app/middleware.php 2>/dev/null

# Legacy: look for session/auth checks at file top
grep -rn "session_start\|isLogin\|checkLogin\|require.*auth" \
  --include="*.php" . | grep -v vendor | head -20
```

**Reconnaissance output:** write summary to `/data/workspace/audit/report/recon.md`.

---

## Step 2: Automated Scan
```bash
semgrep --config p/php \
  . \
  --exclude=vendor \
  --json \
  --output /data/workspace/audit/semgrep/php-results.json \
  2>/data/workspace/audit/semgrep/semgrep-errors.log
```

Parse results, keep HIGH and MEDIUM severity only. For each finding, verify it traces to a reachable route — discard unreachable sinks.

---

## Step 3: Manual Audit (Priority Order)

For each finding, verify the complete **Source → Sink** chain before recording.

PHP sources to track:
```
$_GET  $_POST  $_REQUEST  $_COOKIE  $_FILES  $_SERVER['HTTP_*']
getallheaders()  file_get_contents('php://input')
```

### P0 — Unauthenticated Attack Surface

Cross-reference semgrep hits with unauthenticated routes from Step 1d. Any exploitable finding on an unauthenticated route is critical.

For legacy multi-file projects — every `.php` file directly under webroot is potentially unauthenticated:
```bash
find . -maxdepth 2 -name "*.php" -not -path "*/vendor/*" \
  | xargs grep -l "\$_GET\|\$_POST\|\$_REQUEST" 2>/dev/null
```

### P0 — Remote Code Execution
```bash
# Direct execution sinks
rg "eval\s*\(|assert\s*\(|preg_replace.*\/e|create_function" \
  --type php -g "!vendor"

# System command sinks
rg "system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|\`" \
  --type php -g "!vendor"

# Dynamic include (file inclusion → RCE)
rg "include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\(" \
  --type php -g "!vendor" \
  | grep -v "vendor\|autoload\|__DIR__\|dirname"
```

For each hit: trace whether any user-controlled source reaches the sink without sanitization.

**File inclusion** — check if the included path contains user input:
```bash
rg "include.*\\\$_(GET|POST|REQUEST|COOKIE)\|require.*\\\$_(GET|POST|REQUEST|COOKIE)" \
  --type php -g "!vendor"
```

### P0 — Deserialization
```bash
rg "unserialize\s*\(" --type php -g "!vendor"

# Check if input reaches unserialize
rg "unserialize" --type php -g "!vendor" -B3 \
  | grep -i "get\|post\|request\|cookie\|input"
```

For Laravel: `APP_KEY` exposure (found in Step 1c) enables forging signed/encrypted cookies. If `unserialize` is called on cookie data, this is a critical RCE chain.

For Yii2: check `yii\rest\Serializer` and `__wakeup` / `__destruct` in loaded classes.

### P0 — File Upload
```bash
rg "move_uploaded_file|file_put_contents|imagecreatefrom" \
  --type php -g "!vendor"

rg "\\\$_FILES" --type php -g "!vendor" -A 10
```

Check:
- Is extension validated? Client-side only (`$_FILES['type']`) is bypassable — look for server-side checks
- Is the upload directory within webroot? If yes and PHP execution isn't disabled, this is a webshell upload
- Is the filename used directly (path traversal)?
```bash
# Path traversal in upload filename
rg "getClientOriginalName\|getOriginalName\|\\\$_FILES.*name" \
  --type php -g "!vendor" -A5
```

### P1 — SQL Injection
```bash
# String concatenation in queries
rg "\"SELECT|'SELECT|\"INSERT|\"UPDATE|\"DELETE" \
  --type php -g "!vendor" \
  | grep "\."

# Direct variable in query
rg "\\\$(GET|POST|REQUEST|COOKIE)\[" --type php -g "!vendor" -A3 \
  | grep -i "query\|sql\|select\|where"

# Common query execution functions
rg "mysql_query\|mysqli_query\|->query\|->execute\|PDO::query" \
  --type php -g "!vendor" -B5 | grep "\$"
```

Look for raw variable interpolation in SQL strings — this is the most common pattern in legacy PHP:
```php
// Dangerous pattern to find:
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$sql = "SELECT * FROM users WHERE name = '$name'";
```

### P1 — SSRF
```bash
rg "curl_init|file_get_contents|fsockopen|SoapClient" \
  --type php -g "!vendor" -B3 \
  | grep -i "get\|post\|request\|cookie\|url\|uri"

rg "curl_setopt.*CURLOPT_URL" --type php -g "!vendor" -B5
```

Check whether URL is constructed from user input without allowlist validation.

### P1 — XXE
```bash
rg "simplexml_load|DOMDocument|SimpleXMLElement|XMLReader|xml_parse" \
  --type php -g "!vendor" -A5 \
  | grep -v "libxml_disable_entity_loader\|LIBXML_NOENT"

# Confirm: is LIBXML_NOENT set (dangerous) or libxml_disable_entity_loader(true) absent?
```

### P1 — Local/Remote File Inclusion via Path Traversal
```bash
# Read operations with user-controlled path
rg "file_get_contents|file|readfile|fopen|SplFileObject" \
  --type php -g "!vendor" -B3 \
  | grep -i "get\|post\|request\|cookie\|path\|file\|name"

# Check for ../  filtering (missing or bypassable)
rg "str_replace.*\.\." --type php -g "!vendor"
rg "realpath\|basename" --type php -g "!vendor" -B3
```

### P1 — Authentication Issues
```bash
# Type juggling in comparisons (== vs ===)
rg "==\s*['\"]0[Ee]\|==\s*true\|==\s*false\|==\s*0\b" \
  --type php -g "!vendor" \
  | grep -v vendor

# Weak comparison in login/token verification
rg "strcmp\s*\(|md5\s*\(.*==\|hash\s*\(.*==" \
  --type php -g "!vendor"
```

PHP type juggling common patterns to look for:
```php
// "0e..." magic hash bypass
if (md5($input) == $hash)  // use === instead

// strcmp null bypass
if (strcmp($input, $secret) == 0)  // returns null for array input
```
```bash
# Session fixation
rg "session_id\s*\(\|session_regenerate_id" --type php -g "!vendor"
```

### P1 — Framework-Specific CVEs

If ThinkPHP was identified in Step 1a, check method override route:
```bash
# ThinkPHP RCE: _method parameter abuse
rg "_method\|__construct\|filterValue\|invokeFunction" \
  --type php -g "!vendor" | head -10
```

If Laravel with known `APP_KEY`, document that signed URL / cookie forgery is possible — this is a high-severity finding regardless of other code.

### P2 — Secondary Findings
```bash
# XSS: output without escaping
rg "echo\s+\\\$_\|print\s+\\\$_\|echo.*\\\$_(GET|POST|REQUEST)" \
  --type php -g "!vendor"

# Open redirect
rg "header.*Location.*\\\$_(GET|POST|REQUEST)" --type php -g "!vendor"

# Sensitive data in comments or debug output
rg "var_dump\|print_r\|phpinfo\|die\s*\(" --type php -g "!vendor"

# Insecure direct object reference
rg "\\\$_(GET|POST)\[.*(id|ID|Id)\]" --type php -g "!vendor" -A5 \
  | grep -i "query\|find\|select\|fetch"
```

---

## Step 4: Reporting

Write all findings to `/data/workspace/audit/report/audit_report.md`.
Record findings as discovered — do not wait until all steps are complete.

### Finding Template
```markdown
## [VULN-XXX] Title

| Field | Value |
|---|---|
| Severity | Critical / High / Medium / Low |
| Type | RCE / SQLi / File Inclusion / ... |
| Authentication Required | None / User / Admin |
| Affected File | path/to/file.php (line N) |

### Code Context
\```php
// ~20-40 lines showing the vulnerable code and surrounding context
\```

### Root Cause
One sentence: what is wrong and why it is exploitable.

### Attack Path
```
HTTP endpoint → file.php → dangerous function()
Source: $_GET['param'] → Sink: system()
```

### Request Template
\```http
GET /vulnerable.php?param=PAYLOAD HTTP/1.1
Host: {{TARGET}}

\```

### Payload
\```
# Detection
...
# Exploitation
...
\```

### Remediation
One-line fix recommendation.
```

### Severity Criteria

| Severity | Criteria                                                     |
| -------- | ------------------------------------------------------------ |
| Critical | RCE (eval/exec/include with user input), deserialization with gadget chain, unauthenticated file upload to webroot |
| High     | SQLi, SSRF, authenticated file upload bypass, XXE, LFI/RFI   |
| Medium   | Path traversal (read-only), IDOR, open redirect, type juggling auth bypass |
| Low      | XSS, information disclosure (debug output, stack traces), weak session config |

### Deduplication Rule

For repeated vulnerability patterns (e.g., SQLi in 5 different query files), document the 2-3 most critical instances in full, list remaining locations in an appendix table.

---

## Execution Constraints

- Write reconnaissance summary to `recon.md` after Step 1 completes.
- Append each finding to `audit_report.md` as it is discovered.
- Do not stop to ask the user unless: source code is incomplete for a critical path, or the audit is substantially complete and ready for review.
- If a test URL is provided: include a fully-formed HTTP request for each finding. Do not send requests automatically — output is for manual testing by the operator.
- Do not report findings where Source → Sink reachability cannot be confirmed.
- `vendor/` directory: skip for vulnerability hunting. Reference only when tracing a known CVE in a specific dependency version.