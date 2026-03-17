# Python Web Code Audit Skill

Read this file before starting any Python code audit task.

---

## Step 0: Project Intake

```bash
mkdir -p /data/workspace/audit/{report,semgrep}
```

Python projects are always source code -- no decompilation needed. Confirm the project root:
```bash
find /data/workspace/audit/ -name "*.py" | head -5
tree /data/workspace/audit/ -L 3 --dirsfirst
```

---

## Step 1: Reconnaissance

**Goal: understand the project structure, framework, and entry points before reading business logic.**

### 1a. Framework Identification
```bash
# Check dependencies
cat requirements.txt 2>/dev/null || cat Pipfile 2>/dev/null || cat pyproject.toml 2>/dev/null
pip show flask django fastapi tornado 2>/dev/null

# Framework indicators
rg "from flask|from django|from fastapi|from tornado|from sanic" --type py | head -5
```

Record: framework name and version, Python version requirement.

### 1b. Dangerous Dependency Versions

| Component | Dangerous Versions |
|-----------|-------------------|
| Django | < 3.2.25, < 4.2.16 (multiple CVEs) |
| Flask | < 2.3.2 (debugger PIN bypass) |
| Jinja2 | < 3.1.3 (sandbox bypass) |
| Werkzeug | < 3.0.6 (debugger RCE) |
| PyYAML | Using yaml.load instead of safe_load |
| Pillow | < 10.0.1 (multiple overflows) |
| paramiko | < 3.4.0 |
| requests | < 2.32.0 |
| SQLAlchemy | Check for text() + concatenation |

### 1c. Configuration Files
```bash
find . -name ".env" -o -name ".env.*" -o -name "settings.py" \
  -o -name "config.py" -o -name "*.cfg" -o -name "*.ini" \
  | grep -v venv | grep -v __pycache__
cat .env 2>/dev/null

# Django settings
find . -name "settings.py" -not -path "*/venv/*" | xargs cat 2>/dev/null

# Flask config
rg "app\.config\[|app\.secret_key|SECRET_KEY" --type py
```

Extract and record:
- SECRET_KEY / APP_KEY (Django/Flask session signing key)
- Database credentials
- DEBUG = True (this is itself a finding -- enables debug pages with stack traces)
- JWT secrets
- Third-party API keys

**`DEBUG = True` and hardcoded secrets are findings -- record immediately.**

### 1d. Entry Points and Routing
```bash
# Flask
rg "@app\.route|@bp\.route|@blueprint\.route" --type py | head -30

# Django
find . -name "urls.py" -not -path "*/venv/*" | xargs cat 2>/dev/null
rg "path\(|url\(|re_path\(" --type py | grep -v venv | head -30

# FastAPI
rg "@app\.(get|post|put|delete|patch)|@router\.(get|post|put|delete|patch)" --type py | head -30

# Django REST Framework
rg "class.*ViewSet|class.*APIView|@api_view" --type py | head -20
```

Identify authentication middleware and which routes bypass it:
```bash
# Django
rg "login_required|permission_required|IsAuthenticated|AllowAny" --type py
rg "MIDDLEWARE" --type py -A20 | grep -i "auth\|session\|csrf"

# Flask
rg "login_required|before_request|@jwt_required|@auth\.login_required" --type py

# FastAPI
rg "Depends\(|Security\(|OAuth2|HTTPBearer" --type py
```

**Reconnaissance output:** write summary to `/data/workspace/audit/report/recon.md`.

---

## Step 2: Automated Scan

```bash
semgrep --config p/python \
  . \
  --exclude=venv --exclude=__pycache__ --exclude=.git \
  --json \
  --output /data/workspace/audit/semgrep/python-results.json \
  2>/data/workspace/audit/semgrep/semgrep-errors.log

# Framework-specific rulesets
semgrep --config p/flask . --exclude=venv --json \
  --output /data/workspace/audit/semgrep/flask-results.json 2>/dev/null

semgrep --config p/django . --exclude=venv --json \
  --output /data/workspace/audit/semgrep/django-results.json 2>/dev/null
```

Filter to HIGH and MEDIUM severity. Map each finding to a route from Step 1d -- discard findings with no reachable route.

If the project uses a non-standard framework, refer to `/data/skills/semgrep-custom-rules.md` to write custom taint rules.

---

## Step 3: Manual Audit (Priority Order)

Python sources to track:
```
request.args / request.form / request.json / request.data  (Flask)
request.GET / request.POST / request.body                  (Django)
Request.query_params / Request.data                        (FastAPI/DRF)
```

### P0 -- Unauthenticated Attack Surface

Cross-reference semgrep hits with unauthenticated routes from Step 1d.
```bash
# Flask: routes without login_required
rg "@app\.route|@bp\.route" --type py -A5 | grep -v "login_required\|jwt_required"

# Django: AllowAny or empty permission_classes
rg "AllowAny|permission_classes\s*=\s*\[\]" --type py
```

### P0 -- SSTI (Server-Side Template Injection)
```bash
rg "render_template_string|Template\(|from_string\(" --type py
rg "render_template_string\|Template\(" --type py -B3 \
  | grep -iE 'request|input|args|form|param'
rg "Environment\(" --type py -A5 | grep "from_string"
rg "mako\.template|Template\(" --type py | grep -v "jinja"
```

> Detailed patterns: /data/skills/vuln-rules/code-injection.md

### P0 -- Deserialization
```bash
rg "pickle\.loads|pickle\.load|shelve\.open|marshal\.loads" --type py
rg "yaml\.load\(" --type py | grep -v "Loader=SafeLoader\|safe_load"
rg "jsonpickle\.decode" --type py
rg "pickle" --type py -B5 | grep -iE 'request|input|b64decode|cookie'
```

> Detailed patterns: /data/skills/vuln-rules/insecure-deserialization.md

### P0 -- Command Injection
```bash
rg "os\.system\(|os\.popen\(|subprocess\.(call|run|Popen|check_output)\(" --type py
rg "subprocess" --type py -A3 | grep "shell=True"
rg "subprocess|os\.system|os\.popen" --type py -B5 | grep -iE 'request|input|args'
```

> Detailed patterns: /data/skills/vuln-rules/command-injection.md

### P0 -- File Operations
```bash
rg "save\(|FileField|ImageField|upload_to" --type py
rg "request\.files|FileStorage" --type py
rg "open\(|send_file|send_from_directory" --type py -B3 \
  | grep -iE 'request|input|args|form'
rg "os\.path\.join\(" --type py -B3 | grep -iE 'request|input'
```

> Detailed patterns: /data/skills/vuln-rules/path-traversal.md

### P1 -- SQL Injection
```bash
rg "\.raw\(|\.extra\(|RawSQL|connection\.cursor|text\(" --type py
rg "cursor\.(execute|executemany)\(" --type py -B3
rg "execute\(.*format\|execute\(.*%\|execute\(f\"" --type py
```

> Detailed patterns: /data/skills/vuln-rules/sql-injection.md

### P1 -- SSRF
```bash
rg "requests\.(get|post|put|delete|head)\(" --type py -B3 \
  | grep -iE 'request|input|args|form|url|uri'
rg "urllib\.request\.urlopen|urllib2\.urlopen" --type py -B3
rg "aiohttp\.ClientSession" --type py -B5
```

> Detailed patterns: /data/skills/vuln-rules/ssrf.md

### P1 -- Authentication and Authorization
```bash
rg "jwt\.decode\(" --type py -A3
rg "verify_signature.*False\|verify.*False" --type py
rg "SECRET_KEY" --type py
rg "md5\(|sha1\(" --type py | grep -iE 'password|passwd|pwd'
rg "check_password|set_password|make_password" --type py
```

> Detailed patterns: /data/skills/vuln-rules/authentication-jwt.md

### P1 -- XXE
```bash
rg "xml\.etree|xml\.dom|xml\.sax|lxml\.etree|xml\.parsers" --type py
rg "defusedxml" --type py  # if not imported, XXE may be possible
```

> Detailed patterns: /data/skills/vuln-rules/xxe.md

### P2 -- Secondary Findings
```bash
# XSS
rg "make_response\(|Response\(|HttpResponse\(" --type py -B3 | grep -iE 'request\.'
rg "mark_safe\(|\|safe\b" --type py -g '*.py' -g '*.html'

# Open redirect
rg "redirect\(" --type py -B3 | grep -iE 'request\.|args\.|form\.'

# CSRF
rg "@csrf_exempt" --type py
rg "WTF_CSRF_ENABLED.*False|CSRF.*False" --type py

# Debug info disclosure
rg "DEBUG\s*=\s*True|app\.debug\s*=\s*True" --type py
rg "traceback\.print_exc|traceback\.format_exc" --type py

# IDOR
rg "request\.(args|form|json).*id\b" --type py -A5 | grep -iE 'query\|filter\|get\|find'
```

---

## Step 4: Reporting

Write all findings to `/data/workspace/audit/report/audit_report.md`.
Record findings as discovered -- do not wait until all steps are complete.

### Finding Template
```markdown
## [VULN-XXX] Title

| Field | Value |
|---|---|
| Severity | Critical / High / Medium / Low |
| Type | RCE / SQLi / SSTI / ... |
| Authentication Required | None / User / Admin |
| Affected File | path/to/file.py (line N) |

### Code Context
\```python
// ~20-40 lines showing the vulnerable code and surrounding context
\```

### Root Cause
One sentence: what is wrong and why it is exploitable.

### Attack Path
```
HTTP endpoint -> view_function() -> dangerous_function()
Source: request.args['param'] -> Sink: eval()
```

### Request Template
\```http
GET /vulnerable?param=PAYLOAD HTTP/1.1
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

| Severity | Criteria |
|----------|---------|
| Critical | RCE (SSTI/pickle/eval), deserialization with gadget, unauthenticated file write |
| High | SQLi, SSRF, file upload bypass, JWT forgery, SECRET_KEY leak |
| Medium | Path traversal (read-only), IDOR, open redirect, DEBUG=True |
| Low | XSS, info disclosure, weak session config, weak crypto |

---

## Execution Constraints

- Write reconnaissance summary to `recon.md` after Step 1 completes.
- Append each finding to `audit_report.md` as it is discovered.
- Do not stop to ask the user unless: source code is incomplete for a critical path, or the audit is substantially complete and ready for review.
- If a test URL is provided: include a fully-formed HTTP request for each finding. Do not send requests automatically -- output is for manual testing by the operator.
- Do not report findings where Source to Sink reachability cannot be confirmed.
