# Semgrep Custom Rule Writing Guide

> Use this when built-in rulesets (p/java, p/php, etc.) cannot cover project-specific frameworks or patterns.

---

## When Custom Rules Are Needed

- Project uses a custom framework (custom annotations, custom Controller base class, custom ORM)
- Built-in rules miss project-specific patterns
- Non-standard sources/sinks need to be tracked (e.g. a custom `getParam()` method)

## Approach Selection

| Approach | Use When | Example |
|----------|----------|---------|
| **Taint mode** | Data flows from untrusted source to dangerous sink | SQLi, command injection, SSRF, XSS |
| **Pattern matching** | Syntactic patterns, no data flow needed | Hardcoded keys, deprecated APIs, misconfigurations |

**Prefer taint mode for injection vulnerabilities.** Pattern matching alone cannot distinguish `eval(user_input)` from `eval("safe_literal")`.

---

## Taint Mode Template

```yaml
rules:
  - id: custom-sqli
    mode: taint
    languages: [java]  # or python, javascript, php, go, ruby, ...
    severity: ERROR
    message: "User input from $SOURCE flows to SQL execution"
    metadata:
      cwe: "CWE-89"

    pattern-sources:
      # Input acquisition methods -- adjust to match the target project
      - pattern: (HttpServletRequest $REQ).getParameter(...)
      - pattern: (BaseController $C).getParam(...)  # custom base class
      - pattern: $REQ.getHeader(...)

    pattern-sinks:
      - pattern: $STMT.execute($SQL, ...)
        focus-metavariable: $SQL
      - pattern: $STMT.executeQuery($SQL, ...)
        focus-metavariable: $SQL

    pattern-sanitizers:
      - pattern: Integer.parseInt(...)
      - pattern: Long.parseLong(...)
      - pattern: $PSTMT.setString(...)
```

## Pattern Matching Template

```yaml
rules:
  - id: hardcoded-db-password
    languages: [java]
    severity: WARNING
    message: "Hardcoded database password found: $PWD"
    patterns:
      - pattern: $X.setPassword("$PWD")
      - metavariable-regex:
          metavariable: $PWD
          regex: ".+"
```

---

## Pattern Syntax Reference

| Syntax | Meaning | Example |
|--------|---------|---------|
| `...` | Match any arguments/statements | `func(...)` |
| `$VAR` | Capture metavariable | `$FUNC($INPUT)` |
| `<... ...>` | Deep expression match | `<... user_input ...>` |
| `pattern-either` | OR relationship | Any of the patterns matches |
| `patterns` | AND relationship | All patterns must match |
| `pattern-not` | Exclusion | Remove safe patterns |
| `pattern-inside` | Scope restriction | Only match inside a given method/class |
| `metavariable-regex` | Regex filter on captured variable | `$FUNC` matches `eval\|exec` |
| `focus-metavariable` | Specify reported location | Only flag the SQL argument in a sink |

---

## Workflow

### 1. Analyze the target project
```bash
# Identify input acquisition methods (source)
rg "getParameter|getParam|@RequestParam|@PathVariable|@RequestBody" --type java -l | head -10

# Identify database operations (sink)
rg "\.execute|\.query|\.update|\.insert|\.selectList" --type java -l | head -10

# Identify sanitization methods (sanitizer)
rg "sanitize|escape|validate|filter|encode" --type java -l | head -10
```

### 2. Write test cases first (before the rule)

Create `test-custom-sqli.java`:
```java
class Test {
    // ruleid: custom-sqli
    void bad(HttpServletRequest req) {
        String id = req.getParameter("id");
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }

    // ok: custom-sqli
    void good(HttpServletRequest req) {
        String id = req.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
```

### 3. Write the rule and test it
```bash
semgrep --validate --config custom-sqli.yaml
semgrep --test --config custom-sqli.yaml test-custom-sqli.java
semgrep --dataflow-traces -f custom-sqli.yaml test-custom-sqli.java  # debug taint flow
```

### 4. Run against the target project
```bash
semgrep --config /data/workspace/audit/custom-rules/ \
  /data/workspace/audit/decompiled \
  --json --output /data/workspace/audit/semgrep/custom-results.json
```

---

## Practical Examples

### Example 1: Project uses @NoAuth annotation + custom BaseController.getParam()

```yaml
rules:
  - id: noauth-sqli
    mode: taint
    languages: [java]
    severity: ERROR
    message: "Unauthenticated endpoint has SQL injection"
    pattern-sources:
      - pattern: (BaseController $C).getParam(...)
    pattern-sinks:
      - pattern: $MAPPER.$METHOD(...)
```

### Example 2: PHP ThinkPHP input() method

```yaml
rules:
  - id: thinkphp-sqli
    mode: taint
    languages: [php]
    severity: ERROR
    message: "ThinkPHP input() flows to SQL"
    pattern-sources:
      - pattern: input(...)
      - pattern: $this->request->param(...)
    pattern-sinks:
      - pattern: Db::query(...)
      - pattern: $this->where(...)
      - pattern: Db::name(...)->where(...)
```

### Example 3: Python Flask route parameters

```yaml
rules:
  - id: flask-sqli
    mode: taint
    languages: [python]
    severity: ERROR
    message: "Flask request parameter flows to SQL"
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.json.get(...)
    pattern-sinks:
      - pattern: cursor.execute($Q, ...)
        focus-metavariable: $Q
      - pattern: db.engine.execute($Q, ...)
        focus-metavariable: $Q
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: bleach.clean(...)
```

---

## Command Reference

| Task | Command |
|------|---------|
| Built-in ruleset scan | `semgrep --config p/java .` |
| Multiple rulesets | `semgrep --config p/security-audit --config p/owasp-top-ten .` |
| Custom rule scan | `semgrep --config ./my-rules/ .` |
| JSON output | `semgrep --config p/java --json -o results.json .` |
| Validate rule | `semgrep --validate --config rule.yaml` |
| Test rule | `semgrep --test --config rule.yaml test-file` |
| Debug data flow | `semgrep --dataflow-traces -f rule.yaml file` |
| Dump AST | `semgrep --dump-ast -l java file.java` |

## Common Rulesets

| Ruleset | Description |
|---------|-------------|
| `p/default` | General security + code quality |
| `p/security-audit` | Comprehensive security audit |
| `p/owasp-top-ten` | OWASP Top 10 |
| `p/cwe-top-25` | CWE Top 25 |
| `p/java` / `p/spring` | Java / Spring specific |
| `p/php` / `p/laravel` | PHP / Laravel specific |
| `p/python` / `p/flask` / `p/django` | Python framework specific |
| `p/javascript` / `p/nodejs` | JS / Node.js specific |
| `p/trailofbits` | Trail of Bits security rules |
