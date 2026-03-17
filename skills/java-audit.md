# Java Web Code Audit Skill

Read this file before starting any Java code audit task.

---

## Step 0: Project Intake

Identify what you received and prepare the working directory:
```bash
mkdir -p /data/workspace/audit/{decompiled,report,semgrep}
```

| Input Type                 | Action                                                       |
| -------------------------- | ------------------------------------------------------------ |
| `.jar` file                | Decompile with CFR first (see Step 1)                        |
| Tomcat `webapp/` directory | Contains mixed `.class` and config files, decompile `.class` files selectively |
| Pre-decompiled source      | Skip to Step 2                                               |

If target URL is provided, note it for later — do not actively probe until report stage.

---

## Step 1: Decompilation
```bash
# Decompile entire jar
java -jar /data/tools/cfr-0.152/cfr-0.152.jar <input.jar> \
  --outputdir /data/workspace/audit/decompiled \
  --silent true

# If JVM version mismatch error appears, check class version:
file <input.jar>
# Then try adding: --jvmversion 17
```

Verify output — if a large number of files show `// This method has a ternary body` or similar CFR errors, note it but continue. Do not abort due to partial decompilation failures.

Working source root from this point: `/data/workspace/audit/decompiled/`

---

## Step 2: Reconnaissance

**Goal: understand the project before reading any business logic.**

### 2a. Project Structure
```bash
tree /data/workspace/audit/decompiled -L 4 --dirsfirst
```

Identify:
- Framework: Spring Boot / Spring MVC / Struts2 / others
- ORM: MyBatis / Hibernate / JdbcTemplate
- Whether it is a monolith or multi-module Maven project

### 2b. Dependency Analysis

Check in order:
```bash
# From decompiled source
find /data/workspace/audit/decompiled -name "pom.xml" | head -5
cat <found pom.xml>

# From jar manifest
unzip -p <input.jar> META-INF/MANIFEST.MF

# List bundled jars (fat jar / WEB-INF/lib)
unzip -l <input.jar> | grep "\.jar$"
```

Extract and record versions for these components — flag any known-vulnerable versions immediately:

| Component        | Dangerous Versions                              |
| ---------------- | ----------------------------------------------- |
| Shiro            | < 1.7.0 (rememberMe RCE), < 1.9.0 (auth bypass) |
| Log4j            | 2.0 - 2.14.1 (Log4Shell)                        |
| FastJSON         | < 1.2.83                                        |
| Spring Framework | 5.3.0 - 5.3.17, 5.2.0 - 5.2.19 (Spring4Shell)   |
| Struts2          | Check against S2-001 ~ S2-066 range             |
| XStream          | < 1.4.19                                        |

### 2c. Configuration Files
```bash
find /data/workspace/audit/decompiled -name "*.yml" -o -name "*.yaml" \
  -o -name "*.properties" -o -name "*.xml" \
  | grep -v "target/" | grep -v "test/"
```

From each config file, extract:
- Database credentials and JDBC URLs
- JWT secrets / signing keys
- Encryption keys or hardcoded passwords
- Internal service addresses (SSRF surface)
- Third-party API keys

**Hardcoded secrets are a finding — record immediately.**

### 2d. Route Mapping

Identify all externally exposed endpoints and their authentication status:
```bash
# Spring MVC / Spring Boot
rg "@(Request|Get|Post|Put|Delete|Patch)Mapping" /data/workspace/audit/decompiled \
  -l | head -20

# web.xml (traditional)
find /data/workspace/audit/decompiled -name "web.xml"

# Struts2
find /data/workspace/audit/decompiled -name "struts*.xml"
```

For Spring Security / Shiro — **this is critical**:
```bash
# Find security config
rg "antMatchers|permitAll|filterChain|ShiroFilterFactoryBean|filterChainDefinitionMap" \
  /data/workspace/audit/decompiled -l

# Find Shiro whitelist paths
rg "anon|authc" /data/workspace/audit/decompiled
```

Build a rough route table in your notes:
- Unauthenticated routes (highest priority attack surface)
- Routes accepting file input
- Routes with serialization-related parameters

**Reconnaissance output:** write a summary to `/data/workspace/audit/report/recon.md` covering framework, dangerous dependency versions, sensitive configs found, and route authentication overview.

---

## Step 3: Automated Scan

Run semgrep against the decompiled source:
```bash
semgrep --config p/java \
  /data/workspace/audit/decompiled \
  --json \
  --output /data/workspace/audit/semgrep/java-results.json \
  --error \
  2>/data/workspace/audit/semgrep/semgrep-errors.log

# Also run Spring-specific rules if applicable
semgrep --config p/spring \
  /data/workspace/audit/decompiled \
  --json \
  --output /data/workspace/audit/semgrep/spring-results.json
```

Parse results and filter to HIGH and MEDIUM severity findings only. Map each finding back to a route identified in Step 2d — discard findings with no reachable route.

---

## Step 4: Manual Audit (Priority Order)

Work through attack surfaces in this order. For each finding, verify the complete **Source → Gadget → Sink** chain before recording.

### P0 — Unauthenticated Attack Surface

Start here. Every finding on an unauthenticated route is critical regardless of vulnerability type.
```bash
# Cross-reference semgrep hits with unauthenticated routes from Step 2d
# Manually trace any controller method on a whitelisted/anon path
```

### P0 — Deserialization
```bash
rg "ObjectInputStream|readObject|readUnshared" /data/workspace/audit/decompiled
rg "rememberMe|SerializationUtils" /data/workspace/audit/decompiled
rg "JSON\.parseObject|@type|TypeReference" /data/workspace/audit/decompiled  # FastJSON
rg "XStream|fromXML" /data/workspace/audit/decompiled
rg "HessianInput|HessianOutput" /data/workspace/audit/decompiled
```

For confirmed deserialization sinks, check available Gadget chains against the dependency list from Step 2b. Use ysoserial to document usable payloads:
```bash
java -jar /data/tools/ysoserial-0.0.6/ysoserial.jar --help 2>&1 | grep -i "commons\|spring\|beanshell"
```

### P0 — File Operations
```bash
rg "new File\(|Paths\.get\|FileInputStream|FileOutputStream|MultipartFile" \
  /data/workspace/audit/decompiled

# Look for path traversal: user input concatenated into file path
rg "getOriginalFilename|getParameter.*[Ff]ile|filePath|fileName" \
  /data/workspace/audit/decompiled
```

Check:
- Upload: is file extension validated? Server-side or client-side only?
- Download/read: is path sanitized? Is `../` blocked?
- ZIP extraction: ZipSlip vulnerability (`entry.getName()` used directly)

### P0 — Command Execution
```bash
rg "Runtime\.exec|ProcessBuilder|getRuntime|exec\(" \
  /data/workspace/audit/decompiled

# Expression injection
rg "SpelExpressionParser|MVEL|GroovyShell|ScriptEngine|ognl\." \
  /data/workspace/audit/decompiled
```

### P1 — SSRF
```bash
rg "HttpURLConnection|OkHttpClient|RestTemplate|WebClient|HttpClient" \
  /data/workspace/audit/decompiled

# URL constructed from user input?
rg "getParameter|getHeader|getBody" /data/workspace/audit/decompiled -A3 \
  | grep -i "url\|uri\|host\|endpoint"
```

### P1 — SQL Injection
```bash
# MyBatis: ${ } is dangerous, #{ } is safe
rg '\$\{' /data/workspace/audit/decompiled

# Direct string concatenation in queries
rg "\"SELECT|\"INSERT|\"UPDATE|\"DELETE" /data/workspace/audit/decompiled \
  | grep "\+"
```

### P1 — Authentication & Authorization
```bash
# JWT
rg "none|HS256|secret|JWT|Jwts\." /data/workspace/audit/decompiled

# Check for weak/hardcoded JWT secret in configs (already done in Step 2c)

# Shiro bypass: check URL pattern matching rules
rg "\/\*\*|\/\*$" /data/workspace/audit/decompiled | grep -i "anon"
```

For authorization: check whether user-controlled IDs (order IDs, user IDs) are validated against session identity before data is returned.

### P1 — Known CVE Verification

If dangerous versions were identified in Step 2b, use dedicated scanners against the test URL (if provided):
```bash
# Spring Boot actuators + known CVEs
python3 /data/tools/web-SpringBoot-Scan/SpringBoot-Scan.py -u <TARGET_URL>

# Struts2
python3 /data/tools/web-strust2scan/struts2scan.py -u <TARGET_URL>
```

### P2 — Secondary Findings (after P0/P1 complete)

- Sensitive data exposure in API responses (passwords, tokens in JSON)
- Exception stack traces returned to client
- Horizontal privilege escalation (IDOR)
- Weak cryptography (MD5 for passwords, ECB mode, predictable IVs)
- CSRF on state-changing operations

---

## Step 5: Reporting

Write all findings to `/data/workspace/audit/report/audit_report.md`.

Record findings as discovered — do not wait until all audit steps are complete.

### Finding Template
```markdown
## [VULN-XXX] Title

| Field | Value |
|---|---|
| Severity | Critical / High / Medium / Low |
| Type | RCE / SQLi / SSRF / ... |
| Authentication Required | None / User / Admin |
| Affected Component | Class#method (file path) |

### Code Context
\```java
// ~20-40 lines showing the vulnerable code and surrounding context
\```

### Root Cause
One sentence: what is wrong and why it is exploitable.

### Attack Path
```
HTTP endpoint → Controller#method → Service#method → dangerous sink
```

### Request Template
\```http
POST /vulnerable/endpoint HTTP/1.1
Host: {{TARGET}}
Content-Type: application/json

{"param": "PAYLOAD_HERE"}
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
| Critical | RCE, deserialization with available gadget chain, auth bypass leading to admin |
| High     | SQLi, SSRF, file write/upload to webroot, JWT bypass         |
| Medium   | Path traversal (read-only), IDOR, sensitive data exposure    |
| Low      | Information disclosure, weak crypto, missing security headers |

### Deduplication Rule

For the same vulnerability class appearing in multiple locations (e.g., 3 different SQLi endpoints), document the 2-3 most impactful instances in full, then list the remaining locations in an appendix table.

---

## Execution Constraints

- Write reconnaissance summary to `recon.md` after Step 2 completes.
- Append each finding to `audit_report.md` as it is discovered.
- Do not stop to ask the user unless: source code is missing/incomplete for a critical path, or the audit is substantially complete and ready for review.
- If a test URL is provided: include a fully-formed HTTP request for each finding. Do not send requests automatically — output is for manual testing by the operator.
- For deserialization findings: document which ysoserial gadget chains are applicable based on the classpath.
- Do not report findings where Source → Sink reachability cannot be confirmed.