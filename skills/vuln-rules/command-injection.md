# Command Injection Detection Guide

## Quick Search Commands

### Java
```bash
rg "Runtime\.exec|ProcessBuilder|getRuntime\(\)\.exec" --type java
rg 'new ProcessBuilder\(' --type java -A5 | grep -iE 'request|param|input|header'

# Expression injection (SpEL / OGNL / MVEL / Groovy)
rg "SpelExpressionParser|parseExpression|MVEL|GroovyShell|ScriptEngine|ognl\." --type java
rg "EvaluationContext|StandardEvaluationContext" --type java
```

### PHP
```bash
# System command execution
rg "system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(" \
  --type php -g '!vendor'

# Backtick execution
rg '`.*\$' --type php -g '!vendor'

# Check for escapeshellarg/escapeshellcmd protection
rg "system\|exec\|shell_exec\|passthru" --type php -g '!vendor' -B5 \
  | grep -v 'escapeshellarg\|escapeshellcmd'
```

### Python
```bash
rg "subprocess\.(call|run|Popen|check_output)\(" --type py -A3 | grep "shell=True"
rg "os\.system\(|os\.popen\(" --type py
rg "subprocess|os\.system|os\.popen" --type py -B5 | grep -iE 'request|input|argv|param'
```

### JavaScript / Node.js
```bash
rg "child_process|exec\(|execSync\(|spawn\(" --type js --type ts
rg "exec\(" --type js --type ts -B3 | grep -iE 'req\.|request\.|params\.|query\.'
```

### Go
```bash
rg "exec\.Command\(" --type go -A5 | grep -iE 'request|param|input|query'
rg 'exec\.Command\("bash"|exec\.Command\("sh"' --type go
```

---

## Vulnerability Patterns

### Python
**Dangerous -- shell=True with user input:**
```python
ip = flask.request.args.get("ip")
subprocess.run("ping " + ip, shell=True)  # ; rm -rf / injectable
```
**Safe -- array arguments, no shell:**
```python
subprocess.run(["ping", ip])  # argument isolation, no shell metachar injection
```

### Java
**Dangerous -- user input passed to bash -c:**
```java
String[] cmd = {"/bin/bash", "-c", userInput};
new ProcessBuilder(cmd).start();
```
**Safe -- array arguments, no shell:**
```java
new ProcessBuilder("cat", filename).start();
```

### PHP
**Dangerous -- unescaped user input:**
```php
$username = $_COOKIE['username'];
exec("wto -n \"$username\" -g", $ret);
```
**Safe -- escapeshellarg:**
```php
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));
```

### JavaScript / Node.js
**Dangerous -- exec with template literal:**
```javascript
exec(`cat ${userInput}`, (error, stdout) => { ... });
```
**Safe -- spawn with array arguments:**
```javascript
const proc = spawn('cat', [userInput]);
```

---

## Audit Checklist

1. **Locate sinks**: Find all command execution functions
2. **Check shell usage**: Is a shell involved? (shell=True / bash -c / backticks)
3. **Trace source**: Do arguments contain user-controllable input?
4. **Check filtering**: Is escapeshellarg / shlex.quote or equivalent in place?
5. **Expression injection**: SpEL/OGNL/MVEL are often overlooked but can execute system commands
6. **Severity**: Command injection is almost always **Critical** (direct RCE)
