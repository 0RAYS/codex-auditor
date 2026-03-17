# Code Injection / SSTI Detection Guide

## Quick Search Commands

### Java
```bash
# ScriptEngine (Nashorn / GraalJS)
rg "ScriptEngine|getEngineByExtension|getEngineByName|\.eval\(" --type java
rg "ScriptEngine" --type java -A5 | grep -iE 'request|param|input|header|\+'

# SpEL expression injection
rg "SpelExpressionParser|parseExpression|EvaluationContext" --type java
rg "StandardEvaluationContext" --type java -A10 | grep -iE 'request|param'

# OGNL (Struts2)
rg "ognl\.Ognl|OgnlUtil|ActionContext|ValueStack" --type java

# Groovy
rg "GroovyShell|GroovyClassLoader|GroovyScriptEngine|Eval\.me" --type java

# EL injection
rg "ELProcessor|createValueExpression|evaluateValueExpression" --type java
```

### PHP
```bash
# eval / assert / create_function
rg "eval\s*\(|assert\s*\(|create_function\s*\(" --type php -g '!vendor'

# preg_replace /e modifier (PHP < 7.0)
rg 'preg_replace.*\/.*e["\x27]' --type php -g '!vendor'

# SSTI -- template engines
rg "Twig.*render\(|Smarty.*display\(|Blade.*render" --type php -g '!vendor' -B5 \
  | grep -iE '\$_GET|\$_POST|\$_REQUEST'

# Dynamic function calls
rg '\$[a-zA-Z_]+\s*\(' --type php -g '!vendor' | grep -iE 'get|post|request'
```

### Python
```bash
# eval / exec
rg "eval\s*\(|exec\s*\(" --type py
rg "eval\|exec" --type py -B3 | grep -iE 'request|input|argv|param'

# SSTI (Jinja2 / Mako / Django)
rg "render_template_string|Template\(.*request|render_string" --type py
rg "from_string\(" --type py -B3 | grep -iE 'request|input'

# compile + exec
rg "compile\(.*exec\|compile\(.*eval" --type py
```

### JavaScript / Node.js
```bash
# eval / Function constructor
rg "eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(.*," --type js --type ts
rg "eval\(" --type js --type ts -B3 | grep -iE 'req\.|request\.|body\.|query\.'

# vm module
rg "vm\.runIn|vm\.createScript|vm\.compileFunction" --type js --type ts

# SSTI (EJS / Pug / Nunjucks)
rg "ejs\.render\(|pug\.render\(|nunjucks.*renderString" --type js --type ts -B3
```

---

## Vulnerability Patterns

### Python -- eval
**Dangerous:**
```python
code = request.POST.get('code')
eval(code)  # arbitrary Python code execution
```

### Python -- SSTI (Jinja2)
**Dangerous:**
```python
template = Template(request.args.get('tpl'))  # {{config}} / {{''.__class__...}} leads to RCE
```
**Safe:**
```python
return render_template('page.html', name=request.args.get('name'))  # user input as variable, not template
```

### Java -- ScriptEngine
**Dangerous:**
```java
ScriptEngine se = sem.getEngineByExtension("js");
Object result = se.eval("test=1;" + userInput);  # JS code injection
```

### PHP -- eval / dynamic function
**Dangerous:**
```php
eval($user_input);
$func = $_GET['f']; $func();  # equivalent to eval
```
**Safe:**
```php
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));
```

---

## Audit Checklist

1. **Distinguish code injection from command injection**: eval/exec runs application-language code; system/exec runs OS commands
2. **SSTI focus**: Is user input used as **template content** (dangerous) vs **template variable** (safe)?
3. **Java expression engines**: SpEL / OGNL / MVEL / EL can all call Runtime.exec() -- do not overlook
4. **PHP dynamic functions**: `$func = $_GET['f']; $func();` is equivalent to eval
5. **Severity**: Code injection = **Critical** (direct RCE)
