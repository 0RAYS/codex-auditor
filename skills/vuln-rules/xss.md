# XSS (Cross-Site Scripting) Detection Guide

## Quick Search Commands

### Java
```bash
rg "getWriter\(\)\.write|getWriter\(\)\.print|getOutputStream" --type java -B5 \
  | grep -iE 'getParameter|getHeader|getCookie'
rg '<%= ' -g '*.jsp' | grep -v 'encode\|escape\|ESAPI'
rg "@ResponseBody" --type java -A10 | grep -iE 'request\.|param\.'
```

### PHP
```bash
rg "echo\s+\\\$_|print\s+\\\$_|echo.*\\\$_(GET|POST|REQUEST)" --type php -g '!vendor'
rg "echo.*\\\$|print.*\\\$" --type php -g '!vendor' | grep -v 'htmlspecialchars\|htmlentities\|strip_tags'
rg '{!!.*\$|{!!.*request' -g '*.blade.php'  # {!! !!} unescaped, {{ }} escaped
```

### Python
```bash
rg "make_response\(|Response\(" --type py -B3 | grep -iE 'request|args|form'
rg "render_template_string" --type py
rg "HttpResponse\(" --type py -B3 | grep -iE 'request\.'
rg "mark_safe\(|safe\b" --type py -g '*.py' -g '*.html'
```

### JavaScript / Node.js
```bash
rg "innerHTML|outerHTML|document\.write|insertAdjacentHTML" --type js --type ts
rg "res\.send\(|res\.write\(" --type js --type ts -B3 | grep -iE 'req\.\|params\.\|query\.'
rg "dangerouslySetInnerHTML" --type js --type ts --type jsx --type tsx
```

### Go
```bash
rg "fmt\.Fprintf.*http\.ResponseWriter|w\.Write\(" --type go -B3 \
  | grep -iE 'request\.|FormValue\|URL\.Query'
rg "text/template" --type go  # text/template does not escape; html/template does
```

---

## Vulnerability Patterns

### Java -- Servlet
**Dangerous:**
```java
String name = req.getParameter("name");
resp.getWriter().write("<h1>Hello " + name + "</h1>");
```
**Safe:**
```java
resp.getWriter().write("<h1>Hello " + Encode.forHtml(name) + "</h1>");
```

### PHP
**Dangerous:**
```php
echo "Hello: " . $_REQUEST['name'];
```
**Safe:**
```php
echo "Hello: " . htmlspecialchars($_REQUEST['name'], ENT_QUOTES, 'UTF-8');
```

### Python -- Flask
**Dangerous:**
```python
return make_response(f"Results for: {query}")
```
**Safe:**
```python
from markupsafe import escape
return make_response(f"Results for: {escape(query)}")
```

---

## Audit Checklist

1. **Locate output points**: Responses that directly include user input
2. **Check encoding**: HTML entity encoding / JS encoding / URL encoding present?
3. **Framework auto-escaping**:
   - Django/Jinja2 templates escape by default (but `|safe` / `mark_safe` bypasses it)
   - Laravel Blade `{{ }}` escapes, `{!! !!}` does not
   - React JSX escapes by default (but `dangerouslySetInnerHTML` bypasses it)
4. **Stored vs reflected**: Stored XSS is higher severity
5. **Severity**: Reflected = **Medium to High**, Stored = **High to Critical**
