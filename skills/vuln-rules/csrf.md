# CSRF (Cross-Site Request Forgery) Detection Guide

## Quick Search Commands

### Java (Spring)
```bash
rg "csrf\(\)\.disable\(\)|csrf\.disable" --type java
rg "CsrfConfigurer|csrfTokenRepository" --type java
rg "@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping" --type java -A10 \
  | grep -v "csrf\|CsrfToken"
```

### PHP
```bash
# Laravel -- VerifyCsrfToken exclusion list
rg "VerifyCsrfToken|\\\$except" --type php -g '!vendor' -A10
rg "csrf_token|_token|anti_csrf" --type php -g '!vendor'
```

### Python (Django)
```bash
rg "@csrf_exempt" --type py
rg "CsrfViewMiddleware" --type py | grep -i "comment\|#\|remove"
rg "CSRFProtect\|csrf\.init_app\|WTF_CSRF" --type py
```

### JavaScript / Express
```bash
rg "csurf|csrf|csrfProtection" --type js --type ts
rg "Access-Control-Allow-Origin.*\*|cors\(\)" --type js --type ts
```

---

## Vulnerability Patterns

### Django -- @csrf_exempt
**Dangerous:** `@csrf_exempt` on a state-changing view disables CSRF protection.

### Spring -- csrf().disable()
**Dangerous:** `http.csrf().disable()` globally disables CSRF protection.

### Express -- missing CSRF middleware
**Dangerous:** POST routes without csurf middleware have no CSRF token validation.

---

## Audit Checklist

1. **Framework defaults**: Django/Spring enable CSRF by default -- check whether it is disabled
2. **Only state-changing operations matter**: GET requests do not need CSRF protection
3. **API endpoints**: Pure APIs with Bearer token auth generally do not need CSRF; cookie-based auth does
4. **SameSite cookie**: If cookies have SameSite=Strict/Lax, CSRF risk is reduced
5. **Severity**: Involves fund transfers / password changes = **High**, general data operations = **Medium**
