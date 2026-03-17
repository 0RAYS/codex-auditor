# Hardcoded Secrets Detection Guide

## Quick Search Commands

### Universal (all languages)
```bash
# High-frequency keywords
rg -i "password\s*=\s*['\"]|passwd\s*=\s*['\"]|secret\s*=\s*['\"]" --type-not binary
rg -i "api_key\s*=\s*['\"]|apikey\s*=\s*['\"]|access_key\s*=\s*['\"]" --type-not binary
rg -i "token\s*=\s*['\"].*[a-zA-Z0-9]{16}" --type-not binary

# AWS credentials
rg "AKIA[0-9A-Z]{16}" --type-not binary
rg -i "aws_secret_access_key|aws_access_key_id" --type-not binary

# Private keys
rg "BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY" --type-not binary

# JWT secret
rg -i "jwt.*secret|sign.*secret|HS256.*secret" --type-not binary

# Database connection strings
rg "mysql://|postgres://|mongodb://|redis://|jdbc:" --type-not binary | grep -iE 'password|passwd|pwd'

# GitHub / GitLab tokens
rg "ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9]{20}" --type-not binary
```

### Configuration files
```bash
find . -name ".env" -o -name ".env.*" -o -name "*.properties" \
  -o -name "*.yml" -o -name "*.yaml" -o -name "config.php" \
  | grep -v vendor | grep -v node_modules | xargs cat 2>/dev/null

# Spring Boot
rg "spring\.datasource\.password|spring\.redis\.password|spring\.mail\.password" -g '*.properties' -g '*.yml'

# Laravel
rg "APP_KEY=|DB_PASSWORD=|MAIL_PASSWORD=|AWS_" -g '.env*'

# Django
rg "SECRET_KEY\s*=\s*['\"]" --type py
```

---

## Vulnerability Patterns

### Python -- Flask SECRET_KEY
**Dangerous:** `app.config["SECRET_KEY"] = '_5#y2L"F4Q8z'`
**Safe:** `app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]`

### JavaScript -- JWT secret
**Dangerous:** `jwt.sign(payload, 'my-secret-key')`
**Safe:** `jwt.sign(payload, process.env.JWT_SECRET)`

### Python -- AWS credentials
**Dangerous:** `boto3.resource("s3", aws_access_key_id="AKIAxxxx", aws_secret_access_key="jWnyxxxx")`
**Safe:** `boto3.resource("s3", aws_access_key_id=os.environ.get("ACCESS_KEY_ID"), ...)`

---

## Audit Checklist

1. **Scan all configuration files**: .env / properties / yml / xml / config.php
2. **Distinguish real credentials from examples**: `password=changeme` may be a placeholder, but may also be a production leftover
3. **High-value targets**:
   - `APP_KEY` / `SECRET_KEY` leak = can forge signed cookies/sessions
   - Database passwords = direct data breach if network-reachable
   - JWT secret = can forge arbitrary user tokens
4. **Git history**: `git log --all --diff-filter=D -- '*.env'` to check whether secret files were deleted
5. **Severity**: Hardcoded credentials = **Critical** (especially for reachable external services)
