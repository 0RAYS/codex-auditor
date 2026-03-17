# Unsafe Functions Detection Guide

## Quick Search Commands

### C / C++
```bash
rg "\bgets\(|strcpy\(|strcat\(|sprintf\(|scanf\(" --type c --type cpp
rg "\bstrncpy\(|strncat\(" --type c --type cpp  # bounded but still error-prone
```

### PHP
```bash
rg "mcrypt_|MCRYPT_|mdecrypt_generic" --type php -g '!vendor'  # deprecated crypto
rg "phpinfo\(\)|var_dump\(|print_r\(" --type php -g '!vendor'  # info disclosure
rg "display_errors\s*=\s*On|error_reporting.*E_ALL" --type php -g '!vendor'
rg "mysql_query\(|mysql_connect\(" --type php -g '!vendor'  # deprecated, use mysqli/PDO
```

### Python
```bash
rg "tempfile\.mktemp\(" --type py  # race condition, use mkstemp/NamedTemporaryFile
```

### Go
```bash
rg '"unsafe"' --type go | grep "import"  # unsafe package bypasses type safety
```

---

## C/C++ Dangerous Function Replacements

| Dangerous | Risk | Safe Alternative |
|-----------|------|-----------------|
| `gets()` | No bounds check | `fgets()` / `gets_s()` |
| `strcpy()` | Buffer overflow | `strcpy_s()` / `strncpy()` |
| `strcat()` | Buffer overflow | `strcat_s()` / `strncat()` |
| `sprintf()` | Buffer overflow | `snprintf()` |
| `scanf("%s")` | Buffer overflow | `fgets()` + `sscanf()` |
| `strtok()` | Modifies buffer, not thread-safe | `strtok_r()` |

## PHP Deprecated Function Replacements

| Dangerous | Safe Alternative |
|-----------|-----------------|
| `mcrypt_*` | `openssl_encrypt` / `sodium_*` |
| `mysql_*` | `mysqli_*` / `PDO` |
| `ereg()` | `preg_match()` |
| `create_function()` | Anonymous functions `function() {}` |

---

## Audit Checklist

1. **C/C++**: Focus on string operations without bounds checking
2. **PHP**: Watch for deprecated functions and info-disclosure functions left in production (phpinfo/var_dump)
3. **Severity**: C/C++ buffer overflow = **Critical** (potential RCE), PHP deprecated crypto = **High**, info disclosure = **Low to Medium**
