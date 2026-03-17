# Insecure Cryptography Detection Guide

## Quick Search Commands

### Universal (all languages)
```bash
# Weak hashing
rg -i "md5|sha1\b|sha-1" --type-not binary | grep -v "vendor\|node_modules\|\.git"

# Weak encryption
rg -i "\bdes\b|rc4|blowfish|ecb" --type-not binary | grep -iE 'cipher|encrypt|crypt'

# Weak random numbers
rg "Math\.random|random\.random\|rand\(\)|mt_rand" --type-not binary
```

### Java
```bash
rg 'getInstance\("MD5"\)|getInstance\("SHA-1"\)' --type java
rg 'getInstance\("DES|getInstance\("RC4|ECB' --type java
rg 'java\.util\.Random\b' --type java  # should use SecureRandom
```

### PHP
```bash
rg "md5\(|sha1\(" --type php -g '!vendor' | grep -iE 'password|passwd|pwd|token'
rg "mcrypt_|MCRYPT_" --type php -g '!vendor'  # deprecated
```

### Python
```bash
rg "hashlib\.md5|hashlib\.sha1" --type py | grep -iE 'password|passwd|secret|token'
rg "DES\.new\(|ARC4\.new\(|Blowfish\.new\(" --type py
rg "AES.*MODE_ECB" --type py
```

---

## Secure Alternatives Summary

| Weak Algorithm | Secure Replacement |
|----------------|-------------------|
| MD5 / SHA-1 (general hashing) | SHA-256 / SHA-512 |
| MD5 / SHA-1 (passwords) | bcrypt / scrypt / Argon2 |
| DES / 3DES / RC4 | AES-256 |
| ECB mode | GCM / CBC+HMAC / EAX |
| java.util.Random | java.security.SecureRandom |
| Math.random() | crypto.getRandomValues() |
| rand() / mt_rand() | random_bytes() / random_int() |

---

## Audit Checklist

1. **Password storage**: Is MD5/SHA1 used for passwords? (should use bcrypt/Argon2)
2. **Encryption mode**: Is ECB used? (each block encrypted independently, reveals plaintext patterns)
3. **Key length**: RSA < 2048 bits, AES < 128 bits = insecure
4. **Random numbers**: Are security-sensitive operations (token/nonce/IV) using a CSPRNG?
5. **Severity**: Passwords with MD5 = **High**, Encryption with ECB/DES = **High**, File checksum with MD5 = **Low** (non-security context)
