# JWT Authentication Flaws Detection Guide

## Quick Search Commands

### Universal
```bash
rg -i "jwt|jsonwebtoken|jose|nimbus|java-jwt|pyjwt" --type-not binary
rg -i '"none"|alg.*none|algorithm.*none' --type-not binary
```

### Java
```bash
rg "JWT\.decode\(|JWT\.require\|JWTVerifier" --type java
# decode does NOT verify signature; verify does -- confirm verify is used
rg "JWT\.decode\(" --type java -A5 | grep -v "verify\|require"
rg "Jwts\.parser|Jwts\.parserBuilder" --type java -A5
rg "setSigningKey" --type java
```

### Python
```bash
rg "jwt\.decode\(" --type py -A3
rg "verify_signature.*False|verify.*False|options.*verify" --type py
rg "algorithms=\[" --type py
```

### JavaScript / Node.js
```bash
rg "jwt\.decode\(|jwt\.verify\(" --type js --type ts
# decode does NOT verify -- if decode is used for auth decisions, it is vulnerable
rg "jwt\.decode\(" --type js --type ts -A5 | grep -iE 'admin|role|user|auth|permission'
rg "express-jwt|expressJwt" --type js --type ts -A5 | grep "secret"
```

---

## Vulnerability Patterns

### JavaScript -- decode vs verify
**Dangerous:**
```javascript
const decoded = jwt.decode(token, true);  // does NOT verify signature
if (decoded.isAdmin) { return getAdminData(); }
```
**Safe:**
```javascript
jwt.verify(token, secretKey);  // verify signature first
const decoded = jwt.decode(token, true);
```

### Python -- signature verification disabled
**Dangerous:** `jwt.decode(token, key, options={"verify_signature": False})`
**Safe:** `jwt.decode(token, key, algorithms=["HS256"])`

### Java -- JWT.decode does not verify
**Dangerous:** `DecodedJWT jwt = JWT.decode(token);`
**Safe:** `JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret)).build(); verifier.verify(token);`

---

## Audit Checklist

1. **decode vs verify**: Many libraries have `decode()` that skips verification; only `verify()` validates
2. **none algorithm**: Does the application accept tokens with `alg: none`?
3. **Weak secret**: Is the HS256 secret hardcoded or guessable? (can be brute-forced with hashcat/jwt_tool)
4. **Algorithm confusion**: RS256 to HS256 attack (using public key as HMAC secret)
5. **Expiration check**: Is the `exp` field validated?
6. **Severity**: Can forge tokens = **Critical**, weak brute-forceable secret = **High**
