# Race Condition / TOCTOU Detection Guide

## Quick Search Commands

### Universal
```bash
rg "os\.path\.exists|os\.access|File\.exists|file_exists" --type-not binary -A3 \
  | grep -iE 'open|read|write|delete|unlink|remove'
rg "mktemp\(|/tmp/" --type-not binary
```

### Python
```bash
rg "tempfile\.mktemp\(" --type py
rg "open.*['\"/]tmp/" --type py
rg "os\.path\.exists\(" --type py -A3 | grep "open\|os\."
```

### Go
```bash
rg 'ioutil\.WriteFile.*"/tmp/|os\.WriteFile.*"/tmp/' --type go
rg "os\.Stat\(" --type go -A3 | grep "os\.Open\|os\.Create"
```

### Java
```bash
rg "File\.createTempFile\(" --type java -A5
rg "\.exists\(\)" --type java -A3 | grep "new FileOutputStream\|new FileWriter"
```

---

## Secure Alternatives

| Language | Insecure | Safe Alternative |
|----------|----------|-----------------|
| Python | `tempfile.mktemp()` | `tempfile.NamedTemporaryFile()` / `tempfile.mkstemp()` |
| Python | `open("/tmp/fixed.txt")` | `tempfile.NamedTemporaryFile(dir=...)` |
| Go | `ioutil.WriteFile("/tmp/...")` | `os.CreateTemp()` |
| Java | `File.createTempFile()` then open | `Files.createTempFile()` with immediate use |
| C | `tmpnam()` / `tempnam()` | `mkstemp()` |

---

## Audit Checklist

1. **TOCTOU**: Is there a window between checking file existence and operating on the file?
2. **Temporary files**: Are predictable filenames used? Are they in a shared /tmp directory?
3. **Concurrent operations**: Are database operations protected by transactions? (e.g. balance/inventory deductions)
4. **File locking**: Do multiple processes writing to the same file use a locking mechanism?
5. **Severity**: TOCTOU with privilege escalation = **Medium to High**, temp file race = **Medium**
