# Path Traversal / File Inclusion Detection Guide

## Quick Search Commands

### Java
```bash
# File operations
rg "new File\(|Paths\.get\(|FileInputStream|FileOutputStream|MultipartFile" --type java
rg "getOriginalFilename|getParameter.*[Ff]ile|filePath|fileName" --type java

# Path concatenation with user input
rg "new File\(" --type java -A3 | grep -iE 'request|param|input|header'

# ZIP extraction (ZipSlip)
rg "ZipEntry|entry\.getName|ZipInputStream" --type java
rg "entry\.getName" --type java -A5 | grep "new File\|Paths\.get"

# Download functionality
rg "sendFile|transferTo|StreamUtils\.copy|IOUtils\.copy" --type java -B5 \
  | grep -iE 'request|param'
```

### PHP
```bash
# File inclusion (LFI/RFI)
rg "include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\(" \
  --type php -g '!vendor' | grep -v "vendor\|autoload\|__DIR__\|dirname\|ABSPATH"
rg "include.*\\\$_(GET|POST|REQUEST|COOKIE)" --type php -g '!vendor'

# File read operations
rg "file_get_contents|readfile|fopen|SplFileObject|file\(" --type php -g '!vendor' -B3 \
  | grep -iE 'get|post|request|cookie|path|file|name'

# File deletion
rg "unlink\(|rmdir\(" --type php -g '!vendor' -B3 | grep '\$'

# ../ filter check (may be bypassable)
rg "str_replace.*\.\." --type php -g '!vendor'
rg "realpath\|basename" --type php -g '!vendor' -B3
```

### Python
```bash
rg "open\(|send_file|send_from_directory" --type py -B3 \
  | grep -iE 'request|input|param|args'

# os.path.join does not prevent absolute paths (e.g. /etc/passwd)
rg "os\.path\.join\(" --type py -B3 | grep -iE 'request|input|args'

# Django/Flask file handling
rg "FileResponse|HttpResponse.*open\|send_file" --type py -B5
```

### JavaScript / Node.js
```bash
rg "fs\.readFile|fs\.createReadStream|fs\.writeFile|fs\.unlink" --type js --type ts -B3 \
  | grep -iE 'req\.|request\.|params\.|query\.'
rg "path\.join|path\.resolve" --type js --type ts -B3 | grep -iE 'req\.|params\.'
rg "res\.sendFile|res\.download" --type js --type ts -B3
```

### Go
```bash
rg "os\.Open|ioutil\.ReadFile|os\.ReadFile|filepath\.Join" --type go -B3 \
  | grep -iE 'request|param|query'
rg "http\.ServeFile" --type go -B3
```

---

## Vulnerability Patterns

### Java -- HttpServlet
**Dangerous:**
```java
String image = request.getParameter("image");
File file = new File("static/images/", image);  // ../../../etc/passwd
```
**Safe:**
```java
File file = new File("static/images/", FilenameUtils.getName(image));
```

### PHP -- file inclusion
**Dangerous:**
```php
include($_GET["page"]);  // ../../etc/passwd or php://filter/convert.base64-encode/resource=index.php
```
**Safe:**
```php
include('templates/header.php');  // hardcoded path
```

### Python -- open()
**Dangerous:**
```python
filename = request.POST.get('filename')
f = open(filename, 'r')  # arbitrary file read
```

### Go -- filepath.Clean is insufficient
**Dangerous:**
```go
filename := filepath.Clean(r.URL.Path)  // Clean does not prevent absolute paths
filename = filepath.Join(root, strings.Trim(filename, "/"))
```
**Safe:**
```go
filename := path.Clean("/" + r.URL.Path)  // prefix "/" ensures relative path
```

---

## Audit Checklist

1. **Identify file operation sinks**: read / write / delete / include
2. **Trace path construction**: Does the path contain user input?
3. **Check filters**:
   - `str_replace("../", "")` is bypassable: `....//` becomes `../`
   - `basename()` / `FilenameUtils.getName()` is effective protection
   - `realpath()` + directory prefix check is the best practice
4. **Special techniques**:
   - PHP: `php://filter`, `phar://`, `data://` wrappers
   - Java: ZipSlip (`entry.getName()` containing `../`)
   - Python: `os.path.join("/safe", "/etc/passwd")` = `/etc/passwd` (absolute path override)
5. **Severity**:
   - Arbitrary file read/write = **High to Critical**
   - PHP file inclusion with code execution = **Critical** (LFI to RCE)
   - Limited to specific directory = **Medium**
