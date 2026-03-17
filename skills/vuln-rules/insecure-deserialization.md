# Insecure Deserialization Detection Guide

## Quick Search Commands

### Java
```bash
# Native deserialization
rg "ObjectInputStream|readObject|readUnshared" --type java
rg "rememberMe|SerializationUtils" --type java

# FastJSON (autoType RCE)
rg "JSON\.parseObject|@type|TypeReference" --type java
rg "ParserConfig|autoTypeSupport" --type java

# XStream
rg "XStream|fromXML|toXML" --type java

# Hessian
rg "HessianInput|HessianOutput|Hessian2Input" --type java

# SnakeYAML
rg "Yaml\(\)|new Yaml|yaml\.load" --type java

# Check available gadget chains against classpath
unzip -l <target.jar> | grep -iE "commons-collections|commons-beanutils|spring-core|c3p0|rome|bcel"
java -jar /data/tools/ysoserial-0.0.6/ysoserial.jar --help 2>&1 | head -30
```

### PHP
```bash
# unserialize
rg "unserialize\s*\(" --type php -g '!vendor'
rg "unserialize" --type php -g '!vendor' -B5 | grep -iE 'get|post|request|cookie|input|base64'

# phar deserialization (phar:// wrapper triggers __destruct)
rg "phar://|Phar\(" --type php -g '!vendor'
rg "file_exists|is_dir|is_file|filesize|file_get_contents" --type php -g '!vendor' -B3 \
  | grep -iE 'get|post|request|cookie'

# Available POP chain magic methods
rg "__destruct|__wakeup|__toString|__call" --type php -g '!vendor'
```

### Python
```bash
# pickle / shelve / marshal
rg "pickle\.loads|pickle\.load|shelve\.open|marshal\.loads" --type py
rg "pickle" --type py -B5 | grep -iE 'request|input|argv|stdin|socket|b64decode'

# PyYAML unsafe load
rg "yaml\.load\(" --type py | grep -v "Loader=SafeLoader\|safe_load"
rg "yaml\.unsafe_load\|yaml\.full_load" --type py

# jsonpickle
rg "jsonpickle\.decode\|jsonpickle\.loads" --type py
```

### JavaScript / Node.js
```bash
rg "node-serialize|serialize\.unserialize" --type js --type ts
rg "yaml\.load\(" --type js --type ts | grep -v "safeLoad\|SAFE_SCHEMA"
```

### Ruby
```bash
rg "Marshal\.load\|Marshal\.restore" --type ruby
rg "YAML\.load\b" --type ruby | grep -v "safe_load\|YAML\.safe_load"
```

### C#
```bash
rg "BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter" --type cs
rg "TypeNameHandling" --type cs | grep -v "None"
rg "NetDataContractSerializer|XmlSerializer" --type cs -B3
```

---

## Vulnerability Patterns

### Java -- ObjectInputStream
**Dangerous:**
```java
ObjectInputStream in = new ObjectInputStream(receivedData);
return in.readObject();  // gadget chain in classpath leads to RCE
```
**Safe:**
```java
ObjectMapper mapper = new ObjectMapper();
return mapper.readValue(data, MyClass.class);  // type-safe
```

### PHP -- unserialize / phar
**Dangerous:**
```php
$object = unserialize($_GET["data"]);  // __destruct/__wakeup POP chain leads to RCE

file_exists($_GET['path']);  // phar:///tmp/evil.phar triggers deserialization
```
**Safe:**
```php
$object = json_decode($_GET["data"], true);
```

### Python -- pickle
**Dangerous:**
```python
data = pickle.loads(b64decode(user_obj))  # __reduce__ executes arbitrary code
```
**Safe:**
```python
user_data = json.loads(request.data)
```

### Ruby -- Marshal / YAML
**Dangerous:**
```ruby
obj = Marshal.load(params['data'])
config = YAML.load(params['yaml'])  # YAML.load instantiates arbitrary Ruby objects
```
**Safe:**
```ruby
config = YAML.safe_load(params['yaml'])
data = JSON.parse(params['data'])
```

### C# -- BinaryFormatter
**Dangerous:**
```csharp
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);  // marked dangerous by Microsoft
```
**Safe:**
```csharp
return JsonSerializer.Deserialize<MyClass>(json);
```

---

## Audit Checklist

1. **Input source**: Is the deserialized data user-controllable? (HTTP params/cookies/uploads/message queues)
2. **Signature verification**: Is there HMAC/encryption protection? (leaked key = still exploitable; check Step 2c configs)
3. **Gadget chain availability**:
   - Java: cross-reference ysoserial `--help` output with dependency list
   - PHP: search for `__destruct` / `__wakeup` POP chains
   - Python: pickle is inherently RCE-capable, no gadget chain needed
4. **Severity**:
   - User-controllable + gadget chain available = **Critical (RCE)**
   - User-controllable + no known gadget = **High** (future dependency changes may introduce one)
   - Non-controllable input (e.g. local file) = note but downgrade
