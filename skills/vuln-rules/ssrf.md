# SSRF (Server-Side Request Forgery) Detection Guide

## Quick Search Commands

### Java
```bash
rg "HttpURLConnection|OkHttpClient|RestTemplate|WebClient|HttpClient|URLConnection" --type java
rg "new URL\(" --type java -B3 | grep -iE 'request|param|input|header'
rg "openConnection|openStream" --type java -B5 | grep -iE 'request|param'
rg "restTemplate\.(getForObject|postForObject|exchange)\(" --type java -B3
rg "webClient\.get\(\)|webClient\.post\(\)" --type java -B5
```

### PHP
```bash
rg "curl_init|file_get_contents|fsockopen|SoapClient|fopen" --type php -g '!vendor' -B3 \
  | grep -iE 'get|post|request|cookie|url|uri'
rg "curl_setopt.*CURLOPT_URL" --type php -g '!vendor' -B5
rg "guzzle\|Http::get\|Http::post" --type php -g '!vendor' -B3
```

### Python
```bash
rg "requests\.(get|post|put|delete|head|patch)\(" --type py -B3 \
  | grep -iE 'request|input|args|form|param'
rg "urllib\.request\.urlopen|urllib2\.urlopen|httplib|http\.client" --type py -B3
rg "aiohttp\.ClientSession" --type py -B5
```

### JavaScript / Node.js
```bash
rg "axios\.(get|post)|fetch\(|http\.request|https\.request" --type js --type ts -B3 \
  | grep -iE 'req\.|request\.|params\.|query\.|body\.'
```

### Go
```bash
rg "http\.Get\(|http\.Post\(|http\.NewRequest\(" --type go -B3 \
  | grep -iE 'request|param|query|FormValue'
```

---

## Vulnerability Patterns

**Dangerous -- user controls URL host:**
```python
host = request.POST.get('host')
response = requests.get(f"https://{host}/api/users/{user_id}")
```
**Safe -- fixed host:**
```python
response = requests.get(f"https://api.example.com/users/{user_id}")
```

---

## Audit Checklist

1. **Locate HTTP request sinks**: All libraries and functions that issue HTTP requests
2. **Which part of the URL is user-controllable?**: host = most dangerous, path = moderate, query = lower risk
3. **Check filters**: URL allowlist? Protocol check (http/https only)? Internal IP filtering (127.0.0.1, 10.x, 172.16-31.x, 169.254.169.254)? DNS rebinding bypass?
4. **Cloud risk**: `http://169.254.169.254/latest/meta-data/` (AWS/GCP/Azure metadata endpoint)
5. **Severity**: Can reach internal/metadata = **High to Critical**, external only = **Medium**
