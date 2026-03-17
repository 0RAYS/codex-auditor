# XXE (XML External Entity) Detection Guide

## Quick Search Commands

### Java
```bash
rg "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory" --type java
rg "XMLReader|SAXReader|SAXBuilder|Digester" --type java

# Check whether external entities are disabled
rg "DocumentBuilderFactory" --type java -A10 | grep -v "disallow-doctype-decl\|FEATURE_SECURE_PROCESSING"
rg "SAXParserFactory" --type java -A10 | grep -v "disallow-doctype-decl"
rg "XMLInputFactory" --type java -A10 | grep -v "SUPPORT_DTD.*false\|IS_SUPPORTING_EXTERNAL_ENTITIES.*false"

# XPath injection (often coexists with XXE)
rg "XPathFactory|XPath\.compile|XPath\.evaluate" --type java
```

### PHP
```bash
rg "simplexml_load|DOMDocument|SimpleXMLElement|XMLReader|xml_parse" --type php -g '!vendor'
rg "simplexml_load|DOMDocument" --type php -g '!vendor' -A5 \
  | grep -v "libxml_disable_entity_loader\|LIBXML_NOENT"
# WARNING: LIBXML_NOENT actually ENABLES entity substitution, contrary to what many expect
rg "LIBXML_NOENT" --type php -g '!vendor'
```

### Python
```bash
rg "xml\.etree|xml\.dom|xml\.sax|xml\.parsers" --type py
rg "defusedxml" --type py  # if defusedxml is not imported, XXE may be possible
rg "lxml\.etree" --type py -A3 | grep -v "resolve_entities=False"
```

### JavaScript / Node.js
```bash
rg "libxmljs|xml2js|fast-xml-parser|DOMParser" --type js --type ts
rg "noent.*true|noent: true" --type js --type ts  # noent:true = entity substitution enabled = dangerous
```

### C#
```bash
rg "XmlReader|XmlDocument|XDocument|XmlTextReader" --type cs
rg "DtdProcessing\.Parse\|DtdProcessing\.Ignore" --type cs  # should use Prohibit
rg "ProhibitDtd.*false|XmlResolver" --type cs
```

---

## Vulnerability Patterns

### Java -- DocumentBuilderFactory
**Dangerous:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.newDocumentBuilder();  // allows DOCTYPE by default
```
**Safe:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.newDocumentBuilder();
```

### PHP -- LIBXML_NOENT trap
```php
// Many developers misuse LIBXML_NOENT, thinking it disables entities.
// It actually ENABLES entity substitution.
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);  // DANGEROUS
```
**Safe:**
```php
libxml_disable_entity_loader(true);  // PHP < 8.0
$xml = simplexml_load_string($data);
```

### Python
**Dangerous:**
```python
from xml.etree import ElementTree
tree = ElementTree.parse('data.xml')  # stdlib, may be vulnerable to XXE
```
**Safe:**
```python
from defusedxml.etree import ElementTree
tree = ElementTree.parse('data.xml')
```

---

## Audit Checklist

1. **Locate all XML parsing points**
2. **Check whether DTD / external entities are disabled**: disabling method varies per parser
3. **Is XML input user-controllable?**: POST body / file uploads / SOAP endpoints
4. **Exploitation vectors**: file read (`file:///etc/passwd`), SSRF (`http://internal/`), DoS (Billion Laughs)
5. **Severity**: File read = **High**, SSRF = **High**, Blind XXE + OOB = **High**
