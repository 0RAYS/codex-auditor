# SQL Injection Detection Guide

## Quick Search Commands

### Java
```bash
# MyBatis: ${} is dangerous, #{} is safe
rg '\$\{' --type xml --type java
rg '\$\{' -g '*.xml' | grep -v '#{'

# JDBC string concatenation
rg '"SELECT|"INSERT|"UPDATE|"DELETE' --type java | grep "\+"
rg 'String\.format.*SELECT|String\.format.*INSERT' --type java

# Raw Statement (should use PreparedStatement)
rg 'createStatement|\.execute\(' --type java | grep -v 'prepareStatement'

# JPA / Hibernate native queries
rg 'createNativeQuery|createQuery.*\+' --type java

# Spring JdbcTemplate
rg 'jdbcTemplate\.(query|update|execute)' --type java -A3 | grep "\+"
```

### PHP
```bash
# Direct variable concatenation into SQL
rg 'mysql_query|mysqli_query|->query|->execute|PDO::query' --type php -g '!vendor' -B5 | grep '\$'
rg '\$_(GET|POST|REQUEST|COOKIE)\[' --type php -g '!vendor' -A3 | grep -i 'query\|sql\|select\|where'

# String interpolation
rg '"SELECT.*\$|"INSERT.*\$|"UPDATE.*\$|"DELETE.*\$' --type php -g '!vendor'

# Laravel raw queries
rg 'DB::raw|whereRaw|selectRaw|orderByRaw|groupByRaw|havingRaw' --type php -g '!vendor'

# ThinkPHP
rg '->where\(.*\$|->field\(.*\$' --type php -g '!vendor'
```

### Python
```bash
# String concatenation/formatting into SQL
rg 'execute\(.*format|execute\(.*%|execute\(f"' --type py
rg 'cursor\.(execute|executemany)\(' --type py -B3 | grep -v '%s\|?\|:param\|:1'

# Django ORM bypass
rg 'raw\(|extra\(|RawSQL|connection\.cursor' --type py

# SQLAlchemy text()
rg 'text\(.*\+|text\(f"|text\(.*format' --type py
```

### JavaScript / Node.js
```bash
# Template literal concatenation
rg 'query\(`.*\$\{|query\(".*\+' --type js --type ts

# Sequelize raw queries
rg 'sequelize\.query\(' --type js --type ts -A2 | grep -v 'replacements\|bind'

# Knex raw
rg 'knex\.raw\(|\.whereRaw\(' --type js --type ts
```

### Go
```bash
rg 'fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT' --type go
rg '\.Query\(.*\+|\.Exec\(.*\+' --type go
```

---

## Vulnerability Patterns

### Python (psycopg2)

**Dangerous -- string concatenation:**
```python
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
cur.execute(query)
```

**Dangerous -- format / f-string:**
```python
cur.execute("SELECT * FROM users WHERE id = {}".format(user_input))
cur.execute(f"SELECT * FROM users WHERE id = {user_input}")
```

**Safe -- parameterized query:**
```python
cur.execute("SELECT * FROM users WHERE name = %s", [user_input])
```

### Java (JDBC)

**Dangerous -- Statement + string concatenation:**
```java
Statement stmt = connection.createStatement();
String sql = "SELECT * FROM users WHERE name = '" + input + "'";
return stmt.executeQuery(sql);
```

**Safe -- PreparedStatement:**
```java
PreparedStatement pstmt = connection.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
pstmt.setString(1, input);
return pstmt.executeQuery();
```

### PHP

**Dangerous -- direct variable interpolation:**
```php
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$sql = "SELECT * FROM users WHERE name = '$name'";
```

**Safe -- PDO prepared statement:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$name]);
```

### JavaScript / Node.js (pg)

**Dangerous -- template literal:**
```javascript
const sql = `SELECT * FROM users WHERE id = ${userId}`;
const { rows } = await pool.query(sql);
```

**Safe -- parameterized:**
```javascript
const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
```

### Go

**Dangerous -- fmt.Sprintf:**
```go
query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
db.Query(query)
```

**Safe -- parameterized:**
```go
db.Query("SELECT * FROM users WHERE name = $1", userInput)
```

---

## Audit Checklist

1. **Locate sinks**: Find all SQL execution points (execute/query/...)
2. **Trace source**: Does the SQL string contain user-controllable input?
3. **Check handling**: Is parameterization/prepared statements used, or string concatenation?
4. **Framework-specific cases**:
   - MyBatis `${}` = dangerous, `#{}` = safe
   - Django `raw()` / `extra()` = check whether parameters are bound
   - Laravel `DB::raw()` = check whether user input is concatenated inside
5. **Severity**:
   - Unauthenticated + injectable = **Critical**
   - Authenticated + injectable = **High**
   - ORDER BY / LIMIT injection only = **Medium** (usually no UNION, but blind SQLi possible)
