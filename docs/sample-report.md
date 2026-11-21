# secretscan Report

- **Target:** `demo`
- **Scanned:** 2026-11-21T01:58:20+00:00 UTC (0.003s)
- **Files scanned:** 4 (skipped 0)
- **Total findings:** 29

## Summary

| Severity | Count |
|----------|------:|
| CRITICAL | 4 |
| HIGH | 15 |
| MEDIUM | 6 |
| LOW | 3 |
| INFO | 1 |

Secrets: 9 · Code issues: 20

## Findings

| Severity | Rule | Location | Issue |
|----------|------|----------|-------|
| CRITICAL | SEC002 | `config.py:3` | AWS secret access key |
| CRITICAL | SEC008 | `deploy.sh:4` | Stripe live secret key |
| CRITICAL | SEC006 | `deploy.sh:5` | GitHub token |
| CRITICAL | SEC005 | `id_rsa_demo:1` | Private key block |
| HIGH | SEC010 | `app.py:24` | Credentials in URL |
| HIGH | PY007 | `app.py:37` | SQL built with string formatting |
| HIGH | PY007 | `app.py:38` | SQL built with string formatting |
| HIGH | PY007 | `app.py:39` | SQL built with string formatting |
| HIGH | PY007 | `app.py:40` | SQL built with string formatting |
| HIGH | PY007 | `app.py:42` | SQL built with string formatting |
| HIGH | PY001 | `app.py:50` | Use of eval() |
| HIGH | PY005 | `app.py:55` | subprocess with shell=True |
| HIGH | PY003 | `app.py:61` | Unsafe deserialization (pickle/marshal/shelve) |
| HIGH | PY004 | `app.py:65` | yaml.load without a safe loader |
| HIGH | PY009 | `app.py:77` | TLS certificate verification disabled |
| HIGH | PY002 | `app.py:91` | Use of exec() |
| HIGH | SEC001 | `config.py:2` | AWS access key ID |
| HIGH | SEC003 | `config.py:4` | Google API key |
| HIGH | SEC007 | `deploy.sh:3` | Slack token |
| MEDIUM | SEC011 | `app.py:22` | Hardcoded password or secret |
| MEDIUM | PY014 | `app.py:23` | Hardcoded credential in assignment |
| MEDIUM | PY006 | `app.py:56` | os.system / os.popen call |
| MEDIUM | PY008 | `app.py:73` | Weak hash algorithm (MD5/SHA-1) |
| MEDIUM | PY010 | `app.py:85` | Insecure temporary file (mktemp) |
| MEDIUM | PY011 | `app.py:97` | Debug mode enabled |
| LOW | PY013 | `app.py:81` | Insecure random for security use |
| LOW | PY012 | `app.py:89` | assert used for a check |
| LOW | PY016 | `app.py:97` | Binding to all network interfaces |
| INFO | PY015 | `app.py:92` | Bare except clause |

## Details

### CRITICAL

#### SEC002: AWS secret access key
**Location:** `config.py:3`  
**Category:** secret

```
AWS_SECRET_ACCESS_KEY = "wJal************EY"
```
A 40-character secret appears next to an AWS secret-key identifier.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

#### SEC008: Stripe live secret key
**Location:** `deploy.sh:4`  
**Category:** secret

```
export STRIPE_KEY="sk_l************f3"
```
String matches the format of a live Stripe secret or restricted key.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

#### SEC006: GitHub token
**Location:** `deploy.sh:5`  
**Category:** secret

```
curl -H "Authorization: Bearer ghp_************89" https://api.example.com/deploy
```
String matches the format of a GitHub personal access or app token.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

#### SEC005: Private key block
**Location:** `id_rsa_demo:1`  
**Category:** secret

```
-----BEGIN OPENSSH PRIVATE ***-----
```
A PEM/OpenSSH/PGP private key header was found in source.

**Fix:** Remove the key from the repository, rotate it, and purge it from git history.

### HIGH

#### SEC010: Credentials in URL
**Location:** `app.py:24`  
**Category:** secret

```
DATABASE_URL = "postgres://admin:hunt********r2@db.internal.example.com:5432/prod"
```
A URL embeds a username and password.

**Fix:** Move credentials out of connection strings into configuration or a secrets manager.

#### PY007: SQL built with string formatting
**Location:** `app.py:37`  
**Category:** code

```
cur.execute(f"SELECT * FROM users WHERE id = {uid}")
```
A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection. Value is interpolated directly into the query text.

**Fix:** Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,)).

#### PY007: SQL built with string formatting
**Location:** `app.py:38`  
**Category:** code

```
cur.execute("SELECT * FROM users WHERE name = '%s'" % uid)
```
A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection. Value is interpolated directly into the query text.

**Fix:** Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,)).

#### PY007: SQL built with string formatting
**Location:** `app.py:39`  
**Category:** code

```
cur.execute("SELECT * FROM users WHERE name = '" + uid + "'")
```
A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection. Value is interpolated directly into the query text.

**Fix:** Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,)).

#### PY007: SQL built with string formatting
**Location:** `app.py:40`  
**Category:** code

```
cur.execute("DELETE FROM sessions WHERE user = '{}'".format(uid))
```
A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection. Value is interpolated directly into the query text.

**Fix:** Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,)).

#### PY007: SQL built with string formatting
**Location:** `app.py:42`  
**Category:** code

```
cur.execute(query)
```
A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection. Query variable 'query' was built with string formatting.

**Fix:** Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,)).

#### PY001: Use of eval()
**Location:** `app.py:50`  
**Category:** code

```
return str(eval(request.args["expr"]))
```
eval() executes arbitrary Python from a string and enables code injection.

**Fix:** Use ast.literal_eval() for literals, or parse input with a purpose-built parser.

#### PY005: subprocess with shell=True
**Location:** `app.py:55`  
**Category:** code

```
subprocess.run("ls " + request.args["d"], shell=True)
```
Running commands through a shell exposes the call to command injection.

**Fix:** Pass an argument list and leave shell=False.

#### PY003: Unsafe deserialization (pickle/marshal/shelve)
**Location:** `app.py:61`  
**Category:** code

```
return pickle.loads(blob)
```
Unpickling untrusted data can execute arbitrary code.

**Fix:** Use JSON or another data-only format; sign and verify data if pickle is unavoidable.

#### PY004: yaml.load without a safe loader
**Location:** `app.py:65`  
**Category:** code

```
return yaml.load(text)
```
yaml.load with the default or full loader can construct arbitrary objects.

**Fix:** Use yaml.safe_load() or pass Loader=yaml.SafeLoader.

#### PY009: TLS certificate verification disabled
**Location:** `app.py:77`  
**Category:** code

```
return requests.get(url, verify=False)
```
verify=False allows man-in-the-middle attacks.

**Fix:** Leave verification on; supply a CA bundle path if you need a private CA.

#### PY002: Use of exec()
**Location:** `app.py:91`  
**Category:** code

```
exec(user.startup_script)
```
exec() executes arbitrary Python from a string and enables code injection.

**Fix:** Avoid dynamic code execution; dispatch through an explicit mapping of allowed functions.

#### SEC001: AWS access key ID
**Location:** `config.py:2`  
**Category:** secret

```
AWS_ACCESS_KEY_ID = "AKIA************LE"
```
String matches the format of an AWS access key ID.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager. Prefer IAM roles over long-lived keys.

#### SEC003: Google API key
**Location:** `config.py:4`  
**Category:** secret

```
GOOGLE_MAPS_KEY = "AIza************6Q"
```
String matches the format of a Google API key.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager. Restrict the key by API and referrer in Google Cloud.

#### SEC007: Slack token
**Location:** `deploy.sh:3`  
**Category:** secret

```
export SLACK_TOKEN="xoxb************wx"
```
String matches the format of a Slack API token.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

### MEDIUM

#### SEC011: Hardcoded password or secret
**Location:** `app.py:22`  
**Category:** secret

```
DB_PASSWORD = "Sup3************d!"
```
A credential-like variable is assigned a high-entropy string literal.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

#### PY014: Hardcoded credential in assignment
**Location:** `app.py:23`  
**Category:** code

```
ADMIN_PASSWORD = "letmein"  # too short for the regex pass; the AST pass catches it
```
A credential-like variable is assigned a non-empty string constant. Variable 'ADMIN_PASSWORD' holds a string literal.

**Fix:** Revoke and rotate this credential, then load it from an environment variable or a secrets manager.

#### PY006: os.system / os.popen call
**Location:** `app.py:56`  
**Category:** code

```
os.system("echo " + request.args["msg"])
```
Shell command execution is vulnerable to command injection when input is untrusted.

**Fix:** Use subprocess.run() with an argument list.

#### PY008: Weak hash algorithm (MD5/SHA-1)
**Location:** `app.py:73`  
**Category:** code

```
return hashlib.md5(data).hexdigest()
```
MD5 and SHA-1 are broken for security purposes.

**Fix:** Use SHA-256 or better; use bcrypt/scrypt/argon2 for passwords.

#### PY010: Insecure temporary file (mktemp)
**Location:** `app.py:85`  
**Category:** code

```
return tempfile.mktemp()
```
tempfile.mktemp() is subject to race conditions.

**Fix:** Use tempfile.NamedTemporaryFile() or tempfile.mkstemp().

#### PY011: Debug mode enabled
**Location:** `app.py:97`  
**Category:** code

```
app.run(host="0.0.0.0", debug=True)
```
Running a web framework with debug=True can expose an interactive debugger.

**Fix:** Disable debug mode in production and drive it from configuration.

### LOW

#### PY013: Insecure random for security use
**Location:** `app.py:81`  
**Category:** code

```
return str(random.randint(100000, 999999))
```
The random module is not cryptographically secure.

**Fix:** Use the secrets module for tokens, passwords and keys.

#### PY012: assert used for a check
**Location:** `app.py:89`  
**Category:** code

```
assert user.is_admin, "not allowed"
```
assert statements are stripped when Python runs with -O, so checks vanish.

**Fix:** Raise an explicit exception for validation and authorization checks.

#### PY016: Binding to all network interfaces
**Location:** `app.py:97`  
**Category:** code

```
app.run(host="0.0.0.0", debug=True)
```
Binding to 0.0.0.0 exposes the service on every interface.

**Fix:** Bind to 127.0.0.1 unless external access is intended and protected.

### INFO

#### PY015: Bare except clause
**Location:** `app.py:92`  
**Category:** code

```
except:
```
A bare except hides errors, including security-relevant ones.

**Fix:** Catch specific exception types.

