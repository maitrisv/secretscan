# secretscan

[![CI](https://github.com/YOUR-USERNAME/secretscan/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/secretscan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**A DevSecOps scanner that catches hardcoded secrets and risky code before it ships.**
One file, standard library only, built to run as a CI gate or a pre-commit hook.

It combines two techniques that real application-security pipelines use:

| Pass | Technique | Scope | Finds |
|------|-----------|-------|-------|
| **Secret detection** | Regex + Shannon entropy + placeholder filtering | Any text file | AWS / Google / GitHub / Slack / Stripe credentials, private keys, JWTs, passwords in URLs, hardcoded passwords |
| **Code analysis** | Python `ast` visitor with import-alias resolution | `.py` files | `eval`/`exec`, SQL injection, command injection, unsafe deserialization, weak crypto, disabled TLS verification, and more |

Findings are ranked by severity and reported with file and line number as text, Markdown or JSON.
The process exits non-zero when findings reach a chosen severity, so a pipeline can block the merge.

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/secretscan.git
cd secretscan

# run the bundled demo (fake secrets are generated at runtime)
python3 examples/make_secret_fixtures.py demo
cp examples/vulnerable_app/app.py demo/
python3 secretscan.py demo
```

Or install it as a command:

```bash
pip install .
secretscan path/to/your/project -f markdown -o report.md
```

Example output (full reports in [`docs/sample-report.md`](docs/sample-report.md) and [`docs/sample-report.json`](docs/sample-report.json)):

```
config.py:3:22:  [CRITICAL] SEC002 AWS secret access key
    AWS_SECRET_ACCESS_KEY = "wJal************EY"
app.py:37:5:     [HIGH] PY007 SQL built with string formatting
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
app.py:50:16:    [HIGH] PY001 Use of eval()
    return str(eval(request.args["expr"]))

29 finding(s) in 4 file(s) [CRITICAL=4, HIGH=15, MEDIUM=6, LOW=3, INFO=1]
```

Matched secrets are always **redacted** in output, so the report itself never leaks a credential.

## Usage

```bash
secretscan PATH                          # text report
secretscan PATH -f markdown -o report.md # Markdown report
secretscan PATH -f json -o report.json   # machine-readable report
secretscan PATH --min-severity MEDIUM    # hide LOW and INFO
secretscan PATH --fail-on CRITICAL       # only fail the build on CRITICAL
secretscan PATH --exclude 'tests/*' --exclude-dir fixtures
secretscan PATH --no-code                # secrets only
secretscan PATH --no-secrets             # AST checks only
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Nothing at or above `--fail-on` (default `HIGH`) |
| `1` | Findings at or above the threshold |
| `2` | Usage error (bad path, no scans enabled) |

Suppress a reviewed line with a trailing comment: `# secretscan:ignore`.
Without installing, replace `secretscan` with `python3 secretscan.py`.

## Rules

**Secrets** (`SEC001` to `SEC011`)

| Rule | Detects | Severity |
|------|---------|----------|
| SEC001 | AWS access key ID | HIGH |
| SEC002 | AWS secret access key (entropy-checked) | CRITICAL |
| SEC003 / SEC004 | Google API key / OAuth client secret | HIGH |
| SEC005 | Private key block (RSA, EC, OpenSSH, PGP) | CRITICAL |
| SEC006 | GitHub token | CRITICAL |
| SEC007 | Slack token | HIGH |
| SEC008 | Stripe live secret key | CRITICAL |
| SEC009 | JSON Web Token | MEDIUM |
| SEC010 | Credentials embedded in a URL | HIGH |
| SEC011 | Generic hardcoded password/secret (entropy-checked) | MEDIUM |

**Code** (`PY001` to `PY016`)

| Rule | Detects | Severity |
|------|---------|----------|
| PY001 / PY002 | `eval()` / `exec()` | HIGH |
| PY003 | `pickle` / `marshal` / `shelve` deserialization | HIGH |
| PY004 | `yaml.load` without a safe loader | HIGH |
| PY005 | `subprocess` with `shell=True` | HIGH |
| PY006 | `os.system` / `os.popen` | MEDIUM |
| PY007 | SQL built with f-strings, `%`, `+` or `.format()` and passed to `execute()`, including via an intermediate variable | HIGH |
| PY008 | MD5 / SHA-1 | MEDIUM |
| PY009 | `verify=False` on HTTP requests | HIGH |
| PY010 | `tempfile.mktemp` | MEDIUM |
| PY011 | `debug=True` | MEDIUM |
| PY012 | `assert` used for checks | LOW |
| PY013 | `random` used inside token/password/key functions | LOW |
| PY014 | Credential-named variable assigned a string literal | MEDIUM |
| PY015 | Bare `except:` | INFO |
| PY016 | Binding to `0.0.0.0` | LOW |

## How it works

```
 files ──► walk tree (skip .git, node_modules, binaries, >1 MB)
            │
            ├─► regex rules ──► entropy + placeholder filter ──► redact ──┐
            │                                                              ├─► dedupe ─► sort by severity ─► report
            └─► (.py only) ast.parse ─► CodeVisitor ─► SQL variable pass ─┘                                  (text | md | json)
```

- **Entropy filtering** drops low-randomness matches such as `password = "aaaaaaaa"`, and a placeholder list skips `changeme`, `your-api-key`, `${VAR}` and similar.
- **Alias resolution** means `import subprocess as sp; sp.run(x, shell=True)` and `from pickle import loads as L` are still caught.
- **SQL injection** is detected structurally, not by grepping for "SELECT": the first argument of an `execute`-style call must be a dynamically built string containing a SQL verb. Parameterized queries are not flagged. A second pass follows `query = f"..."; cur.execute(query)`.
- **De-duplication:** a specific rule (e.g. an AWS key) wins over the generic password rule on the same line.

## Use it in CI

This repo already does: see [`.github/workflows/ci.yml`](.github/workflows/ci.yml), which runs the tests on three Python versions and then scans the repository itself. To gate another project:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.13" }
- run: python3 secretscan.py . --fail-on HIGH -f markdown -o report.md
- if: always()
  uses: actions/upload-artifact@v4
  with: { name: secretscan-report, path: report.md }
```

As a git pre-commit hook (`.git/hooks/pre-commit`, then `chmod +x`):

```bash
#!/bin/sh
python3 secretscan.py . --fail-on HIGH
```

## Project layout

```
secretscan.py                  the scanner (rules, AST visitor, reporters, CLI)
tests/test_secretscan.py       40+ unit and CLI tests
examples/vulnerable_app/       deliberately insecure Flask app (code issues)
examples/make_secret_fixtures.py   generates fake credentials at runtime
docs/                          sample Markdown and JSON reports
.github/workflows/ci.yml       tests + self-scan
```

Why are the fake credentials generated at runtime? A repository full of realistic-looking tokens trips GitHub push protection and every other secret scanner. The generator assembles them from fragments, so the repo stays clean while the scanner still has real-format input to find.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

- Regex plus entropy is heuristic: expect some false positives (use the ignore marker) and some misses (secrets split across lines or built at runtime).
- The AST pass understands Python only. Other languages get the secret scan.
- SQL injection detection is syntactic. There is no taint tracking, so it can't tell whether the interpolated value is user-controlled.
- Only the working tree is scanned, not git history. A secret removed in a later commit is still compromised: rotate it. [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) cover history.

## Roadmap

- `--baseline` file so CI fails only on *new* findings
- SARIF output for GitHub code scanning
- AST rules for JavaScript/TypeScript
- Git-history scanning mode

## License

MIT, see [LICENSE](LICENSE).
