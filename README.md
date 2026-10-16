# RepoSentinel

Static security scanner for source-code repositories. No external dependencies — standard library only, Python 3.7+.

RepoSentinel performs **AST-based analysis** on Python files and **regex-based analysis** on all supported file types, detecting common vulnerability patterns and outputting structured JSON and Markdown reports.

---

## What it detects

| Rule ID | Category | Severity | CWE | Description |
|---------|----------|----------|-----|-------------|
| SECRET-001 | Hardcoded Credentials | HIGH | CWE-798 | Hardcoded secrets in Python variable assignments |
| SECRET-002 | Hardcoded Credentials | HIGH | CWE-798 | Hardcoded secrets in non-Python files |
| SECRET-003 | Hardcoded Credentials | HIGH | CWE-798 | AWS access key IDs |
| SECRET-004 | Hardcoded Credentials | HIGH | CWE-321 | Private key material in source files |
| SHELL-001 | Shell Injection | HIGH | CWE-78 | `os.system()` calls |
| SHELL-002 | Shell Injection | HIGH | CWE-78 | `subprocess.*()` with `shell=True` |
| SHELL-003 | Code Injection | HIGH | CWE-94 | `eval()` / `exec()` with dynamic arguments |
| SHELL-004 | Shell Injection | MEDIUM | CWE-78 | `eval $var` in shell scripts |
| DESER-001 | Unsafe Deserialisation | HIGH | CWE-502 | `pickle.loads()` / `pickle.load()` |
| DESER-002 | Unsafe Deserialisation | HIGH | CWE-502 | `marshal.loads()` |
| DESER-003 | Unsafe Deserialisation | HIGH | CWE-502 | `yaml.load()` without `SafeLoader` |
| SSTI-001 | Template Injection | HIGH | CWE-94 | `render_template_string()` with non-literal template |
| TLS-001 | TLS Verification Disabled | HIGH | CWE-295 | `requests.*()` with `verify=False` (Python) |
| TLS-002 | TLS Verification Disabled | HIGH | CWE-295 | `rejectUnauthorized: false` (JavaScript/Node) |
| REDIR-001 | Open Redirect | MEDIUM | CWE-601 | `redirect()` target from request input directly |
| REDIR-002 | Open Redirect | LOW | CWE-601 | `redirect()` target is an unvalidated variable |
| CRYPTO-001 | Weak Cryptography | MEDIUM | CWE-327 | `hashlib.md5()` / `hashlib.sha1()` |
| CRYPTO-002 | Weak Cryptography | MEDIUM | CWE-327 | MD5/SHA-1 in JavaScript/Java code |
| CONFIG-001 | Security Misconfiguration | MEDIUM | CWE-215 | `DEBUG = True` in config files |
| SQLI-001 | SQL Injection | HIGH | CWE-89 | SQL query built with an f-string |
| SQLI-002 | SQL Injection | HIGH | CWE-89 | SQL query built with `.format()` |
| SQLI-003 | SQL Injection | HIGH | CWE-89 | SQL query built with string concatenation |

---

## Installation

No packages to install.

```bash
git clone https://github.com/YOUR_USERNAME/reposentinel.git
cd reposentinel
python scanner.py --help
```

Requires Python 3.7 or newer.

---

## Usage

```bash
# Scan a repository and write scan_report.json + scan_report.md
python scanner.py /path/to/target/repo

# Custom output file name
python scanner.py /path/to/repo --output my_audit

# Only show HIGH severity findings
python scanner.py /path/to/repo --severity HIGH

# Disable colour output (useful when piping to a log file)
python scanner.py /path/to/repo --no-color
```

---

## Example output

```
RepoSentinel — Source Code Security Scanner
───────────────────────────────────────────────────────
Repository    : /home/user/myapp
Scan time     : 2025-01-15 14:23:07
Files scanned : 38
───────────────────────────────────────────────────────

[HIGH  ]  Hardcoded secret in variable 'api_key'
  SECRET-001 · CWE-798 · app/config.py:12
  → 12 | api_key = "sk-live-9f3kQx82mPzT"

[HIGH  ]  requests.get() called with verify=False
  TLS-001 · CWE-295 · app/utils.py:47
  → 47 |     response = requests.get(url, verify=False)

[HIGH  ]  SQL query built with an f-string — potential injection
  SQLI-001 · CWE-89 · app/db.py:93
  → 93 |     cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

[MEDIUM]  Weak hash function MD5 used
  CRYPTO-001 · CWE-327 · app/auth.py:31
  → 31 |     return hashlib.md5(password.encode()).hexdigest()

───────────────────────────────────────────────────────
Results: 8 HIGH  3 MEDIUM  1 LOW  (12 total findings)

Reports written:
  JSON     → scan_report.json
  Markdown → scan_report.md
```

---

## Output files

**`scan_report.json`** — machine-readable, suitable for parsing in CI/CD pipelines:

```json
{
  "repo": "/path/to/repo",
  "scan_time": "2025-01-15 14:23:07",
  "files_scanned": 38,
  "summary": { "total": 12, "HIGH": 8, "MEDIUM": 3, "LOW": 1 },
  "findings": [
    {
      "rule_id": "SECRET-001",
      "title": "Hardcoded secret in variable 'api_key'",
      "severity": "HIGH",
      "cwe": "CWE-798",
      "category": "Hardcoded Credentials",
      "file": "app/config.py",
      "line": 12,
      "snippet": "→  12 | api_key = \"sk-live-9f3kQx82mPzT\"",
      "remediation": "Move secrets to environment variables..."
    }
  ]
}
```

**`scan_report.md`** — human-readable report with tables, code snippets, and remediation notes for each finding. Suitable for sharing with developers.

---

## Demo

A deliberately vulnerable demo file (`test_target.py`) is included to verify the scanner works:

```bash
python scanner.py . --output demo_report
```

This should produce findings for every detection category.

---

## How it works

The scanner has two analysis modes:

**AST analysis (Python files):**  
Python source files are parsed into an Abstract Syntax Tree using Python's built-in `ast` module. A `NodeVisitor` subclass walks the tree and checks for dangerous patterns at the code structure level — more precise than text matching because it understands the code's logic rather than just its surface appearance.

**Regex analysis (all file types):**  
For JavaScript, Java, YAML, configuration files and other non-Python files, the scanner applies regular expression patterns line by line to detect common security anti-patterns.

For Python files, both analyses run. The results are deduplicated so the same issue at the same location is only reported once.

---

## Adding a custom rule

To add a new regex rule, append an entry to the `REGEX_RULES` list in `scanner.py`:

```python
{
    "rule_id":    "CUSTOM-001",
    "title":      "Insecure random number generation",
    "severity":   "MEDIUM",
    "cwe":        "CWE-338",
    "category":   "Weak Cryptography",
    "pattern":    re.compile(r"random\.random\(\)|Math\.random\(\)"),
    "remediation": "Use secrets.token_bytes() or os.urandom() for security-sensitive random values.",
},
```

To add a new AST rule for Python, add a check inside `PythonScanner.visit_Call()` or `PythonScanner.visit_Assign()`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no HIGH findings |
| 1 | Scan completed, one or more HIGH findings detected |
| 2 | Invalid arguments or path not found |

Exit code 1 for HIGH findings makes RepoSentinel easy to integrate into CI/CD pipelines — a pipeline stage can fail automatically when critical issues are found.

---

## Limitations

- Python AST rules only cover Python files; other languages use regex only
- The scanner performs static analysis and cannot detect logic flaws or issues that only appear at runtime
- Some findings may be false positives and require manual triage
- Not a replacement for manual code review or a full SAST platform — intended as a first-pass filter and learning tool

---

## Tested against

- [test_target.py](test_target.py) — included demo vulnerable app
- [Whoogle Search](https://github.com/benbusby/whoogle-search) — confirmed detection of SSRF, SSTI, hardcoded secret, TLS bypass, and mass-assignment patterns (see writeup)
