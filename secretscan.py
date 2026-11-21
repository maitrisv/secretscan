#!/usr/bin/env python3
"""secretscan - a small DevSecOps scanner for source code repositories.

Two analysis passes, standard library only:

1. Secret detection: regular expressions for hardcoded credentials (AWS keys,
   Google API keys, private keys, tokens, password assignments) plus a Shannon
   entropy filter on generic assignments to cut false positives.
2. Static analysis: Python AST visitor that flags risky constructs (eval/exec,
   unsafe deserialization, shell injection, SQL built with string formatting,
   weak hashes, disabled TLS verification, and similar).

Output is text, Markdown or JSON. The exit code is non-zero when findings at or
above --fail-on severity exist, so it can gate a CI pipeline.

Suppress a finding on a line with a trailing comment:  # secretscan:ignore
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

__version__ = "1.0.0"

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

IGNORE_MARKER = "secretscan:ignore"
MAX_FILE_BYTES = 1_000_000

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".idea", ".vscode", "site-packages",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".bz2", ".xz", ".7z", ".jar", ".class", ".so", ".dll", ".exe",
    ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
    ".mov", ".avi", ".db", ".sqlite", ".bin", ".lock",
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str  # "secret" or "code"
    file: str
    line: int
    snippet: str
    description: str
    remediation: str
    column: int = 0

    def key(self) -> tuple:
        return (self.file, self.line, self.rule_id)


@dataclass
class ScanResult:
    root: str
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    parse_errors: list = field(default_factory=list)
    started: str = ""
    duration_s: float = 0.0


# --------------------------------------------------------------------------
# Secret rules (regex)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern
    description: str
    remediation: str
    group: int = 0          # capture group holding the secret value
    min_entropy: float = 0  # 0 disables the entropy filter


ROTATE = "Revoke and rotate this credential, then load it from an environment variable or a secrets manager."

SECRET_RULES: list[SecretRule] = [
    SecretRule(
        "SEC001", "AWS access key ID", "HIGH",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b"),
        "String matches the format of an AWS access key ID.",
        ROTATE + " Prefer IAM roles over long-lived keys.", group=1,
    ),
    SecretRule(
        "SEC002", "AWS secret access key", "CRITICAL",
        re.compile(
            r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=: ]\s*[\"']?"
            r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        "A 40-character secret appears next to an AWS secret-key identifier.",
        ROTATE, group=1, min_entropy=3.5,
    ),
    SecretRule(
        "SEC003", "Google API key", "HIGH",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        "String matches the format of a Google API key.",
        ROTATE + " Restrict the key by API and referrer in Google Cloud.", group=1,
    ),
    SecretRule(
        "SEC004", "Google OAuth client secret", "HIGH",
        re.compile(r"\b(GOCSPX-[0-9A-Za-z_\-]{28})\b"),
        "String matches the format of a Google OAuth client secret.",
        ROTATE, group=1,
    ),
    SecretRule(
        "SEC005", "Private key block", "CRITICAL",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        "A PEM/OpenSSH/PGP private key header was found in source.",
        "Remove the key from the repository, rotate it, and purge it from git history.",
    ),
    SecretRule(
        "SEC006", "GitHub token", "CRITICAL",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b"),
        "String matches the format of a GitHub personal access or app token.",
        ROTATE, group=1,
    ),
    SecretRule(
        "SEC007", "Slack token", "HIGH",
        re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,72})\b"),
        "String matches the format of a Slack API token.",
        ROTATE, group=1,
    ),
    SecretRule(
        "SEC008", "Stripe live secret key", "CRITICAL",
        re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,99})\b"),
        "String matches the format of a live Stripe secret or restricted key.",
        ROTATE, group=1,
    ),
    SecretRule(
        "SEC009", "JSON Web Token", "MEDIUM",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
        "A JWT is embedded in source; it may be a live session or service token.",
        "Do not commit tokens. Issue short-lived tokens at runtime.", group=1,
    ),
    SecretRule(
        "SEC010", "Credentials in URL", "HIGH",
        re.compile(r"\b[a-z][a-z0-9+.\-]{2,15}://[^\s/:@'\"]{1,64}:([^\s/:@'\"]{3,64})@[^\s/'\"]+"),
        "A URL embeds a username and password.",
        "Move credentials out of connection strings into configuration or a secrets manager.",
        group=1,
    ),
    SecretRule(
        "SEC011", "Hardcoded password or secret", "MEDIUM",
        re.compile(
            r"(?i)\b[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token)"
            r"[\w.\-]*\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        "A credential-like variable is assigned a high-entropy string literal.",
        ROTATE, group=1, min_entropy=3.0,
    ),
]

# Values that are obviously placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|your[_\-]?.*|changeme|change[_\-]?me|"
    r"example.*|placeholder|dummy|test|sample|todo|none|null|password|secret|"
    r"os\.environ.*|getenv.*)$"
)


# e.g. "pkg.module:main" in packaging metadata: names containing "secret" but not secrets.
CODE_REF_RE = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_][\w.]*$")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """Show just enough of a secret to identify it in a report."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 6, 12)}{value[-2:]}"


def scan_text_for_secrets(path: str, text: str) -> Iterator[Finding]:
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if IGNORE_MARKER in line or len(line) > 2000:
            continue
        line_findings: list[Finding] = []
        for rule in SECRET_RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group) if rule.group else m.group(0)
                if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                    continue
                if PLACEHOLDER_RE.match(value):
                    continue
                if rule.rule_id == "SEC011" and CODE_REF_RE.match(value):
                    continue
                shown = redact(value)
                if rule.rule_id == "SEC005":
                    # Mask the header so reports don't themselves look like leaked keys.
                    snippet = line.strip().replace("PRIVATE KEY", "PRIVATE ***")
                else:
                    snippet = line.strip().replace(value, shown)
                line_findings.append(Finding(
                    rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
                    category="secret", file=path, line=lineno,
                    snippet=snippet[:200], description=rule.description,
                    remediation=rule.remediation, column=m.start() + 1,
                ))
        # A specific rule (e.g. AWS key) beats the generic password/secret rule on the same line.
        if any(f.rule_id != "SEC011" for f in line_findings):
            line_findings = [f for f in line_findings if f.rule_id != "SEC011"]
        yield from line_findings


# --------------------------------------------------------------------------
# AST analysis
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeRule:
    rule_id: str
    title: str
    severity: str
    description: str
    remediation: str


CODE_RULES = {
    "PY001": CodeRule("PY001", "Use of eval()", "HIGH",
        "eval() executes arbitrary Python from a string and enables code injection.",
        "Use ast.literal_eval() for literals, or parse input with a purpose-built parser."),
    "PY002": CodeRule("PY002", "Use of exec()", "HIGH",
        "exec() executes arbitrary Python from a string and enables code injection.",
        "Avoid dynamic code execution; dispatch through an explicit mapping of allowed functions."),
    "PY003": CodeRule("PY003", "Unsafe deserialization (pickle/marshal/shelve)", "HIGH",
        "Unpickling untrusted data can execute arbitrary code.",
        "Use JSON or another data-only format; sign and verify data if pickle is unavoidable."),
    "PY004": CodeRule("PY004", "yaml.load without a safe loader", "HIGH",
        "yaml.load with the default or full loader can construct arbitrary objects.",
        "Use yaml.safe_load() or pass Loader=yaml.SafeLoader."),
    "PY005": CodeRule("PY005", "subprocess with shell=True", "HIGH",
        "Running commands through a shell exposes the call to command injection.",
        "Pass an argument list and leave shell=False."),
    "PY006": CodeRule("PY006", "os.system / os.popen call", "MEDIUM",
        "Shell command execution is vulnerable to command injection when input is untrusted.",
        "Use subprocess.run() with an argument list."),
    "PY007": CodeRule("PY007", "SQL built with string formatting", "HIGH",
        "A query is assembled with f-strings, %, .format() or concatenation, which allows SQL injection.",
        "Use parameterized queries, e.g. cursor.execute('... WHERE id = ?', (user_id,))."),
    "PY008": CodeRule("PY008", "Weak hash algorithm (MD5/SHA-1)", "MEDIUM",
        "MD5 and SHA-1 are broken for security purposes.",
        "Use SHA-256 or better; use bcrypt/scrypt/argon2 for passwords."),
    "PY009": CodeRule("PY009", "TLS certificate verification disabled", "HIGH",
        "verify=False allows man-in-the-middle attacks.",
        "Leave verification on; supply a CA bundle path if you need a private CA."),
    "PY010": CodeRule("PY010", "Insecure temporary file (mktemp)", "MEDIUM",
        "tempfile.mktemp() is subject to race conditions.",
        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp()."),
    "PY011": CodeRule("PY011", "Debug mode enabled", "MEDIUM",
        "Running a web framework with debug=True can expose an interactive debugger.",
        "Disable debug mode in production and drive it from configuration."),
    "PY012": CodeRule("PY012", "assert used for a check", "LOW",
        "assert statements are stripped when Python runs with -O, so checks vanish.",
        "Raise an explicit exception for validation and authorization checks."),
    "PY013": CodeRule("PY013", "Insecure random for security use", "LOW",
        "The random module is not cryptographically secure.",
        "Use the secrets module for tokens, passwords and keys."),
    "PY014": CodeRule("PY014", "Hardcoded credential in assignment", "MEDIUM",
        "A credential-like variable is assigned a non-empty string constant.",
        ROTATE),
    "PY015": CodeRule("PY015", "Bare except clause", "INFO",
        "A bare except hides errors, including security-relevant ones.",
        "Catch specific exception types."),
    "PY016": CodeRule("PY016", "Binding to all network interfaces", "LOW",
        "Binding to 0.0.0.0 exposes the service on every interface.",
        "Bind to 127.0.0.1 unless external access is intended and protected."),
}

SQL_VERBS = re.compile(r"(?i)\b(select|insert\s+into|update|delete\s+from|drop\s+table|union\s+select)\b")
EXECUTE_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
CRED_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token|private[_\-]?key)"
)
RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "getrandbits", "sample"}


class CodeVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str]):
        self.path = path
        self.lines = source_lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}   # local name -> dotted origin

    # -- helpers ---------------------------------------------------------
    def _add(self, rule_id: str, node: ast.AST, extra: str = ""):
        lineno = getattr(node, "lineno", 1)
        line = self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""
        if IGNORE_MARKER in line:
            return
        rule = CODE_RULES[rule_id]
        desc = rule.description + (f" {extra}" if extra else "")
        self.findings.append(Finding(
            rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
            category="code", file=self.path, line=lineno,
            snippet=line.strip()[:200], description=desc,
            remediation=rule.remediation, column=getattr(node, "col_offset", 0) + 1,
        ))

    def _dotted(self, node: ast.AST) -> Optional[str]:
        """Resolve a Name/Attribute chain to a dotted string, expanding import aliases."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _kw(node: ast.Call, name: str):
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _is_true(node) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def _is_false(node) -> bool:
        return isinstance(node, ast.Constant) and node.value is False

    def _is_dynamic_sql(self, node: ast.AST) -> bool:
        """True if node builds a SQL-looking string from non-constant parts."""
        if isinstance(node, ast.JoinedStr):  # f-string
            literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            has_expr = any(isinstance(v, ast.FormattedValue) for v in node.values)
            return has_expr and bool(SQL_VERBS.search(literal))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            literal = " ".join(self._string_literals(node))
            has_dynamic = self._has_non_constant(node)
            return has_dynamic and bool(SQL_VERBS.search(literal))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = node.func.value
            if isinstance(base, ast.Constant) and isinstance(base.value, str):
                return bool(SQL_VERBS.search(base.value)) and bool(node.args or node.keywords)
        return False

    def _string_literals(self, node: ast.AST) -> list[str]:
        return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]

    def _has_non_constant(self, node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp):
            return self._has_non_constant(node.left) or self._has_non_constant(node.right)
        return not isinstance(node, ast.Constant)

    # -- imports (alias tracking) ----------------------------------------
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    # -- calls -----------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        name = self._dotted(node.func) or ""
        short = name.rsplit(".", 1)[-1]

        if name in ("eval", "builtins.eval"):
            self._add("PY001", node)
        elif name in ("exec", "builtins.exec"):
            self._add("PY002", node)

        if name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                    "marshal.load", "marshal.loads", "shelve.open", "dill.load", "dill.loads",
                    "_pickle.load", "_pickle.loads"):
            self._add("PY003", node)

        if name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"):
            loader = self._kw(node, "Loader")
            loader_name = self._dotted(loader) if loader is not None else ""
            if name in ("yaml.unsafe_load", "yaml.full_load") or not (loader_name and "Safe" in loader_name):
                self._add("PY004", node)

        if name.startswith("subprocess.") and short in ("run", "call", "check_call", "check_output", "Popen"):
            if self._is_true(self._kw(node, "shell")):
                self._add("PY005", node)
        if name in ("os.system", "os.popen", "commands.getoutput"):
            self._add("PY006", node)

        # SQL injection: .execute(<dynamic sql>)
        if isinstance(node.func, ast.Attribute) and node.func.attr in EXECUTE_METHODS and node.args:
            if self._is_dynamic_sql(node.args[0]):
                self._add("PY007", node, "Value is interpolated directly into the query text.")
            elif isinstance(node.args[0], ast.Name):
                pass  # handled via assignment tracking in visit_Assign

        if name in ("hashlib.md5", "hashlib.sha1"):
            self._add("PY008", node)
        elif name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).lower() in ("md5", "sha1", "sha-1"):
            self._add("PY008", node)

        if self._is_false(self._kw(node, "verify")) and (
            name.startswith(("requests.", "httpx.", "urllib3.")) or short in ("get", "post", "put", "delete", "request", "Session")
        ):
            self._add("PY009", node)

        if name == "tempfile.mktemp":
            self._add("PY010", node)

        if short == "run" and self._is_true(self._kw(node, "debug")):
            self._add("PY011", node)
        elif self._is_true(self._kw(node, "debug")) and short in ("run", "Flask", "FastAPI"):
            self._add("PY011", node)

        if name.startswith("random.") and short in RANDOM_FUNCS and self._in_security_context(node):
            self._add("PY013", node)

        host = self._kw(node, "host")
        if isinstance(host, ast.Constant) and host.value == "0.0.0.0" and short in ("run", "serve", "listen"):
            self._add("PY016", node)

        self.generic_visit(node)

    def _in_security_context(self, node: ast.AST) -> bool:
        # Cheap heuristic: flag random.* when the enclosing function name hints at secrets.
        func = getattr(node, "_enclosing_func", "")
        return bool(re.search(r"(?i)token|password|secret|key|salt|nonce|otp|session", func))

    # -- functions: tag enclosing name for the heuristic above ------------
    def visit_FunctionDef(self, node):
        for child in ast.walk(node):
            child._enclosing_func = node.name  # type: ignore[attr-defined]
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- assignments -----------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        self._check_credential_assign(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self._check_credential_assign([node.target], node.value, node)
        self.generic_visit(node)

    def _check_credential_assign(self, targets, value, node):
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return
        text = value.value
        if len(text) < 4 or PLACEHOLDER_RE.match(text):
            return
        for t in targets:
            tname = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if tname and CRED_NAME_RE.search(tname):
                self._add("PY014", node, f"Variable '{tname}' holds a string literal.")
                return

    # -- misc statements -------------------------------------------------
    def visit_Assert(self, node: ast.Assert):
        self._add("PY012", node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self._add("PY015", node)
        self.generic_visit(node)


def _tracked_sql_variables(tree: ast.AST) -> dict[str, ast.AST]:
    """Names assigned a dynamic SQL string anywhere in the module (name -> assignment node)."""
    probe = CodeVisitor("", [])
    found: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and probe._is_dynamic_sql(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    found[t.id] = node
    return found


def scan_python_ast(path: str, text: str) -> tuple[list[Finding], Optional[str]]:
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError) as exc:
        return [], f"{path}: {exc.__class__.__name__}: {exc}"
    visitor = CodeVisitor(path, text.splitlines())
    visitor.visit(tree)

    # Second pass: query = f"SELECT ... {x}" ... cursor.execute(query)
    sql_vars = _tracked_sql_variables(tree)
    if sql_vars:
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in EXECUTE_METHODS and node.args
                    and isinstance(node.args[0], ast.Name) and node.args[0].id in sql_vars):
                visitor._add("PY007", node, f"Query variable '{node.args[0].id}' was built with string formatting.")
    return visitor.findings, None


# --------------------------------------------------------------------------
# File walking and orchestration
# --------------------------------------------------------------------------

def iter_files(root: Path, exclude_dirs: set[str], exclude_globs: list[str]) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
        for fname in sorted(filenames):
            p = Path(dirpath) / fname
            rel = p.relative_to(root).as_posix()
            if any(p.match(g) or Path(rel).match(g) for g in exclude_globs):
                continue
            yield p


def looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def scan_path(root: Path, exclude_dirs: set[str], exclude_globs: list[str],
              secrets: bool = True, code: bool = True) -> ScanResult:
    started = datetime.now(timezone.utc)
    result = ScanResult(root=str(root), started=started.isoformat(timespec="seconds"))
    base = root if root.is_dir() else root.parent

    for p in iter_files(root, exclude_dirs, exclude_globs):
        if p.suffix.lower() in BINARY_EXTENSIONS or p.is_symlink():
            result.files_skipped += 1
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                result.files_skipped += 1
                continue
            raw = p.read_bytes()
        except OSError:
            result.files_skipped += 1
            continue
        if looks_binary(raw[:4096]):
            result.files_skipped += 1
            continue

        text = raw.decode("utf-8", errors="replace")
        rel = p.relative_to(base).as_posix() if p != base else p.name
        result.files_scanned += 1

        py_findings: list[Finding] = []
        if code and p.suffix == ".py":
            py_findings, err = scan_python_ast(rel, text)
            if err:
                result.parse_errors.append(err)
        sec_findings = list(scan_text_for_secrets(rel, text)) if secrets else []

        # De-duplicate: if both passes flag the same line as a credential, keep the
        # higher-severity regex finding.
        seen = {f.key() for f in sec_findings}
        result.findings.extend(sec_findings)
        for f in py_findings:
            if f.rule_id == "PY014" and any(s.file == f.file and s.line == f.line for s in sec_findings):
                continue
            if f.key() not in seen:
                result.findings.append(f)

    result.findings.sort(key=lambda f: (-SEV_RANK[f.severity], f.file, f.line, f.rule_id))
    result.duration_s = round((datetime.now(timezone.utc) - started).total_seconds(), 3)
    return result


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def summarize(result: ScanResult) -> dict:
    by_sev = Counter(f.severity for f in result.findings)
    by_cat = Counter(f.category for f in result.findings)
    return {
        "total": len(result.findings),
        "by_severity": {s: by_sev.get(s, 0) for s in reversed(SEVERITIES)},
        "by_category": dict(by_cat),
    }


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "secretscan",
        "version": __version__,
        "scanned_path": result.root,
        "started": result.started,
        "duration_seconds": result.duration_s,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "summary": summarize(result),
        "parse_errors": result.parse_errors,
        "findings": [asdict(f) for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("`", "'")


def render_markdown(result: ScanResult) -> str:
    s = summarize(result)
    out: list[str] = []
    out.append("# secretscan Report\n")
    out.append(f"- **Target:** `{result.root}`")
    out.append(f"- **Scanned:** {result.started} UTC ({result.duration_s}s)")
    out.append(f"- **Files scanned:** {result.files_scanned} (skipped {result.files_skipped})")
    out.append(f"- **Total findings:** {s['total']}\n")

    out.append("## Summary\n")
    out.append("| Severity | Count |")
    out.append("|----------|------:|")
    for sev, n in s["by_severity"].items():
        out.append(f"| {sev} | {n} |")
    out.append("")
    out.append(f"Secrets: {s['by_category'].get('secret', 0)} · Code issues: {s['by_category'].get('code', 0)}\n")

    if not result.findings:
        out.append("No findings. ✅\n")
    else:
        out.append("## Findings\n")
        out.append("| Severity | Rule | Location | Issue |")
        out.append("|----------|------|----------|-------|")
        for f in result.findings:
            out.append(f"| {f.severity} | {f.rule_id} | `{f.file}:{f.line}` | {_md_escape(f.title)} |")
        out.append("")

        out.append("## Details\n")
        current = None
        for f in result.findings:
            if f.severity != current:
                current = f.severity
                out.append(f"### {current}\n")
            out.append(f"#### {f.rule_id}: {f.title}")
            out.append(f"**Location:** `{f.file}:{f.line}`  ")
            out.append(f"**Category:** {f.category}\n")
            out.append("```")
            out.append(f.snippet)
            out.append("```")
            out.append(f"{f.description}\n")
            out.append(f"**Fix:** {f.remediation}\n")

    if result.parse_errors:
        out.append("## Files that could not be parsed\n")
        for e in result.parse_errors:
            out.append(f"- {e}")
        out.append("")
    return "\n".join(out)


def render_text(result: ScanResult) -> str:
    s = summarize(result)
    out = []
    for f in result.findings:
        out.append(f"{f.file}:{f.line}:{f.column}: [{f.severity}] {f.rule_id} {f.title}")
        out.append(f"    {f.snippet}")
    if result.parse_errors:
        out.append("")
        out.extend(f"parse error: {e}" for e in result.parse_errors)
    sev = ", ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v) or "none"
    out.append("")
    out.append(f"{s['total']} finding(s) in {result.files_scanned} file(s) [{sev}]")
    return "\n".join(out)


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan source code for hardcoded secrets and risky Python constructs.",
    )
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text",
                   help="report format (default: text)")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="only report findings at or above this severity")
    p.add_argument("--fail-on", choices=SEVERITIES + ["NONE"], default="HIGH",
                   help="exit with status 1 if any finding is at or above this severity (default: HIGH)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. 'tests/*'")
    p.add_argument("--exclude-dir", action="append", default=[], metavar="NAME",
                   help="extra directory name to skip (repeatable)")
    p.add_argument("--no-secrets", action="store_true", help="skip the regex secret scan")
    p.add_argument("--no-code", action="store_true", help="skip the AST code analysis")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"secretscan: path not found: {root}", file=sys.stderr)
        return 2
    if args.no_secrets and args.no_code:
        print("secretscan: nothing to do (both scans disabled)", file=sys.stderr)
        return 2

    exclude_dirs = DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir)
    result = scan_path(root, exclude_dirs, args.exclude,
                       secrets=not args.no_secrets, code=not args.no_code)
    floor = SEV_RANK[args.min_severity]
    result.findings = [f for f in result.findings if SEV_RANK[f.severity] >= floor]

    report = RENDERERS[args.format](result)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        s = summarize(result)
        print(f"Report written to {args.output} ({s['total']} finding(s)).", file=sys.stderr)
    else:
        print(report)

    if args.fail_on != "NONE":
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
