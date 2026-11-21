import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

import secretscan as ss  # noqa: E402
from make_secret_fixtures import write_fixtures  # noqa: E402

# Demo target = committed vulnerable app + runtime-generated fake credentials.
_TMP = None
SAMPLE = None


def setUpModule():
    global _TMP, SAMPLE
    _TMP = tempfile.TemporaryDirectory()
    SAMPLE = Path(_TMP.name) / "demo"
    SAMPLE.mkdir()
    shutil.copy(ROOT / "examples" / "vulnerable_app" / "app.py", SAMPLE / "app.py")
    write_fixtures(SAMPLE)


def tearDownModule():
    _TMP.cleanup()


def code_findings(src: str):
    findings, err = ss.scan_python_ast("t.py", src)
    assert err is None, err
    return findings


def ids(findings):
    return {f.rule_id for f in findings}


def secret_ids(src: str):
    return {f.rule_id for f in ss.scan_text_for_secrets("t.txt", src)}


class SecretRegexTests(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("SEC001", secret_ids('k = "' + "AKIA" + "IOSFODNN7EXAMPLE" + '"'))

    def test_aws_secret_key(self):
        src = 'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/" + 'bPxRfiCYEXAMPLEKEY"'
        self.assertIn("SEC002", secret_ids(src))

    def test_google_api_key(self):
        self.assertIn("SEC003", secret_ids("key=" + "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"))

    def test_private_key_header(self):
        self.assertIn("SEC005", secret_ids("-----BEGIN RSA PRIVATE" + " KEY-----"))

    def test_github_token(self):
        self.assertIn("SEC006", secret_ids("t = " + "ghp_" + "a" * 10 + "B" * 10 + "c" * 10 + "D" * 10))

    def test_url_credentials(self):
        self.assertIn("SEC010", secret_ids("u = 'mysql://root:Tr0ub4dor&3x@host/db'"))

    def test_generic_password_needs_entropy(self):
        self.assertIn("SEC011", secret_ids('db_password = "Xk9#mP2$vL7qZ"'))
        self.assertNotIn("SEC011", secret_ids('db_password = "aaaaaaaaaaaa"'))

    def test_placeholders_ignored(self):
        self.assertFalse(secret_ids('api_key = "your-api-key-here"'))
        self.assertFalse(secret_ids('password = "changeme"'))
        self.assertFalse(secret_ids('secret = "${SECRET_FROM_ENV}"'))

    def test_entry_point_reference_not_a_secret(self):
        self.assertFalse(secret_ids('secretscan = "secretscan:main"'))

    def test_inline_ignore(self):
        line = 'k = "' + "AKIA" + 'IOSFODNN7EXAMPLE"  # secretscan:ignore'
        self.assertFalse(secret_ids(line))

    def test_secret_is_redacted_in_output(self):
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        f = list(ss.scan_text_for_secrets("t.txt", f'k = "{key}"'))[0]
        self.assertNotIn(key, f.snippet)
        self.assertIn("AKIA", f.snippet)

    def test_line_numbers(self):
        src = "x = 1\n\nk = '" + "AKIA" + "IOSFODNN7EXAMPLE'\n"
        f = list(ss.scan_text_for_secrets("t.txt", src))[0]
        self.assertEqual(f.line, 3)

    def test_entropy_function(self):
        self.assertEqual(ss.shannon_entropy("aaaa"), 0)
        self.assertGreater(ss.shannon_entropy("aB3$xY9!"), 2.9)


class ASTTests(unittest.TestCase):
    def test_eval_exec(self):
        f = code_findings("eval(x)\nexec(y)\n")
        self.assertEqual(ids(f), {"PY001", "PY002"})
        self.assertEqual(sorted(x.line for x in f), [1, 2])

    def test_literal_eval_not_flagged(self):
        self.assertFalse(code_findings("import ast\nast.literal_eval(x)\n"))

    def test_sql_injection_variants(self):
        src = (
            "def f(cur, u):\n"
            "    cur.execute(f'SELECT * FROM t WHERE a = {u}')\n"
            "    cur.execute('SELECT * FROM t WHERE a = %s' % u)\n"
            "    cur.execute('SELECT * FROM t WHERE a = ' + u)\n"
            "    cur.execute('SELECT * FROM t WHERE a = {}'.format(u))\n"
        )
        f = [x for x in code_findings(src) if x.rule_id == "PY007"]
        self.assertEqual(sorted(x.line for x in f), [2, 3, 4, 5])

    def test_sql_via_variable(self):
        src = "q = f'DELETE FROM t WHERE id = {i}'\ncur.execute(q)\n"
        self.assertIn("PY007", ids(code_findings(src)))

    def test_parameterized_sql_is_safe(self):
        src = "cur.execute('SELECT * FROM t WHERE a = ?', (u,))\ncur.execute('SELECT 1')\n"
        self.assertNotIn("PY007", ids(code_findings(src)))

    def test_non_sql_fstring_to_execute_is_safe(self):
        self.assertNotIn("PY007", ids(code_findings("cur.execute(f'{name} is cool')\n")))

    def test_import_aliases_resolved(self):
        src = "import subprocess as sp\nfrom pickle import loads as L\nsp.run('x', shell=True)\nL(b)\n"
        self.assertEqual(ids(code_findings(src)), {"PY003", "PY005"})

    def test_shell_false_not_flagged(self):
        self.assertFalse(code_findings("import subprocess\nsubprocess.run(['ls'], shell=False)\n"))

    def test_yaml(self):
        self.assertIn("PY004", ids(code_findings("import yaml\nyaml.load(s)\n")))
        self.assertNotIn("PY004", ids(code_findings("import yaml\nyaml.safe_load(s)\n")))
        self.assertNotIn("PY004", ids(code_findings("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n")))

    def test_weak_hash_and_verify(self):
        src = "import hashlib, requests\nhashlib.md5(b'')\nrequests.get(u, verify=False)\n"
        self.assertEqual(ids(code_findings(src)), {"PY008", "PY009"})

    def test_debug_and_bind_all(self):
        self.assertEqual(ids(code_findings("app.run(host='0.0.0.0', debug=True)\n")), {"PY011", "PY016"})

    def test_hardcoded_credential_assignment(self):
        self.assertIn("PY014", ids(code_findings("db_password = 'hunter2hunter2'\n")))
        self.assertFalse(code_findings("db_password = os.environ['X']\n"))
        self.assertFalse(code_findings("db_password = ''\n"))

    def test_random_only_flagged_in_security_context(self):
        bad = "import random\ndef make_token():\n    return random.randint(1, 9)\n"
        ok = "import random\ndef roll_dice():\n    return random.randint(1, 6)\n"
        self.assertIn("PY013", ids(code_findings(bad)))
        self.assertFalse(code_findings(ok))

    def test_ignore_marker(self):
        self.assertFalse(code_findings("eval(x)  # secretscan:ignore\n"))

    def test_syntax_error_reported_not_raised(self):
        findings, err = ss.scan_python_ast("bad.py", "def (:\n")
        self.assertEqual(findings, [])
        self.assertIn("SyntaxError", err)


class ScanAndReportTests(unittest.TestCase):
    def setUp(self):
        self.result = ss.scan_path(SAMPLE, ss.DEFAULT_EXCLUDE_DIRS, [])

    def test_sample_detects_expected_rules(self):
        found = ids(self.result.findings)
        expected = {"SEC001", "SEC002", "SEC003", "SEC005", "SEC006", "SEC007", "SEC008", "SEC010",
                    "PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007", "PY008",
                    "PY009", "PY011", "PY012", "PY013", "PY014", "PY015", "PY016", "PY010"}
        self.assertTrue(expected <= found, f"missing: {expected - found}")

    def test_sample_ignored_line_not_reported(self):
        lines = [f.line for f in self.result.findings if f.file == "config.py" and f.rule_id == "SEC001"]
        self.assertEqual(len(lines), 1)  # KNOWN_TEST_KEY carries secretscan:ignore

    def test_sorted_by_severity(self):
        ranks = [ss.SEV_RANK[f.severity] for f in self.result.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_json_report_schema(self):
        data = json.loads(ss.render_json(self.result))
        self.assertEqual(data["tool"], "secretscan")
        self.assertEqual(data["summary"]["total"], len(data["findings"]))
        for key in ("rule_id", "severity", "file", "line", "snippet", "remediation"):
            self.assertIn(key, data["findings"][0])

    def test_markdown_report(self):
        md = ss.render_markdown(self.result)
        self.assertIn("# secretscan Report", md)
        self.assertIn("| Severity | Count |", md)
        self.assertIn("`app.py:", md)

    def test_no_raw_secrets_in_any_report(self):
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        for render in ss.RENDERERS.values():
            self.assertNotIn(secret, render(self.result))

    def test_skips_excluded_dirs_and_binaries(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "x.py").write_text("eval(x)\n")
            (root / "blob.bin").write_bytes(b"\x00\x01eval(x)")
            (root / "ok.py").write_text("print('hi')\n")
            res = ss.scan_path(root, ss.DEFAULT_EXCLUDE_DIRS, [])
            self.assertEqual(res.findings, [])
            self.assertEqual(res.files_scanned, 1)


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "secretscan.py"), *args],
                              capture_output=True, text=True)

    def test_exit_code_1_on_findings(self):
        self.assertEqual(self.run_cli(str(SAMPLE)).returncode, 1)

    def test_exit_code_0_when_fail_on_none(self):
        self.assertEqual(self.run_cli(str(SAMPLE), "--fail-on", "NONE").returncode, 0)

    def test_exit_code_0_on_clean_dir(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("print('hello')\n")
            self.assertEqual(self.run_cli(d).returncode, 0)

    def test_missing_path_exit_2(self):
        self.assertEqual(self.run_cli("/no/such/path").returncode, 2)

    def test_min_severity_filter(self):
        out = self.run_cli(str(SAMPLE), "-f", "json", "--min-severity", "CRITICAL", "--fail-on", "NONE")
        data = json.loads(out.stdout)
        self.assertTrue(data["findings"])
        self.assertTrue(all(f["severity"] == "CRITICAL" for f in data["findings"]))

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.md"
            self.run_cli(str(SAMPLE), "-f", "markdown", "-o", str(out))
            self.assertIn("# secretscan Report", out.read_text())


if __name__ == "__main__":
    unittest.main()
