"""DELIBERATELY INSECURE demo app for exercising secretscan.

Every credential below is fake. Provider-format tokens (AWS, Google, Slack, ...) are
generated at runtime by examples/make_secret_fixtures.py instead of living in this file.
Do not copy any of this code into a real project.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

# --- hardcoded secrets --------------------------------------------------
DB_PASSWORD = "Sup3rS3cretP@ssw0rd!"
ADMIN_PASSWORD = "letmein"  # too short for the regex pass; the AST pass catches it
DATABASE_URL = "postgres://admin:hunter2hunter2@db.internal.example.com:5432/prod"

# These are fine and should NOT be reported:
SAFE_PASSWORD = os.environ.get("APP_PASSWORD")
PLACEHOLDER_KEY = "your-api-key-here"


@app.route("/user")
def get_user():
    uid = request.args["id"]
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # SQL injection: f-string, % formatting, concatenation and .format()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    cur.execute("SELECT * FROM users WHERE name = '%s'" % uid)
    cur.execute("SELECT * FROM users WHERE name = '" + uid + "'")
    cur.execute("DELETE FROM sessions WHERE user = '{}'".format(uid))
    query = f"UPDATE users SET seen = 1 WHERE id = {uid}"
    cur.execute(query)
    # Safe, parameterized version (not reported):
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cur.fetchall())


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/run")
def run_cmd():
    subprocess.run("ls " + request.args["d"], shell=True)
    os.system("echo " + request.args["msg"])
    return "ok"


def load_session(blob: bytes):
    return pickle.loads(blob)


def load_config(text: str):
    return yaml.load(text)


def safe_config(text: str):
    return yaml.safe_load(text)  # not reported


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def fetch(url: str):
    return requests.get(url, verify=False)


def make_reset_token():
    return str(random.randint(100000, 999999))


def scratch_file():
    return tempfile.mktemp()


def check_admin(user):
    assert user.is_admin, "not allowed"
    try:
        exec(user.startup_script)
    except:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
