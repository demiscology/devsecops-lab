"""
INSECURE BY DESIGN — a deliberately vulnerable Flask app for a DevSecOps lab.

Every route below contains a classic, well-known vulnerability so that the
security scanners in the CI pipeline have something real to find. DO NOT copy
any of these patterns into production code. Each flaw is annotated with the
vulnerability class and the CWE id (the industry-standard "Common Weakness
Enumeration" catalogue that most tools map their findings to).

Runs with zero external services: it creates a local SQLite database on start,
so it works the same on your laptop and inside the Docker container that the
DAST (OWASP ZAP) job scans.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, g, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULN: Hardcoded secrets (CWE-798: Use of Hard-coded Credentials).
# Secrets scanners (Gitleaks/TruffleHog) and SAST (Semgrep/Bandit) both flag
# these. In reality a secret like this would come from an environment variable
# or a secrets manager (Vault, AWS Secrets Manager), never the source tree.
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = "sup3r-s3cret-flask-key-do-not-commit"
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
DB_PATH = "users.db"


def get_db():
    """Open (and cache per-request) a SQLite connection."""
    if "db" not in g.__dict__:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception):  # noqa: ARG001
    db = g.__dict__.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Seed a tiny users table so the SQL-injection demo has data to leak."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        [
            ("alice", "password123", "alice@example.com"),
            ("bob", "hunter2", "bob@example.com"),
            ("admin", "admin", "admin@example.com"),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return (
        "<h1>DevSecOps Lab — Vulnerable App</h1>"
        "<p>Deliberately insecure. Try these routes:</p>"
        "<ul>"
        "<li><a href='/search?username=alice'>/search?username=alice</a> (SQL injection)</li>"
        "<li><a href='/greet?name=World'>/greet?name=World</a> (reflected XSS)</li>"
        "<li><a href='/ping?host=127.0.0.1'>/ping?host=127.0.0.1</a> (command injection)</li>"
        "<li><a href='/hash?password=test'>/hash?password=test</a> (weak hashing)</li>"
        "<li>/fetch?url=... (SSRF) &middot; /load (insecure deserialization)</li>"
        "</ul>"
    )


@app.route("/search")
def search():
    """
    VULN: SQL Injection (CWE-89). The username is concatenated straight into
    the query string. Try /search?username=alice' OR '1'='1 to dump every row.
    The fix is a parameterised query: cursor.execute(sql, (username,)).
    """
    username = request.args.get("username", "")
    db = get_db()
    query = "SELECT id, username, email FROM users WHERE username = '%s'" % username
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as exc:
        return "SQL error: %s" % exc, 500
    return {"query": query, "results": rows}


@app.route("/greet")
def greet():
    """
    VULN: Reflected Cross-Site Scripting (CWE-79). User input is echoed into
    HTML without escaping. Try /greet?name=<script>alert(1)</script>.
    SAST sees the tainted sink in code; DAST (ZAP) proves it fires at runtime.
    """
    name = request.args.get("name", "friend")
    return "<h1>Hello, " + name + "!</h1>"


@app.route("/ping")
def ping():
    """
    VULN: OS Command Injection (CWE-78). The host is passed to a shell.
    Try /ping?host=127.0.0.1;id to run arbitrary commands.
    The fix: never use shell=True with user input; pass an argument list.
    """
    host = request.args.get("host", "127.0.0.1")
    # shell=True + string concatenation is the dangerous combination.
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return "<pre>" + result.decode(errors="replace") + "</pre>"


@app.route("/hash")
def weak_hash():
    """
    VULN: Use of a Broken/Weak Hash (CWE-327). MD5 is unsuitable for passwords.
    Real password storage uses a slow, salted KDF such as bcrypt/argon2/scrypt.
    """
    password = request.args.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()  # noqa: S324
    return {"algorithm": "md5", "digest": digest}


@app.route("/fetch")
def fetch():
    """
    VULN: Server-Side Request Forgery (CWE-918). The server fetches any URL the
    client supplies, so an attacker can reach internal services / cloud metadata
    (e.g. http://169.254.169.254/). The fix is an allow-list of hosts.
    """
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, timeout=5)  # no allow-list, no timeout governance
    return resp.text[:500]


@app.route("/load", methods=["POST"])
def load():
    """
    VULN: Insecure Deserialization (CWE-502). Both pickle.loads and yaml.load
    on untrusted input can execute arbitrary code. Use yaml.safe_load / JSON.
    """
    data = request.get_data()
    try:
        obj = pickle.loads(data)  # noqa: S301
    except Exception:
        obj = yaml.load(data, Loader=yaml.Loader)  # noqa: S506
    return {"loaded": str(obj)}


if __name__ == "__main__":
    init_db()
    # VULN: Debug mode exposes the interactive Werkzeug debugger (RCE) and
    # binding to 0.0.0.0 listens on every interface (CWE-215 / CWE-668).
    app.run(host="0.0.0.0", port=5000, debug=True)  # noqa: S104,S201
