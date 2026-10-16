"""
test_target.py — deliberately vulnerable demo file
====================================================
This file contains intentional security vulnerabilities used to
demonstrate that RepoSentinel detects them correctly.

Run:  python scanner.py . --output demo_report
      (from the reposentinel directory)

It should produce findings for every rule in scanner.py.
Do NOT deploy this code anywhere.
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import sqlite3
import requests
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CWE-798: Hardcoded credentials
# Rule: SECRET-001
# ─────────────────────────────────────────────────────────────────────────────

DATABASE_PASSWORD = "hunter2_production"   # hardcoded DB password
api_key           = "sk-live-9f3kQx82mPzT"
SECRET_KEY        = "flask-secret-do-not-share"
AWS_SECRET        = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# ─────────────────────────────────────────────────────────────────────────────
# CWE-78: Shell injection
# Rules: SHELL-001, SHELL-002, SHELL-003
# ─────────────────────────────────────────────────────────────────────────────

def ping_host(hostname):
    """Pings a host. Vulnerable because hostname is unsanitised."""
    os.system(f"ping -c 1 {hostname}")                              # SHELL-001


def list_directory(path):
    """Lists a directory. Vulnerable because shell=True is set."""
    subprocess.call(f"ls -la {path}", shell=True)                   # SHELL-002


def run_user_expression(expression):
    """Evaluates a user-supplied expression. Never do this."""
    result = eval(expression)                                        # SHELL-003
    return result


# ─────────────────────────────────────────────────────────────────────────────
# CWE-502: Unsafe deserialisation
# Rules: DESER-001, DESER-003
# ─────────────────────────────────────────────────────────────────────────────

def load_session(raw_bytes):
    """Restores a session from bytes. Vulnerable to pickle deserialization."""
    session_data = pickle.loads(raw_bytes)                          # DESER-001
    return session_data


def load_config(config_file):
    """Loads YAML config. Vulnerable because no Loader is specified."""
    with open(config_file) as f:
        config = yaml.load(f)                                       # DESER-003
    return config


# ─────────────────────────────────────────────────────────────────────────────
# CWE-295: TLS certificate verification disabled
# Rule: TLS-001
# ─────────────────────────────────────────────────────────────────────────────

def fetch_internal_api(endpoint):
    """Fetches from an internal API with TLS verification disabled."""
    response = requests.get(endpoint, verify=False)                 # TLS-001
    return response.json()


# ─────────────────────────────────────────────────────────────────────────────
# CWE-94: Server-Side Template Injection (SSTI)
# Rule: SSTI-001
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/greet")
def greet():
    """
    Vulnerable: the template is built from user input.
    An attacker can send: ?name={{ config }} to dump secrets,
    or craft a Jinja2 payload for remote code execution.
    """
    name     = request.args.get("name", "World")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)                         # SSTI-001


# ─────────────────────────────────────────────────────────────────────────────
# CWE-601: Open redirect
# Rules: REDIR-001, REDIR-002
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login")
def login():
    """Vulnerable: redirect target comes straight from the query string."""
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)                                       # REDIR-001


@app.route("/logout")
def logout():
    """Vulnerable: intermediate variable, but still unvalidated."""
    destination = request.form.get("return_to", "/")
    return redirect(destination)                                    # REDIR-002


# ─────────────────────────────────────────────────────────────────────────────
# CWE-327: Weak hash function
# Rule: CRYPTO-001
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(plain_text_password):
    """
    Vulnerable: MD5 is broken for security use.
    It is fast (trivially brute-forced) and has known collision attacks.
    """
    return hashlib.md5(plain_text_password.encode()).hexdigest()    # CRYPTO-001


def generate_token(data):
    """Vulnerable: SHA-1 is deprecated for security-sensitive uses."""
    return hashlib.sha1(data.encode()).hexdigest()                  # CRYPTO-001


# ─────────────────────────────────────────────────────────────────────────────
# CWE-89: SQL injection via string building
# Rules: SQLI-001, SQLI-002
# ─────────────────────────────────────────────────────────────────────────────

def get_user_by_id(user_id):
    """Vulnerable: user_id is interpolated directly into the SQL string."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")     # SQLI-001
    return cursor.fetchone()


def search_products(keyword):
    """Vulnerable: .format() used to build a SQL query."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query  = "SELECT * FROM products WHERE name LIKE '%{}%'".format(keyword)
    cursor.execute(query)                                           # SQLI-002
    return cursor.fetchall()
