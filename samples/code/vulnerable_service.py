"""
Synthetic vulnerable service fixture for testing `breachbench scan-code`.
Contains intentional OWASP / CWE vulnerabilities for static analysis verification.
"""
import hashlib
import os
import pickle
import random
import subprocess
import requests
import yaml

OPENAI_API_KEY = "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"

def get_account_by_name(cursor, name: str):
    # CWE-89: SQL Injection
    query = f"SELECT * FROM accounts WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_diagnostic(host: str):
    # CWE-78: Command Injection
    os.system("ping -c 1 " + host)
    return subprocess.run(f"traceroute {host}", shell=True)

def fetch_preview(url: str):
    # CWE-918: SSRF & Unvalidated Redirects
    return requests.get(url, allow_redirects=True, timeout=5).text

def get_note_vuln(note_id: str, notes_store: dict):
    # CWE-639 / API1:2023 BOLA: Missing tenant/account ownership check
    return notes_store.get(note_id)

def load_untrusted_state(blob: bytes, raw_yaml: str):
    # CWE-502: Unsafe Deserialization
    data = pickle.loads(blob)
    cfg = yaml.load(raw_yaml, Loader=yaml.Loader)
    return data, cfg

def read_template(user_path: str):
    # CWE-22: Path Traversal
    with open("/var/app/templates/" + user_path, "r") as f:
        return f.read()

def legacy_password_hash(password: str):
    # CWE-327: Weak Crypto
    return hashlib.md5(password.encode()).hexdigest(), random.random()
