"""
Hardened reference service fixture for testing `breachbench scan-code`.
Zero vulnerabilities should be reported on this file.
"""
import hashlib
import os
import secrets
import subprocess
from pathlib import Path
import yaml

def get_account_by_name_safe(cursor, name: str):
    cursor.execute("SELECT * FROM accounts WHERE name = ?", (name,))
    return cursor.fetchall()

def run_diagnostic_safe():
    return subprocess.run(["/usr/bin/uptime"], shell=False, check=True, capture_output=True, text=True)

def get_note_safe(note_id: str, account_id: str, notes_store: dict):
    note = notes_store.get(note_id)
    if not note or note.get("owner_account_id") != account_id:
        raise PermissionError("Not authorized for this tenant scope")
    return note

def load_config_safe(raw_yaml: str):
    return yaml.safe_load(raw_yaml)

def hash_password_safe(password: str):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return digest.hex(), secrets.token_urlsafe(32)
