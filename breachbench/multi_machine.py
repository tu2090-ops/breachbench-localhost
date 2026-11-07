"""
BreachBench Permission-Gated Multi-Machine Runner.
Enforces explicit owner authorization before deploying or running BreachBench
over SSH across local/lab machines. Logs every invocation to an immutable JSONL audit trail.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MACHINES_FILE = ROOT_DIR / "config" / "machines.example.json"
DEFAULT_AUDIT_LOG = ROOT_DIR / "results" / "deployment_audit.jsonl"

AUTHORIZATION_PHRASE = "YES_I_HAVE_AUTHORIZATION"


def load_machines_manifest(
    machines_csv: Optional[str] = None,
    machines_file: Optional[str | Path] = None,
) -> List[Dict[str, Any]]:
    """Load target machine specifications from a JSON allowlist or comma-separated host list."""
    if machines_csv:
        hosts = [h.strip() for h in machines_csv.split(",") if h.strip()]
        return [
            {
                "name": f"cli-host-{idx + 1}",
                "host": h.split("@")[-1] if "@" in h else h,
                "ssh_user": h.split("@")[0] if "@" in h else "ubuntu",
                "port": 22,
                "authorized": True,
                "owner_approval": "Explicit CLI --machines flag with permission confirmation",
                "workdir": "/tmp/breachbench-eval",
            }
            for idx, h in enumerate(hosts)
        ]

    manifest_path = Path(machines_file) if machines_file else DEFAULT_MACHINES_FILE
    if not manifest_path.exists():
        raise FileNotFoundError(f"Machines manifest not found: {manifest_path}")
    data = json.loads(manifest_path.read_text())
    return list(data.get("machines", []))


def verify_explicit_permission(confirm_permission: bool, interactive: bool = True) -> bool:
    """Verify explicit user authorization via flag or interactive confirmation phrase."""
    if confirm_permission:
        return True
    if not interactive or not sys.stdin.isatty():
        return False
    print("\n======================================================================")
    print("  BreachBench Multi-Machine Permission Gate")
    print("======================================================================")
    print("You are requesting to deploy/execute BreachBench across local/SSH hosts.")
    print(f"Type '{AUTHORIZATION_PHRASE}' to confirm you have explicit owner permission:")
    try:
        answer = input("> ").strip()
    except EOFError:
        return False
    return answer == AUTHORIZATION_PHRASE


def append_audit_entry(entry: Dict[str, Any], audit_log_path: Path = DEFAULT_AUDIT_LOG) -> None:
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def deploy_machines(
    machines_csv: Optional[str] = None,
    machines_file: Optional[str | Path] = None,
    confirm_permission: bool = False,
    execute_ssh: bool = False,
    provider: str = "deterministic",
    model: str = "gpt-4.1-mini",
    interactive: bool = True,
    audit_log_path: Path = DEFAULT_AUDIT_LOG,
) -> Dict[str, Any]:
    """
    Validate explicit permission, filter allowlisted machines, and run (or dry-run)
    BreachBench installation & evaluation over SSH.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    permitted = verify_explicit_permission(confirm_permission, interactive=interactive)

    if not permitted:
        audit_record = {
            "timestamp_utc": now_iso,
            "status": "blocked_missing_permission",
            "reason": (
                f"Multi-machine deployment refused: caller did not supply --confirm-permission "
                f"or interactive '{AUTHORIZATION_PHRASE}' confirmation."
            ),
        }
        append_audit_entry(audit_record, audit_log_path=audit_log_path)
        return {
            "status": "blocked_missing_permission",
            "authorized": False,
            "audit_log": str(audit_log_path),
            "message": audit_record["reason"],
        }

    machines = load_machines_manifest(machines_csv=machines_csv, machines_file=machines_file)
    host_results: List[Dict[str, Any]] = []

    for m in machines:
        host = m.get("host", "127.0.0.1")
        user = m.get("ssh_user", "ubuntu")
        port = int(m.get("port", 22))
        workdir = m.get("workdir", "/tmp/breachbench-eval")
        is_auth = bool(m.get("authorized", False))

        if not is_auth:
            host_results.append({
                "name": m.get("name", host),
                "host": host,
                "status": "skipped_unauthorized_in_allowlist",
                "authorized": False,
                "owner_approval": m.get("owner_approval", "None"),
                "detail": "Host has 'authorized': false in allowlist manifest; skipped by permission gate.",
            })
            continue

        remote_cmd = (
            f"mkdir -p {shlex.quote(workdir)} && "
            f"python3 -m breachbench benchmark --out {shlex.quote(workdir)}/report.json && "
            f"python3 -m breachbench eval-agent --provider {shlex.quote(provider)} --model {shlex.quote(model)}"
        )
        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            "-p", str(port),
            f"{user}@{host}",
            remote_cmd,
        ]

        if not execute_ssh:
            host_results.append({
                "name": m.get("name", host),
                "host": host,
                "ssh_user": user,
                "port": port,
                "authorized": True,
                "status": "dry_run_ready",
                "planned_ssh_command": " ".join(shlex.quote(part) for part in ssh_cmd),
                "owner_approval": m.get("owner_approval", "Verified"),
            })
        else:
            try:
                proc = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                host_results.append({
                    "name": m.get("name", host),
                    "host": host,
                    "ssh_user": user,
                    "port": port,
                    "authorized": True,
                    "status": "executed" if proc.returncode == 0 else "ssh_error",
                    "exit_code": proc.returncode,
                    "stdout_preview": proc.stdout[:400],
                    "stderr_preview": proc.stderr[:400],
                })
            except Exception as exc:
                host_results.append({
                    "name": m.get("name", host),
                    "host": host,
                    "authorized": True,
                    "status": "ssh_exception",
                    "detail": str(exc)[:200],
                })

    summary = {
        "timestamp_utc": now_iso,
        "status": "completed",
        "authorized": True,
        "mode": "ssh_execute" if execute_ssh else "dry_run",
        "total_hosts_in_manifest": len(machines),
        "authorized_hosts_count": sum(1 for r in host_results if r.get("authorized")),
        "skipped_unauthorized_count": sum(1 for r in host_results if not r.get("authorized")),
        "audit_log": str(audit_log_path),
        "hosts": host_results,
    }
    append_audit_entry(summary, audit_log_path=audit_log_path)
    return summary
