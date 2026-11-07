"""Tiny read-only HTTP wrapper for BreachBench inside a Tinfoil enclave (stdlib only)."""
import json, os, subprocess, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_URL = os.environ.get("BB_URL", "https://inference.tinfoil.sh/v1").rstrip("/")
MODEL = os.environ.get("BB_MODEL", "gemma4-31b")
API_KEY = os.environ.get("TINFOIL_API_KEY", "")
RESULTS = os.environ.get("BB_RESULTS", "/tmp/results")
DATA = os.environ.get("BB_DATA", "/app/data/hf")
ALLOWED_SUITES = {"ih", "jbb", "all"}
state = {"running": False, "started": None, "finished": None, "rc": None, "suite": None, "limit": None}
lock = threading.Lock()

def key_ready():
    """True if the API key is present (no network call, no spend)."""
    return bool(API_KEY)

def run_job(suite, limit):
    os.makedirs(RESULTS, exist_ok=True)
    cmd = ["python", "/app/scripts/hf_suite.py", "run", "--suite", suite, "--limit", str(limit),
           "--compare", "--model", MODEL, "--base-url", BASE_URL,
           "--spotlight-mode", "selective", "--reasoning-effort", "omit", "--max-tokens", "512",
           "--out", f"{RESULTS}/latest.json", "--md", f"{RESULTS}/latest.md"]
    if os.environ.get("BB_PASS_DATA_DIR") == "1":
        cmd += ["--data-dir", DATA]
    with open(f"{RESULTS}/run.log", "w") as log:
        env = dict(os.environ, BB_API_KEY=API_KEY)  # hf_suite reads BB_API_KEY -> Bearer header
        rc = subprocess.call(cmd, cwd="/app", stdout=log, stderr=subprocess.STDOUT, env=env)
    with lock:
        state.update(running=False, finished=time.time(), rc=rc)

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "api_key_present": key_ready(), "base_url": BASE_URL, "model": MODEL, **state})
        if self.path in ("/results", "/results.md"):
            f = f"{RESULTS}/latest.json" if self.path == "/results" else f"{RESULTS}/latest.md"
            if not os.path.exists(f):
                return self._send(404, {"error": "no results yet", **state})
            ctype = "application/json" if f.endswith("json") else "text/markdown"
            return self._send(200, open(f, "rb").read(), ctype)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            suite = body.get("suite", "all"); limit = int(body.get("limit", 25))
        except Exception:
            return self._send(400, {"error": "bad json"})
        if suite not in ALLOWED_SUITES or not 1 <= limit <= 25:
            return self._send(400, {"error": "suite must be ih|jbb|all, limit 1-25"})
        if not key_ready():
            return self._send(503, {"error": "TINFOIL_API_KEY secret missing"})
        with lock:
            if state["running"]:
                return self._send(409, {"error": "run already in progress", **state})
            state.update(running=True, started=time.time(), finished=None, rc=None, suite=suite, limit=limit)
        threading.Thread(target=run_job, args=(suite, limit), daemon=True).start()
        self._send(202, {"accepted": True, **state})

ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
