#!/usr/bin/env python3
"""
HydraX Server Agent v1.0
========================
Install this on a target server to enable remote continuous scanning from HydraX.

Usage:
    python server_agent.py --key YOUR_API_KEY [--port 7474] [--host 0.0.0.0]

HydraX connects to http://<server>:<port> and authenticates with the API key.
"""
from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

VERSION = "1.0.0"


class ScanJob:
    def __init__(self, job_id: str, target: str, modules: List[str]):
        self.id          = job_id
        self.target      = target
        self.modules     = modules
        self.status      = "queued"
        self.progress    = 0.0
        self.findings:   List[Dict[str, Any]] = []
        self.log:        List[str] = []
        self.started_at: Optional[float] = None
        self.ended_at:   Optional[float] = None
        self._thread:    Optional[threading.Thread] = None

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "target":     self.target,
            "modules":    self.modules,
            "status":     self.status,
            "progress":   self.progress,
            "findings":   self.findings,
            "log":        self.log[-50:],
            "started_at": self.started_at,
            "ended_at":   self.ended_at,
        }


_jobs: Dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()


def _run_cmd(cmd: List[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except FileNotFoundError:
        return f"[tool not found: {cmd[0]}]"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


def _run_nmap(target: str, job: ScanJob) -> None:
    job.log.append(f"[nmap] Scanning {target}...")
    out = _run_cmd(["nmap", "-sV", "--open", "-T4", target], timeout=180)
    for line in out.splitlines():
        if ("/tcp" in line or "/udp" in line) and "open" in line:
            job.findings.append({
                "type": "Open Port",
                "severity": "Info",
                "description": line.strip(),
                "url": target,
                "tool": "nmap",
            })
    job.log.append(f"[nmap] Done — {sum(1 for f in job.findings if f['tool']=='nmap')} ports found")


def _run_nikto(target: str, job: ScanJob) -> None:
    job.log.append(f"[nikto] Scanning {target}...")
    out = _run_cmd(["nikto", "-h", target, "-Format", "txt", "-nointeractive"], timeout=240)
    for line in out.splitlines():
        if line.startswith("+ ") and len(line) > 4:
            sev = "High" if any(k in line.lower() for k in ["inject", "xss", "exec", "rce"]) else "Medium"
            job.findings.append({
                "type": "Nikto Finding",
                "severity": sev,
                "description": line[2:].strip(),
                "url": target,
                "tool": "nikto",
            })
    job.log.append("[nikto] Done")


def _run_nuclei(target: str, job: ScanJob) -> None:
    job.log.append(f"[nuclei] Scanning {target}...")
    out = _run_cmd(["nuclei", "-u", target, "-silent", "-json"], timeout=300)
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}
    for line in out.splitlines():
        try:
            d = json.loads(line)
            job.findings.append({
                "type": d.get("template-id", "Nuclei Finding"),
                "severity": sev_map.get(d.get("info", {}).get("severity", "info"), "Info"),
                "description": d.get("info", {}).get("description", ""),
                "url": d.get("matched-at", target),
                "tool": "nuclei",
                "cve": d.get("info", {}).get("classification", {}).get("cve-id", [""])[0],
            })
        except (json.JSONDecodeError, KeyError):
            pass
    job.log.append("[nuclei] Done")


def _run_whatweb(target: str, job: ScanJob) -> None:
    job.log.append(f"[whatweb] Fingerprinting {target}...")
    out = _run_cmd(["whatweb", "--no-errors", target], timeout=60)
    if out and "[tool not found" not in out:
        job.findings.append({
            "type": "Technology Fingerprint",
            "severity": "Info",
            "description": out[:500],
            "url": target,
            "tool": "whatweb",
        })
    job.log.append("[whatweb] Done")


_MODULE_RUNNERS = {
    "nmap":    _run_nmap,
    "nikto":   _run_nikto,
    "nuclei":  _run_nuclei,
    "whatweb": _run_whatweb,
}


def _execute_scan(job: ScanJob) -> None:
    job.status     = "running"
    job.started_at = time.time()
    modules = job.modules or list(_MODULE_RUNNERS.keys())
    step = 1.0 / max(len(modules), 1)
    for i, mod in enumerate(modules):
        if mod in _MODULE_RUNNERS:
            try:
                _MODULE_RUNNERS[mod](job.target, job)
            except Exception as e:
                job.log.append(f"[{mod}] Error: {e}")
        job.progress = round((i + 1) * step, 2)
    job.status   = "done"
    job.progress = 1.0
    job.ended_at = time.time()
    job.log.append(f"Scan complete — {len(job.findings)} findings")


_API_KEY: str = ""


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _auth(self) -> bool:
        return self.headers.get("X-HydraX-Key", "") == _API_KEY

    def _json(self, code: int, data: Any) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/ping":
            self._json(200, {
                "status": "ok", "version": VERSION,
                "tools": {t: bool(shutil.which(t)) for t in ("nmap", "nikto", "nuclei", "whatweb")},
            })
            return

        if not self._auth():
            self._json(401, {"error": "Unauthorized"}); return

        if path == "/scans":
            with _jobs_lock:
                self._json(200, [j.to_dict() for j in _jobs.values()])
            return

        parts = path.split("/")
        if len(parts) == 3 and parts[1] == "scan":
            with _jobs_lock:
                job = _jobs.get(parts[2])
            self._json(200, job.to_dict()) if job else self._json(404, {"error": "not found"})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if not self._auth():
            self._json(401, {"error": "Unauthorized"}); return

        if path == "/scan":
            body   = self._read_body()
            target = body.get("target", "")
            if not target:
                self._json(400, {"error": "target required"}); return
            job = ScanJob(str(uuid.uuid4()), target,
                          body.get("modules", list(_MODULE_RUNNERS.keys())))
            with _jobs_lock:
                _jobs[job.id] = job
            t = threading.Thread(target=_execute_scan, args=(job,), daemon=True)
            job._thread = t
            t.start()
            self._json(202, {"scan_id": job.id, "status": "queued"})
            return

        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._auth():
            self._json(401, {"error": "Unauthorized"}); return
        parts = urlparse(self.path).path.rstrip("/").split("/")
        if len(parts) == 3 and parts[1] == "scan":
            with _jobs_lock:
                job = _jobs.pop(parts[2], None)
            if job:
                job.status = "cancelled"
                self._json(200, {"cancelled": parts[2]})
            else:
                self._json(404, {"error": "not found"})
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    global _API_KEY
    parser = argparse.ArgumentParser(description="HydraX Server Agent")
    parser.add_argument("--key",  default="", help="API key")
    parser.add_argument("--port", type=int, default=7474)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    if not args.key:
        args.key = secrets.token_hex(16)
        print(f"[agent] No --key provided. Generated key: {args.key}")
        print("[agent] Add to HydraX Company Scanner connection settings.")

    _API_KEY = args.key
    server = HTTPServer((args.host, args.port), AgentHandler)
    print(f"[agent] HydraX Server Agent v{VERSION} listening on {args.host}:{args.port}")
    print(f"[agent] API key: {_API_KEY}")
    available = ", ".join(t for t in ("nmap", "nikto", "nuclei", "whatweb") if shutil.which(t))
    print(f"[agent] Available tools: {available or 'none detected'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[agent] Stopped.")


if __name__ == "__main__":
    main()
