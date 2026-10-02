#!/usr/bin/env python3
"""
HydraX Company Connector agent (spec §5, §6).

A standalone artifact meant to be installed inside a customer's authorized
environment — deliberately independent of the rest of this repository
(imports nothing from webapp/core/scanners/utils) so it can be copied to a
machine that has none of that installed. Only two third-party packages are
required: `requests` and `cryptography` (pip install requests cryptography).

Security model (docs/SECURITY_MODEL.md §4 — read that before touching this
file):
  * The connector generates its own Ed25519 keypair locally at enrollment.
    The private key NEVER leaves this machine — not in a request body, not
    in a log line, nowhere.
  * Every job the platform sends is signed with the platform's own
    job-signing key. This agent verifies that signature, the expiry, and
    that job_type is one of the 4 allowlisted types (JOB_HANDLERS below)
    BEFORE calling the corresponding handler. There is no code path here
    that takes a job-supplied string and eval()s/exec()s/shells it out —
    job_type selects one of a fixed set of Python functions; the job's
    `scope` is only ever passed as *data* into that fixed function, never
    interpreted as code.
  * Every result this agent sends back is signed with its own private key,
    so the platform can detect tampering in transit and hold this specific
    connector identity accountable for what it reports.

Usage:
    python agent.py enroll --server https://hydrax.example.com --token <TOKEN> --name "prod-dc1"
    python agent.py run    --server https://hydrax.example.com
"""
import argparse
import json
import os
import shutil
import socket
import sys
import time
import traceback
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IDENTITY_DIR = Path(os.environ.get("HYDRAX_CONNECTOR_HOME", str(Path.home() / ".hydrax-connector")))
IDENTITY_FILE = IDENTITY_DIR / "identity.json"
HEARTBEAT_INTERVAL_SECONDS = 30
POLL_INTERVAL_SECONDS = 10
REQUEST_TIMEOUT_SECONDS = 15


# --- crypto (mirrors webapp/services/connector_crypto.py's canonical form) --
def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(private_key_pem: str, payload: dict) -> str:
    import base64
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return base64.b64encode(key.sign(canonical_bytes(payload))).decode()


def verify(public_key_pem: str, payload: dict, signature_b64: str) -> bool:
    import base64
    from cryptography.exceptions import InvalidSignature
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
        key.verify(base64.b64decode(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- identity (private key never leaves this file) --------------------------
def _save_identity(data: dict) -> None:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(IDENTITY_FILE, 0o600)  # best-effort; no-op on platforms without POSIX perms
    except OSError:
        pass


def _load_identity() -> dict:
    if not IDENTITY_FILE.exists():
        print(f"No identity found at {IDENTITY_FILE}. Run 'enroll' first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(IDENTITY_FILE.read_text())


# --- allowlisted job handlers -------------------------------------------------
# This is the entire attack surface for "what can the platform make this
# connector do" — a fixed dict of functions, each taking only `scope` as
# structured data. Adding a capability means adding a function here and
# reviewing it, never accepting a new kind of instruction from a job payload.
def _job_inventory_check(scope: dict) -> dict:
    """Read-only host inventory — no customer-specific assumptions, works
    the same shape on Windows/Linux/macOS."""
    import platform as _platform
    info = {
        "hostname": socket.gethostname(),
        "os": _platform.system(),
        "os_release": _platform.release(),
        "python_version": _platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    try:
        usage = shutil.disk_usage(scope.get("path", "/"))
        info["disk_total_bytes"] = usage.total
        info["disk_free_bytes"] = usage.free
    except OSError as e:
        info["disk_error"] = str(e)
    return info


def _job_configuration_check(scope: dict) -> dict:
    """Checks file permissions on an admin-supplied, explicitly authorized
    path list (scope['paths']) — never a path this agent invents itself.
    Flags world-writable files, a common, real misconfiguration class."""
    findings = []
    for path in scope.get("paths", []):
        try:
            mode = os.stat(path).st_mode
            world_writable = bool(mode & 0o002)
            findings.append({"path": path, "exists": True, "world_writable": world_writable})
        except OSError as e:
            findings.append({"path": path, "exists": False, "error": str(e)})
    return {"checked": len(findings), "findings": findings}


def _job_vulnerability_assessment(scope: dict) -> dict:
    """Non-destructive: attempts a local TCP connect to each admin-supplied
    port on localhost (scope['ports']) to report what's actually listening —
    never a network scan of anything beyond this host itself."""
    results = []
    for port in scope.get("ports", [22, 80, 443, 3306, 5432, 6379, 27017]):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            open_ = sock.connect_ex(("127.0.0.1", int(port))) == 0
        except (OSError, ValueError):
            open_ = False
        finally:
            sock.close()
        results.append({"port": port, "listening": open_})
    return {"host": socket.gethostname(), "ports": results}


def _job_telemetry_collection(scope: dict) -> dict:
    """Basic health telemetry — degrades gracefully on platforms without a
    given stdlib facility rather than crashing the whole job."""
    telemetry = {"hostname": socket.gethostname(), "uptime_seconds": None, "load_average": None}
    try:
        telemetry["load_average"] = os.getloadavg()  # POSIX only
    except (AttributeError, OSError):
        pass
    try:
        import psutil  # optional; not a hard dependency of this agent
        telemetry["uptime_seconds"] = time.time() - psutil.boot_time()
        telemetry["memory_percent"] = psutil.virtual_memory().percent
    except ImportError:
        pass
    return telemetry


JOB_HANDLERS = {
    "inventory_check": _job_inventory_check,
    "configuration_check": _job_configuration_check,
    "vulnerability_assessment": _job_vulnerability_assessment,
    "telemetry_collection": _job_telemetry_collection,
}


# --- enrollment ---------------------------------------------------------------
def cmd_enroll(args):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
    pub_pem = pub.public_bytes(serialization.Encoding.PEM,
                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    resp = requests.post(f"{args.server}/api/connectors/enroll", json={
        "enrollment_token": args.token, "name": args.name,
        "public_key_pem": pub_pem, "version": "1.0.0",
        "os": f"{sys.platform}",
    }, timeout=REQUEST_TIMEOUT_SECONDS)
    resp.raise_for_status()
    body = resp.json()

    _save_identity({
        "server": args.server,
        "connector_id": body["connector_id"],
        "connector_secret": body["connector_secret"],
        "private_key_pem": priv_pem,
        "platform_public_key_pem": body["platform_public_key_pem"],
    })
    print(f"Enrolled as connector {body['connector_id']}. Identity saved to {IDENTITY_FILE}.")
    print("Run 'python agent.py run' to start.")


# --- main loop ------------------------------------------------------------
def _headers(identity: dict) -> dict:
    return {"X-Connector-Secret": identity["connector_secret"]}


def _execute_job(identity: dict, job: dict) -> None:
    # Every field GET .../jobs/next returns except `signature` itself is
    # part of what that signature covers (see webapp/schemas.py::
    # SignedJobOut and connector_crypto.job_signing_payload) — reconstruct
    # exactly that payload.
    payload = {
        "job_id": job["job_id"], "organization_id": job["organization_id"],
        "connector_id": job["connector_id"], "job_type": job["job_type"],
        "scope": job["scope"], "authorization": job["authorization"],
        "created_at": job["created_at"], "expires_at": job["expires_at"],
    }
    if not verify(identity["platform_public_key_pem"], payload, job["signature"]):
        print(f"Job {job['job_id']}: signature verification FAILED — refusing to execute.", file=sys.stderr)
        return

    import datetime
    expires_at = datetime.datetime.fromisoformat(job["expires_at"].replace("Z", "+00:00"))
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if datetime.datetime.now(datetime.timezone.utc) >= expires_at:
        print(f"Job {job['job_id']}: expired — refusing to execute.", file=sys.stderr)
        return

    handler = JOB_HANDLERS.get(job["job_type"])
    if handler is None:
        # Can't happen if the platform only ever sends allowlisted types, but
        # fail closed rather than guess if it somehow did.
        print(f"Job {job['job_id']}: unknown job_type '{job['job_type']}' — refusing to execute.", file=sys.stderr)
        return

    try:
        result = handler(job.get("scope") or {})
    except Exception as e:  # noqa: BLE001 — a handler bug must not crash the agent loop
        result = {"error": str(e), "traceback": traceback.format_exc()}

    signature = sign(identity["private_key_pem"], result)
    r = requests.post(
        f"{identity['server']}/api/connectors/jobs/{job['job_id']}/result",
        headers=_headers(identity), json={"result": result, "signature": signature},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if r.status_code == 200:
        print(f"Job {job['job_id']} ({job['job_type']}): completed and reported.")
    else:
        print(f"Job {job['job_id']}: result submission failed ({r.status_code}): {r.text}", file=sys.stderr)


def cmd_run(args):
    identity = _load_identity()
    last_heartbeat = 0.0
    print(f"HydraX connector {identity['connector_id']} running against {identity['server']}. Ctrl+C to stop.")
    while True:
        now = time.time()
        try:
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                requests.post(f"{identity['server']}/api/connectors/me/heartbeat",
                             headers=_headers(identity),
                             json={"version": "1.0.0", "os": sys.platform},
                             timeout=REQUEST_TIMEOUT_SECONDS)
                last_heartbeat = now

            r = requests.get(f"{identity['server']}/api/connectors/me/jobs/next",
                            headers=_headers(identity), timeout=REQUEST_TIMEOUT_SECONDS)
            if r.status_code == 403:
                print("This connector has been revoked by the platform. Exiting.", file=sys.stderr)
                return
            job = r.json() if r.status_code == 200 else None
            if job:
                _execute_job(identity, job)
        except requests.RequestException as e:
            print(f"Communication error (will retry): {e}", file=sys.stderr)

        time.sleep(POLL_INTERVAL_SECONDS)


def main():
    parser = argparse.ArgumentParser(description="HydraX Company Connector agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enroll = sub.add_parser("enroll", help="Enroll this machine as a connector")
    p_enroll.add_argument("--server", required=True, help="Platform base URL, e.g. https://hydrax.example.com")
    p_enroll.add_argument("--token", required=True, help="Single-use enrollment token from an org admin")
    p_enroll.add_argument("--name", required=True, help="A name for this connector")
    p_enroll.set_defaults(func=cmd_enroll)

    p_run = sub.add_parser("run", help="Run the connector loop (heartbeat + job polling)")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
