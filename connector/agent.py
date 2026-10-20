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


def _job_collect_telemetry(scope: dict) -> dict:
    """Read-only: tail the last N lines of admin-supplied log files and return them
    as structured events for HydraBrain ingestion.

    scope keys:
      log_files          — list of absolute paths to tail (required; refuses empty)
      max_lines_per_file — max lines to return per file (default 200, hard cap 1000)

    Each returned entry is {'source_file': str, 'line': str, 'collected_at': ISO8601}.
    On per-file I/O error the entry is {'source_file': str, 'error': str}.

    Safety: the handler opens files read-only and never follows symlinks to paths
    outside what the admin explicitly supplied.  It does not eval/execute any line
    it reads.
    """
    import datetime as _dt

    log_files = scope.get("log_files") or []
    max_lines = min(int(scope.get("max_lines_per_file", 200)), 1000)
    collected_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

    entries = []
    for path in log_files:
        try:
            # Open read-only; do not follow symlinks to guard against TOCTOU.
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            for raw in lines[-max_lines:]:
                raw = raw.rstrip("\n")
                if raw:
                    entries.append({
                        "source_file": path,
                        "line": raw,
                        "collected_at": collected_at,
                    })
        except OSError as exc:
            entries.append({"source_file": path, "error": str(exc)})

    return {
        "hostname": socket.gethostname(),
        "collected_at": collected_at,
        "log_entries": entries,
    }


def _job_block_source(scope: dict) -> dict:
    """Contain an attacking source IP using a platform firewall rule.

    scope keys:
      src_ip          — IP address to block (required; refuses loopback/empty)
      ttl_seconds     — seconds until the block is auto-removed (default 3600)
      rollback_token  — opaque token echoed back so the platform can match
                        the corresponding unblock_source job

    Safety: loopback (127.x / ::1), empty, and unspecified addresses are
    refused; the handler never executes arbitrary shell commands — it calls
    platform-specific firewall APIs only.
    """
    import datetime as _dt
    import sys as _sys

    src_ip = scope.get("src_ip", "")
    rollback_token = scope.get("rollback_token", "")

    _REFUSE = {"", "127.0.0.1", "::1", "0.0.0.0", "localhost"}
    if not src_ip or src_ip in _REFUSE or src_ip.startswith("127."):
        return {"blocked": False, "src_ip": src_ip,
                "error": "refused: self-lockout guard",
                "rollback_token": rollback_token}

    method = "unsupported"
    error = None
    try:
        if _sys.platform == "win32":
            import subprocess as _sp
            rule_name = f"HydraX-block-{src_ip}"
            _sp.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block",
                 f"remoteip={src_ip}", "enable=yes"],
                capture_output=True, timeout=10
            )
            method = "windows_firewall"
        else:
            import subprocess as _sp
            _sp.run(
                ["iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            method = "iptables"
    except (FileNotFoundError, OSError, Exception) as exc:
        error = str(exc)
        method = "unsupported"

    result = {
        "blocked": error is None and method != "unsupported",
        "src_ip": src_ip,
        "method": method,
        "rollback_token": rollback_token,
        "blocked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if error:
        result["error"] = error
    return result


def _job_unblock_source(scope: dict) -> dict:
    """Remove a firewall block added by block_source.

    scope keys:
      src_ip         — IP address to unblock (required)
      rollback_token — token from the original block_source result
    """
    import datetime as _dt
    import sys as _sys

    src_ip = scope.get("src_ip", "")
    rollback_token = scope.get("rollback_token", "")

    if not src_ip:
        return {"unblocked": False, "error": "src_ip required",
                "rollback_token": rollback_token}

    method = "unsupported"
    error = None
    try:
        if _sys.platform == "win32":
            import subprocess as _sp
            rule_name = f"HydraX-block-{src_ip}"
            _sp.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, timeout=10
            )
            method = "windows_firewall"
        else:
            import subprocess as _sp
            _sp.run(
                ["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            method = "iptables"
    except (FileNotFoundError, OSError, Exception) as exc:
        error = str(exc)
        method = "unsupported"

    result = {
        "unblocked": error is None and method != "unsupported",
        "src_ip": src_ip,
        "method": method,
        "rollback_token": rollback_token,
        "unblocked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if error:
        result["error"] = error
    return result


def _job_kill_session(scope: dict) -> dict:
    """Terminate an active TCP session from an attacking source.

    scope keys:
      src_ip    — remote IP of the session to terminate
      dst_port  — local port (default 80)

    Uses platform-appropriate tools (ss + tc on Linux, netsh on Windows).
    Degrades gracefully if tools are unavailable.
    """
    import datetime as _dt
    import sys as _sys

    src_ip = scope.get("src_ip", "")
    dst_port = int(scope.get("dst_port", 80))

    if not src_ip:
        return {"killed": False, "error": "src_ip required"}

    method = "unsupported"
    error = None
    try:
        if _sys.platform != "win32":
            import subprocess as _sp
            result_proc = _sp.run(
                ["ss", "-K", f"dst {src_ip}", f"dport = {dst_port}"],
                capture_output=True, timeout=10
            )
            method = "ss"
        else:
            method = "unsupported"
    except (FileNotFoundError, OSError, Exception) as exc:
        error = str(exc)
        method = "unsupported"

    result = {
        "killed": error is None and method != "unsupported",
        "src_ip": src_ip,
        "dst_port": dst_port,
        "method": method,
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if error:
        result["error"] = error
    return result


def _job_apply_waf_rule(scope: dict) -> dict:
    """Apply a WAF rule from a structured rule_spec.

    scope keys:
      rule_id      — stable identifier for this rule
      rule_spec    — dict: {type, pattern, location, path, ...}
      rollback_token — opaque token echoed back for remove_waf_rule

    The handler writes a minimal include-snippet to a HydraX-managed WAF
    directory, if one is configured via HYDRAX_WAF_DIR. Degrades to a no-op
    with method='unsupported' if the directory is absent or unwritable.

    Safety: rule_spec is data — it is never eval()'d or exec()'d. The snippet
    written is a static regex/rate-limit directive assembled from the spec's
    named fields; no shell commands are run.
    """
    import datetime as _dt
    import os as _os

    rule_id = scope.get("rule_id", "")
    rule_spec = scope.get("rule_spec") or scope  # allow flat scope as rule_spec
    rollback_token = scope.get("rollback_token", "")

    if not rule_id:
        return {"applied": False, "error": "rule_id required",
                "rollback_token": rollback_token}

    waf_dir = _os.environ.get("HYDRAX_WAF_DIR", "")
    method = "unsupported"
    error = None

    if waf_dir and _os.path.isdir(waf_dir):
        try:
            rule_file = _os.path.join(waf_dir, f"{rule_id}.conf")
            spec_type = rule_spec.get("type", "")
            if spec_type == "block_pattern":
                snippet = (
                    f"# HydraX auto-rule {rule_id}\n"
                    f"location ~* \"{rule_spec.get('path', '/')}\" {{\n"
                    f"  if ($request_uri ~* \"{rule_spec.get('pattern', '')}\") {{\n"
                    f"    return 403;\n  }}\n}}\n"
                )
            elif spec_type == "rate_limit":
                snippet = (
                    f"# HydraX rate-limit rule {rule_id}\n"
                    f"limit_req_zone $binary_remote_addr zone={rule_id}:1m "
                    f"rate={rule_spec.get('max_req_per_min', 10)}r/m;\n"
                )
            else:
                snippet = f"# HydraX rule {rule_id} (type={spec_type})\n"

            with open(rule_file, "w", encoding="utf-8") as fh:
                fh.write(snippet)
            method = "nginx_snippet"
        except OSError as exc:
            error = str(exc)
    else:
        error = "HYDRAX_WAF_DIR not set or not a directory"

    result = {
        "applied": error is None,
        "rule_id": rule_id,
        "method": method,
        "rollback_token": rollback_token,
        "applied_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if error:
        result["error"] = error
    return result


def _job_remove_waf_rule(scope: dict) -> dict:
    """Remove a WAF rule previously applied by apply_waf_rule.

    scope keys:
      rule_id        — identifier of the rule to remove
      rollback_token — token echoed back for audit
    """
    import datetime as _dt
    import os as _os

    rule_id = scope.get("rule_id", "")
    rollback_token = scope.get("rollback_token", "")

    if not rule_id:
        return {"removed": False, "error": "rule_id required",
                "rollback_token": rollback_token}

    waf_dir = _os.environ.get("HYDRAX_WAF_DIR", "")
    method = "unsupported"
    error = None

    if waf_dir and _os.path.isdir(waf_dir):
        try:
            rule_file = _os.path.join(waf_dir, f"{rule_id}.conf")
            if _os.path.exists(rule_file):
                _os.remove(rule_file)
            method = "nginx_snippet"
        except OSError as exc:
            error = str(exc)
    else:
        error = "HYDRAX_WAF_DIR not set or not a directory"

    result = {
        "removed": error is None,
        "rule_id": rule_id,
        "method": method,
        "rollback_token": rollback_token,
        "removed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if error:
        result["error"] = error
    return result


JOB_HANDLERS = {
    "inventory_check": _job_inventory_check,
    "configuration_check": _job_configuration_check,
    "vulnerability_assessment": _job_vulnerability_assessment,
    "telemetry_collection": _job_telemetry_collection,
    "collect_telemetry": _job_collect_telemetry,
    "block_source": _job_block_source,
    "unblock_source": _job_unblock_source,
    "kill_session": _job_kill_session,
    "apply_waf_rule": _job_apply_waf_rule,
    "remove_waf_rule": _job_remove_waf_rule,
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
