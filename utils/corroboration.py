"""
Tool corroboration layer.

After HydraX's heuristic flags a candidate finding, run the relevant
mature tool against the SAME endpoint and update the finding's confidence
only when the tool independently agrees.

Rules
-----
- A candidate becomes confirmed when: (HydraX heuristic) AND at least ONE of:
    * corroborating tool agrees
    * active re-proof passes
    * OOB callback arrives
- If the corroborating tool is absent (not installed), the finding stays
  unconfirmed and is returned unchanged.
- Every tool call is a bounded arg-list subprocess (no shell=True) with a
  hard timeout and captured output.
- Record which oracle fired in finding["confirmation"].

References
----------
- Nuclei:  https://github.com/projectdiscovery/nuclei
- sqlmap:  https://github.com/sqlmapproject/sqlmap
- Dalfox:  https://github.com/hahwul/dalfox
- httpx:   https://github.com/projectdiscovery/httpx
"""

import os
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webapp.services.kali_tools import tool_available, run_nuclei


# ---------------------------------------------------------------------------
# XSS — corroborate via dalfox
# ---------------------------------------------------------------------------

def corroborate_xss(url: str, param: str, payload: str = "",
                    timeout: int = 60) -> Optional[dict]:
    """Run dalfox against a URL+param to corroborate an XSS candidate.

    Returns a confirmation dict when dalfox confirms, None otherwise.
    If dalfox is not installed, returns None (finding stays unconfirmed).
    """
    if not tool_available("dalfox"):
        return None

    cmd = [
        "dalfox", "url", url,
        "--param", param,
        "--silence",
        "--no-color",
        "--timeout", str(timeout),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if "[POC]" in output or "FOUND XSS" in output.upper():
            poc_line = next(
                (line for line in output.splitlines() if "[POC]" in line),
                output[:200],
            )
            return {
                "method": "tool",
                "oracle": "dalfox confirmed XSS execution",
                "evidence": poc_line.strip()[:500],
                "reproduced": True,
                "corroborating_tool": "dalfox",
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# SQL injection — corroborate via sqlmap
# ---------------------------------------------------------------------------

def corroborate_sqli(url: str, timeout: int = 120) -> Optional[dict]:
    """Run sqlmap (bounded: level=1, risk=1) to corroborate a SQLi candidate.

    Returns a confirmation dict when sqlmap reports injectable, None otherwise.
    If sqlmap is not installed, returns None.
    """
    if not tool_available("sqlmap"):
        return None

    out_dir = tempfile.mkdtemp(prefix="hydrax-corr-sqlmap-")
    cmd = [
        "sqlmap", "-u", url,
        "--batch", "--level", "1", "--risk", "1",
        "--timeout", "10", "--retries", "1",
        "--output-dir", out_dir,
        "--flush-session", "--smart",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (result.stdout or "") + (result.stderr or "")
        if "is vulnerable" in out or "injection point" in out.lower():
            match_line = next(
                (
                    line for line in out.splitlines()
                    if "is vulnerable" in line or "injection point" in line.lower()
                ),
                out[:200],
            )
            return {
                "method": "tool",
                "oracle": "sqlmap confirmed SQL injection",
                "evidence": match_line.strip()[:500],
                "reproduced": True,
                "corroborating_tool": "sqlmap",
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return None


# ---------------------------------------------------------------------------
# Misconfiguration / exposure — corroborate via nuclei
# ---------------------------------------------------------------------------

def corroborate_misconfig(
    url: str,
    template_tags: str = "misconfig,exposure",
    timeout: int = 120,
) -> List[dict]:
    """Run nuclei with misconfig/exposure tags to corroborate misconfig candidates.

    Returns a list of confirmation dicts (one per nuclei match).
    Returns [] when nuclei is not installed or finds nothing.
    """
    if not tool_available("nuclei"):
        return []

    findings = run_nuclei(url, tags=template_tags, timeout=timeout)
    results = []
    for f in findings:
        results.append({
            "method": "tool",
            "oracle": f"nuclei template match: {f.get('type', 'unknown')}",
            "evidence": str(f.get("evidence", ""))[:500],
            "reproduced": True,
            "corroborating_tool": "nuclei",
            "nuclei_finding": f,
        })
    return results


# ---------------------------------------------------------------------------
# Header / status probing — corroborate via httpx
# ---------------------------------------------------------------------------

def corroborate_with_httpx(url: str, timeout: int = 30) -> Optional[dict]:
    """Use httpx to probe headers/status for missing-header / tech findings.

    Returns a confirmation dict with the actual header probe evidence.
    Returns None when httpx is not installed or probe fails.
    """
    if not tool_available("httpx"):
        return None

    cmd = [
        "httpx", "-u", url,
        "-silent", "-status-code", "-response-time",
        "-timeout", str(timeout),
        "-json",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        out = result.stdout.strip()
        if out:
            return {
                "method": "tool",
                "oracle": "httpx header probe",
                "evidence": out[:500],
                "reproduced": True,
                "corroborating_tool": "httpx",
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None
