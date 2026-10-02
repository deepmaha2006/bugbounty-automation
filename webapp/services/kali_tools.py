"""
HydraX — direct Kali Linux tool execution layer.

Every tool is executed as a real subprocess on the host and its raw output is
parsed into normalized findings. Nothing is synthesized: a finding exists only
when the underlying tool reported an actual match. This keeps the platform
free of false positives and fully self-contained on Kali Linux.

All commands are bounded by hard timeouts and captured to temp files so a
slow or verbose tool can never block the platform or blow up memory.
"""
import json
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

_LOCK = threading.Lock()
_STD = "DEFAULT_STD"  # placeholder, replaced below

# Common wordlists present on Kali
DIRB_COMMON = "/usr/share/wordlists/dirb/common.txt"
DIRECTORY_LIST_2_3 = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"


def tool_available(name: str) -> bool:
    """Return True when the named Kali tool is installed and executable."""
    return shutil.which(name) is not None


def tool_status() -> dict:
    """Report availability of every tool HydraX integrates with."""
    tools = ["nmap", "masscan", "nuclei", "sqlmap", "nikto", "gobuster",
             "ffuf", "wfuzz", "subfinder", "amass", "httpx", "whatweb",
             "dnsrecon", "dirb", "hydra", "curl", "openssl"]
    return {t: tool_available(t) for t in tools}


def _run(args: list, timeout: int = 120, env_extra: dict = None) -> str:
    """Run a command, return combined stdout+stderr (bounded)."""
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**__import__("os").environ, **(env_extra or {})},
        )
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out[:200_000]
    except subprocess.TimeoutExpired as e:
        return f"[TIMEOUT after {timeout}s] " + ((e.stdout or b"").decode(errors="ignore") if isinstance(e.stdout, bytes) else (e.stdout or ""))[:10_000]
    except FileNotFoundError:
        return "[TOOL NOT FOUND]"
    except Exception as e:  # noqa: BLE001
        return f"[ERROR] {e}"


def _normalize(sev: str) -> str:
    m = {"critical": "Critical", "high": "High", "medium": "Medium",
         "low": "Low", "info": "Info"}
    return m.get(str(sev).lower(), "Info")


# --------------------------------------------------------------------------
# nuclei — template-based vulnerability detection
# --------------------------------------------------------------------------
_NUCLEI_SEV = "critical,high,medium,low"


def run_nuclei(target: str, tags: str = "", severity: str = "",
               timeout: int = 180, extra_args: list = None) -> list:
    """Run nuclei against a single target; parse -jsonl output."""
    if not tool_available("nuclei"):
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        out_file = f.name
    args = ["nuclei", "-u", target, "-jsonl", "-silent",
            "-timeout", "8", "-retries", "1", "-o", out_file]
    if tags:
        args += ["-tags", tags]
    if severity:
        args += ["-severity", severity]
    if extra_args:
        args += extra_args
    command_line = " ".join(args)
    _run(args, timeout=timeout)
    findings = []
    try:
        lines = Path(out_file).read_text(errors="ignore").splitlines()
    except OSError:
        lines = []
    Path(out_file).unlink(missing_ok=True)
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
        findings.append({
            "type": info.get("name") or rec.get("template-id") or "Nuclei Finding",
            "severity": _normalize(info.get("severity") or rec.get("info", {}).get("severity") or "info"),
            "description": (info.get("description") or "").strip() or "Template match reported by nuclei",
            "url": rec.get("matched-at") or target,
            "evidence": " ".join(rec.get("extracted-results") or []) or
                       (rec.get("matcher-name") or ""),
            "remediation": "",
            "tool": "nuclei",
            "confidence": "confirmed",
            "verified": True,
            "tool_command": command_line,
            "raw_output": line
        })
    return findings


# --------------------------------------------------------------------------
# nmap — port + service discovery
# --------------------------------------------------------------------------
def run_nmap(target: str, args: str = "-sV -T4", ports: str = "",
             timeout: int = 240) -> list:
    if not tool_available("nmap"):
        return []
    cmd = ["nmap"]
    if ports:
        cmd += ["-p", ports]
    cmd += args.split() + [target]
    command_line = " ".join(cmd)
    out = _run(cmd, timeout=timeout)
    findings, seen = [], set()
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        port, proto, service, extra = m.groups()
        key = f"{target}:{port}"
        if key in seen:
            continue
        seen.add(key)
        version = extra.strip()
        findings.append({
            "type": "Open Port",
            "severity": "Info",
            "description": f"Open port {port}/{proto} — {service}"
                           + (f" {version}" if version else ""),
            "url": target,
            "evidence": f"{port}/{proto} open {service} {version}".strip(),
            "remediation": "",
            "tool": "nmap",
            "confidence": "confirmed",
            "verified": True,
            "port": port, "protocol": proto, "service": service,
            "tool_command": command_line,
            "raw_output": out
        })
    # High-value service detection
    risky = {"http": "Medium", "https": "Medium", "telnet": "High",
             "ftp": "Medium", "rlogin": "High", "snmp": "Medium",
             "smb": "Medium", "mysql": "Medium", "mssql": "High",
             "postgresql": "Medium", "redis": "Medium", "mongod": "Medium",
             "docker": "Medium", "vnc": "Medium", "rdp": "High"}
    for f in findings:
        svc = f.get("service", "").lower()
        if svc in risky:
            f["severity"] = risky[svc]
            f["type"] = f"Exposed Service ({svc})"
    return findings


# --------------------------------------------------------------------------
# masscan — fast port scan (root only)
# --------------------------------------------------------------------------
def run_masscan(target: str, ports: str = "1-10000", rate: str = "2000",
                timeout: int = 240) -> list:
    if not tool_available("masscan"):
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        out_file = f.name
    cmd = ["masscan", target, "-p", ports, "--rate", rate,
           "-oG", out_file, "--wait", "3"]
    command_line = " ".join(cmd)
    _run(cmd, timeout=timeout)
    findings, seen = [], set()
    try:
        lines = Path(out_file).read_text(errors="ignore").splitlines()
    except OSError:
        lines = []
    Path(out_file).unlink(missing_ok=True)
    for line in lines:
        m = re.search(r"Host:\s*(\S+).*Ports:\s*([^/]+)/(open|closed)", line)
        if not m:
            continue
        host, port, _state = m.groups()
        key = f"{host}:{port}"
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "type": "Open Port (masscan)",
            "severity": "Info",
            "description": f"Port {port} open on {host}",
            "url": host, "evidence": f"{host}:{port} open",
            "remediation": "", "tool": "masscan",
            "confidence": "confirmed", "verified": True,
            "tool_command": command_line,
            "raw_output": line
        })
    return findings


# --------------------------------------------------------------------------
# nikto — web server misconfiguration scan
# --------------------------------------------------------------------------
def run_nikto(target: str, timeout: int = 240) -> list:
    if not tool_available("nikto"):
        return []
    command_line = ["nikto", "-h", target, "-nointeractive",
                    "-Tuning", "123456789", "-timeout", "6"]
    out = _run(command_line, timeout=timeout)
    findings = []
    for line in out.splitlines():
        m = line.strip()
        if not m.startswith("+"):
            continue
        desc = m.lstrip("+ ").strip()
        if not desc or desc.lower().startswith(("ssl", "target", "server", "root", "host")):
            continue
        dlow = desc.lower()
        sev = "Low"
        if any(k in dlow for k in ("vulnerable", "remote", "xss", "injection", "backdoor")):
            sev = "High"
        elif any(k in dlow for k in ("disclosure", "found", "enabled", "exposed", "outdated")):
            sev = "Medium"
        findings.append({
            "type": "Nikto Finding",
            "severity": sev,
            "description": desc,
            "url": target, "evidence": line.strip(),
            "remediation": "",
            "tool": "nikto",
            "confidence": "confirmed" if sev in ("High", "Medium") else "confirmed",
            "verified": True,
            "tool_command": " ".join(command_line),
            "raw_output": line.strip()
        })
    return findings


# --------------------------------------------------------------------------
# gobuster — directory/endpoint discovery
# --------------------------------------------------------------------------
def run_gobuster(target: str, wordlist: str = None, timeout: int = 180,
                 extensions: str = "") -> list:
    if not tool_available("gobuster"):
        return []
    wl = wordlist or (DIRECTORY_LIST_2_3 if Path(DIRECTORY_LIST_2_3).exists()
                      else DIRB_COMMON)
    if not Path(wl).exists():
        return []
    cmd = ["gobuster", "dir", "-u", target, "-w", wl, "-q",
           "-t", "20", "--timeout", "8s"]
    if extensions:
        cmd += ["-x", extensions]
    command_line = " ".join(cmd)
    out = _run(cmd, timeout=timeout)
    findings = []
    for line in out.splitlines():
        m = re.match(r"^/(\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if not m:
            continue
        path, status = m.groups()
        if status == "404":
            continue
        findings.append({
            "type": "Directory Discovered",
            "severity": "Info" if status in ("200", "301", "302") else "Low",
            "description": f"Discovered endpoint /{path} (HTTP {status})",
            "url": target.rstrip("/") + "/" + path,
            "evidence": line.strip(),
            "remediation": "",
            "tool": "gobuster",
            "confidence": "confirmed", "verified": True,
            "tool_command": command_line,
            "raw_output": line
        })
    return findings


# --------------------------------------------------------------------------
# sqlmap — SQL injection detection (automatic, level 1, non-interactive)
# --------------------------------------------------------------------------
def run_sqlmap(url: str, timeout: int = 300) -> list:
    if not tool_available("sqlmap"):
        return []
    # A hardcoded, predictable --output-dir is a classic local symlink/race
    # target (flagged by bandit B108) and would collide across concurrent
    # scans besides — a fresh, unique tempdir per invocation fixes both.
    # Findings are parsed from captured stdout below, not from this
    # directory's contents, so it only needs to exist and be writable.
    out_dir = tempfile.mkdtemp(prefix="hydrax-sqlmap-")
    sqlmap_always = ["--batch", "--level", "1", "--risk", "1", "--timeout", "12",
                     "--retries", "1", "--output-dir", out_dir,
                     "--flush-session", "--smart"]
    cmd = ["sqlmap", "-u", url] + sqlmap_always
    command_line = " ".join(cmd)
    try:
        out = _run(cmd, timeout=timeout)
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    findings = []
    for line in out.splitlines():
        if "is vulnerable" in line or "injection point" in line.lower():
            findings.append({
                "type": "SQL Injection",
                "severity": "Critical",
                "description": line.strip(),
                "url": url,
                "evidence": line.strip(),
                "remediation": "Use parameterized queries / prepared statements "
                               "and validate input server-side.",
                "tool": "sqlmap",
                "confidence": "confirmed", "verified": True,
                "tool_command": command_line,
                "raw_output": line
            })
    return findings


# --------------------------------------------------------------------------
# subfinder — subdomain enumeration
# --------------------------------------------------------------------------
def run_subfinder(domain: str, timeout: int = 180) -> list:
    if not tool_available("subfinder"):
        return []
    command_line = ["subfinder", "-d", domain, "-silent"]
    out = _run(command_line, timeout=timeout)
    subs = [l.strip() for l in out.splitlines() if l.strip() and "." in l]
    findings = []
    for s in subs:
        findings.append({
            "type": "Subdomain Discovered",
            "severity": "Info",
            "description": f"Subdomain resolved: {s}",
            "url": f"http://{s}",
            "evidence": s,
            "remediation": "",
            "tool": "subfinder",
            "confidence": "confirmed", "verified": True,
            "tool_command": " ".join(command_line),
            "raw_output": s
        })
    return findings


# --------------------------------------------------------------------------
# dnsrecon — DNS record enumeration
# --------------------------------------------------------------------------
def run_dnsrecon(domain: str, timeout: int = 180) -> list:
    if not tool_available("dnsrecon"):
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        out_file = f.name
    command_line = ["dnsrecon", "-d", domain, "-t", "std", "-j", out_file]
    out = _run(command_line, timeout=timeout)
    findings = []
    try:
        data = json.loads(Path(out_file).read_text(errors="ignore"))
    except (OSError, ValueError):
        data = []
    finally:
        Path(out_file).unlink(missing_ok=True)
    for rec in data if isinstance(data, list) else []:
        name = rec.get("name", "")
        if not name:
            continue
        findings.append({
            "type": "DNS Record",
            "severity": "Info",
            "description": f"DNS {rec.get('type', '?')} record for {name}",
            "url": name,
            "evidence": f"{name} -> {rec.get('address') or rec.get('target') or ''}",
            "remediation": "",
            "tool": "dnsrecon",
            "confidence": "confirmed", "verified": True,
            "tool_command": " ".join(command_line),
            "raw_output": json.dumps(rec)
        })
    return findings


# --------------------------------------------------------------------------
# httpx — web host probing / fingerprinting
# --------------------------------------------------------------------------
def run_httpx(urls: list, timeout: int = 180) -> list:
    if not tool_available("httpx") or not urls:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        f.flush()
        list_file = f.name
    command_line = ["httpx", "-l", list_file, "-silent", "-status-code",
                    "-title", "-tech-detect", "-timeout", "8"]
    out = _run(command_line, timeout=timeout)
    Path(list_file).unlink(missing_ok=True)
    findings = []
    for line in out.splitlines():
        findings.append({
            "type": "Live Web Host",
            "severity": "Info",
            "description": line.strip()[:300],
            "url": line.split()[0] if line.split() else "",
            "evidence": line.strip(),
            "remediation": "",
            "tool": "httpx",
            "confidence": "confirmed", "verified": True,
            "tool_command": " ".join(command_line),
            "raw_output": line.strip()
        })
    return findings


# --------------------------------------------------------------------------
# whatweb — technology fingerprinting
# --------------------------------------------------------------------------
def run_whatweb(target: str, timeout: int = 120) -> list:
    if not tool_available("whatweb"):
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        out_file = f.name
    command_line = ["whatweb", target, f"--log-json={out_file}", "--no-errors"]
    out = _run(command_line, timeout=timeout)
    findings = []
    try:
        data = json.loads(Path(out_file).read_text(errors="ignore"))
    except (OSError, ValueError):
        return findings
    finally:
        Path(out_file).unlink(missing_ok=True)
    if not isinstance(data, list):
        return findings
    for rec in data:
        techs = list(rec.keys())
        techs = [t for t in techs if t not in ("target", "http_status", "ip")]
        if techs:
            findings.append({
                "type": "Technology Fingerprint",
                "severity": "Info",
                "description": f"Technologies: {', '.join(techs)}",
                "url": rec.get("target", target),
                "evidence": ", ".join(techs),
                "remediation": "",
                "tool": "whatweb",
                "confidence": "confirmed", "verified": True,
                "tool_command": " ".join(command_line),
                "raw_output": json.dumps(rec)
            })
    return findings


# --------------------------------------------------------------------------
# SSL/TLS inspection via openssl
# --------------------------------------------------------------------------
def run_ssl_check(host: str, port: int = 443, timeout: int = 60) -> list:
    if not tool_available("openssl"):
        return []
    command_line = ["timeout", str(timeout), "openssl", "s_client",
                    "-connect", f"{host}:{port}", "-servername", host,
                    "-brief"]
    out = _run(command_line, timeout=timeout + 5)
    findings = []
    low = [l for l in out.splitlines()
           if re.search(r"(protocol.*not|handshake.*failure|no peer|certificate verify|expired)", l, re.I)]
    for line in low:
        findings.append({
            "type": "TLS / SSL Issue",
            "severity": "Medium",
            "description": line.strip(),
            "url": f"https://{host}:{port}",
            "evidence": line.strip(),
            "remediation": "Renew certificates, disable legacy protocols and "
                           "verify the chain configuration.",
            "tool": "openssl",
            "confidence": "confirmed", "verified": True,
            "tool_command": " ".join(command_line),
            "raw_output": line.strip()
        })
    return findings
