"""
HydraX — System / infrastructure scan orchestration.

"Connect to a company's software system": the operator supplies a domain,
host, IP or CIDR range and HydraX performs a real, deep scan of that
infrastructure with the Kali arsenal:

  Phase 1  Recon (parallel)   — subfinder, dnsrecon, whatweb
  Phase 2  Network (parallel) — nmap -sV, masscan (when selected & permitted)
  Phase 3  Web (parallel)     — httpx probe, then nuclei/nikto/gobuster/TLS
                                against every live web host discovered
  Phase 4  Aggregation        — dedupe, severity stats, HTML+JSON report

Every finding is parsed from real tool output. Nothing is synthesized.
"""
import ipaddress
import re
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webapp import db  # noqa: E402
from utils.ssrf_guard import assert_safe_ip_or_cidr, resolve_and_check  # noqa: E402
from webapp.services import alert_engine  # noqa: E402
from webapp.services import events  # noqa: E402
from webapp.services import kali_tools  # noqa: E402
from webapp.services import scan_manager  # noqa: E402
from webapp.services.report_service import generate_html_report, generate_json_report  # noqa: E402

MODE_DEFAULT_TOOLS = {
    "fast": ["nmap", "nuclei", "nikto", "httpx", "subfinder", "whatweb"],
    "full": ["nmap", "masscan", "nuclei", "nikto", "gobuster",
             "httpx", "subfinder", "dnsrecon", "whatweb"],
}


def start_system_scan(user_id: int, target: str, scan_mode: str,
                      tools: list, threads: int = 4) -> int:
    # SSRF self-protection (spec's threat model, docs/THREAT_MODEL.md
    # boundary 5) — system scans explicitly accept raw IPs/CIDR ranges, which
    # is an even sharper risk than web scans: without this, anyone could
    # point nmap/nuclei/nikto at the platform's own internal network (or an
    # entire private /8) just by typing it in. Re-checked here, immediately
    # before the scan is created, not only at some earlier registration step.
    parsed_target = _parse_target(target)
    if parsed_target["is_ip"] or parsed_target["is_cidr"]:
        assert_safe_ip_or_cidr(parsed_target["host"])
    elif parsed_target["domain"]:
        resolve_and_check(parsed_target["domain"])

    # System targets (domain / IP / CIDR) aren't pre-verified web targets.
    # Persist a lightweight targets row so the scans.target_id FK is a real ID.
    try:
        requester = db.get_user_by_id(user_id)
        organization_id = requester["organization_id"] if requester else None
        target_id = db.get_or_create_target(target, organization_id,
                                            verification_method="engagement_letter",
                                            added_by_user_id=user_id)
    except Exception:
        target_id = None
    scan_id = db.create_scan(user_id, target_id, "system",
                             tools or MODE_DEFAULT_TOOLS.get(scan_mode, []))
    events.new_scan_bus(scan_id)
    scan_manager.submit(scan_id, user_id, "system", _run,
                        scan_id, user_id, target, target_id, scan_mode,
                        tools, threads)
    return scan_id


def _emit(scan_id, ev_type, text, **extra):
    events.emit(scan_id, {"type": ev_type, "text": text, **extra})


def _strip_port(raw: str) -> str:
    """'host:port' -> 'host' for a plain IPv4 address or hostname. Never
    touches a CIDR (contains '/') or anything with more than one colon
    (IPv6 literals aren't disambiguated here — no current caller produces
    bracketed IPv6 host:port)."""
    if raw.count(":") == 1 and "/" not in raw:
        host, _, port = raw.rpartition(":")
        if port.isdigit():
            return host
    return raw


# A domain/hostname is passed as a literal argv element to real CLI tools
# (nmap/nikto/whatweb/dirb/...) via webapp/services/kali_tools.py — never
# through a shell, so classic `;`/`|` shell injection isn't possible, but an
# unvalidated value starting with `-` could still be parsed as a FLAG by one
# of those tools (argument injection, e.g. nmap's -oG/-iL/--script). Reject
# anything that isn't a well-formed RFC 1123 hostname before it ever reaches
# a tool invocation.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _parse_target(raw: str) -> dict:
    raw = (raw or "").strip().rstrip("/")
    if not raw:
        raise ValueError("Target cannot be empty")
    parsed = {"raw": raw, "domain": None, "host": None, "is_cidr": False, "is_ip": False}
    # strip scheme if the user pasted a URL
    if raw.startswith(("http://", "https://")):
        raw = urlsplit(raw).netloc or raw
    # A URL's netloc (or a bare "host:port" the caller typed directly) still
    # carries the port at this point — strip it before classifying, so
    # "127.0.0.1:8008" is correctly recognized as the IP 127.0.0.1, not an
    # unparsable domain string (a real bug found while wiring up Phase 7's
    # SSRF guard: this used to silently fall through to the "domain" branch
    # below, carrying a port that would then fail DNS resolution outright).
    raw = _strip_port(raw)
    try:
        net = ipaddress.ip_network(raw, strict=False)
        parsed["is_cidr"] = True
        parsed["host"] = str(net.network_address)
        return parsed
    except ValueError:
        pass
    try:
        ipaddress.ip_address(raw)
        parsed["is_ip"] = True
        parsed["host"] = raw
        return parsed
    except ValueError:
        pass
    # domain / hostname
    if not _HOSTNAME_RE.match(raw):
        raise ValueError(f"'{raw}' is not a valid hostname, IP, or CIDR range")
    parsed["domain"] = raw.lower()
    parsed["host"] = raw.lower()
    return parsed


def _run(scan_id, user_id, target, target_id, scan_mode, tools, threads) -> None:
    db.update_scan(scan_id, status="running", phase="Parsing target",
                   progress=0.02, started_at=db._now())
    try:
        t = _parse_target(target)
        mode_tools = tools or MODE_DEFAULT_TOOLS.get(scan_mode, [])
        ts = set(mode_tools)
        all_findings = []

        # ---------------- Phase 1: Recon (parallel) -----------------------
        db.update_scan(scan_id, phase="Reconnaissance", progress=0.08)
        _emit(scan_id, "phase", "Reconnaissance",
              message="subfinder / dnsrecon / whatweb — parallel")
        recon_jobs = []
        if "subfinder" in ts and t["domain"]:
            recon_jobs.append(("subfinder",
                               lambda d=t["domain"]: kali_tools.run_subfinder(d)))
        if "dnsrecon" in ts and t["domain"]:
            recon_jobs.append(("dnsrecon",
                               lambda d=t["domain"]: kali_tools.run_dnsrecon(d)))
        if "whatweb" in ts and t["host"] and not t["is_cidr"]:
            recon_jobs.append(("whatweb",
                               lambda h=t["host"]: kali_tools.run_whatweb(
                                   "http://" + h if not t["is_ip"] else "http://" + h)))
        if recon_jobs:
            with ThreadPoolExecutor(max_workers=len(recon_jobs)) as ex:
                futures = [ex.submit(fn) for _n, fn in recon_jobs]
                for fut in futures:
                    res = fut.result(timeout=600)
                    all_findings.extend(res)

        subdomains = [f["evidence"] for f in all_findings
                      if f.get("type") == "Subdomain Discovered"]
        _emit(scan_id, "status",
              f"Recon complete: {len(subdomains)} subdomains, "
              f"{sum(1 for f in all_findings if f.get('type') == 'DNS Record')} DNS records")

        # ---------------- Phase 2: Network scan (parallel) ----------------
        db.update_scan(scan_id, phase="Network scanning", progress=0.3)
        _emit(scan_id, "phase", "Network scanning",
              message="nmap -sV + masscan — parallel")
        net_jobs = []
        if "nmap" in ts:
            net_jobs.append(lambda: kali_tools.run_nmap(t["host"], args="-sV -T4"))
        if "masscan" in ts and (t["is_cidr"] or t["is_ip"]):
            net_jobs.append(lambda: kali_tools.run_masscan(t["host"]))
        if "masscan" in ts and not (t["is_cidr"] or t["is_ip"]):
            _emit(scan_id, "status", "masscan skipped: supply an IP or CIDR range")
        if net_jobs:
            with ThreadPoolExecutor(max_workers=len(net_jobs)) as ex:
                futures = [ex.submit(j) for j in net_jobs]
                for fut in futures:
                    res = fut.result(timeout=600)
                    all_findings.extend(res)
        open_ports = [f for f in all_findings if f.get("type", "").startswith("Open Port")]
        _emit(scan_id, "status", f"Network scan complete: {len(open_ports)} open ports")

        # ---------------- Phase 3: Web scans (parallel) -------------------
        db.update_scan(scan_id, phase="Web service testing", progress=0.55)
        _emit(scan_id, "phase", "Web service testing",
              message="httpx probe → nuclei / nikto / gobuster on live hosts")
        probe_targets = []
        if t["host"]:
            probe_targets.append(f"http://{t['host']}" if t["is_ip"] or t["is_cidr"]
                                 else f"https://{t['host']}")
        probe_targets += [f"https://{s}" for s in subdomains[:12]]

        live_urls = []
        if "httpx" in ts:
            httpx_findings = kali_tools.run_httpx(probe_targets[:20])
            for f in httpx_findings:
                live_urls.append(f["url"])
            all_findings.extend(httpx_findings)
        else:
            live_urls = probe_targets[:6]
        _emit(scan_id, "status", f"Live web hosts: {len(live_urls)}")

        web_jobs = []
        for url in live_urls[:8]:
            if "nuclei" in ts:
                web_jobs.append(lambda u=url: kali_tools.run_nuclei(
                    u, tags="exposure,tech,default-login,misconfig,config"))
            if "nikto" in ts:
                web_jobs.append(lambda u=url: kali_tools.run_nikto(u))
            if "gobuster" in ts:
                web_jobs.append(lambda u=url: kali_tools.run_gobuster(u))
            if url.startswith("https://"):
                host = urlsplit(url).netloc
                web_jobs.append(lambda h=host: kali_tools.run_ssl_check(h))
        if web_jobs:
            with ThreadPoolExecutor(max_workers=min(6, len(web_jobs))) as ex:
                futures = [ex.submit(j) for j in web_jobs]
                for fut in futures:
                    res = fut.result(timeout=900)
                    all_findings.extend(res)

        # ---------------- Phase 4: Aggregate + persist ---------------------
        db.update_scan(scan_id, phase="Aggregating", progress=0.9)
        all_findings = _dedupe([_normalize(f) for f in all_findings])
        for f in all_findings:
            result = db.add_finding(scan_id, f)
            if result["is_new_or_reopened"]:
                alert_engine.maybe_alert(result["finding_id"])
            _emit(scan_id, "finding", **{k: f[k] for k in
                   ("severity", "type", "description", "evidence", "url",
                    "remediation", "tool", "parameter", "payload") if k in f})

        stats = _build_stats(all_findings)
        db.update_scan(scan_id, status="completed", progress=1.0,
                       phase="Complete",
                       message=f"Found {len(all_findings)} findings",
                       stats=stats, finished_at=db._now())

        html_path = generate_html_report(scan_id, target, "system",
                                         all_findings, stats)
        db.add_report(scan_id, target_id, "system", "html", str(html_path))
        json_path = generate_json_report(scan_id, target, "system",
                                         all_findings, stats)
        db.add_report(scan_id, target_id, "system", "json", str(json_path))
        _emit(scan_id, "done", "Scan complete", report=str(html_path),
              total=len(all_findings))

    except Exception as e:  # noqa: BLE001
        db.update_scan(scan_id, status="error", phase="Error",
                       message=str(e), finished_at=db._now())
        _emit(scan_id, "error", f"Scan failed: {e}")
        traceback.print_exc()
    finally:
        _emit(scan_id, "phase", "Scan finished")


def _normalize(f: dict) -> dict:
    sev = str(f.get("severity", "Info") or "Info")
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}
    sev = sev_map.get(sev.lower(), sev if sev in
                      ("Critical", "High", "Medium", "Low", "Info") else "Info")
    return {
        "severity": sev,
        "type": f.get("type") or "Finding",
        "description": f.get("description") or "",
        "evidence": f.get("evidence") or "",
        "url": f.get("url") or "",
        "remediation": f.get("remediation") or "",
        "tool": f.get("tool") or "kali",
        "parameter": f.get("parameter"),
        "payload": f.get("payload"),
        "confidence": f.get("confidence", "confirmed"),
        "verified": bool(f.get("verified", True)),
        "tool_command": f.get("tool_command", ""),
        "raw_output": f.get("raw_output", "")
    }


def _dedupe(findings: list) -> list:
    seen, out = set(), []
    for f in findings:
        key = (f["type"], f["url"], f["severity"], f.get("evidence", "")[:60])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _build_stats(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    weights = {"Critical": -40, "High": -20, "Medium": -10, "Low": -3, "Info": 0}
    score = 100 + sum(counts[s] * weights[s] for s in counts)
    score = max(0, min(100, score))
    return {"total_findings": len(findings), **counts, "security_score": score}
