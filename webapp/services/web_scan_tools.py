"""
HydraX — Kali tool orchestration for web scans.

Selected vulnerability types map to real Kali tools (nuclei, sqlmap, nmap,
nikto, gobuster, ...) executed directly on the host via
webapp.services.kali_tools. All tool groups run in parallel; every finding is
parsed from real tool output — nothing is synthesized.
"""
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from webapp.services import kali_tools

# vuln-type key -> (tool, params) for targeted scans
TOOL_MAP = {
    "sqli":          ("sqlmap", {}),
    "xss":           ("nuclei", {"tags": "xss"}),
    "rce":           ("nuclei", {"tags": "rce,lfi,command-injection,ssti"}),
    "ssrf":          ("nuclei", {"tags": "ssrf"}),
    "api":           ("nuclei", {"tags": "api,graphql,exposure"}),
    "sub_takeover":  ("nuclei", {"tags": "takeover"}),
    "proto_pollution": ("nuclei", {"tags": "prototype-pollution"}),
    "xml":           ("nuclei", {"tags": "xxe,xml"}),
    "open_redirect": ("nuclei", {"tags": "redirect"}),
    "info_disclosure": ("nuclei", {"tags": "exposure,config,misconfig,secrets"}),
    "sec_misconfig": ("nuclei", {"tags": "misconfig,exposure"}),
    "cloud":         ("nuclei", {"tags": "cloud,s3,storage"}),
    "websocket":     ("nuclei", {"tags": "websocket"}),
    "cache":         ("nuclei", {"tags": "cache"}),
    "smuggling":     ("nuclei", {"tags": "smuggling,desync"}),
    "llm":           ("nuclei", {"tags": "ai,llm,prompt-injection"}),
    "ddos":          ("nuclei", {"tags": "dos,panic,ratelimit"}),
}


def _generic_jobs(target: str) -> list:
    """Recon jobs that run for every web scan regardless of vuln selection."""
    return [
        lambda: kali_tools.run_nmap(target, args="-sV -T4"),
        lambda: kali_tools.run_nikto(target),
        lambda: kali_tools.run_gobuster(target),
    ]


def _run_generic(target: str) -> list:
    """Run the always-on recon tools in parallel."""
    jobs = _generic_jobs(target)
    if target.startswith("https://"):
        host = urlsplit(target).netloc
        jobs.append(lambda h=host: kali_tools.run_ssl_check(h))
    out = []
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futures = [ex.submit(j) for j in jobs]
        for fut in futures:
            try:
                res = fut.result(timeout=600)
                if isinstance(res, list):
                    out.extend(res)
            except Exception:  # noqa: BLE001
                continue
    return out


def run_web_tools(target: str, vuln_types: list) -> list:
    """Run the Kali tools mapped to the selected vuln types, in parallel.

    Returns a flat list of normalized finding dicts parsed from real output.
    """
    findings = []
    selected = set(vuln_types)
    jobs = []

    # Targeted nuclei scans per selected vuln type
    for key, (_tool, params) in TOOL_MAP.items():
        if key not in selected:
            continue
        tags = params.get("tags", "")
        jobs.append(lambda t=target, tg=tags: kali_tools.run_nuclei(t, tags=tg))

    # Deep SQLi verification via sqlmap when selected
    if "sqli" in selected:
        jobs.append(lambda: kali_tools.run_sqlmap(target))

    # Generic recon (nmap / nikto / gobuster / TLS) — internally parallel
    jobs.append(lambda: _run_generic(target))

    if not jobs:
        return findings

    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
        futures = [ex.submit(j) for j in jobs]
        for fut in futures:
            try:
                res = fut.result(timeout=900)
                if isinstance(res, list):
                    findings.extend(res)
            except Exception:  # noqa: BLE001
                continue

    return findings
