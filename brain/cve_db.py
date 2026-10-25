"""
Local CVE intelligence — no external API.

Maintains a small in-process database of high-impact CVE patterns.
Used by the brain for finding enrichment and severity correlation.

Actual NVD lookups can be added on top when network is available,
but the base patterns work fully offline.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Embedded high-impact CVE pattern DB
# Keep entries minimal — one line each so this file stays readable.
# Format: (pattern, CVE-ID, CVSS, description)
# ---------------------------------------------------------------------------
_CVE_PATTERNS: List[Tuple[str, str, float, str]] = [
    # Web app vulnerabilities
    (r"log4j|jndi:ldap",          "CVE-2021-44228",  10.0, "Log4Shell — JNDI injection in Log4j"),
    (r"spring\.cloud\.gateway",    "CVE-2022-22947",  10.0, "Spring Cloud Gateway SPEL injection"),
    (r"confluent|cve-2022-26134",  "CVE-2022-26134",  9.8,  "Confluence OGNL injection RCE"),
    (r"shellshock|bash.*env",      "CVE-2014-6271",   9.8,  "Shellshock — Bash env var injection"),
    (r"heartbleed|openssl.*leak",  "CVE-2014-0160",   7.5,  "Heartbleed — OpenSSL memory disclosure"),
    (r"drupal.*ajax|drupalgeddon", "CVE-2018-7600",   9.8,  "Drupalgeddon2 — unauthenticated RCE"),
    (r"wordpress.*xmlrpc",         "CVE-2020-28037",  9.8,  "WordPress xmlrpc.php brute-force/RCE"),
    (r"struts2|ognl.*inject",      "CVE-2017-5638",   10.0, "Apache Struts2 OGNL injection"),
    (r"phpmyadmin.*setup",         "CVE-2018-12613",  7.5,  "phpMyAdmin LFI via SetupController"),
    (r"weblogic.*t3",              "CVE-2020-14882",  9.8,  "Oracle WebLogic Console RCE"),
    (r"exchange.*ecp",             "CVE-2021-26855",  9.8,  "Microsoft Exchange ProxyLogon SSRF"),
    (r"citrix.*gateway.*cve",      "CVE-2019-19781",  9.8,  "Citrix ADC directory traversal"),
    (r"fortinet.*vpn",             "CVE-2018-13379",  9.8,  "FortiOS path traversal credential leak"),
    (r"pulse.*vpn.*unauthorized",  "CVE-2019-11510",  10.0, "Pulse Secure VPN arbitrary file read"),
    # Injection
    (r"' OR '1'='1|UNION SELECT",  "CWE-89",          8.0,  "SQL Injection pattern detected"),
    (r"<script.*alert|onerror=",   "CWE-79",          6.1,  "Cross-Site Scripting (XSS) pattern"),
    (r"169\.254\.169\.254",        "CWE-918",         9.0,  "SSRF targeting cloud metadata service"),
    (r"\.\./\.\.|%2e%2e",          "CWE-22",          7.5,  "Path traversal pattern"),
    # Crypto / config
    (r"sslv2|sslv3|rc4|des-cbc",   "CWE-327",         7.5,  "Weak/deprecated cryptographic algorithm"),
    (r"private.?key|BEGIN RSA",    "CWE-312",         9.0,  "Private key exposed in response"),
    (r"\.git/HEAD|\.svn/",         "CWE-538",         7.5,  "Source control directory exposed"),
    (r"aws_access_key|AKIA[A-Z0-9]{16}", "CWE-312",  9.8,  "AWS access key exposed"),
]

# Severity-to-CVSS band
_CVSS_BAND: List[Tuple[float, str]] = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]


def lookup_cve(text: str) -> Optional[Dict]:
    """Scan `text` for known CVE/CWE patterns.  Returns first match or None."""
    lower = text.lower()
    for pattern, cve_id, cvss, desc in _CVE_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            severity = next(
                (s for threshold, s in _CVSS_BAND if cvss >= threshold),
                "Info"
            )
            return {
                "cve_id":      cve_id,
                "cvss":        cvss,
                "severity":    severity,
                "description": desc,
            }
    return None


def enrich_with_cve(finding: Dict) -> Dict:
    """Add CVE metadata to a finding dict if a pattern matches."""
    search_text = " ".join([
        finding.get("type", ""),
        finding.get("description", ""),
        finding.get("evidence", ""),
        finding.get("url", ""),
    ])
    match = lookup_cve(search_text)
    if match:
        f = dict(finding)
        f["cve_id"]   = match["cve_id"]
        f["cvss"]     = match["cvss"]
        # Only escalate severity, never downgrade
        from brain.vuln_brain import _SEV_SCORE
        if _SEV_SCORE.get(match["severity"], 0) > _SEV_SCORE.get(f.get("severity", "Info"), 0):
            f["severity"] = match["severity"]
        f["cve_description"] = match["description"]
        return f
    return finding



def from_type(vuln_type: str) -> Optional[Dict]:
    """Look up CVE by vulnerability type string alone."""
    return lookup_cve(vuln_type)
