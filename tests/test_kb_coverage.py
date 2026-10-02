"""Full KB coverage guard: every finding type the platform emits (the Stage 0
inventory) must resolve to a real, curated KB entry by alias — not by a
category/keyword guess and not by the generic fallback.

The KB was declared complete on 2026-09-29, so this runs on every test run
and fails if a scanner starts emitting a new type string without a KB entry,
or if an alias is renamed/removed. When adding a scanner finding type, add
it to STAGE0_FINDING_TYPES *and* give it a KB alias (see docs/BRAIN.md).

HYDRAX_KB_COMPLETE used to gate this file while the KB was being filled; it
is no longer read. Setting it has no effect.
"""
import pytest

from webapp.services import remediation_kb as kbm
from webapp.services import remediation_service as rs


@pytest.fixture(scope="module")
def kb():
    return kbm.load_kb()


# Stage 0 inventory: finding-type strings emitted by scanners/ and the local
# tool bridge (webapp/services/kali_tools.py). nuclei template names are
# open-ended and intentionally excluded (they resolve by category/keyword).
STAGE0_FINDING_TYPES = [
    # sqli
    "Error-based SQL Injection", "Union-based SQL Injection", "Time-based SQL Injection",
    "Boolean-based Blind SQL Injection", "Out-of-band SQL Injection Attempt",
    # xss
    "Stored XSS", "Reflected XSS", "DOM-based XSS", "DOM-based XSS Sinks Detected", "Blind XSS",
    # csrf
    "Missing CSRF Token", "CSRF via GET Request", "SameSite=None Cookie",
    # ssrf
    "SSRF Confirmed", "SSRF via Form Input", "SSRF via Headers", "Potential SSRF Parameter",
    # rce
    "Command Injection", "Server-Side Template Injection (SSTI)", "Web Shell Found",
    "PHP Serialization Data Found", "Python Pickle Data Found",
    # file_upload / open_redirect / clickjack
    "File Upload Endpoint", "Open Redirect",
    "Missing Clickjacking Protection", "Weak Clickjacking Protection",
    # auth_session
    "Session Cookie Missing HttpOnly Flag", "Session Cookie Missing Secure Flag",
    "Session Cookie Missing SameSite Attribute", "Session ID Persistence",
    "Weak Password Accepted", "Weak Password Policy", "Missing MFA",
    "Password Reset Enumeration", "OAuth Endpoint Detected",
    "JWT None Algorithm", "JWT Weak Secret Key", "JWT KID Injection",
    # business_logic
    "Potential Price Manipulation", "Workflow Bypass Potential", "Inventory Parameters Exposed",
    "Potential Race Condition", "Coupon/Discount Functionality", "Payment/Checkout Endpoint",
    # bac
    "Privilege Escalation via HTTP Method", "Potential IDOR", "Forced Browsing",
    "Broken Access Control - Exposed Path", "Information Disclosure - Robots.txt",
    # sub_takeover
    "Subdomain Takeover", "Subdomain Enumeration", "No Subdomains Found",
    # sec_misconfig
    ".git Repository Exposure", "Environment File Exposure", "PHPInfo Exposure",
    "Debug Mode Enabled", "CORS Misconfiguration", "Permissive CORS Policy",
    "Missing Security Header", "Insecure Cookie", "Dangerous HTTP Method Enabled",
    "Directory Listing Enabled", "Server Information Disclosure", "Technology Disclosure",
    # info_disclosure
    "Exposed Sensitive File",
    # cloud
    "Public S3 Bucket", "Accessible S3 Bucket", "AWS Credential Exposure",
    "GCP Credential Exposure", "Kubernetes API Exposure", "Cloud Metadata Accessible",
    # ddos
    "Missing Rate Limiting", "Weak Rate Limiting", "No Connection Limiting",
    "Large Payload Accepted", "Rate Limiting Detected",
    # recon
    "SSL/TLS Issue", "Non-HTTPS Connection", "SSL Certificate", "API Endpoint Detected",
    "Technology Stack Fingerprinting", "URL Parameters",
    # api
    "Potential BOLA/BFLA", "GraphQL Full Introspection", "GraphQL Introspection Enabled",
    "Mass Assignment Risk", "API Documentation Exposed",
    # proto_pollution
    "Potential Server-Side Prototype Pollution", "Client-Side Prototype Pollution",
    "Prototype Pollution Sink",
    # xml
    "XXE (File Read)", "XML/XPath Injection", "XML Endpoint Detected",
    # websocket / llm / mobile
    "WebSocket Missing Authentication", "WebSocket Endpoint",
    "LLM Prompt Injection", "LLM Prompt Leakage", "AI/LLM Endpoint Detected",
    "Mobile API Endpoint",
    # cache / smuggling
    "Web Cache Poisoning", "Web Cache Deception", "Host Header Injection",
    "Potential CL.TE Smuggling", "Potential TE.CL Smuggling",
    # local tool bridge (kali_tools.py)
    "SQL Injection", "TLS / SSL Issue", "Nikto Finding", "Directory Discovered",
    "Open Port", "Open Port (masscan)", "Live Web Host", "DNS Record",
    "Subdomain Discovered", "Technology Fingerprint",
]


def test_inventory_has_no_duplicates():
    assert len(STAGE0_FINDING_TYPES) == len(set(STAGE0_FINDING_TYPES))


@pytest.mark.parametrize("finding_type", STAGE0_FINDING_TYPES)
def test_every_stage0_type_resolves_to_a_curated_entry(finding_type, kb):
    r = rs.resolve({"type": finding_type}, kb=kb)
    assert r["unresolved"] is False, f"{finding_type!r} has no KB entry (generic fallback)"
    assert r["resolved_by"] == "alias", (
        f"{finding_type!r} matched only by {r['resolved_by']} ({r['key']}); add it as an alias")
