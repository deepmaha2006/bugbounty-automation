"""HydraBrain CVE Database Migration — Populate known CVEs for autonomous detection and remediation.

This script downloads CVE data from NVD and populates the brain_cve_db table.
Run once during initial setup or periodically to update.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database connection from environment
DB_CONFIG = {
    "host": os.environ.get("POSTGRES_HOST", "localhost"),
    "port": int(os.environ.get("POSTGRES_PORT", "5432")),
    "database": os.environ.get("POSTGRES_DB", "hydrax"),
    "user": os.environ.get("POSTGRES_USER", "postgres"),
    "password": os.environ.get("POSTGRES_PASSWORD", ""),
}

# NVD API - public, no key needed for basic queries
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_LIMIT = 10000  # Top CVEs to import

# Attack class mapping from CWE to HydraBrain attack_class
CWE_TO_ATTACK_CLASS = {
    "CWE-79": "xss",          # Cross-site Scripting
    "CWE-89": "sql_injection", # SQL Injection
    "CWE-22": "path_traversal", # Path Traversal
    "CWE-918": "ssrf",        # SSRF
    "CWE-78": "rce",          # OS Command Injection
    "CWE-94": "rce",          # Code Injection
    "CWE-502": "rce",         # Deserialization
    "CWE-200": "info_disclosure", # Information Exposure
    "CWE-284": "bac",         # Broken Access Control
    "CWE-287": "auth_bypass", # Authentication Bypass
    "CWE-288": "auth_bypass", # Authentication Bypass Using Alternate Path
    "CWE-306": "auth_bypass", # Missing Authentication
    "CWE-352": "csrf",        # CSRF
    "CWE-434": "file_upload", # Unrestricted File Upload
    "CWE-601": "open_redirect", # Open Redirect
    "CWE-74": "injection",    # Injection (generic)
    "CWE-113": "header_injection", # HTTP Response Splitting
    "CWE-79": "xss",
    "CWE-80": "xss",          # XSS (basic)
    "CWE-81": "xss",          # XSS (improper neutralization)
    "CWE-90": "ldap_injection", # LDAP Injection
    "CWE-564": "sql_injection", # SQL Injection (Hibernate)
    "CWE-862": "bac",         # Missing Authorization
    "CWE-863": "bac",         # Incorrect Authorization
    "CWE-269": "privilege_escalation", # Improper Privilege Management
    "CWE-425": "rce",         # Direct Request (Forced Browsing)
    "CWE-611": "xxe",         # XXE
    "CWE-502": "deserialization", # Deserialization
    "CWE-295": "ssl_bypass",  # Certificate Validation
    "CWE-327": "weak_crypto", # Broken Crypto
    "CWE-330": "weak_random", # Insufficient Entropy
    "CWE-338": "weak_random", # Cryptographically Weak PRNG
}


def get_db_connection():
    """Create database connection."""
    return psycopg2.connect(**DB_CONFIG)


def init_cve_table(conn):
    """Create brain_cve_db table if not exists."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS brain_cve_db (
                cve_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                attack_vector TEXT[] DEFAULT '{}',
                cwe_ids TEXT[] DEFAULT '{}',
                attack_class TEXT,
                fix_recommendation JSONB NOT NULL DEFAULT '{}',
                confidence NUMERIC(5,4) DEFAULT 0.99,
                source TEXT DEFAULT 'nvd',
                imported_at TIMESTAMP DEFAULT NOW(),
                published_date TIMESTAMP,
                cvss_vector TEXT,
                cvss_score NUMERIC(4,1)
            );
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_brain_cve_severity ON brain_cve_db(severity);
            CREATE INDEX IF NOT EXISTS idx_brain_cve_attack_class ON brain_cve_db(attack_class);
            CREATE INDEX IF NOT EXISTS idx_brain_cve_cwe ON brain_cve_db USING GIN(cwe_ids);
        """)
        conn.commit()
    logger.info("brain_cve_db table initialized")


def map_cwe_to_attack_class(cwe_ids: list) -> str:
    """Map CWE IDs to HydraBrain attack class."""
    for cwe in cwe_ids:
        if cwe in CWE_TO_ATTACK_CLASS:
            return CWE_TO_ATTACK_CLASS[cwe]
    return "unknown"


def generate_fix_recommendation(cve: dict, attack_class: str) -> dict:
    """Generate fix recommendation based on attack class."""
    fixes = {
        "xss": {
            "type": "patch_config",
            "description": "Implement output encoding and CSP headers",
            "actions": [
                "Set Content-Security-Policy header",
                "Encode all user-supplied data in HTML context",
                "Use HttpOnly and Secure cookie flags"
            ],
            "virtual_patch": True,
            "waf_rule_template": "xss"
        },
        "sql_injection": {
            "type": "patch_config",
            "description": "Use parameterized queries and input validation",
            "actions": [
                "Replace string concatenation with parameterized queries",
                "Implement input validation and sanitization",
                "Apply least-privilege database accounts"
            ],
            "virtual_patch": True,
            "waf_rule_template": "sql_injection"
        },
        "path_traversal": {
            "type": "patch_config",
            "description": "Validate and sanitize file paths",
            "actions": [
                "Use path normalization and validation",
                "Restrict file access to allowed directories",
                "Implement chroot/jail for file operations"
            ],
            "virtual_patch": True,
            "waf_rule_template": "path_traversal"
        },
        "ssrf": {
            "type": "patch_config",
            "description": "Block internal IP ranges and validate URLs",
            "actions": [
                "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x)",
                "Implement allowlist for outbound destinations",
                "Disable unnecessary URL schemes (file://, gopher://, etc.)"
            ],
            "virtual_patch": True,
            "waf_rule_template": "scanner_probe"
        },
        "rce": {
            "type": "patch_config",
            "description": "Disable dangerous functions and sandbox execution",
            "actions": [
                "Disable shell_exec, exec, system, passthru in PHP",
                "Use container/sandbox for user code execution",
                "Implement strict input validation for command arguments"
            ],
            "virtual_patch": True,
            "waf_rule_template": "scanner_probe"
        },
        "auth_bypass": {
            "type": "patch_config",
            "description": "Strengthen authentication mechanisms",
            "actions": [
                "Implement MFA for all admin interfaces",
                "Use secure session management",
                "Implement rate limiting on auth endpoints"
            ],
            "virtual_patch": False
        },
        "csrf": {
            "type": "patch_config",
            "description": "Implement anti-CSRF tokens",
            "actions": [
                "Add CSRF tokens to all state-changing forms",
                "Set SameSite=Strict/Lax on cookies",
                "Verify Origin/Referer headers"
            ],
            "virtual_patch": True,
            "waf_rule_template": "scanner_probe"
        },
        "file_upload": {
            "type": "patch_config",
            "description": "Validate file uploads and restrict execution",
            "actions": [
                "Validate MIME type and file extension",
                "Store uploads outside webroot",
                "Disable script execution in upload directory"
            ],
            "virtual_patch": True,
            "waf_rule_template": "scanner_probe"
        },
        "open_redirect": {
            "type": "patch_config",
            "description": "Validate redirect URLs",
            "actions": [
                "Use allowlist for redirect destinations",
                "Avoid user-supplied redirect parameters",
                "Implement intermediate confirmation page"
            ],
            "virtual_patch": False
        },
        "xxe": {
            "type": "patch_config",
            "description": "Disable external entity processing",
            "actions": [
                "Set XML parser to disable external entities",
                "Use safe XML parsing libraries",
                "Validate XML input against schema"
            ],
            "virtual_patch": False
        },
        "deserialization": {
            "type": "patch_config",
            "description": "Restrict deserialization of untrusted data",
            "actions": [
                "Avoid deserializing user-supplied data",
                "Use safe serialization formats (JSON)",
                "Implement integrity checks on serialized data"
            ],
            "virtual_patch": False
        },
    }
    return fixes.get(attack_class, {
        "type": "manual_review",
        "description": "Review CVE details and apply vendor patches",
        "actions": ["Check vendor advisory for patching instructions"],
        "virtual_patch": False
    })


def fetch_cves_from_nvd(start_index: int = 0, results_per_page: int = 2000) -> list:
    """Fetch CVEs from NVD API with pagination."""
    url = f"{NVD_API_BASE}?startIndex={start_index}&resultsPerPage={results_per_page}"
    logger.info(f"Fetching CVEs from NVD: {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HydraX/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode())
            return data.get("vulnerabilities", [])
    except Exception as e:
        logger.error(f"Failed to fetch CVEs: {e}")
        return []


def parse_cve(cve_item: dict) -> dict:
    """Parse NVD CVE item into our schema."""
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS metrics
    cvss_score = None
    cvss_vector = None
    severity = "Unknown"
    metrics = cve.get("metrics", {})
    for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metric_type in metrics and metrics[metric_type]:
            m = metrics[metric_type][0]
            cvss_score = m.get("cvssData", {}).get("baseScore")
            cvss_vector = m.get("cvssData", {}).get("vectorString")
            severity = m.get("cvssData", {}).get("baseSeverity", "Unknown")
            break

    # CWE IDs
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                cwe_ids.append(desc.get("value", ""))

    # Attack vectors
    attack_vectors = []
    if cvss_vector:
        # Parse attack vector from CVSS
        if "AV:N" in cvss_vector:
            attack_vectors.append("network")
        elif "AV:A" in cvss_vector:
            attack_vectors.append("adjacent")
        elif "AV:L" in cvss_vector:
            attack_vectors.append("local")
        elif "AV:P" in cvss_vector:
            attack_vectors.append("physical")

    # Published date
    published = cve.get("published", "")
    try:
        published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except:
        published_date = None

    attack_class = map_cwe_to_attack_class(cwe_ids)
    fix_recommendation = generate_fix_recommendation(cve, attack_class)

    return {
        "cve_id": cve_id,
        "severity": severity,
        "description": description[:2000],
        "attack_vector": attack_vectors,
        "cwe_ids": cwe_ids,
        "attack_class": attack_class,
        "fix_recommendation": json.dumps(fix_recommendation),
        "confidence": 0.99,
        "source": "nvd",
        "published_date": published_date,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
    }


def import_cves(conn, limit: int = CVE_LIMIT):
    """Import CVEs from NVD into database."""
    imported = 0
    start_index = 0
    page_size = 2000

    while imported < limit:
        vulnerabilities = fetch_cves_from_nvd(start_index, page_size)
        if not vulnerabilities:
            logger.info("No more CVEs to fetch")
            break

        logger.info(f"Processing {len(vulnerabilities)} CVEs (start={start_index})...")

        with conn.cursor() as cur:
            for vuln in vulnerabilities:
                if imported >= limit:
                    break

                try:
                    parsed = parse_cve(vuln)
                    if not parsed["cve_id"]:
                        continue

                    # Upsert CVE
                    cur.execute("""
                        INSERT INTO brain_cve_db (
                            cve_id, severity, description, attack_vector, cwe_ids,
                            attack_class, fix_recommendation, confidence, source,
                            published_date, cvss_vector, cvss_score
                        ) VALUES (
                            %(cve_id)s, %(severity)s, %(description)s, %(attack_vector)s,
                            %(cwe_ids)s, %(attack_class)s, %(fix_recommendation)s,
                            %(confidence)s, %(source)s, %(published_date)s,
                            %(cvss_vector)s, %(cvss_score)s
                        )
                        ON CONFLICT (cve_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            description = EXCLUDED.description,
                            attack_vector = EXCLUDED.attack_vector,
                            cwe_ids = EXCLUDED.cwe_ids,
                            attack_class = EXCLUDED.attack_class,
                            fix_recommendation = EXCLUDED.fix_recommendation,
                            updated_at = NOW()
                    """, parsed)
                    imported += 1

                except Exception as e:
                    logger.warning(f"Failed to import CVE {vuln.get('cve', {}).get('id', 'unknown')}: {e}")

            conn.commit()

        start_index += page_size
        time.sleep(0.5)  # Rate limiting courtesy

    logger.info(f"Imported {imported} CVEs")


def main():
    """Main entry point."""
    logger.info("Starting CVE database population...")

    try:
        conn = get_db_connection()
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        logger.error("Ensure POSTGRES_* environment variables are set and database is running")
        sys.exit(1)

    try:
        init_cve_table(conn)
        import_cves(conn)
        logger.info("CVE database population complete!")
    finally:
        conn.close()


if __name__ == "__main__":
    main()