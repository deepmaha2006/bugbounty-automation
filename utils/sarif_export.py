"""
SARIF 2.1.0 Export for Bug Bounty Professional.

Generates Static Analysis Results Interchange Format (SARIF) files compatible with:
- GitHub Advanced Security / Code Scanning
- Azure DevOps Security
- SonarQube / SonarCloud
- GitLab SAST
- DefectDojo
- Other enterprise security tooling
"""

import json
import uuid
import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from config.settings import SEVERITY_ORDER, SEVERITY_WEIGHTS


class SarifExporter:
    """Exports scan results to SARIF 2.1.0 format."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"

    # Map our severity to SARIF levels
    SEVERITY_MAP = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }

    # Map vulnerability types to CWE IDs where possible
    CWE_MAP = {
        "xss": "79",           # Cross-site Scripting
        "sqli": "89",          # SQL Injection
        "bac": "284",          # Improper Access Control
        "ssrf": "918",         # Server-Side Request Forgery
        "rce": "94",           # Code Injection
        "file_upload": "434",  # Unrestricted Upload
        "open_redirect": "601", # URL Redirection
        "clickjack": "1021",   # UI Redressing
        "csrf": "352",         # Cross-Site Request Forgery
        "proto_pollution": "1321", # Prototype Pollution
        "xml": "611",          # XML External Entity (XXE)
        "websocket": "346",    # Origin Validation Error
        "llm": "1337",         # AI/ML Security (custom)
        "cache": "346",        # Cache Poisoning
        "smuggling": "444",    # HTTP Request Smuggling
        "info_disclosure": "200", # Information Exposure
        "sec_misconfig": "16",  # Configuration
        "sub_takeover": "346",  # Subdomain Takeover
        "cloud": "284",         # Cloud Misconfiguration
        "auth_session": "306",  # Authentication Bypass
        "business_logic": "840", # Business Logic Error
        "mobile": "200",        # Mobile Security
        "recon": "200",         # Reconnaissance
        "ddos": "400",          # Resource Exhaustion
    }

    # Map to OWASP Top 10 2021 categories
    OWASP_MAP = {
        "xss": "A03:2021",      # Injection
        "sqli": "A03:2021",     # Injection
        "bac": "A01:2021",      # Broken Access Control
        "ssrf": "A10:2021",     # SSRF
        "rce": "A03:2021",      # Injection
        "file_upload": "A03:2021", # Injection
        "open_redirect": "A01:2021", # Broken Access Control
        "clickjack": "A01:2021", # Broken Access Control
        "csrf": "A01:2021",     # Broken Access Control
        "proto_pollution": "A03:2021", # Injection
        "xml": "A03:2021",      # Injection
        "websocket": "A10:2021", # SSRF
        "llm": "A03:2021",      # Injection (Prompt Injection)
        "cache": "A10:2021",    # SSRF
        "smuggling": "A10:2021", # SSRF
        "info_disclosure": "A04:2021", # Insecure Design
        "sec_misconfig": "A05:2021", # Security Misconfiguration
        "sub_takeover": "A05:2021", # Security Misconfiguration
        "cloud": "A05:2021",    # Security Misconfiguration
        "auth_session": "A07:2021", # Identification and Authentication Failures
        "business_logic": "A04:2021", # Insecure Design
        "mobile": "A04:2021",   # Insecure Design
    }

    def __init__(self, tool_name: str = "Bug Bounty Professional", tool_version: str = "4.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def export(self, report_data: Dict[str, Any]) -> str:
        """
        Export scan results to SARIF format.

        Args:
            report_data: Dictionary containing scan results from ScanReport.to_dict()

        Returns:
            SARIF 2.1.0 compliant JSON string
        """
        results = report_data.get("results", {})
        target = report_data.get("target", "unknown")
        timestamp = report_data.get("timestamp", datetime.datetime.now().isoformat())
        duration = report_data.get("duration", "0s")

        # Build SARIF structure
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/bugbounty-professional",
                        "rules": [],
                        "fullDescription": {
                            "text": f"Automated vulnerability assessment of {target} performed by {self.tool_name} v{self.tool_version}"
                        }
                    }
                },
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": timestamp,
                    "endTimeUtc": datetime.datetime.now().isoformat() + "Z",
                    "commandLine": f"bugbounty scan {target}",
                    "exitCode": 0,
                    "exitCodeDescription": "Scan completed successfully",
                    "properties": {
                        "target": target,
                        "duration": duration,
                        "scanType": "web-application"
                    }
                }],
                "results": [],
                "columnKind": "utf16CodeUnits"
            }]
        }

        # Track rules we've seen to avoid duplicates in the driver.rules array
        rule_index = {}
        rule_counter = 0

        for scan_key, scan_res in results.items():
            scanner_name = scan_res.get("scanner", scan_key)
            vulns = scan_res.get("vulnerabilities", []) or []

            for vuln in vulns:
                # Get or create rule for this finding type
                rule_key = f"{scan_key}_{vuln.get('type', 'Unknown')}"
                if rule_key not in rule_index:
                    rule_index[rule_key] = rule_counter
                    sarif["runs"][0]["tool"]["driver"]["rules"].append(
                        self._build_rule(scan_key, vuln)
                    )
                    rule_counter += 1

                rule_id = rule_index[rule_key]

                # Build result entry
                result = self._build_result(
                    scan_key=scan_key,
                    scanner_name=scanner_name,
                    vuln=vuln,
                    rule_id=rule_id,
                    target=target
                )
                sarif["runs"][0]["results"].append(result)

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _build_rule(self, scan_key: str, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Build a SARIF rule object."""
        severity = vuln.get("severity", "Info")
        vuln_type = vuln.get("type", "Unknown")
        description = vuln.get("description", "")
        remediation = vuln.get("remediation", "")

        cwe_id = self.CWE_MAP.get(scan_key, "0")
        owasp_category = self.OWASP_MAP.get(scan_key, "Unknown")

        # Build help markdown
        help_md = f"""## {vuln_type}

**Severity:** {severity}
**Scanner:** {scan_key}
**OWASP Top 10 2021:** {owasp_category}
**CWE:** CWE-{cwe_id}

### Description
{description}

### Remediation
{remediation or "No specific remediation provided. Refer to secure coding practices for this vulnerability type."}
"""

        return {
            "id": f"{scan_key}_{vuln_type}",
            "name": f"{scan_key}: {vuln_type}",
            "shortDescription": {
                "text": f"{vuln_type} detected by {scan_key} scanner"
            },
            "fullDescription": {
                "text": description
            },
            "help": {
                "text": help_md,
                "markdown": help_md
            },
            "defaultConfiguration": {
                "level": self.SEVERITY_MAP.get(severity, "note")
            },
            "properties": {
                "tags": ["security", "vulnerability", scan_key],
                "precision": "high",
                "problem.severity": severity.lower(),
                "security-severity": self._severity_to_score(severity),
                "cwe": f"CWE-{cwe_id}",
                "owasp": owasp_category,
                "scanner": scan_key
            }
        }

    def _build_result(
        self,
        scan_key: str,
        scanner_name: str,
        vuln: Dict[str, Any],
        rule_id: int,
        target: str
    ) -> Dict[str, Any]:
        """Build a SARIF result object."""
        severity = vuln.get("severity", "Info")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")
        description = vuln.get("description", "")
        vuln_type = vuln.get("type", "Unknown")

        # Parse URL to extract path for location
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # Build message
        message = {
            "text": f"{vuln_type}: {description}",
            "markdown": f"**{vuln_type}** ({severity})\n\n{description}"
        }

        if evidence:
            message["markdown"] += f"\n\n**Evidence:**\n```\n{evidence}\n```"

        # Build location
        locations = [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": target,
                    "uriBaseId": "%TARGET%",
                    "index": 0
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1,
                    "snippet": {
                        "text": path
                    }
                }
            }
        }]

        # Add web request/response info if available
        if "request" in vuln or "response" in vuln:
            locations[0]["physicalLocation"]["contextRegion"] = {
                "snippet": {
                    "text": f"Request/Response data available in finding evidence"
                }
            }

        return {
            "ruleId": f"{scan_key}_{vuln_type}",
            "ruleIndex": rule_id,
            "level": self.SEVERITY_MAP.get(severity, "note"),
            "message": message,
            "locations": locations,
            "partialFingerprints": {
                "findingType": vuln_type,
                "url": url,
                "scanner": scan_key
            },
            "properties": {
                "severity": severity,
                "scanner": scan_key,
                "scannerName": scanner_name,
                "url": url,
                "vulnerabilityType": vuln_type,
                "evidence": evidence,
                "remediation": vuln.get("remediation", ""),
                "cwe": f"CWE-{self.CWE_MAP.get(scan_key, '0')}",
                "owasp": self.OWASP_MAP.get(scan_key, "Unknown")
            }
        }

    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to CVSS-like numeric score (0-10)."""
        scores = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Info": 0.0,
        }
        return scores.get(severity, 0.0)

    def save(self, report_data: Dict[str, Any], path: str) -> str:
        """Save SARIF report to file."""
        sarif_json = self.export(report_data)
        with open(path, "w", encoding="utf-8") as f:
            f.write(sarif_json)
        return path


def generate_sarif(report_data: Dict[str, Any]) -> str:
    """Convenience function to generate SARIF report."""
    exporter = SarifExporter()
    return exporter.export(report_data)


def save_sarif(report_data: Dict[str, Any], path: str) -> str:
    """Convenience function to save SARIF report."""
    exporter = SarifExporter()
    return exporter.save(report_data, path)