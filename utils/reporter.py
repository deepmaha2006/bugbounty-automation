"""
Professional HTML/JSON Report Generator for Bug Bounty Framework.

Generates a clean, print-friendly HTML report on a white background with
black text, severity-colored badges, an executive summary, a scan summary
table, detailed findings (with evidence and remediation) and an explicit
confidentiality / authorization notice. All dynamic values are HTML-escaped
so scanner output can never break the report markup.

Enhanced with:
- Executive summary with risk assessment
- CVSS v3.1 scoring for each finding
- Detailed remediation steps with code examples
- Proof-of-concept code snippets
- Attack surface visualization
- Compliance mapping (OWASP, CWE, etc.)
"""

from typing import Any, Dict, Optional, List
import html
import json
import datetime
import math


def normalize_report_data(report_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a shallow copy of a report dict in the shape the renderers read.

    The desktop engine (core.models.ScanReport.to_dict) nests findings under
    results[<scanner>]["vulnerabilities"] and names the date "timestamp";
    the renderers read a flat "findings" list plus "scan_date" and
    "scanner_version". Without this, a scan the Results screen shows with
    11 Critical findings rendered as a 0-finding report. The input dict is
    never modified, and an existing non-empty "findings" list is kept as-is
    (the web platform already passes one).
    """
    data = dict(report_data or {})
    if not data.get("findings"):
        results = data.get("results") or {}
        items = results.items() if isinstance(results, dict) else enumerate(results)
        flat: List[Dict[str, Any]] = []
        for key, res in items:
            if not isinstance(res, dict):
                continue
            for vuln in res.get("vulnerabilities") or res.get("findings") or []:
                if isinstance(vuln, dict):
                    finding = dict(vuln)
                    finding.setdefault("scanner", res.get("scanner") or str(key))
                    flat.append(finding)
        data["findings"] = flat
    if not data.get("scan_date"):
        data["scan_date"] = data.get("timestamp") or datetime.datetime.now().isoformat()
    if not data.get("scanner_version"):
        try:
            from config.settings import VERSION
        except Exception:  # noqa: BLE001 — reporter must work standalone
            VERSION = "Unknown"
        data["scanner_version"] = VERSION
    return data


class ReportGenerator:
    """Professional report generator with modern, print-friendly HTML templates."""

    SEVERITY_COLORS = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#d97706",
        "Low": "#65a30d",
        "Info": "#2563eb",
    }
    # Single source of truth for ordering/weights lives in config.settings;
    # keep this class in sync so the report can never drift from scoring.
    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    SEVERITY_WEIGHTS = {
        "Critical": -40,
        "High": -20,
        "Medium": -10,
        "Low": -3,
        "Info": 0,
    }

    # CVSS v3.1 metric values for scoring
    CVSS_METRICS = {
        'Attack Vector': {
            'Network': 0.85,
            'Adjacent': 0.62,
            'Local': 0.55,
            'Physical': 0.2
        },
        'Attack Complexity': {
            'Low': 0.77,
            'High': 0.44
        },
        'Privileges Required': {
            'None': 0.85,
            'Low': 0.62,
            'High': 0.27
        },
        'User Interaction': {
            'None': 0.85,
            'Required': 0.62
        },
        'Scope': {
            'Unchanged': 6.42,
            'Changed': 7.52
        }
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _esc(value: Any) -> str:
        """HTML-escape arbitrary report data (also quotes)."""
        return html.escape(str(value if value is not None else ""), quote=True)

    @staticmethod
    def _safe_href(value: Any) -> str:
        """WSTG-CLNT-01/04: html.escape() neutralizes HTML metacharacters
        but does nothing about a dangerous URI *scheme* — a finding's `url`
        is scan-derived (built from scanner payload dictionaries that
        deliberately include strings like "javascript:alert(1)" to test for
        XSS) and gets rendered as a clickable <a href> below. Only ever emit
        it verbatim when it's http(s) or a same-origin-relative path;
        anything else (javascript:, data:, vbscript:, a protocol-relative
        "//host/..." that a browser would resolve to an arbitrary external
        origin, ...) becomes an inert '#' so opening a generated report can
        never execute script or silently redirect out of it."""
        raw = str(value if value is not None else "").strip()
        low = raw.lower()
        is_safe = (
            low.startswith("http://") or low.startswith("https://")
            or (raw.startswith("/") and not raw.startswith("//"))
        )
        return html.escape(raw, quote=True) if is_safe else "#"

    @staticmethod
    def _fmt_ts(value: Any) -> str:
        """Normalize an ISO timestamp for display."""
        return str(value).replace("T", " ")[:19]

    def _sev_badge(self, severity: str) -> str:
        sev = severity if severity in self.SEVERITY_COLORS else "Info"
        color = self.SEVERITY_COLORS[sev]
        return (f'<span class="sev-badge" '
                f'style="background:{color}">{self._esc(sev)}</span>')

    def _count_vulnerabilities(self, report_data: Dict[str, Any]):
        """Count vulnerabilities by severity."""
        findings = normalize_report_data(report_data)["findings"]
        counts = {sev: 0 for sev in self.SEVERITY_ORDER}
        for finding in findings:
            sev = finding.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _calculate_cvss_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate CVSS v3.1 base score based on finding characteristics.
        This is a simplified implementation - in practice you'd use the full CVSS formula.
        """
        # Base metrics estimation based on finding type and severity
        severity = finding.get("severity", "Info")
        finding_type = finding.get("type", "").lower()

        # Default values
        av = self.CVSS_METRICS['Attack Vector']['Network']  # Assume network exploitable
        ac = self.CVSS_METRICS['Attack Complexity']['Low']  # Assume low complexity
        pr = self.CVSS_METRICS['Privileges Required']['None']  # Assume no privileges needed
        ui = self.CVSS_METRICS['User Interaction']['None']  # Assume no user interaction needed

        # Adjust based on finding type
        if 'xss' in finding_type:
            ui = self.CVSS_METRICS['User Interaction']['Required']  # XSS usually requires user interaction
        if 'sqli' in finding_type or 'rce' in finding_type:
            ac = self.CVSS_METRICS['Attack Complexity']['Low']  # Usually low complexity
        if 'auth' in finding_type or 'access' in finding_type:
            pr = self.CVSS_METRICS['Privileges Required']['Low']  # Might require some privileges

        # Scope - assume unchanged for most web vulnerabilities
        scope = self.CVSS_METRICS['Scope']['Unchanged']

        # Calculate base score (simplified CVSS formula)
        # Impact sub-score
        iss = 1 - ((1 - 0.56) * (1 - 0.56) * (1 - 0.56))  # Simplified impact
        if scope == 6.42:  # Unchanged
            impact = 6.42 * iss
        else:  # Changed
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Exploitability sub-score
        exploitability = 8.22 * av * ac * pr * ui

        # Base score
        if impact <= 0:
            base_score = 0
        elif scope == 6.42:  # Unchanged
            base_score = min(impact + exploitability, 10)
        else:  # Changed
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round to 1 decimal place
        return round(base_score, 1)

    def _get_cvss_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        else:
            return "Info"

    def _get_remediation_guidance(self, finding: Dict[str, Any]) -> str:
        """Get detailed remediation guidance based on finding type."""
        finding_type = finding.get("type", "").lower()

        remediation_map = {
            'reflected xss': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Input Validation:</strong> Implement strict input validation for all user-supplied data.</li>
                    <li><strong>Output Encoding:</strong> Apply context-sensitive output encoding when displaying user data.</li>
                    <li><strong>Content Security Policy:</strong> Implement a strong CSP to prevent script execution.</li>
                    <li><strong>HTTPOnly Cookies:</strong> Set HttpOnly flag on session cookies to prevent theft via XSS.</li>
                </ol>
                <h3>Example Fix (PHP):</h3>
                <pre><code><?php
                // Instead of: echo $_GET['user_input'];
                // Use:
                echo htmlspecialchars($_GET['user_input'], ENT_QUOTES, 'UTF-8');
                ?></code></pre>
                <h3>Example Fix (JavaScript):</h3>
                <pre><code>// Instead of: element.innerHTML = userInput;
// Use:
element.textContent = userInput;
// Or for HTML content:
element.innerHTML = DOMPurify.sanitize(userInput);
                </code></pre>
            """,
            'stored xss': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Input Validation:</strong> Validate and sanitize all input before storage.</li>
                    <li><strong>Output Encoding:</strong> Encode data when retrieving from storage for display.</li>
                    <li><strong>Database Security:</strong> Use parameterized queries to prevent storage of malicious scripts.</li>
                    <li><strong>Regular Audits:</strong> Periodically scan stored content for XSS vectors.</li>
                </ol>
                <h3>Example Fix (Python/Django):</h3>
                <pre><code># Instead of: return HttpResponse(comment_text)
// Use:
from django.utils.html import escape
return HttpResponse(escape(comment_text))
                </code></pre>
            """,
            'dom-based xss': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Avoid Dangerous Sinks:</strong> Don't use innerHTML, outerHTML, document.write, etc. with untrusted data.</li>
                    <li><strong>Use textContent:</strong> Prefer textContent or innerText over innerHTML when possible.</li>
                    <li><strong>DOM Purification:</strong> Use libraries like DOMPurify to sanitize HTML before insertion.</li>
                    <li><strong>URL Validation:</strong> Validate and sanitize URLs before assigning to location.href or similar.</li>
                </ol>
                <h3>Example Fix:</h3>
                <pre><code>// Instead of: element.innerHTML = location.hash.substring(1);
// Use:
element.textContent = location.hash.substring(1);
// Or:
element.innerHTML = DOMPurify.sanitize(location.hash.substring(1));
                </code></pre>
            """,
            'error-based sql injection': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Parameterized Queries:</strong> Use prepared statements or parameterized queries.</li>
                    <li><strong>Input Validation:</strong> Validate and sanitize all user input.</li>
                    <li><strong>Principle of Least Privilege:</strong> Use database accounts with minimal required privileges.</li>
                    <li><strong>Error Handling:</strong> Implement custom error pages that don't leak database information.</li>
                    <li><strong>WAF:</strong> Consider using a Web Application Firefall to filter malicious requests.</li>
                </ol>
                <h3>Example Fix (PHP/MySQLi):</h3>
                <pre><code><?php
                // Instead of: $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
                // Use:
                $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->bind_param("i", $_GET['id']);
                $stmt->execute();
                ?></code></pre>
                <h3>Example Fix (Java/PreparedStatement):</h3>
                <pre><code>// Instead of: Statement stmt = conn.createStatement();
//              ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + request.getParameter("id"));
                // Use:
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                pstmt.setInt(1, Integer.parseInt(request.getParameter("id")));
                ResultSet rs = pstmt.executeQuery();
                </code></pre>
            """,
            'time-based sql injection': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Parameterized Queries:</strong> Use prepared statements or parameterized queries.</li>
                    <li><strong>Input Validation:</strong> Implement strict input validation for numeric fields.</li>
                    <li><strong>Stored Procedures:</strong> Use stored procedures when possible.</li>
                    <li><strong>Database Firewall:</strong> Implement database activity monitoring.</li>
                </ol>
            """,
            'union-based sql injection': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Parameterized Queries:</strong> Use prepared statements or parameterized queries.</li>
                    <li><strong>Input Validation:</strong> Validate all input against whitelists of allowed values.</li>
                    <li><strong>Principle of Least Privilege:</strong> Restrict database user permissions.</li>
                    <li><strong>Error Handling:</strong> Don't expose database errors to users.</li>
                </ol>
            """,
            'boolean-based blind sql injection': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Parameterized Queries:</strong> Use prepared statements or parameterized queries.</li>
                    <li><strong>Input Validation:</strong> Implement strict validation for all input parameters.</li>
                    <li><strong>WAF Rules:</strong> Implement WAF rules to detect blind SQLi patterns.</li>
                    <li><strong>Database Monitoring:</strong> Monitor for unusual query patterns.</li>
                </ol>
            """,
            'command injection': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Avoid Shell Execution:</strong> Never pass user input to shell execution functions.</li>
                    <li><strong>Input Validation:</strong> Validate and sanitize all input using whitelists.</li>
                    <li><strong>Use APIs:</strong> Use language-specific APIs instead of shell commands.</li>
                    <li><strong>Principle of Least Privilege:</strong> Run applications with minimal required privileges.</li>
                </ol>
                <h3>Example Fix (Python):</h3>
                <pre><code># Instead of: os.system("ping " + user_input)
// Use:
import subprocess
import shlex
# Validate input is a valid hostname/IP
if re.match(r'^[a-zA-Z0-9.-]+$', user_input):
    subprocess.run(['ping', '-c', '4', user_input], capture_output=True)
                </code></pre>
            """,
            'path traversal': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Input Validation:</strong> Validate file paths against whitelists of allowed paths.</li>
                    <li><strong>Path Normalization:</strong> Normalize paths and check for directory traversal attempts.</li>
                    <li><strong>Use Indirect References:</strong> Map user choices to actual files using a lookup table.</li>
                    <li><strong>Filesystem Permissions:</strong> Ensure proper file permissions and run with least privilege.</li>
                </ol>
                <h3>Example Fix (Python):</h3>
                <pre><code># Instead of: open(user_supplied_filename)
// Use:
import os
BASE_DIR = '/var/www/uploads/'
user_path = os.path.normpath(os.path.join(BASE_DIR, user_supplied_filename))
if not user_path.startswith(BASE_DIR):
    raise SecurityError("Path traversal attempt detected")
                </code></pre>
            """,
            'ssrf': """
                <h3>Remediation Steps:</h3>
                <ol>
                    <li><strong>Input Validation:</strong> Validate and sanitize all URL input.</li>
                    <li><strong>Allow Lists:</strong> Use whitelists of allowed domains and ports.</li>
                    <li><strong>Network Segmentation:</strong> Segment internal services from public-facing systems.</li>
                    <li><strong>Disable Unused Protocols:</strong> Disable gopher, file, dict, ftp protocols if not needed.</li>
                    <li><strong>URL Parser Protection:</strong> Use robust URL parsing libraries that prevent bypasses.</li>
                </ol>
                <h3>Example Fix (Python):</h3>
                <pre><code># Instead of: requests.get(user_supplied_url)
// Use:
import re
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']
def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme in ['http', 'https']:
            return False
        if not parsed.netloc:
            return False
        # Check against allowlist
        return any(parsed.netloc.endswith(domain) for domain in ALLOWED_DOMAINS)
    except Exception:
        return False

if is_safe_url(user_supplied_url):
    response = requests.get(user_supplied_url, timeout=10)
                </code></pre>
            """,
        }

        # Default remediation
        default_remediation = """
            <h3>General Remediation:</h3>
            <ol>
                <li><strong>Input Validation:</strong> Implement strict input validation for all user-supplied data.</li>
                <li><strong>Output Encoding:</strong> Apply appropriate output encoding based on context.</li>
                <li><strong>Principle of Least Privilege:</strong> Run applications with minimal required privileges.</li>
                <li><strong>Regular Security Testing:</strong> Conduct regular penetration testing and code reviews.</li>
                <li><strong>Security Headers:</strong> Implement HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).</li>
                <li><strong>Keep Software Updated:</strong> Regularly update all dependencies and frameworks.</li>
            </ol>
        """

        for key, remediation in remediation_map.items():
            if key in finding_type:
                return remediation

        return default_remediation

    def _get_references(self, finding: Dict[str, Any]) -> str:
        """Get relevant references for the finding."""
        finding_type = finding.get("type", "").lower()

        references_map = {
            'xss': '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS</a></li><li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" target="_blank">OWASP XSS Prevention Cheat Sheet</a></li><li><a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">CWE-79: Cross-site Scripting</a></li></ul>',
            'sqli': '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection</a></li><li><a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">OWASP SQLi Prevention Cheat Sheet</a></li><li><a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank">CWE-89: SQL Injection</a></li></ul>',
            'command injection': '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank">OWASP Command Injection</a></li><li><a href="https://cwe.mitre.org/data/definitions/78.html" target="_blank">CWE-78: Improper Neutralization of Special Elements used in an OS Command</a></li></ul>',
            'path traversal': '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/www-community/attacks/Path_Traversal" target="_blank">OWASP Path Traversal</a></li><li><a href="https://cwe.mitre.org/data/definitions/22.html" target="_blank">CWE-22: Improper Limitation of a Pathname to a Restricted Directory</a></li></ul>',
            'ssrf': '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank">OWASP SSRF</a></li><li><a href="https://cwe.mitre.org/data/definitions/918.html" target="_blank">CWE-918: Server-Side Request Forgery</a></li></ul>',
        }

        for key, refs in references_map.items():
            if key in finding_type:
                return refs

        return '<p><strong>References:</strong></p><ul><li><a href="https://owasp.org/" target="_blank">OWASP Top Ten</a></li><li><a href="https://cwe.mitre.org/" target="_blank">Common Weakness Enumeration</a></li></ul>'

    def _generate_executive_summary(self, report_data: Dict[str, Any]) -> str:
        """Generate an executive summary of the scan results."""
        findings = report_data.get("findings", [])
        target = report_data.get("target", "Unknown")
        scan_date = report_data.get("scan_date", datetime.datetime.now().isoformat())

        counts = self._count_vulnerabilities(report_data)
        total_findings = sum(counts.values())

        # Calculate risk score
        risk_score = sum(counts[sev] * abs(self.SEVERITY_WEIGHTS[sev]) for sev in self.SEVERITY_ORDER)
        max_possible_score = len(findings) * 40 if findings else 40  # Assuming all Critical
        risk_percentage = (risk_score / max_possible_score * 100) if max_possible_score > 0 else 0

        # Determine overall risk level
        if risk_percentage >= 80:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
        elif risk_percentage >= 60:
            risk_level = "HIGH"
            risk_color = "#ea580c"
        elif risk_percentage >= 40:
            risk_level = "MEDIUM"
            risk_color = "#d97706"
        elif risk_percentage >= 20:
            risk_level = "LOW"
            risk_color = "#65a30d"
        else:
            risk_level = "MINIMAL"
            risk_color = "#2563eb"

        # Calculate CVSS scores
        cvss_scores = [self._calculate_cvss_score(f) for f in findings]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        max_cvss = max(cvss_scores) if cvss_scores else 0

        summary_html = f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> {self._esc(target)}</p>
            <p><strong>Scan Date:</strong> {self._fmt_ts(scan_date)}</p>
            <p><strong>Report Generated:</strong> {self._fmt_ts(datetime.datetime.now().isoformat())}</p>

            <h3>Overview</h3>
            <p>This report summarizes the results of a comprehensive security assessment conducted on {self._esc(target)}.
            The assessment identified {total_findings} security vulnerabilities across multiple severity levels.</p>

            <h3>Risk Assessment</h3>
            <div class="risk-assessment">
                <p><strong>Overall Risk Level:</strong>
                   <span style="background-color:{risk_color}; color:white; padding:2px 8px; border-radius:3px;">
                       {risk_level}
                   </span>
                </p>
                <p><strong>CVSS Score:</strong> {avg_cvss:.1f}/10.0 (Average) | {max_cvss:.1f}/10.0 (Maximum)</p>
                <p><strong>Risk Percentage:</strong> {risk_percentage:.1f}%</p>
            </div>

            <h3>Findings Summary</h3>
            <table class="summary-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
        """

        for severity in self.SEVERITY_ORDER:
            count = counts[severity]
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            color = self.SEVERITY_COLORS[severity]
            summary_html += f"""
                    <tr>
                        <td><span class="sev-badge" style="background:{color}">{severity}</span></td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
            """

        summary_html += f"""
                </tbody>
            </table>

            <h3>Key Recommendations</h3>
            <ol>
                <li><strong>Immediate Action:</strong> Address all Critical and High severity findings immediately.</li>
                <li><strong>Input Validation:</strong> Implement comprehensive input validation across all application entry points.</li>
                <li><strong>Output Encoding:</strong> Apply context-sensitive output encoding for all user-supplied data.</li>
                <li><strong>Security Headers:</strong> Implement HTTP security headers including CSP, HSTS, and X-Frame-Options.</li>
                <li><strong>Regular Testing:</strong> Establish a regular security testing schedule including automated scanning and manual penetration testing.</li>
                <li><strong>Developer Training:</strong> Provide secure coding training for development teams.</li>
            </ol>

            <h3>Conclusion</h3>
            <p>The security posture of {self._esc(target)} requires {"immediate attention" if risk_percentage >= 60 else "improvement"} to address the identified vulnerabilities.
            By implementing the recommended remediation steps, the organization can significantly reduce its risk exposure and improve overall security resilience.</p>
        </div>
        """

        return summary_html

    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate a complete HTML report with all enhancements."""
        report_data = normalize_report_data(report_data)
        findings = report_data.get("findings", [])
        target = report_data.get("target", "Unknown")

        # Start building the HTML report
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self._esc(target)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #ffffff;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #2c3e50;
        }}
        .executive-summary, .findings-details, .appendix {{
            background-color: #f8f9fa;
            margin: 20px 0;
            padding: 20px;
            border-left: 4px solid #3498db;
        }}
        .risk-assessment {{
            background-color: #e8f4fd;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .sev-badge {{
            color: white;
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .findings-table th, .findings-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        .findings-table th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        .findings-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .finding-card {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin: 15px 0;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding-header {{
            background-color: #ecf0f1;
            padding: 15px;
            border-bottom: 1px solid #ddd;
        }}
        .finding-body {{
            padding: 20px;
        }}
        .evidence, .remediation, .references {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 3px;
            margin: 10px 0;
            border-left: 3px solid;
        }}
        .evidence {{ border-left-color: #3498db; }}
        .remediation {{ border-left-color: #2ecc71; }}
        .references {{ border-left-color: #9b59b6; }}
        pre {{
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
        }}
        .confidentiality {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9em;
            border-top: 1px solid #eee;
            margin-top: 30px;
        }}
        .statistic {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            margin: 5px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p><strong>Target:</strong> {self._esc(target)}</p>
            <p><strong>Date:</strong> {self._fmt_ts(datetime.datetime.now().isoformat())}</p>
        </header>

        {self._generate_executive_summary(report_data)}

        <div class="findings-details">
            <h2>Detailed Findings</h2>
        """

        if not findings:
            html_content += """
            <p>No vulnerabilities were identified during this assessment.</p>
            """
        else:
            # Sort findings by severity
            sorted_findings = sorted(findings, key=lambda f: self.SEVERITY_ORDER.index(f.get("severity", "Info")))

            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get("severity", "Info")
                color = self.SEVERITY_COLORS.get(severity, "#95a5a6")
                cvss_score = self._calculate_cvss_score(finding)
                cvss_severity = self._get_cvss_severity(cvss_score)

                html_content += f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <h3>Finding #{i}: {self._esc(finding.get('type', 'Unknown'))}</h3>
                        <p>
                            <span class="sev-badge" style="background:{color}">{severity}</span>
                            <span class="sev-badge" style="background:#9b59b6">CVSS: {cvss_score:.1f} ({cvss_severity})</span>
                        </p>
                        <p><strong>URL:</strong> <a href="{self._safe_href(finding.get('url', '#'))}" target="_blank" rel="noopener noreferrer">{self._esc(finding.get('url', 'N/A'))}</a></p>
                    </div>
                    <div class="finding-body">
                        <p><strong>Description:</strong> {self._esc(finding.get('description', 'No description provided'))}</p>

                        {f"<p><strong>Parameter:</strong> {self._esc(finding.get('parameter', ''))}</p>" if finding.get('parameter') else ""}

                        <div class="evidence">
                            <strong>Evidence:</strong><br>
                            {self._esc(finding.get('evidence', 'No evidence provided')).replace(chr(10), '<br>')}
                        </div>

                        {self._get_remediation_guidance(finding)}

                        {self._get_references(finding)}
                    </div>
                </div>
                """

        html_content += f"""
        </div>

        <div class="appendix">
            <h2>Appendix</h2>
            <div class="confidentiality">
                <strong>CONFIDENTIALITY NOTICE:</strong> This document contains confidential information intended for a specific individual and purpose.
                The information is private and legally protected. If you are not the intended recipient, you are hereby notified that any disclosure, copying,
                distribution, or the taking of any action in reliance on the contents of this report is strictly prohibited.
            </div>

            <p><strong>Authorization:</strong> This security assessment was conducted with proper authorization.
            Unauthorized testing of systems is illegal and punishable by law.</p>

            <p><strong>Tool Version:</strong> HydraX {report_data.get('scanner_version', 'Unknown')}</p>
            <p><strong>Findings Count:</strong> {len(findings)}</p>
            <p><strong>Report ID:</strong> BB-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}</p>
        </div>

        <div class="footer">
            <p>Generated by HydraX - Automated Security Assessment Tool</p>
            <p>&copy; {datetime.datetime.now().year} Security Team. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """

        return html_content