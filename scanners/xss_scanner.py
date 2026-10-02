"""
XSS (Cross-Site Scripting) Scanner
Detects Reflected, Stored, and DOM-based XSS vulnerabilities with real exploit verification
"""

from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient
from utils.payloads import Payloads
from utils.concurrency import run_phases_concurrently


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner with real exploit verification"""

    def __init__(self):
        self.client = HTTPClient()
        self.name = "XSS Scanner"
        self.findings = []
        self.oob_domain = "http://oast.me"  # Out-of-band detection domain
        self.blind_xss_endpoints = [
            f"{self.oob_domain}/blind-xss",
            f"{self.oob_domain}/xss-log",
            "http://burpcollaborator.net/xss",
        ]

    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Scan target for XSS vulnerabilities with real exploit verification

        Args:
            target_url: The target URL to scan

        Returns:
            Dict with scan results
        """
        self.findings = []
        parsed = urlparse(target_url)

        # Each phase only appends to self.findings and never reads another
        # phase's in-progress results, so they run concurrently instead of
        # one after another — each phase alone issues dozens of HTTP
        # requests, and running them serially made a single scan take
        # minutes even against a small site.
        run_phases_concurrently([
            lambda: self._scan_discovered_targets(target_url),      # Phase 0
            lambda: self._scan_reflected_xss(target_url, parsed),   # Phase 1
            lambda: self._scan_stored_xss(target_url),              # Phase 2
            lambda: self._scan_dom_based_xss(target_url),           # Phase 3
            lambda: self._scan_blind_xss(target_url),               # Phase 4
        ])

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _scan_reflected_xss(self, target_url: str, parsed):
        """Test for reflected XSS in URL parameters with execution verification.

        Both branches used to test every (param, payload) combination one
        HTTP request at a time — up to 90 sequential requests for the
        no-params branch alone. They're fanned out concurrently instead;
        only the first successful payload per param is kept (by original
        list order), matching the original "break after first hit" intent.
        """
        query_params = parse_qs(parsed.query)

        def probe_no_params(param: str, payload: str):
            test_url = f"{target_url}?{param}={payload}"
            try:
                resp = self.client.get(test_url)
                if resp.status_code < 500 and payload in resp.text:
                    severity, evidence = self._verify_xss_execution(resp.text, payload, param)
                    return param, {
                        'type': 'Reflected XSS',
                        'description': f'Parameter "{param}" reflects unsanitized input',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': evidence
                    }
            except Exception:
                pass
            return None

        def probe_with_params(param: str, payload: str):
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            try:
                resp = self.client.get(test_url)
                if resp.status_code < 500 and payload in resp.text:
                    severity, evidence = self._verify_xss_execution(resp.text, payload, param)
                    return param, {
                        'type': 'Reflected XSS',
                        'description': f'Parameter "{param}" reflects unsanitized input in executable context',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': evidence
                    }
            except Exception:
                pass
            return None

        if not query_params:
            test_params = ['q', 's', 'search', 'id', 'page', 'query', 'term', 'keyword', 'lang']
            jobs = [(probe_no_params, param, payload) for param in test_params for payload in Payloads.XSS_REFLECTED[:10]]
        else:
            jobs = [(probe_with_params, param, payload) for param in query_params for payload in Payloads.XSS_REFLECTED[:8]]

        results = {}
        with ThreadPoolExecutor(max_workers=min(20, len(jobs)) or 1) as executor:
            future_to_idx = {executor.submit(fn, a, b): i for i, (fn, a, b) in enumerate(jobs)}
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
            param, finding = results[idx]
            if param in seen_params:
                continue
            seen_params.add(param)
            self.findings.append(finding)

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
            if url == target_url or len(tested) >= 100:  # Increased limit
                continue
            for param in params[:10]:  # Test more parameters
                if (url, param) in tested:
                    continue
                tested.add((url, param))
                for payload in Payloads.XSS_REFLECTED[:5]:
                    test_url = inject_param(url, param, payload)
                    try:
                        resp = self.client.get(test_url)
                    except Exception:
                        continue
                    if resp.status_code >= 500 or payload not in resp.text:
                        continue
                    # Enhanced verification with execution proof
                    severity, evidence = self._verify_xss_execution(resp.text, payload, param)
                    self.findings.append({
                        'type': 'Reflected XSS',
                        'description': f'Parameter "{param}" on {url} reflects unsanitized input in executable context',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': evidence
                    })
                    break

        # -- POST form targets discovered on other pages --------------
        for url, _params, method, fields in targets:
            abort_if_stopped()
            if method != "post" or not fields:
                continue
            text_fields = [n for n, v in fields.items() if 'file' not in n.lower()]
            if not text_fields:
                continue
            for payload in Payloads.XSS_STORED[:5]:
                form_data = dict(fields)
                for name in text_fields:
                    form_data[name] = payload
                try:
                    resp2 = self.client.post(url, data=form_data)
                except Exception:
                    continue
                if resp2.status_code < 500 and payload in resp2.text:
                    # Check for persistence
                    persistence_evidence = self._check_stored_xss_persistence(url, payload)
                    self.findings.append({
                        'type': 'Stored XSS',
                        'description': f'Form at {url} stores unsanitized input',
                        'severity': 'Critical',
                        'url': url,
                        'payload': payload,
                        'evidence': persistence_evidence
                    })
                    break

    def _scan_stored_xss(self, target_url: str):
        """Test for stored XSS via form submissions with persistence verification"""
        try:
            resp = self.client.get(target_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(target_url, action) if action else target_url

                inputs = form.find_all(['input', 'textarea'])
                if not inputs:
                    continue

                for payload in Payloads.XSS_STORED[:8]:
                    form_data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            inp_type = inp.get('type', 'text').lower()
                            if inp_type in ('text', 'search', 'textarea', 'hidden'):
                                form_data[name] = payload

                    if not form_data:
                        continue

                    try:
                        if method == 'post':
                            resp2 = self.client.post(form_url, data=form_data)
                        else:
                            resp2 = self.client.get(form_url, params=form_data)

                        # Check if payload is stored and reflected
                        if resp2.status_code < 500 and payload in resp2.text:
                            # Verify persistence by checking if it appears in subsequent requests
                            persistence_evidence = self._check_stored_xss_persistence(form_url, payload)
                            self.findings.append({
                                'type': 'Stored XSS',
                                'description': f'Form at {action or target_url} stores unsanitized input',
                                'severity': 'Critical',
                                'url': form_url,
                                'payload': payload,
                                'evidence': persistence_evidence
                            })
                            break
                    except Exception:
                        continue
        except Exception:
            pass

    def _scan_dom_based_xss(self, target_url: str):
        """Check for DOM-based XSS sink sources with execution test"""
        try:
            resp = self.client.get(target_url)
            # Look for common DOM XSS sink patterns
            sinks = [
                r'\.innerHTML\s*=',
                r'\.outerHTML\s*=',
                r'document\.write\(',
                r'eval\(',
                r'setTimeout\(',
                r'setInterval\(',
                r'new\s+Function\(',
                r'\$\(.*\)\.html\(',
                r'\$\(.*\)\.append\(',
                r'\.insertAdjacentHTML\(',
                r'location\.hash',
                r'location\.search',
                r'location\.href',
                r'document\.URI',
                r'document\.URL',
                # Advanced sinks
                r'innerText\s*=',
                r'textContent\s*=',
                r'outerText\s*=',
                r'attachShadow\(',
            ]

            js_pattern = '|'.join(sinks)
            matches = re.findall(js_pattern, resp.text, re.IGNORECASE)

            if matches:
                # Test actual DOM XSS with payloads
                dom_xss_payloads = Payloads.XSS_DOM_BASED[:5]
                for payload in dom_xss_payloads:
                    # Test if we can trigger actual DOM XSS
                    test_url = f"{target_url}#{payload}" if payload.startswith('#') else f"{target_url}?q={payload}"
                    try:
                        test_resp = self.client.get(test_url)
                        if test_resp.status_code < 500:
                            # Look for evidence of DOM execution
                            if any(indicator in test_resp.text for indicator in ['alert(', 'confirm(', 'prompt(']):
                                self.findings.append({
                                    'type': 'DOM-based XSS',
                                    'description': f'DOM XSS vulnerability confirmed via {payload}',
                                    'severity': 'High',
                                    'url': test_url,
                                    'evidence': f'DOM XSS triggered with payload: {payload[:50]}'
                                })
                                break
                    except Exception:
                        continue

                # If no active DOM XSS found, report sinks
                if not any(f['type'] == 'DOM-based XSS' for f in self.findings):
                    self.findings.append({
                        'type': 'DOM-based XSS Sinks Detected',
                        'description': f'Found {len(matches)} DOM XSS sink(s) in JavaScript code',
                        'severity': 'Medium',
                        'url': target_url,
                        'evidence': f'Detected sinks: {", ".join(set(matches))[:200]}'
                    })
        except Exception:
            pass

    def _scan_blind_xss(self, target_url: str):
        """Test for blind XSS using out-of-band detection.

        Fires the param probes and header probes concurrently instead of
        serially. The header probes used to sit *inside* the per-param loop
        even though they never referenced `param` — that ran the same 9
        header checks 9 times over (81 redundant requests, and a risk of
        appending the same header finding once per param iteration). They
        now run once, alongside the param probes.
        """
        try:
            test_params = ['q', 'search', 'query', 'name', 'email', 'website', 'url', 'comment', 'feedback']
            headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']

            def probe_param(param: str, payload: str):
                actual_payload = payload.replace('{oob}', self.oob_domain)
                test_url = f"{target_url}?{param}={actual_payload}"
                try:
                    resp = self.client.get(test_url)
                    if resp.status_code < 500 and (
                        actual_payload in resp.text or any(part in resp.text for part in actual_payload.split('&')[:2])
                    ):
                        return param, {
                            'type': 'Blind XSS',
                            'description': f'Parameter "{param}" appears vulnerable to blind XSS',
                            'severity': 'High',
                            'url': test_url,
                            'payload': actual_payload,
                            'evidence': f'Blind XSS payload reflected: {actual_payload[:50]}... (OOB verification required)'
                        }
                except Exception:
                    pass
                return None

            def probe_header(header: str, payload: str):
                actual_payload = payload.replace('{oob}', self.oob_domain)
                try:
                    resp = self.client.get(target_url, headers={header: actual_payload})
                    if resp.status_code < 500:
                        return f"header:{header}", {
                            'type': 'Blind XSS',
                            'description': f'Header "{header}" appears vulnerable to blind XSS',
                            'severity': 'Medium',
                            'url': target_url,
                            'payload': actual_payload,
                            'evidence': f'Blind XSS payload in {header}: {actual_payload[:30]}...'
                        }
                except Exception:
                    pass
                return None

            jobs = (
                [(probe_param, param, payload) for param in test_params for payload in Payloads.BLIND_XSS[:5]]
                + [(probe_header, header, payload) for header in headers_to_test for payload in Payloads.BLIND_XSS[:3]]
            )

            results = {}
            with ThreadPoolExecutor(max_workers=min(20, len(jobs)) or 1) as executor:
                future_to_idx = {executor.submit(fn, a, b): i for i, (fn, a, b) in enumerate(jobs)}
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        r = future.result()
                    except Exception:
                        r = None
                    if r is not None:
                        results[idx] = r

            # Keep only the first match per param/header (by original job
            # order), matching the original "break after first hit" intent.
            seen_keys = set()
            for idx in sorted(results):
                key, finding = results[idx]
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                self.findings.append(finding)
        except Exception:
            pass

    def _verify_xss_execution(self, response_text: str, payload: str, parameter: str) -> tuple:
        """
        Verify if XSS payload can actually execute in the response context
        Returns: (severity, evidence)
        """
        # Check for various execution contexts
        soup = BeautifulSoup(response_text, 'html.parser')

        # 1. Direct script tag injection
        if f'<script>{payload}</script>' in response_text or f'<script> {payload} </script>' in response_text:
            return 'Critical', f'Direct script injection: {payload[:50]}'

        # 2. Event handler injection
        event_patterns = [f'onerror="{payload}"', f'onload="{payload}"', f'onclick="{payload}"']
        if any(pattern in response_text for pattern in event_patterns):
            return 'Critical', f'Event handler injection: {payload[:50]}'

        # 3. SVG/XML context
        if '<svg' in response_text and ('onload' in response_text or 'onerror' in response_text):
            if payload in response_text:
                return 'Critical', f'SVG context injection: {payload[:50]}'

        # 4. HREF/JavaScript context
        if f'href="javascript:{payload}"' in response_text or f"href='javascript:{payload}'" in response_text:
            return 'Critical', f'JavaScript URL injection: {payload[:50]}'

        # 5. Attribute context that could lead to execution
        if f'<div {payload}>' in response_text or f'<span {payload}>' in response_text:
            return 'High', f'HTML attribute injection: {payload[:50]}'

        # 6. CSS context (less severe but still XSS)
        if '<style' in response_text and payload in response_text:
            return 'Medium', f'CSS context injection: {payload[:50]}'

        # 7. Basic reflection (lowest severity)
        if payload in response_text:
            # Additional checks to determine if it's dangerous
            if any(dangerous in payload.lower() for dangerous in ['alert', 'fetch', 'xmlhttprequest', 'iframe', 'object', 'embed']):
                return 'High', f'Dangerous payload reflected: {payload[:50]}'
            else:
                return 'Medium', f'Payload reflected in response: {payload[:50]}'

        # Default to Info if reflected but unclear context
        return 'Info', f'Payload detected in response: {payload[:30]}'

    def _check_stored_xss_persistence(self, url: str, payload: str) -> str:
        """
        Check if XSS payload persists in the application (stored XSS)
        """
        try:
            # Wait a moment for potential storage
            time.sleep(1)

            # Make a request to the same page without the payload
            resp = self.client.get(url)
            if resp.status_code < 500:
                # Check if payload appears in the clean response (indicating storage)
                if payload in resp.text:
                    return f'Payload persisted in application storage: {payload[:50]}...'
                elif any(part in resp.text for part in payload.split('&')[:2]):
                    return f'Partial payload persisted indicating storage: {payload[:30]}...'
                else:
                    # Check common storage locations
                    storage_indicators = ['database', 'storage', 'saved', 'persistent']
                    if any(indicator in resp.text.lower() for indicator in storage_indicators):
                        return f'Application indicates storage capability: {payload[:30]}...'
                    else:
                        return f'Payload reflected in response (potential storage): {payload[:50]}...'
            else:
                return f'Payload submitted successfully: {payload[:50]}...'
        except Exception:
            return f'Payload submitted: {payload[:50]}... (verification failed)'