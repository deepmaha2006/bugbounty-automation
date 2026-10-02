"""
Evidence validators — turn raw scanner observations into confirmed findings.

Every helper here implements the same contract:

    * return ``None`` when the behavior could NOT be demonstrated
    * return a small evidence dict when it was (baseline, deltas, markers...)

The dict is later merged into the finding's ``evidence`` field so a confirmed
finding always carries the numbers that justify it, and the scanners treat
``None`` as "do not report".

Baseline control is the core principle: a payload only counts when it
produces a measurable difference against a neutral request on the SAME
endpoint, and (for time-based checks) a control payload that would delay on
its own disqualifies the experiment.
"""

import difflib
import html as html_mod
import re
import statistics
import time
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------

_TEXT_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _response_text(resp) -> str:
    """Decode + normalize a response body for comparison.

    HTML tags and repeated whitespace are stripped so tiny dynamic bits
    (timestamps, csrf nonces) do not dominate the similarity score.
    """
    body = getattr(resp, "content", b"") or b""
    if isinstance(body, str):
        text = body
    else:
        try:
            text = body.decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            text = str(body)
    text = _TEXT_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def text_similarity(a: str, b: str) -> float:
    """0..1 ratio; 1.0 means (near-)identical after normalization."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def response_similarity(resp_a, resp_b) -> float:
    return text_similarity(_response_text(resp_a), _response_text(resp_b))


# ---------------------------------------------------------------------------
# Time-based confirmation (SQLi / blind command injection / template delay)
# ---------------------------------------------------------------------------

def _elapsed(client, url: str, method: str, params, data, timeout: float) -> Optional[float]:
    """One request with elapsed-seconds measurement (None on transport error)."""
    started = time.perf_counter()
    try:
        if method == "POST":
            client.post(url, data=data, timeout=timeout)
        else:
            client.get(url, params=params, timeout=timeout)
        return time.perf_counter() - started
    except Exception:  # noqa: BLE001 — network errors just invalidate a sample
        return None


def _median_of(values: List[Optional[float]]) -> Optional[float]:
    ok = [v for v in values if v is not None]
    if len(ok) < 2:
        return None
    return statistics.median(ok)


def time_based_confirmer(
    client,
    url: str,
    param_name: str,
    payload: str,
    control_payload: str,
    method: str = "GET",
    extra: Optional[Dict] = None,
    threshold_delta: float = 2.0,
    samples: int = 3,
    timeout: float = 15,
) -> Optional[Dict]:
    """Confirm a time-based injection via baseline-controlled measurement.

    Sequence:
      1. baseline  — ``samples`` neutral requests (random non-matching value)
      2. payload   — ``samples`` requests with the delaying payload
      3. control   — 2 requests with a payload that *would* delay loudly if
                     the parameter was simply echoed into a sleepy code path
                     (e.g. ``SLEEP(0)``-style equivalent). A delayed control
                     means the time delta is not injection-specific.

    Confirmed only when:
      * payload median - baseline median >= threshold_delta seconds
      * at least 2/3 payload requests individually beat baseline median
      * control median stays within threshold_delta of baseline median
    """
    extra = dict(extra or {})
    extra.pop(param_name, None)

    def _mk(value: str):
        params, data = None, None
        if method == "POST":
            data = dict(extra, **{param_name: value})
        else:
            params = dict(extra, **{param_name: value})
        return params, data

    baseline = [_elapsed(client, url, method, *_mk("zz_" + str(i)), timeout) for i in range(samples)]
    baseline_med = _median_of(baseline)
    if baseline_med is None:
        return None

    payload_times = [_elapsed(client, url, method, *_mk(payload), timeout) for _ in range(samples)]
    payload_med = _median_of(payload_times)
    if payload_med is None:
        return None

    control_times = [_elapsed(client, url, method, *_mk(control_payload), timeout) for _ in range(2)]
    control_med = _median_of(control_times)
    if control_med is None:
        return None

    delta = payload_med - baseline_med
    if delta < threshold_delta:
        return None

    # Consistency: most payload samples individually exceed the baseline.
    beaten = sum(1 for t in payload_times if t is not None and t > baseline_med + threshold_delta * 0.5)
    if beaten < max(2, samples - 1):
        return None

    # Control must NOT delay: if the decoy payload also sleeps, the slowdown
    # is not specific to the injection point.
    control_delta = control_med - baseline_med
    if control_delta >= threshold_delta:
        return None

    return {
        "method": method,
        "parameter": param_name,
        "baseline_median_s": round(baseline_med, 3),
        "payload_median_s": round(payload_med, 3),
        "delta_s": round(delta, 3),
        "control_median_s": round(control_med, 3),
        "control_delta_s": round(control_delta, 3),
        "samples": len(payload_times),
        "beaten_samples": beaten,
        "rule": "payload_median - baseline_median >= %.1fs, control not delayed" % threshold_delta,
    }


# ---------------------------------------------------------------------------
# Boolean-pair confirmation (boolean-based blind SQLi)
# ---------------------------------------------------------------------------

def boolean_pair_confirmer(
    client,
    url: str,
    param_name: str,
    true_payload: str,
    false_payload: str,
    method: str = "GET",
    extra: Optional[Dict] = None,
    similarity_cutoff: float = 0.9,
    timeout: float = 15,
) -> Optional[Dict]:
    """Confirm boolean-based injection with two stable, distinct clusters.

    Two rounds of (true, false) plus two neutral controls are fetched:
      * neutral controls must be stable  (> cutoff similarity)
      * true cluster must be stable      (> cutoff)
      * false cluster must be stable     (> cutoff)
      * true vs false must differ        (< cutoff) in each round

    Returning None when any stability requirement fails kills the classic
    false positive where the page produces random content per request.
    """
    extra = dict(extra or {})

    def _fetch(value: str):
        try:
            if method == "POST":
                return client.post(url, data=dict(extra, **{param_name: value}), timeout=timeout)
            return client.get(url, params=dict(extra, **{param_name: value}), timeout=timeout)
        except Exception:  # noqa: BLE001
            return None

    t1, t2 = _fetch(true_payload), _fetch(true_payload)
    f1, f2 = _fetch(false_payload), _fetch(false_payload)
    n1, n2 = _fetch("zz_neutral_1"), _fetch("zz_neutral_2")

    if any(r is None for r in (t1, t2, f1, f2, n1, n2)):
        return None

    sim_tt = response_similarity(t1, t2)
    sim_ff = response_similarity(f1, f2)
    sim_nn = response_similarity(n1, n2)
    sim_tf1 = response_similarity(t1, f1)
    sim_tf2 = response_similarity(t2, f2)
    sim_tn = response_similarity(t1, n1)

    if sim_tt < similarity_cutoff or sim_ff < similarity_cutoff or sim_nn < similarity_cutoff:
        return None
    if min(sim_tf1, sim_tf2) > similarity_cutoff:
        # true and false look the same — no observable condition split.
        return None

    return {
        "method": method,
        "parameter": param_name,
        "true_payload": true_payload,
        "false_payload": false_payload,
        "true_cluster_similarity": round(sim_tt, 3),
        "false_cluster_similarity": round(sim_ff, 3),
        "control_similarity": round(sim_nn, 3),
        "true_vs_false_round1": round(sim_tf1, 3),
        "true_vs_false_round2": round(sim_tf2, 3),
        "true_vs_control": round(sim_tn, 3),
        "rule": "clusters stable (>%.2f), true != false (<%.2f)" % (similarity_cutoff, similarity_cutoff),
    }


# ---------------------------------------------------------------------------
# XSS context verification
# ---------------------------------------------------------------------------

_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_ATTR_RE = re.compile(r"""\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)""", re.I)
_URI_RE = re.compile(r"""(?:href|src|action|formaction|data)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)""", re.I)
_UNQUOTED_RE = re.compile(r"\s[\w:-]+\s*=\s*[^\"'\s>]*")


def _body_text(resp) -> str:
    body = getattr(resp, "content", b"") or b""
    if isinstance(body, str):
        return body
    return body.decode("utf-8", "ignore")


def xss_context_verifier(resp, payload: str) -> Optional[Dict]:
    """Verify a reflected payload sits in an executable HTML context.

    Confirmed contexts:
      * script_block    — inside <script>...</script>
      * event_handler   — inside an on* attribute value (onerror=, onload=, ...)
      * javascript_uri  — javascript: URL in href/src/action/data
      * unquoted_attr   — unquoted attribute breakout
      * html_injection  — literal (unescaped) payload present in a tag we
                          can break out of (payload contains '<')

    Returns None when the payload is absent or only present HTML-escaped.
    """
    text = _body_text(resp)
    if not payload or not text or payload not in text:
        return None

    contexts: List[str] = []

    for m in _SCRIPT_RE.finditer(text):
        if payload in m.group(1):
            contexts.append("script_block")
            break

    for m in _ATTR_RE.finditer(text):
        if payload in m.group(0):
            contexts.append("event_handler")
            break

    for m in _URI_RE.finditer(text):
        val = m.group(0)
        if "javascript:" in val.lower() and payload in val:
            contexts.append("javascript_uri")
            break

    for m in _UNQUOTED_RE.finditer(text):
        if payload in m.group(0):
            contexts.append("unquoted_attr")
            break

    if "<" in payload:
        # Raw, unescaped payload in the body (an escaped one would contain
        # &lt; instead of <).
        escaped = html_mod.escape(payload, quote=False)
        if payload in text and escaped not in text:
            contexts.append("html_injection")

    if not contexts:
        return None

    return {
        "reflected": True,
        "executable_contexts": contexts,
        "rule": "payload reflected into " + ", ".join(contexts),
    }
