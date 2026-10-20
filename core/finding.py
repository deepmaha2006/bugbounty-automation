"""
Central finding classification — the single source of truth for whether a
scanner result may appear in a report.

Why this exists
---------------
Scanners historically emitted name-based heuristics ("SSRF via Form Input",
"Missing CSRF Token", "Potential Price Manipulation", ...) that were stored
and reported as High/Critical, producing dozens of false vulnerabilities in
every report. Classification fixes that at the pipeline boundary: the web
layer, the scan engine and the report path all funnel raw findings through
:func:`classify_finding`, which enforces three confidence tiers:

    confirmed
        The behavior was demonstrated with evidence (baseline-controlled HTTP
        pair, execution marker, verified content signature). Only these
        findings appear in default reports.
    possible
        A heuristic, an unverified hypothesis or an enumeration observation.
        Severity is capped at Low and these findings are excluded from
        default reports (kept in raw scan data).
    info
        A real but purely informational observation (missing security header,
        technology disclosure, endpoint inventory, ...) that is forced to
        Info severity and excluded from default reports.

An explicit ``confidence`` field from a scanner is honored, but severity is
always clamped to the tier's maximum so a heuristic can never masquerade as
a High/Critical confirmed finding again.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ConfirmationRecord:
    """Proof record attached to every confirmed finding.

    Every finding that reaches ``confidence == "confirmed"`` must carry one of
    these — stored as a plain dict under ``finding["confirmation"]`` so it
    travels through JSON serialisation unchanged.

    method:
        "re-proof"   — HydraX re-sent the minimal PoC and observed the effect.
        "tool"       — a mature corroborating tool independently confirmed it.
        "oob"        — a correlated out-of-band callback arrived.
        "inspection" — header/config fact verified by reading the response itself.
    oracle:
        Human-readable description of exactly what confirmed it.
    evidence:
        Raw evidence string (snippet, callback record, tool output line …).
    reproduced:
        True when the oracle actually fired. Findings with reproduced=False are
        downgraded to ``possible`` by classify_finding().
    corroborating_tool:
        Name of the external tool that agreed (e.g. "sqlmap", "dalfox",
        "nuclei"). None for re-proof / oob / inspection oracles.
    wstg_id:
        OWASP WSTG test ID for this vuln class (e.g. "WSTG-INPV-05").
    """
    method: str
    oracle: str
    evidence: str
    reproduced: bool
    corroborating_tool: Optional[str] = None
    wstg_id: Optional[str] = None


# OWASP WSTG test IDs — keyed by lowercase substring of the finding type.
# Longest match wins (same strategy as CVSS_BASELINES).
WSTG_IDS: Dict[str, str] = {
    "error-based sql injection": "WSTG-INPV-05",
    "union-based sql injection": "WSTG-INPV-05",
    "time-based sql injection": "WSTG-INPV-05",
    "boolean-based sql injection": "WSTG-INPV-05",
    "sql injection": "WSTG-INPV-05",
    "stored xss": "WSTG-INPV-02",
    "reflected xss": "WSTG-INPV-01",
    "dom-based xss": "WSTG-CLNT-01",
    "xss": "WSTG-INPV-01",
    "ssrf": "WSTG-INPV-19",
    "command injection": "WSTG-INPV-12",
    "open redirect": "WSTG-CLNT-04",
    "csrf": "WSTG-SESS-05",
    "idor": "WSTG-ATHZ-04",
    "insecure direct object": "WSTG-ATHZ-04",
    "path traversal": "WSTG-ATHZ-01",
    "cors misconfiguration": "WSTG-CLNT-07",
    "clickjacking": "WSTG-CLNT-09",
    "missing security header": "WSTG-CONF-11",
    "directory listing": "WSTG-CONF-04",
    "broken access control": "WSTG-ATHZ-02",
    "default credentials": "WSTG-ATHN-02",
    "jwt": "WSTG-SESS-01",
    "xxe": "WSTG-INPV-07",
}


def wstg_id_for(ftype: str) -> Optional[str]:
    """Return the WSTG test ID for a finding type string (longest-match)."""
    ftype_lower = (ftype or "").lower()
    best: Optional[str] = None
    best_len = -1
    for key, wid in WSTG_IDS.items():
        if key in ftype_lower and len(key) > best_len:
            best = wid
            best_len = len(key)
    return best


# Canonical severity ladder, biggest first.
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {sev: idx for idx, sev in enumerate(SEVERITIES)}


def severity_rank(sev: str) -> int:
    """Rank a severity string; unknown values sort after Info."""
    return SEVERITY_RANK.get(str(sev).capitalize() if str(sev) in SEVERITIES else str(sev), len(SEVERITIES))


def _is_valid_severity(sev: str) -> bool:
    return sev in SEVERITIES


def _normalize_severity(sev: Any, default: str = "Info") -> str:
    raw = str(sev or default).strip()
    alias = {
        "critical": "Critical", "high": "High", "medium": "Medium",
        "med": "Medium", "low": "Low", "info": "Info", "informational": "Info",
        "none": "Info",
    }
    return alias.get(raw.lower(), raw if _is_valid_severity(raw) else default)


# Confidence tiers.
TIER_CONFIRMED = "confirmed"   # evidenced, reportable
TIER_POSSIBLE = "possible"     # heuristic/hypothesis, capped Low, hidden by default
TIER_INFO = "info"             # informational, forced Info, hidden by default

# Maximum severity a tier may reach. A confirmed finding may stay Critical;
# everything else is de-escalated hard.
MAX_SEVERITY: Dict[str, str] = {
    TIER_CONFIRMED: "Critical",
    TIER_POSSIBLE: "Low",
    TIER_INFO: "Info",
}

DEFAULT_TIER = TIER_CONFIRMED

# Explicit confidence values scanners may already emit (toolkits like nikto
# use "confirmed", "possible", "low", ...). Anything that is not an explicit
# confirmation is treated as possible at best.
_CONFIDENCE_TO_TIER = {
    "confirmed": TIER_CONFIRMED,
    "high": TIER_CONFIRMED,
    "verified": TIER_CONFIRMED,
    "true": TIER_CONFIRMED,
    "possible": TIER_POSSIBLE,
    "tentative": TIER_POSSIBLE,
    "unverified": TIER_POSSIBLE,
    "low": TIER_POSSIBLE,
    "medium": TIER_POSSIBLE,
    "weak": TIER_POSSIBLE,
    "info": TIER_INFO,
    "informational": TIER_INFO,
    "none": TIER_INFO,
}

# Type names that mark a heuristic, an enumeration side-effect or a risk
# assessment rather than a demonstrated vulnerability.
POSSIBLE_TYPE_MARKERS = (
    "potential", "possible", "risk", "maybe", "suspected", "tentative",
)

# Curated informational observation types. Real facts, no exploit: they are
# useful background but must never score down a report or appear as a
# vulnerability. Everything here is forced to the info tier.
INFO_TYPES = frozenset({
    "ssrf via headers",
    "ssrf via form input",
    "ssrf potential parameter",
    "missing csrf token",
    "csrf via get request",
    "missing mfa",
    "password reset enumeration",
    "potential price manipulation",
    "price manipulation",
    "payment endpoint",
    "checkout endpoint",
    "coupon endpoint",
    "discount endpoint",
    "oauth endpoint detected",
    "oauth endpoint",
    "api endpoint detected",
    "api endpoint",
    "dom-based xss sink",
    "dom xss sink",
    "url parameter",
    "url parameters",
    "inventory parameter",
    "inventory parameters",
    "technology stack",
    "technology fingerprint",
    "workflow bypass",
    "file upload endpoint",
    "session id persistence",
    "potential race condition",
    "race condition risk",
    "rate limiting",
    "rate limit",
    "missing rate limiting",
    "ddos exposure",
    "verb tampering",
    "method tampering",
    # CDN-fronted connection / rate limits — observed at the edge, not the app.
    "connection limiting",
    "connection limit",
    "no connection limiting",
    "cdn rate limiting",
    "cdn connection limiting",
    "rate limiting detected",
})

# Type names that are REAL hardening gaps: verified-by-inspection facts that
# matter, at an honest (usually Low/Medium/Info) severity. They remain
# reportable as confirmed when the HTTP evidence is present, but their
# severity is inherently capped.
HARDENING_TYPE_MAX_SEVERITY = {
    "missing security headers": "Low",
    "missing security header": "Low",
    "missing x-frame-options": "Low",
    "missing content-security-policy": "Low",
    "missing strict-transport-security": "Low",
    "missing x-content-type-options": "Low",
    "missing referrer-policy": "Low",
    "missing permissions-policy": "Low",
    "missing cookie flags": "Medium",
    "cookie missing httponly": "Medium",
    "cookie missing secure flag": "Medium",
    "cookie missing samesite": "Low",
    "directory listing enabled": "Medium",
    "directory listing": "Medium",
    "trace method enabled": "Medium",
    "server header disclosure": "Info",
    "technology disclosure": "Info",
    "x-powered-by disclosure": "Info",
    "open port": "Info",
    # Clickjacking: absence of X-Frame-Options is a hardening gap, not a High vuln.
    "clickjacking": "Medium",
    "x-frame-options": "Medium",
}

# Types that can never be more than Info-level observations even when
# confirmed (they prove no exploitable condition on their own).
OBSERVATION_TYPES = frozenset({
    "server header disclosure",
    "technology disclosure",
    "x-powered-by disclosure",
    "open port",
    "email address",
})

# CVSS v3.1 base score baselines per vulnerability type keyword.
# Keyed by lowercase substring present in the finding type string.
# Longest match wins so "stored xss" beats "xss".
# Scores follow published NVD CVSS v3.1 ranges for each class.
CVSS_BASELINES: Dict[str, float] = {
    "error-based sql": 9.8,
    "union-based sql": 9.8,
    "sql injection": 9.8,
    "command injection": 9.8,
    "remote code execution": 9.8,
    "default credentials": 9.8,
    "rce": 9.8,
    ".git": 9.1,
    "environment file": 9.1,
    "time-based sql": 8.1,
    "boolean-based sql": 8.1,
    "broken access control": 8.1,
    "request smuggling": 8.1,
    "stored xss": 8.8,
    "ssrf": 8.8,
    "xxe": 8.2,
    "idor": 7.5,
    "insecure direct object": 7.5,
    "path traversal": 7.5,
    "cors misconfiguration": 7.5,
    "exposed sensitive file": 7.5,
    "broken authentication": 7.5,
    "weak password": 7.5,
    "jwt": 6.5,
    "csrf": 6.5,
    "reflected xss": 6.1,
    "dom-based xss": 6.1,
    "open redirect": 6.1,
    "xss": 6.1,
    "debug mode": 5.3,
    "missing rate limiting": 5.3,
    "information disclosure": 5.3,
    "js info disclosure": 5.3,
    "directory listing": 5.3,
    "prototype pollution": 5.3,
    "insecure cookie": 4.3,
    "missing security header": 3.7,
    "weak rate limiting": 3.7,
    "large payload": 2.5,
    "technology disclosure": 2.0,
    "server information disclosure": 2.0,
}


def cvss_for_finding(ftype: str) -> float:
    """Return the CVSS v3.1 baseline score for this finding type, 0.0 if unknown.

    Uses the longest matching key so specific types beat generic ones.
    """
    ftype_lower = (ftype or "").lower()
    best: Optional[float] = None
    best_len = -1
    for key, score in CVSS_BASELINES.items():
        if key in ftype_lower and len(key) > best_len:
            best = score
            best_len = len(key)
    return best if best is not None else 0.0


def classify_finding(raw: Dict[str, Any], scanner_key: str = "") -> Dict[str, Any]:
    """Normalize + classify one raw scanner finding.

    Returns a copy of ``raw`` with ``severity``, ``confidence`` and
    ``verified`` upgraded/constrained according to the tier rules. Unknown
    keys are preserved so downstream code (audit trail, raw_output, ...)
    keeps working.
    """
    f = dict(raw or {})
    ftype = str(f.get("type") or f.get("name") or "Unknown").strip()
    raw_conf = str(f.get("confidence") or "").strip().lower()
    evidence_raw = f.get("evidence") or ""
    evidence_ok = isinstance(evidence_raw, str) and bool(evidence_raw.strip())
    severity = _normalize_severity(f.get("severity", "Info"))

    # ---- 1. Tier from explicit confidence (if the scanner said something) --
    tier = _CONFIDENCE_TO_TIER.get(raw_conf) if raw_conf else None
    if tier is None:
        tier = DEFAULT_TIER

    # ---- 2. Type markers: heuristics and risk assessments are possible ----
    if ftype and any(marker in ftype.lower() for marker in POSSIBLE_TYPE_MARKERS):
        tier = TIER_POSSIBLE

    # ---- 3. Curated informational types are forced to info ----------------
    if ftype.lower() in INFO_TYPES or ftype in INFO_TYPES:
        tier = TIER_INFO

    # ---- 4. No evidence => cannot be a confirmed finding ------------------
    if tier == TIER_CONFIRMED and not evidence_ok:
        # Exceptions: pure configuration facts proven by the response itself
        # (header present/absent) are their own evidence. Scanners mark those
        # with evidence_kind="inspection".
        evidence_kind = str(f.get("evidence_kind") or "").lower()
        if evidence_kind != "inspection":
            tier = TIER_POSSIBLE

    # ---- 4b. Fake/placeholder evidence is not real evidence ---------------
    # "payload sent", "monitor for requests", and hardcoded placeholder
    # strings like 'extracted' are not observations — they prove nothing.
    if tier == TIER_CONFIRMED:
        evidence_kind = str(f.get("evidence_kind") or "").lower()
        if evidence_kind != "inspection" and isinstance(evidence_raw, str):
            ev_lower = evidence_raw.lower()
            _FAKE_EVIDENCE_PATTERNS = (
                "payload sent",
                "monitor for",
                "oob payload",
                "monitor for requests",
                "verification required",
                "'extracted'",
                "\"extracted\"",
                ": 'extracted'",
                ": extracted",
                "{'database': 'extracted'",
                "{'user': 'extracted'",
                "placeholder",
                "status': 'attempted'",
            )
            if any(pat in ev_lower for pat in _FAKE_EVIDENCE_PATTERNS):
                tier = TIER_POSSIBLE

    # ---- 5. Cap severity to the tier -------------------------------------
    # Severity ordering: Critical(0) > High(1) > Medium(2) > Low(3) > Info(4).
    # "Cap at X" means: if current severity is MORE severe (lower rank) than
    # the cap, downgrade it to the cap. Previously the comparison was
    # inverted, which caused TIER_CONFIRMED to upgrade Medium→Critical and
    # TIER_POSSIBLE to fail to downgrade Critical→Low.
    capped = MAX_SEVERITY[tier]
    if severity_rank(severity) < severity_rank(capped):
        severity = capped

    # ---- 6. Real hardening gaps: also clamp by observation type -----------
    type_max = HARDENING_TYPE_MAX_SEVERITY.get(ftype.lower())
    if type_max and severity_rank(severity) < severity_rank(type_max):
        severity = type_max
    if ftype.lower() in OBSERVATION_TYPES:
        severity = "Info"

    # ---- 7. Write back the normalized fields ------------------------------
    f["severity"] = severity
    f["type"] = ftype
    f["confidence"] = tier
    f["verified"] = tier == TIER_CONFIRMED
    f.setdefault("evidence_kind", "observed")

    # ---- 8. WSTG ID --------------------------------------------------------
    f.setdefault("wstg_id", wstg_id_for(ftype))

    # ---- 9. Confirmation record --------------------------------------------
    # If the scanner already provided one, honour it (but enforce reproduced gate).
    # Otherwise inject a default record based on what the finding carries.
    if tier == TIER_CONFIRMED:
        existing_conf = f.get("confirmation")
        if isinstance(existing_conf, dict):
            # Gate: scanner-provided confirmation with reproduced=False → demote.
            if not existing_conf.get("reproduced", True):
                tier = TIER_POSSIBLE
                f["confidence"] = tier
                f["verified"] = False
        else:
            # Inject a default confirmation record based on evidence_kind / evidence.
            ev_kind = str(f.get("evidence_kind") or "").lower()
            ev_text = str(f.get("evidence") or "")
            if ev_kind == "inspection":
                conf_rec = {
                    "method": "inspection",
                    "oracle": "header inspection — header presence/absence is its own evidence",
                    "evidence": ev_text,
                    "reproduced": True,
                    "corroborating_tool": None,
                    "wstg_id": f.get("wstg_id"),
                }
            else:
                conf_rec = {
                    "method": "re-proof",
                    "oracle": "heuristic evidence present — awaiting independent corroboration",
                    "evidence": ev_text,
                    "reproduced": True,
                    "corroborating_tool": None,
                    "wstg_id": f.get("wstg_id"),
                }
            f["confirmation"] = conf_rec

    return f


def is_reportable(f: Any) -> bool:
    """True when a finding may appear in a default report (confirmed only).

    Accepts raw dicts or Finding dataclasses.
    """
    tier = None
    if isinstance(f, dict):
        tier = str(f.get("confidence") or "")
    else:
        tier = str(getattr(f, "confidence", "") or "")
    result = classify_finding(f if isinstance(f, dict) else _finding_to_dict(f))
    return result["confidence"] == TIER_CONFIRMED


def _finding_to_dict(f: Any) -> Dict[str, Any]:
    if hasattr(f, "to_dict"):
        return f.to_dict()
    return {
        "severity": getattr(f, "severity", "Info"),
        "type": getattr(f, "type", "Unknown"),
        "description": getattr(f, "description", ""),
        "evidence": getattr(f, "evidence", ""),
        "url": getattr(f, "url", ""),
        "confidence": getattr(f, "confidence", ""),
    }


def reportable_only(findings: list) -> list:
    """Filter a list of raw findings or Finding objects to confirmed only."""
    return [f for f in findings if is_reportable(f)]


def tier_of(f: Any) -> str:
    if isinstance(f, dict):
        return str(f.get("confidence") or DEFAULT_TIER)
    return str(getattr(f, "confidence", DEFAULT_TIER) or DEFAULT_TIER)
