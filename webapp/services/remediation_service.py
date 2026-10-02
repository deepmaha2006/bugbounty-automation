"""Remediation workflow + automatic fix verification (spec §14, §15).

The critical rule from §15: marking something "fixed" must never just flip a
status flag. submit_fix() schedules a real verification scan; only
check_and_finalize_verifications() — after that scan's real result is known —
is allowed to set FIXED or REOPENED (enforced structurally: db.py's
update_remediation_task() rejects a direct PATCH to any of those statuses).
"""
import logging
from typing import Any, Dict, List, Optional

from webapp import db
from webapp.services import web_scan_service

logger = logging.getLogger("hydrax.remediation")


def submit_fix(task_id: int, organization_id: int, requesting_user_id: int) -> Dict[str, Any]:
    """FIX_SUBMITTED -> schedules a real verification scan -> RESCAN.

    Raises ValueError if the task/finding/asset can't be resolved or the
    finding has no associated web asset to re-scan (e.g. a system/network
    finding — verification for those isn't wired up yet, see docs/ROADMAP.md).
    """
    task = db.get_remediation_task(task_id, organization_id)
    if not task:
        raise ValueError("Remediation task not found")

    finding = db.get_finding(task["finding_id"], organization_id)
    if not finding:
        raise ValueError("The task's finding no longer exists")
    if not finding.get("target_id"):
        raise ValueError("This finding has no associated web asset to verify against")

    asset = db.get_target(finding["target_id"], organization_id)
    if not asset:
        raise ValueError("The finding's asset no longer exists")

    # Re-verify authorization immediately before running, same rule as the
    # scheduler (Phase 5) — an asset can be de-authorized in between.
    if asset["verification_status"] != "verified" or asset["authorization_status"] != "authorized":
        raise ValueError("The finding's asset is not currently authorized for scanning")

    run_as_user_id = task.get("assignee_user_id") or asset.get("added_by_user_id") or requesting_user_id
    scan_id = web_scan_service.start_web_scan(run_as_user_id, asset["url"], [finding["type"]])
    db.submit_fix(task_id, organization_id, scan_id)
    return {"task_id": task_id, "verification_scan_id": scan_id}


def _check_and_finalize_verifications() -> int:
    """Finds every RESCAN task whose verification scan has finished and
    decides FIXED vs REOPENED from what actually happened during that scan —
    never from the pre-scan state. Returns the number finalized."""
    finalized = 0
    for task in db.list_tasks_awaiting_verification():
        finding = db.get_finding_unscoped(task["finding_id"])
        if not finding:
            continue
        # add_finding()'s own fingerprint dedup (Phase 4) already updated
        # finding.scan_id to the verification scan's id if — and only if —
        # the same vulnerability was detected again during that scan. If
        # scan_id still points anywhere else, the verification scan ran and
        # did NOT re-detect it: the fix held.
        still_present = finding.get("scan_id") == task["verification_scan_id"]
        now = db._now()
        db.finalize_verification(task["id"], still_present, evidence={
            "verification_scan_id": task["verification_scan_id"],
            "checked_at": now.isoformat() if hasattr(now, "isoformat") else now,
            "still_present": still_present,
        })
        # No human actor triggers this scheduled sweep — audited with
        # user_id=None (Phase 12) and the task's own organization_id, since
        # a REOPENED/FIXED transition is exactly the kind of security-
        # relevant state change spec §18 wants a durable trail for.
        db.add_audit_log(None, "remediation_verification_finalized",
                         organization_id=task["organization_id"],
                         details={"task_id": task["id"], "finding_id": task["finding_id"],
                                  "result": "REOPENED" if still_present else "FIXED"})
        finalized += 1
    return finalized


def check_and_finalize_verifications() -> int:
    return _check_and_finalize_verifications()



# ===========================================================================
# Analyst engine ("the brain") — resolve a finding to a KB entry and produce
# a deterministic analyst report. The KB itself is data
# (config/remediation_kb.yaml, loaded by remediation_kb); nothing here makes
# network calls or uses randomness: the same finding always yields the same
# report.
# ===========================================================================
import re as _re
import threading as _threading

from webapp.services import remediation_kb as _kbm

# --- Scoring model (documented; keep in sync with docs) --------------------
SEVERITY_BASE = {"Critical": 90, "High": 70, "Medium": 45, "Low": 20, "Info": 5}
EXPLOIT_MOD = {"High": 10, "Medium": 0, "Low": -10}
CONFIDENCE_MOD = {"confirmed": 5, "needs_verification": -10, "unknown": -5}
EXPOSURE_MOD = {"internet_facing": 5, "internal": -5, "unknown": 0}
PRIORITY_THRESHOLDS = ((85, "P1"), (60, "P2"), (35, "P3"))  # else P4
PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
SIGNAL_PRIORITY_CAP = "P3"

# An FP check shorter than this is treated as trivial for the triage flag.
_NONTRIVIAL_FP_WORDS = 12

_STOPWORDS = {
    "the", "and", "via", "for", "with", "found", "detected", "potential",
    "enabled", "exposed", "data", "endpoint", "issue", "from", "into", "not",
}

# --- Correlation rules ------------------------------------------------------
_HARDENING_KEYS = {
    "sec_misconfig.missing_security_header",
    "sec_misconfig.server_info_disclosure",
    "sec_misconfig.technology_disclosure",
}
_COOKIE_KEYS = {
    "auth_session.cookie_missing_httponly",
    "auth_session.cookie_missing_secure",
    "auth_session.cookie_missing_samesite",
    "sec_misconfig.insecure_cookie",
}
_INFO_CATEGORIES = {"info_disclosure", "recon", "local_tools"}
CORRELATION_RULES = (
    # (issue id, title, predicate(report) -> bool, minimum member count, action)
    ("http_hardening_gap", "HTTP Security Hardening Gap",
     lambda r: r["key"] in _HARDENING_KEYS, 3,
     "Apply one baseline header/banner policy at the proxy or middleware "
     "instead of fixing each response individually."),
    ("insecure_cookie_config", "Insecure Cookie Configuration",
     lambda r: r["key"] in _COOKIE_KEYS, 2,
     "Set Secure, HttpOnly and SameSite once in the session/cookie "
     "configuration so every cookie inherits them."),
    ("information_exposure", "Information Exposure (review)",
     lambda r: r["kind"] == "signal" and r["category"] in _INFO_CATEGORIES, 2,
     "Review the exposed information together, record it in the asset "
     "inventory, and suppress what is not needed."),
)

# --- Unresolved store (persistent JSON; one record per signature) ---------
# Each unmatched finding signature is stored once with a counter, first/last
# seen timestamps, and an auto-drafted KB entry template for an analyst to
# complete and append via add_kb_entry(). Store I/O problems are logged and
# never break resolve().
import json as _json
import os as _os
from datetime import datetime as _datetime, timezone as _timezone
from pathlib import Path as _Path

from webapp import config as _wcfg

UNRESOLVED_PATH = _Path(_wcfg.DATA_DIR) / "brain" / "unresolved.json"
_unresolved_lock = _threading.Lock()


def _now_iso() -> str:
    return _datetime.now(_timezone.utc).replace(microsecond=0).isoformat()


def _load_store() -> Dict[str, Dict[str, Any]]:
    path = _Path(UNRESOLVED_PATH)
    if not path.exists():
        return {}
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        logger.exception("unresolved store unreadable at %s; starting empty", path)
        return {}


def _save_store(data: Dict[str, Dict[str, Any]]) -> None:
    path = _Path(UNRESOLVED_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    _os.replace(tmp, path)


def _slug(text: str) -> str:
    s = _re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
    return s[:60] or "unknown"


def draft_entry(ftype: str, category: str, cwe: str = "",
                kb: Optional[Dict[str, Any]] = None,
                nearest: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Schema-shaped template for an analyst to complete.

    If a nearest existing entry is known (keyword overlap > 0), its category,
    CWE/OWASP, kind and references are used as guesses and its remediation
    text is copied under a "DRAFT — review before use" marker. The analyst
    fields stay blank and the entry keeps the `draft` tag, so it can never
    pass validation (and be appended) until someone has reviewed it.
    """
    src = None
    # Pre-fill only from an unambiguous nearest entry: strictly more overlap
    # than the runner-up. A tie (e.g. one shared generic word across several
    # entries) would make the choice arbitrary, so it only leaves hints.
    if kb and nearest and (len(nearest) == 1 or nearest[0]["overlap"] > nearest[1]["overlap"]):
        src = kb.get("entries", {}).get(nearest[0]["key"])
    cat = category or (src["category"] if src else "")
    marker = _kbm.DRAFT_MARKER
    rem = {"immediate_mitigation": "", "short_term_fix": "", "long_term_hardening": "",
           "code_fix_examples": {}, "config_examples": {}}
    if src:
        for f in ("immediate_mitigation", "short_term_fix", "long_term_hardening"):
            rem[f] = f"{marker} (copied from {src['key']}): {src['remediation'][f]}"
    return {
        "key": f"{_slug(cat) if cat else 'unclassified'}.{_slug(ftype)}",
        "kind": src["kind"] if src else "vulnerability",
        "aliases": [ftype] if ftype else [],
        "category": cat,
        "cwe": cwe or (src["cwe"] if src else ""),
        "owasp": src["owasp"] if src else "",
        "severity_guidance": "", "exploitability": "",
        "business_impact": "", "why_it_matters": "", "detection_signal": "",
        "false_positive_check": "", "triage_priority": "",
        "remediation": rem,
        "compensating_controls": [], "verification": "",
        "references": list(src["references"]) if src else [],
        "tags": ["draft"],
    }


def record_unresolved(finding: Dict[str, Any], kb: Optional[Dict[str, Any]] = None) -> str:
    """Record a finding signature that no KB entry matched. Returns the signature.

    Per signature: count, first_seen, last_seen, the top-3 nearest KB keys
    (refreshed on every sighting, since the KB may have grown) and an
    auto-drafted entry pre-filled from the nearest one.
    """
    ftype = str(finding.get("type") or finding.get("title") or "").strip()
    category = str(finding.get("category") or "").strip().lower()
    cwe = str(finding.get("cwe") or "").strip().upper()
    signature = f"{category or '-'}|{ftype.lower() or '-'}"
    logger.warning("remediation KB: no entry for finding signature %s", signature)
    try:
        if kb is None or not kb.get("entries"):
            try:
                kb = _kbm.get_kb()
            except Exception:  # noqa: BLE001 — drafting must not depend on a healthy KB
                kb = {"entries": {}}
        near = nearest_entries(ftype, kb, limit=3)
        with _unresolved_lock:
            data = _load_store()
            now = _now_iso()
            item = data.get(signature)
            if item is None:
                item = {"signature": signature, "type": ftype, "category": category,
                        "cwe": cwe, "count": 0, "first_seen": now,
                        "draft": draft_entry(ftype, category, cwe, kb, near)}
                src = item["draft"]["remediation"]["short_term_fix"]
                item["draft_source"] = (near[0]["key"] if near and src else None)
                data[signature] = item
            item["count"] = int(item.get("count", 0)) + 1
            item["last_seen"] = now
            item["nearest"] = near
            if cwe and not item.get("cwe"):
                item["cwe"] = cwe
            _save_store(data)
    except OSError:
        logger.exception("could not persist unresolved signature %s", signature)
    return signature


_SORTS = {
    "frequency": lambda i: (-int(i.get("count", 0)), i.get("signature", "")),
    "recent": lambda i: (_neg_ts(i.get("last_seen", "")), i.get("signature", "")),
    "signature": lambda i: i.get("signature", ""),
}


def _neg_ts(ts: str) -> tuple:
    # ISO-8601 UTC strings sort lexically; invert character codes for "newest first".
    return tuple(-ord(c) for c in str(ts))


def list_unresolved(sort: str = "frequency") -> List[Dict[str, Any]]:
    """Unresolved signatures. sort: "frequency" (default, most seen first),
    "recent" (last seen first) or "signature" (alphabetical)."""
    if sort not in _SORTS:
        raise ValueError(f"sort must be one of {sorted(_SORTS)}")
    with _unresolved_lock:
        items = list(_load_store().values())
    return sorted(items, key=_SORTS[sort])


# Backward-compatible name used by earlier callers/tests.
get_unresolved = list_unresolved


def dismiss_unresolved(signature: str) -> bool:
    with _unresolved_lock:
        data = _load_store()
        if signature not in data:
            return False
        del data[signature]
        _save_store(data)
        return True


def clear_unresolved() -> None:
    with _unresolved_lock:
        path = _Path(UNRESOLVED_PATH)
        if path.exists():
            path.unlink()


# --- Feedback (analyst marks a resolution correct / incorrect) --------------
# Stored per KB entry, next to the unresolved store — never in the KB YAML.
# score = correct / (correct + incorrect); None until the first vote, so
# "no feedback yet" is never shown as 0 %.
FEEDBACK_PATH = _Path(_wcfg.DATA_DIR) / "brain" / "feedback.json"
_feedback_lock = _threading.Lock()


def _load_json(path) -> Dict[str, Any]:
    path = _Path(path)
    if not path.exists():
        return {}
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        logger.exception("store unreadable at %s; starting empty", path)
        return {}


def _save_json(path, data: Dict[str, Any]) -> None:
    path = _Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    _os.replace(tmp, path)


def _score(correct: int, incorrect: int) -> Optional[float]:
    total = correct + incorrect
    return round(correct / total, 3) if total else None


def record_feedback(kb_key: str, correct: bool, finding_type: str = "",
                    kb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Record that resolving `finding_type` to `kb_key` was right or wrong.
    Only real KB entries accept feedback (KeyError otherwise). Returns the
    entry's updated stats."""
    kb = kb or _kbm.get_kb()
    if kb_key not in kb["entries"]:
        raise KeyError(f"unknown KB entry {kb_key!r}")
    field = "correct" if correct else "incorrect"
    ftype = str(finding_type or "").strip().lower()
    with _feedback_lock:
        data = _load_json(FEEDBACK_PATH)
        rec = data.setdefault(kb_key, {"correct": 0, "incorrect": 0, "by_type": {}})
        rec[field] = int(rec.get(field, 0)) + 1
        if ftype:
            t = rec["by_type"].setdefault(ftype, {"correct": 0, "incorrect": 0})
            t[field] = int(t.get(field, 0)) + 1
        rec["last_feedback"] = _now_iso()
        _save_json(FEEDBACK_PATH, data)
    return get_feedback(kb_key)


def get_feedback(kb_key: str) -> Dict[str, Any]:
    """{"correct", "incorrect", "score", "by_type"} for one entry."""
    with _feedback_lock:
        rec = _load_json(FEEDBACK_PATH).get(kb_key) or {}
    c, i = int(rec.get("correct", 0)), int(rec.get("incorrect", 0))
    by_type = {t: dict(v, score=_score(int(v.get("correct", 0)), int(v.get("incorrect", 0))))
               for t, v in sorted((rec.get("by_type") or {}).items())}
    return {"correct": c, "incorrect": i, "score": _score(c, i), "by_type": by_type}


def clear_feedback() -> None:
    with _feedback_lock:
        path = _Path(FEEDBACK_PATH)
        if path.exists():
            path.unlink()


def add_kb_entry(entry: Dict[str, Any], path=None) -> Dict[str, Any]:
    """Append a completed entry to the KB (validated on write) and drop the
    unresolved signatures it now covers. Returns {"key", "dismissed"}."""
    kw = {"path": path} if path is not None else {}
    _kbm.append_entry(entry, **kw)
    aliases = {str(a).strip().lower() for a in entry.get("aliases", [])}
    dismissed = [i["signature"] for i in list_unresolved()
                 if str(i.get("type", "")).strip().lower() in aliases]
    for sig in dismissed:
        dismiss_unresolved(sig)
    return {"key": entry["key"], "dismissed": dismissed}


def promote_unresolved(signature: str, completed_entry: Dict[str, Any], path=None) -> Dict[str, Any]:
    """Review-queue promotion in one step: validate the analyst-completed
    entry, append it to the KB (add_kb_entry — validated, rolled back on
    failure) and clear the signature. The signature's original type string
    is added to the entry's aliases if the analyst left it out, so the same
    finding resolves by alias afterwards. Raises KeyError for an unknown
    signature and KBValidationError for an invalid entry (store unchanged)."""
    item = next((i for i in list_unresolved() if i["signature"] == signature), None)
    if item is None:
        raise KeyError(f"no unresolved signature {signature!r}")
    entry = dict(completed_entry)
    aliases = list(entry.get("aliases") or [])
    if item.get("type") and item["type"].lower() not in {str(a).lower() for a in aliases}:
        aliases.append(item["type"])
    entry["aliases"] = aliases
    result = add_kb_entry(entry, path=path)
    dismiss_unresolved(signature)          # also covers type strings not in aliases
    if signature not in result["dismissed"]:
        result["dismissed"].append(signature)
    return result


def format_review_queue(limit: int = 20, sort: str = "frequency") -> str:
    """Human-readable queue: what the brain keeps seeing that it cannot yet
    solve, with the nearest existing KB entries as completion hints."""
    items = list_unresolved(sort=sort)
    if not items:
        return "Review queue is empty — every recorded finding type resolves."
    lines = [f"{len(items)} unresolved signature(s), {sort} order"
             + (f" (showing {limit})" if len(items) > limit else "") + ":"]
    for i in items[:limit]:
        near = ", ".join(f"{n['key']}({n['overlap']})" for n in i.get("nearest") or []) or "—"
        src = i.get("draft_source")
        lines.append(f"  {int(i.get('count', 0)):>4}x  {i['signature']}")
        lines.append(f"         seen {i.get('first_seen', '?')} → {i.get('last_seen', '?')}")
        lines.append(f"         nearest: {near}")
        lines.append(f"         draft: key={i['draft']['key']}"
                     + (f", pre-filled from {src}" if src else ", not pre-filled"))
    return "\n".join(lines)


# --- Matching ---------------------------------------------------------------
# Synonym groups: every phrase in a group means the same thing. Phrases are
# written in normalized form (lowercase, punctuation → space). The first
# element is the group's canonical token.
SYNONYM_GROUPS = (
    ("xss", "cross site scripting"),
    ("sqli", "sql injection", "sql i"),
    ("csrf", "xsrf", "cross site request forgery"),
    ("ssrf", "server side request forgery"),
    ("xxe", "xml external entity", "xml external entities"),
    ("ssti", "server side template injection", "template injection"),
    ("idor", "insecure direct object reference", "insecure direct object references"),
    ("cors", "cross origin resource sharing"),
    ("jwt", "json web token", "json web tokens"),
    ("mfa", "2fa", "two factor", "multi factor", "multifactor"),
    ("clickjacking", "ui redress", "ui redressing"),
    ("redirect", "unvalidated redirect", "open redirection"),
    ("dos", "ddos", "denial of service"),
    ("rce", "remote code execution"),
)
# phrase -> canonical token; longest phrases first so multi-word ones win.
_SYNONYM_PHRASES = sorted(
    ((phrase, group[0]) for group in SYNONYM_GROUPS for phrase in group),
    key=lambda pc: (-len(pc[0]), pc[0]))
_GROUP_TOKENS = {group[0]: {w for p in group for w in p.split()} | {group[0]}
                 for group in SYNONYM_GROUPS}


def _normalize(text: str) -> str:
    """lowercase, punctuation → space, collapse whitespace."""
    return " ".join(_re.findall(r"[a-z0-9]+", str(text or "").lower()))


def _canonicalize(norm: str) -> str:
    """Replace every synonym phrase with its group's canonical token."""
    padded = f" {norm} "
    for phrase, canon in _SYNONYM_PHRASES:
        padded = padded.replace(f" {phrase} ", f" {canon} ")
    return padded.strip()


def _canon_key(text: str) -> frozenset:
    """Order-insensitive identity of a title after synonyms, for the
    `synonym` rule: 'Cross-Site Scripting (Stored)' == 'Stored XSS'."""
    return frozenset(w for w in _canonicalize(_normalize(text)).split()
                     if w not in _STOPWORDS)


def _tokens(text: str) -> set:
    """Keyword tokens (≥3 chars, minus stopwords). A synonym anywhere in the
    text adds every word of its whole group, so 'sqli' and 'SQL injection'
    overlap fully in both directions."""
    norm = _normalize(text)
    toks = {t for t in norm.split() if len(t) >= 3 and t not in _STOPWORDS}
    for canon in set(_canonicalize(norm).split()) & set(_GROUP_TOKENS):
        toks |= {t for t in _GROUP_TOKENS[canon] if len(t) >= 3 and t not in _STOPWORDS}
    return toks


def _entry_tokens(entry: Dict[str, Any]) -> set:
    toks = _tokens(entry["key"].replace(".", " ").replace("_", " "))
    for a in entry["aliases"]:
        toks |= _tokens(a)
    for t in entry.get("tags", []):
        toks |= _tokens(t)
    return toks


def _synonym_index(kb: Dict[str, Any]) -> Dict[frozenset, Optional[str]]:
    """canon_key(alias) -> entry key; None marks an ambiguous identity (two
    entries), which the synonym rule then refuses to use."""
    cache = kb.get("_synonym_index")
    if cache is None:
        cache = {}
        for key, entry in kb["entries"].items():
            for alias in entry["aliases"]:
                ck = _canon_key(alias)
                if ck:
                    cache[ck] = key if cache.get(ck, key) == key else None
        kb["_synonym_index"] = cache
    return cache


def _best_by_overlap(keys, entries, title_tokens):
    """Deterministic pick: most token overlap with the title, then key order.
    Returns (key, overlap)."""
    ranked = sorted(((len(title_tokens & _entry_tokens(entries[k])), k) for k in keys),
                    key=lambda t: (-t[0], t[1]))
    return (ranked[0][1], ranked[0][0]) if ranked else (None, 0)


def nearest_entries(text: str, kb: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
    """Top KB entries by keyword overlap with `text` (overlap > 0 only)."""
    toks = _tokens(text)
    if not toks:
        return []
    scored = sorted(((len(toks & _entry_tokens(e)), k) for k, e in kb["entries"].items()),
                    key=lambda t: (-t[0], t[1]))
    return [{"key": k, "overlap": n} for n, k in scored[:limit] if n > 0]


def _match(finding: Dict[str, Any], kb: Dict[str, Any]):
    """Return (entry_key, rule) or (None, None). Match order is fixed:
    alias -> synonym -> canonical key -> scanner category -> CWE -> keyword.

    A category/CWE pick needs at least one shared word with the title when
    the finding has one; with zero overlap it would be a guess (the first
    entry in key order), so the finding falls through instead and — if
    nothing else matches — is recorded as unresolved for the learn loop.
    """
    entries = kb["entries"]
    ftype = str(finding.get("type") or finding.get("title") or "").strip()
    lowered = ftype.lower()
    title_tokens = _tokens(ftype)

    if lowered and lowered in kb["by_alias"]:
        return kb["by_alias"][lowered], "alias"

    ck = _canon_key(ftype)
    if ck:
        hit = _synonym_index(kb).get(ck)
        if hit:
            return hit, "synonym"

    for candidate in (finding.get("key"), lowered):
        if candidate and str(candidate).lower() in entries:
            return str(candidate).lower(), "key"

    category = str(finding.get("category") or "").strip().lower()
    if category and category in kb["by_category"]:
        key, overlap = _best_by_overlap(kb["by_category"][category], entries, title_tokens)
        if key and (overlap > 0 or not title_tokens):
            return key, "category"

    cwe = str(finding.get("cwe") or "").strip().upper()
    if cwe and cwe in kb["by_cwe"]:
        key, overlap = _best_by_overlap(kb["by_cwe"][cwe], entries, title_tokens)
        if key and (overlap > 0 or not title_tokens):
            return key, "cwe"

    if title_tokens:
        scored = sorted(
            ((len(title_tokens & _entry_tokens(e)), k) for k, e in entries.items()),
            key=lambda t: (-t[0], t[1]))
        if scored and scored[0][0] >= 2:
            return scored[0][1], "keyword"

    return None, None


def _generic_entry(category: str) -> Dict[str, Any]:
    """Safe fallback when nothing in the KB matches. No fabricated specifics."""
    label = category or "unclassified"
    return {
        "key": f"generic.{_re.sub(r'[^a-z0-9_]', '_', label.lower()) or 'unclassified'}",
        "kind": "vulnerability", "aliases": [], "category": category or "",
        "cwe": "", "owasp": "",
        "severity_guidance": "Medium — no knowledge-base entry yet; use the scanner's severity.",
        "exploitability": "Medium — not yet assessed for this finding type.",
        "business_impact": "Not yet assessed; review the finding evidence.",
        "why_it_matters": (
            "This finding type has no curated knowledge-base entry yet, so the "
            "guidance below is generic. It has been recorded for an analyst to add."),
        "detection_signal": "See the finding's own description and evidence.",
        "false_positive_check": (
            "Reproduce the observation from the evidence, confirm it applies to "
            "the in-scope asset, and rule out soft-404s, caching, and scanner noise."),
        "remediation": {
            "immediate_mitigation": (
                "Assess exposure from the evidence; restrict access to the affected "
                "component if the impact is unclear."),
            "short_term_fix": (
                "Apply the vendor or framework guidance for this issue class and "
                "follow the reference material for the observed behaviour."),
            "long_term_hardening": (
                "Add a knowledge-base entry for this finding type so future "
                "occurrences get tailored guidance."),
            "code_fix_examples": {}, "config_examples": {},
        },
        "compensating_controls": ["Restrict access to the affected component while it is assessed"],
        "verification": "Re-run the scan that produced the finding and confirm it no longer appears.",
        "references": ["https://owasp.org/www-project-top-ten/"],
        "tags": ["generic", "unresolved"],
    }


# --- Scoring ---------------------------------------------------------------
def _leading_word(text: str, choices) -> Optional[str]:
    t = str(text or "").strip()
    for c in choices:
        if t.startswith(c):
            return c
    return None


def priority_for(score: int) -> str:
    for threshold, prio in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return prio
    return "P4"


def score_risk(severity: str, exploitability: str, confidence: str,
               exposure: str, kind: str = "vulnerability") -> Dict[str, Any]:
    """Deterministic risk score. Unknown inputs fall back to neutral values."""
    sev = severity if severity in SEVERITY_BASE else "Medium"
    exp = exploitability if exploitability in EXPLOIT_MOD else "Medium"
    conf = confidence if confidence in CONFIDENCE_MOD else "unknown"
    expo = exposure if exposure in EXPOSURE_MOD else "unknown"

    parts = [SEVERITY_BASE[sev], EXPLOIT_MOD[exp], CONFIDENCE_MOD[conf], EXPOSURE_MOD[expo]]
    score = max(0, min(100, sum(parts)))
    priority = priority_for(score)
    capped = False
    if kind == "signal" and PRIORITY_ORDER[priority] < PRIORITY_ORDER[SIGNAL_PRIORITY_CAP]:
        priority, capped = SIGNAL_PRIORITY_CAP, True

    def fmt(n):
        return f"{n:+d}" if n else "0"
    rationale = (
        f"{sev} severity ({SEVERITY_BASE[sev]}) · exploitability {exp} ({fmt(EXPLOIT_MOD[exp])})"
        f" · confidence {conf} ({fmt(CONFIDENCE_MOD[conf])}) · exposure {expo}"
        f" ({fmt(EXPOSURE_MOD[expo])}) = {score} → {priority}")
    if capped:
        rationale += " (signal: capped at P3)"
    return {"severity": sev, "exploitability": exp, "confidence": conf,
            "exposure": expo, "risk_score": score, "priority": priority,
            "rationale": rationale}


# --- Public API -------------------------------------------------------------
def resolve(finding: Optional[Dict[str, Any]], context: Optional[Dict[str, Any]] = None,
            kb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolve one finding (the normalized dict the scan pipeline produces)
    to an AnalystReport. Never raises."""
    finding = finding if isinstance(finding, dict) else {}
    context = context if isinstance(context, dict) else {}
    try:
        kb = kb or _kbm.get_kb()
        key, rule = _match(finding, kb)
    except Exception:  # noqa: BLE001 — a broken KB must not break scans
        logger.exception("remediation KB unavailable; using generic guidance")
        key, rule = None, None
        kb = {"entries": {}}

    unresolved = key is None
    if unresolved:
        entry = _generic_entry(str(finding.get("category") or ""))
        record_unresolved(finding, kb=kb if kb.get("entries") else None)
        rule = "generic"
    else:
        entry = kb["entries"][key]

    severity = (finding.get("severity")
                if finding.get("severity") in SEVERITY_BASE
                else _leading_word(entry["severity_guidance"], _kbm.SEVERITIES) or "Medium")
    raw_conf = str(finding.get("confidence") or "").strip().lower()
    confidence = raw_conf if raw_conf in ("confirmed", "needs_verification") else "unknown"
    scored = score_risk(
        severity,
        _leading_word(entry["exploitability"], _kbm.EXPLOITABILITY) or "Medium",
        confidence,
        str(context.get("exposure") or "unknown"),
        entry["kind"])

    fp_check = entry["false_positive_check"]
    if confidence == "needs_verification" and len(str(fp_check).split()) >= _NONTRIVIAL_FP_WORDS:
        triage_note = f"Likely FP — verify: {fp_check}"
    elif confidence == "confirmed":
        triage_note = "Confirmed by the scanner's evidence."
    else:
        triage_note = f"Confidence {confidence}; check: {fp_check}"

    rem = entry["remediation"]
    return {
        "key": entry["key"],
        "title": str(finding.get("type") or finding.get("title") or entry["key"]),
        "kind": entry["kind"],
        "category": entry["category"] or str(finding.get("category") or ""),
        "cwe": entry["cwe"] or str(finding.get("cwe") or ""),
        "owasp": entry["owasp"],
        "severity": scored["severity"],
        "priority": scored["priority"],
        "risk_score": scored["risk_score"],
        "rationale": scored["rationale"],
        "confidence": confidence,
        "triage_note": triage_note,
        "false_positive_check": fp_check,
        "what_it_is": entry["detection_signal"],
        "why_it_matters": entry["why_it_matters"],
        "business_impact": entry["business_impact"],
        "remediation": {
            "immediate": rem["immediate_mitigation"],
            "short_term": rem["short_term_fix"],
            "long_term": rem["long_term_hardening"],
            "code_examples": dict(rem.get("code_fix_examples") or {}),
            "config_examples": dict(rem.get("config_examples") or {}),
        },
        "compensating_controls": list(entry["compensating_controls"]),
        "verification": entry["verification"],
        "references": list(entry["references"]),
        "tags": list(entry["tags"]),
        "resolved_by": rule,
        "unresolved": unresolved,
        "feedback": _report_feedback(entry["key"], unresolved),
    }


def _report_feedback(kb_key: str, unresolved: bool) -> Dict[str, Any]:
    if unresolved:
        return {"correct": 0, "incorrect": 0, "score": None}
    try:
        fb = get_feedback(kb_key)
    except Exception:  # noqa: BLE001 — feedback is optional; never break resolve
        return {"correct": 0, "incorrect": 0, "score": None}
    return {"correct": fb["correct"], "incorrect": fb["incorrect"], "score": fb["score"]}


def correlate(findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None,
              kb: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolve every finding and group related ones into higher-level issues,
    the way an analyst would summarize a scan. Returns
    {"reports": [...], "issues": [...]} (issues ordered by priority)."""
    reports = [resolve(f, context=context, kb=kb) for f in (findings or [])]
    issues = []
    for issue_id, title, predicate, minimum, action in CORRELATION_RULES:
        members = [i for i, r in enumerate(reports) if predicate(r)]
        if len(members) < minimum:
            continue
        child = [reports[i] for i in members]
        top = min(child, key=lambda r: (PRIORITY_ORDER[r["priority"]], -r["risk_score"]))
        issues.append({
            "id": issue_id,
            "title": title,
            "priority": top["priority"],
            "risk_score": max(r["risk_score"] for r in child),
            "count": len(child),
            "member_indexes": members,
            "member_titles": sorted({r["title"] for r in child}),
            "recommended_action": action,
        })
    issues.sort(key=lambda i: (PRIORITY_ORDER[i["priority"]], -i["risk_score"], i["id"]))
    return {"reports": reports, "issues": issues}


TOP_PRIORITIES_LIMIT = 10


def top_priorities(reports: List[Dict[str, Any]], issues: List[Dict[str, Any]],
                   limit: int = TOP_PRIORITIES_LIMIT) -> List[Dict[str, Any]]:
    """Findings sorted by risk_score (desc, ties by original order), capped
    at `limit`, followed by the correlated issues."""
    ranked = sorted(range(len(reports)), key=lambda i: (-reports[i]["risk_score"], i))[:limit]
    items = [{"kind": "finding", "index": i, "title": reports[i]["title"],
              "key": reports[i]["key"], "priority": reports[i]["priority"],
              "risk_score": reports[i]["risk_score"]} for i in ranked]
    items += [{"kind": "issue", "id": iss["id"], "title": iss["title"],
               "priority": iss["priority"], "risk_score": iss["risk_score"],
               "count": iss["count"]} for iss in issues]
    return items


def analyze_scan(findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None
                 ) -> Dict[str, Any]:
    """One call used by the scan API and both report formats. Never raises."""
    try:
        out = correlate(findings or [], context=context)
    except Exception:  # noqa: BLE001 — never let guidance break results/reports
        logger.exception("analyst summary failed")
        return {"reports": [], "issues": [], "top_priorities": []}
    out["top_priorities"] = top_priorities(out["reports"], out["issues"])
    return out
