"""Unit tests for the analyst engine in webapp/services/remediation_service.py."""
import copy

import pytest

from webapp.services import remediation_kb as kbm
from webapp.services import remediation_service as rs


@pytest.fixture(autouse=True)
def _clean_unresolved():
    rs.clear_unresolved()
    yield
    rs.clear_unresolved()


@pytest.fixture(scope="module")
def real_kb():
    return kbm.load_kb()


def _entry(real_kb, key, **overrides):
    e = copy.deepcopy(real_kb["entries"]["sqli.injection"])
    e.update(key=key, **overrides)
    return e


@pytest.fixture()
def tiny_kb(real_kb):
    """Synthetic KB where each match rule has exactly one possible winner."""
    return kbm.parse_kb({"entries": [
        _entry(real_kb, "alpha.by_alias", aliases=["Foo Widget"], category="alpha", cwe="CWE-1"),
        _entry(real_kb, "beta.by_key", aliases=["Unrelated B"], category="beta", cwe="CWE-2"),
        _entry(real_kb, "gamma.first", aliases=["Gamma One"], category="gamma", cwe="CWE-3"),
        _entry(real_kb, "gamma.second", aliases=["Gamma Two"], category="gamma", cwe="CWE-3"),
        _entry(real_kb, "delta.by_cwe", aliases=["Unrelated D"], category="delta", cwe="CWE-4"),
        _entry(real_kb, "eps.keyword", aliases=["Zebra Quokka Marmot"], category="eps",
               cwe="CWE-5", tags=["zebra"]),
    ]})


# --- Match order --------------------------------------------------------------
def test_alias_wins_over_category_and_cwe(tiny_kb):
    r = rs.resolve({"type": "foo widget", "category": "delta", "cwe": "CWE-4"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("alpha.by_alias", "alias")


def test_canonical_key_match(tiny_kb):
    r = rs.resolve({"type": "BETA.BY_KEY", "category": "delta"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("beta.by_key", "key")


def test_category_wins_over_cwe_and_picks_best_overlap(tiny_kb):
    r = rs.resolve({"type": "Gamma Two variant", "category": "gamma", "cwe": "CWE-4"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("gamma.second", "category")


def test_category_tie_breaks_by_key_order(tiny_kb):
    # "gamma" overlaps both gamma entries equally -> key order decides.
    r = rs.resolve({"type": "Gamma variant", "category": "gamma"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("gamma.first", "category")


def test_category_with_zero_overlap_falls_through_and_is_recorded(tiny_kb):
    r = rs.resolve({"type": "Something else", "category": "gamma"}, kb=tiny_kb)
    assert r["unresolved"] is True and r["resolved_by"] == "generic"
    assert rs.list_unresolved()[0]["signature"] == "gamma|something else"


def test_category_without_title_still_matches(tiny_kb):
    r = rs.resolve({"type": "", "category": "gamma"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("gamma.first", "category")


def test_cwe_match(tiny_kb):
    r = rs.resolve({"type": "", "cwe": "cwe-4"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("delta.by_cwe", "cwe")
    r = rs.resolve({"type": "Unrelated D variant", "cwe": "CWE-4"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("delta.by_cwe", "cwe")


def test_cwe_with_zero_overlap_falls_through(tiny_kb):
    r = rs.resolve({"type": "Unknown thing", "cwe": "CWE-4"}, kb=tiny_kb)
    assert r["unresolved"] is True


def test_keyword_fallback_needs_two_tokens(tiny_kb):
    r = rs.resolve({"type": "Zebra and Quokka sighting"}, kb=tiny_kb)
    assert (r["key"], r["resolved_by"]) == ("eps.keyword", "keyword")
    one = rs.resolve({"type": "Lonely zebra"}, kb=tiny_kb)
    assert one["unresolved"] and one["resolved_by"] == "generic"


def test_keyword_fallback_on_real_kb(real_kb):
    r = rs.resolve({"type": "Blind SQL Injection in cookie value"}, kb=real_kb)
    assert (r["key"], r["resolved_by"]) == ("sqli.injection", "keyword")


# --- Unknown -> generic + logged, never throws ---------------------------------
def test_unknown_falls_back_and_is_recorded(real_kb):
    r = rs.resolve({"type": "Quantum Flux Leak", "category": "physics"}, kb=real_kb)
    assert r["unresolved"] is True and r["resolved_by"] == "generic"
    assert r["key"] == "generic.physics"
    rs.resolve({"type": "Quantum Flux Leak", "category": "physics"}, kb=real_kb)
    [item] = rs.get_unresolved()
    assert item["signature"] == "physics|quantum flux leak" and item["count"] == 2


@pytest.mark.parametrize("bad", [None, {}, "not a dict", {"type": None, "severity": 42}])
def test_resolve_never_throws(bad):
    r = rs.resolve(bad)
    assert r["unresolved"] is True and r["priority"] in rs.PRIORITY_ORDER


def test_broken_kb_degrades_to_generic(monkeypatch):
    def boom():
        raise kbm.KBValidationError("broken")
    monkeypatch.setattr(kbm, "get_kb", boom)
    r = rs.resolve({"type": "Stored XSS"})
    assert r["unresolved"] is True


# --- Scoring + priority ------------------------------------------------------
@pytest.mark.parametrize("score,prio", [
    (100, "P1"), (85, "P1"), (84, "P2"), (60, "P2"), (59, "P3"), (35, "P3"), (34, "P4"), (0, "P4"),
])
def test_priority_boundaries(score, prio):
    assert rs.priority_for(score) == prio


def test_score_is_exact_sum_and_clamped():
    s = rs.score_risk("Critical", "High", "confirmed", "internet_facing")
    assert s["risk_score"] == 100 and s["priority"] == "P1"          # 110 clamped
    s = rs.score_risk("Medium", "Medium", "unknown", "unknown")
    assert s["risk_score"] == 40 and s["priority"] == "P3"            # 45+0-5+0
    s = rs.score_risk("High", "Low", "needs_verification", "internal")
    assert s["risk_score"] == 45 and s["priority"] == "P3"            # 70-10-10-5
    s = rs.score_risk("Info", "Low", "needs_verification", "internal")
    assert s["risk_score"] == 0 and s["priority"] == "P4"             # clamped at 0


def test_unknown_score_inputs_are_neutral():
    s = rs.score_risk("Bogus", "Bogus", "bogus", "bogus")
    assert (s["severity"], s["exploitability"], s["confidence"], s["exposure"]) == \
        ("Medium", "Medium", "unknown", "unknown")


def test_rationale_names_every_factor():
    s = rs.score_risk("High", "Medium", "confirmed", "internal")
    for part in ("High severity (70)", "exploitability Medium (0)", "confidence confirmed (+5)",
                 "exposure internal (-5)", "= 70", "P2"):
        assert part in s["rationale"], part


def test_signals_cap_at_p3(real_kb):
    r = rs.resolve({"type": "Technology Fingerprint", "severity": "Critical",
                    "confidence": "confirmed"}, {"exposure": "internet_facing"}, kb=real_kb)
    assert r["kind"] == "signal" and r["risk_score"] >= 85
    assert r["priority"] == "P3" and "capped at P3" in r["rationale"]


def test_finding_severity_overrides_entry_default(real_kb):
    low = rs.resolve({"type": "Stored XSS", "severity": "Low"}, kb=real_kb)
    assert low["severity"] == "Low"
    default = rs.resolve({"type": "Stored XSS"}, kb=real_kb)
    assert default["severity"] == "Critical"   # from the entry's severity_guidance


def test_resolution_is_deterministic(real_kb):
    f = {"type": "CORS Misconfiguration", "severity": "High", "confidence": "confirmed"}
    assert rs.resolve(f, kb=real_kb) == rs.resolve(dict(f), kb=real_kb)


# --- Triage --------------------------------------------------------------------
def test_needs_verification_with_real_fp_check_is_flagged(real_kb):
    r = rs.resolve({"type": "Potential IDOR", "confidence": "needs_verification"}, kb=real_kb)
    assert r["triage_note"].startswith("Likely FP — verify:")
    assert r["false_positive_check"] in r["triage_note"]


def test_confirmed_is_not_flagged(real_kb):
    r = rs.resolve({"type": "Potential IDOR", "confidence": "confirmed"}, kb=real_kb)
    assert not r["triage_note"].startswith("Likely FP")


def test_trivial_fp_check_is_not_flagged(tiny_kb):
    tiny_kb = copy.deepcopy(tiny_kb)
    tiny_kb["entries"]["alpha.by_alias"]["false_positive_check"] = "Check it."
    r = rs.resolve({"type": "Foo Widget", "confidence": "needs_verification"}, kb=tiny_kb)
    assert not r["triage_note"].startswith("Likely FP")


# --- Report shape ---------------------------------------------------------------
REPORT_FIELDS = {
    "key", "title", "kind", "category", "cwe", "owasp", "severity", "priority", "risk_score",
    "rationale", "confidence", "triage_note", "false_positive_check", "what_it_is",
    "why_it_matters", "business_impact", "remediation", "compensating_controls",
    "verification", "references", "tags", "resolved_by", "unresolved", "feedback",
}


def test_report_has_stable_fields(real_kb):
    r = rs.resolve({"type": "Stored XSS"}, kb=real_kb)
    assert set(r) == REPORT_FIELDS
    assert set(r["remediation"]) == {"immediate", "short_term", "long_term",
                                     "code_examples", "config_examples"}


# --- Correlation ----------------------------------------------------------------
def _types(*names):
    return [{"type": n, "severity": "Low", "confidence": "confirmed"} for n in names]


def test_three_header_findings_make_hardening_gap(real_kb):
    out = rs.correlate(_types("Missing Security Header", "Missing Security Header",
                              "Server Information Disclosure", "Stored XSS"), kb=real_kb)
    [issue] = [i for i in out["issues"] if i["id"] == "http_hardening_gap"]
    assert issue["count"] == 3 and issue["member_indexes"] == [0, 1, 2]
    assert len(out["reports"]) == 4


def test_two_header_findings_are_not_enough(real_kb):
    out = rs.correlate(_types("Missing Security Header", "Technology Disclosure"), kb=real_kb)
    assert not [i for i in out["issues"] if i["id"] == "http_hardening_gap"]


def test_cookie_findings_group(real_kb):
    out = rs.correlate(_types("Session Cookie Missing HttpOnly Flag", "Insecure Cookie"), kb=real_kb)
    assert [i["id"] for i in out["issues"]] == ["insecure_cookie_config"]


def test_info_signals_group(real_kb):
    out = rs.correlate(_types("Technology Stack Fingerprinting", "Technology Fingerprint"), kb=real_kb)
    assert [i["id"] for i in out["issues"]] == ["information_exposure"]


def test_issue_priority_is_highest_child(real_kb):
    findings = _types("Missing Security Header", "Server Information Disclosure")
    findings.append({"type": "Missing Security Header", "severity": "Critical",
                     "confidence": "confirmed"})
    out = rs.correlate(findings, {"exposure": "internet_facing"}, kb=real_kb)
    [issue] = out["issues"]
    child_prios = sorted(r["priority"] for r in out["reports"])
    assert issue["priority"] == child_prios[0]


def test_correlate_handles_empty_input():
    assert rs.correlate([]) == {"reports": [], "issues": []}


# --- Synonym-aware matching (Stage 1 of the learning upgrade) ----------------
@pytest.mark.parametrize("title,key", [
    ("Cross-Site Scripting (Stored)", "xss.stored"),
    ("stored   cross site scripting!!", "xss.stored"),
    ("Reflected Cross Site Scripting", "xss.reflected"),
    ("SQLi (union based)", "sqli.injection"),
    ("Cross Site Request Forgery token missing", "csrf.missing_token"),
    ("JSON Web Token none algorithm", "auth_session.jwt_none_algorithm"),
])
def test_reworded_titles_resolve_by_synonym(real_kb, title, key):
    r = rs.resolve({"type": title}, kb=real_kb)
    assert (r["key"], r["resolved_by"]) == (key, "synonym")


def test_synonym_never_overrides_exact_alias(real_kb):
    assert rs.resolve({"type": "Stored XSS"}, kb=real_kb)["resolved_by"] == "alias"


def test_synonyms_help_keyword_both_directions(real_kb):
    r = rs.resolve({"type": "WAF log: repeated SQL injection probes on /login"}, kb=real_kb)
    assert (r["key"], r["resolved_by"]) == ("sqli.injection", "keyword")
    assert rs._tokens("sqli") >= {"sql", "injection", "sqli"}
    assert rs._tokens("SQL Injection") >= {"sql", "injection", "sqli"}


@pytest.mark.parametrize("finding", [
    {"type": "Quarterly Revenue Report Generated"},
    {"type": "Quarterly Revenue Report Generated", "category": "sec_misconfig"},
    {"type": "Exposed Grafana Dashboard", "category": "sec_misconfig"},
    {"type": "Printer toner low", "cwe": "CWE-200"},
])
def test_unrelated_titles_do_not_match(real_kb, finding):
    r = rs.resolve(finding, kb=real_kb)
    assert r["unresolved"] is True and r["resolved_by"] == "generic"


def test_ambiguous_synonym_identity_is_not_used(tiny_kb):
    kb = kbm.parse_kb({"entries": [
        dict(copy.deepcopy(tiny_kb["entries"]["alpha.by_alias"]), key="a.one", aliases=["XSS thing"]),
        dict(copy.deepcopy(tiny_kb["entries"]["beta.by_key"]), key="b.two",
             aliases=["Cross Site Scripting thing"]),
    ]})
    r = rs.resolve({"type": "thing xss"}, kb=kb)
    assert r["resolved_by"] != "synonym"
