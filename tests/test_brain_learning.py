"""Deterministic learning: richer drafts, review queue + promotion, feedback."""
import copy
import shutil

import pytest

from webapp.services import remediation_kb as kbm
from webapp.services import remediation_service as rs

K8S = "Kubernetes dashboard exposed publicly"        # unique nearest: cloud.kubernetes_api_exposure
REDIS = "Redis instance reachable without authentication"   # 3-way tie on one generic word


@pytest.fixture(scope="module")
def kb():
    return kbm.load_kb()


@pytest.fixture()
def kb_copy(tmp_path):
    dest = tmp_path / "remediation_kb.yaml"
    shutil.copyfile(kbm.KB_PATH, dest)
    yield dest
    kbm.get_kb.cache_clear()


def _record(title, **extra):
    rs.resolve(dict({"type": title}, **extra))
    return next(i for i in rs.list_unresolved() if i["type"] == title)


# --- Stage 2: richer auto-drafts ---------------------------------------------
def test_draft_prefilled_from_unique_nearest_entry():
    item = _record(K8S)
    d = item["draft"]
    assert item["nearest"][0]["key"] == "cloud.kubernetes_api_exposure"
    assert item["draft_source"] == "cloud.kubernetes_api_exposure"
    assert (d["category"], d["cwe"]) == ("cloud", "CWE-306")
    assert d["owasp"].startswith("A05:2021") and d["key"] == "cloud.kubernetes_dashboard_exposed_publicly"
    assert d["references"]
    for f in ("immediate_mitigation", "short_term_fix", "long_term_hardening"):
        assert d["remediation"][f].startswith(kbm.DRAFT_MARKER)


def test_ambiguous_nearest_gives_hints_but_no_prefill():
    item = _record(REDIS)
    assert len(item["nearest"]) == 3 and len({n["overlap"] for n in item["nearest"]}) == 1
    assert item["draft_source"] is None
    assert item["draft"]["remediation"]["short_term_fix"] == ""
    assert item["draft"]["category"] == "" and item["draft"]["cwe"] == ""


def test_no_overlap_gives_empty_hints():
    item = _record("Quantum Flux Capacitor")
    assert item["nearest"] == [] and item["draft_source"] is None


def test_nearest_hints_refresh_and_count_increments():
    _record(K8S)
    item = _record(K8S)
    assert item["count"] == 2 and item["first_seen"] <= item["last_seen"]


def test_draft_can_never_pass_validation_until_reviewed(kb):
    d = _record(K8S)["draft"]
    assert kbm.validate_entry(d)
    # Fill every analyst field but leave tag + marker: still rejected.
    done = copy.deepcopy(kb["entries"]["cloud.kubernetes_api_exposure"])
    done.update(key=d["key"], aliases=d["aliases"], tags=["draft"],
                remediation=d["remediation"])
    errs = kbm.validate_entry(done)
    assert any("still tagged 'draft'" in e for e in errs)
    assert any(kbm.DRAFT_MARKER in e for e in errs)
    done["tags"] = ["cloud"]
    assert any(kbm.DRAFT_MARKER in e for e in kbm.validate_entry(done))
    done["remediation"] = copy.deepcopy(kb["entries"]["cloud.kubernetes_api_exposure"]["remediation"])
    assert kbm.validate_entry(done) == []


# --- Stage 3: review queue + promotion ---------------------------------------
def test_list_unresolved_sorts():
    for _ in range(3):
        rs.resolve({"type": "Beta Thing"})
    rs.resolve({"type": "Alpha Thing"})
    assert [i["type"] for i in rs.list_unresolved()] == ["Beta Thing", "Alpha Thing"]
    assert [i["type"] for i in rs.list_unresolved(sort="signature")] == ["Alpha Thing", "Beta Thing"]
    assert rs.list_unresolved(sort="recent")[0]["type"] in ("Alpha Thing", "Beta Thing")
    with pytest.raises(ValueError):
        rs.list_unresolved(sort="random")


def _completed_entry(kb, key="cloud.kubernetes_dashboard_exposed_publicly", aliases=None):
    e = copy.deepcopy(kb["entries"]["cloud.kubernetes_api_exposure"])
    e.update(key=key, aliases=aliases if aliases is not None else ["K8s dashboard open"],
             tags=["cloud", "kubernetes"])
    return e


def test_promote_clears_signature_adds_alias_and_resolves_by_alias(kb, kb_copy):
    sig = _record(K8S)["signature"]
    out = rs.promote_unresolved(sig, _completed_entry(kb), path=kb_copy)
    assert sig in out["dismissed"]
    assert not [i for i in rs.list_unresolved() if i["signature"] == sig]
    new_kb = kbm.load_kb(kb_copy)
    assert K8S in new_kb["entries"]["cloud.kubernetes_dashboard_exposed_publicly"]["aliases"]
    r = rs.resolve({"type": K8S}, kb=new_kb)
    assert (r["key"], r["resolved_by"], r["unresolved"]) == (
        "cloud.kubernetes_dashboard_exposed_publicly", "alias", False)


def test_promote_unknown_signature_raises(kb, kb_copy):
    with pytest.raises(KeyError):
        rs.promote_unresolved("-|never seen", _completed_entry(kb), path=kb_copy)


def test_promote_invalid_entry_changes_nothing(kb, kb_copy):
    sig = _record(K8S)["signature"]
    before = kb_copy.read_text(encoding="utf-8")
    bad = _completed_entry(kb)
    bad["tags"] = ["draft"]
    with pytest.raises(kbm.KBValidationError):
        rs.promote_unresolved(sig, bad, path=kb_copy)
    assert kb_copy.read_text(encoding="utf-8") == before
    assert [i for i in rs.list_unresolved() if i["signature"] == sig]


def test_review_queue_text():
    assert "empty" in rs.format_review_queue()
    for _ in range(2):
        rs.resolve({"type": K8S})
    rs.resolve({"type": REDIS})
    text = rs.format_review_queue()
    lines = text.splitlines()
    assert lines[0].startswith("2 unresolved signature(s), frequency order")
    assert "2x  -|kubernetes dashboard exposed publicly" in text
    assert text.index("kubernetes dashboard") < text.index("redis instance")
    assert "pre-filled from cloud.kubernetes_api_exposure" in text and "not pre-filled" in text
    assert "nearest: cloud.kubernetes_api_exposure(1)" in text


# --- Stage 4: feedback ----------------------------------------------------------
def test_feedback_counts_and_score():
    assert rs.get_feedback("xss.stored") == {"correct": 0, "incorrect": 0, "score": None, "by_type": {}}
    rs.record_feedback("xss.stored", True, "Stored XSS")
    rs.record_feedback("xss.stored", True, "Cross-Site Scripting (Stored)")
    fb = rs.record_feedback("xss.stored", False, "Stored XSS")
    assert (fb["correct"], fb["incorrect"], fb["score"]) == (2, 1, 0.667)
    assert fb["by_type"]["stored xss"] == {"correct": 1, "incorrect": 1, "score": 0.5}


def test_feedback_surfaces_on_reports():
    assert rs.resolve({"type": "Stored XSS"})["feedback"] == {"correct": 0, "incorrect": 0, "score": None}
    rs.record_feedback("xss.stored", True)
    assert rs.resolve({"type": "Stored XSS"})["feedback"] == {"correct": 1, "incorrect": 0, "score": 1.0}
    unknown = rs.resolve({"type": "Quantum Flux Capacitor"})
    assert unknown["feedback"]["score"] is None


def test_feedback_rejects_unknown_entry():
    with pytest.raises(KeyError):
        rs.record_feedback("generic.unclassified", True)


def test_feedback_is_stored_outside_the_kb(kb):
    before = kbm.KB_PATH.read_bytes()
    rs.record_feedback("sqli.injection", True)
    assert kbm.KB_PATH.read_bytes() == before
    assert rs.FEEDBACK_PATH.exists() and "brain" in str(rs.FEEDBACK_PATH)
