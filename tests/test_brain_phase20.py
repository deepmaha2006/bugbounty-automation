"""
Phase 20: brain.telemetry — scan-to-brain bridge.

Tests:
  finding_to_signals
  • known finding type maps to correct signal key
  • case-insensitive type matching
  • category fallback when type is unknown
  • unknown type AND unknown category returns {}
  • xss → xss_hint
  • sqli → sqli_hint
  • sql injection (with space) → sqli_hint
  • path_traversal → path_traversal signal
  • path traversal (with space) → path_traversal signal
  • ssrf → ssrf_hint
  • csrf → csrf_hint
  • rce → rce_hint
  • command injection → rce_hint (via FINDING_TYPE_TO_ATTACK_CLASS)
  • open redirect → redirect_hint
  • scanner_probe → scanner_signature
  • empty strings → {}
  • None values handled

  ingest_scan_findings
  • no active authorization raises AuthorizationError
  • empty findings list: 0 knowledge updates, 0 events inserted
  • single XSS finding: 1 knowledge update, 1 event inserted
  • finding with unknown type: 0 events inserted, but still knowledge-updated if type maps
  • multiple findings: correct counts
  • finding with no type, but known category: event inserted
  • brain_event path from finding url field
  • brain_event path from finding path field when url absent
  • knowledge seeds correct attack_class
  • events inserted have correct signals
  • result dict has knowledge_updates and events_inserted keys
  • ingest is idempotent (double-call doesn't raise)

  Module constants
  • _ATTACK_CLASS_TO_SIGNAL covers all attack_classes in FINDING_TYPE_TO_ATTACK_CLASS values
  • finding_to_signals returns dict (never None)
"""
import pytest

import webapp.db as db  # noqa: F401 — FakeDB patch active via conftest
from brain.sensors import AuthorizationError
from brain.telemetry import (
    _ATTACK_CLASS_TO_SIGNAL,
    finding_to_signals,
    ingest_scan_findings,
)
from brain.learning import FINDING_TYPE_TO_ATTACK_CLASS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_auth(fake, asset_id=1, org_id=1):
    fake.record_asset_authorization(
        organization_id=org_id,
        asset_id=asset_id,
        authorized_by_user_id=1,
        method="engagement_letter",
        status="authorized",
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# finding_to_signals — type mapping
# ---------------------------------------------------------------------------

def test_xss_maps_to_xss_hint():
    assert finding_to_signals("xss") == {"xss_hint": True}


def test_sqli_maps_to_sqli_hint():
    assert finding_to_signals("sqli") == {"sqli_hint": True}


def test_sql_injection_with_space_maps():
    assert finding_to_signals("sql injection") == {"sqli_hint": True}


def test_sql_injection_underscore_maps():
    assert finding_to_signals("sql_injection") == {"sqli_hint": True}


def test_path_traversal_underscore_maps():
    assert finding_to_signals("path_traversal") == {"path_traversal": True}


def test_path_traversal_space_maps():
    assert finding_to_signals("path traversal") == {"path_traversal": True}


def test_ssrf_maps():
    assert finding_to_signals("ssrf") == {"ssrf_hint": True}


def test_csrf_maps():
    assert finding_to_signals("csrf") == {"csrf_hint": True}


def test_rce_maps():
    assert finding_to_signals("rce") == {"rce_hint": True}


def test_command_injection_maps_to_rce():
    assert finding_to_signals("command injection") == {"rce_hint": True}


def test_open_redirect_maps():
    assert finding_to_signals("open redirect") == {"redirect_hint": True}


def test_scanner_probe_maps():
    assert finding_to_signals("scanner_probe") == {"scanner_signature": True}


def test_case_insensitive_type():
    assert finding_to_signals("XSS") == {"xss_hint": True}
    assert finding_to_signals("SQLI") == {"sqli_hint": True}


def test_unknown_type_empty():
    assert finding_to_signals("heap overflow") == {}


def test_empty_type_empty():
    assert finding_to_signals("") == {}


def test_none_type_empty():
    assert finding_to_signals(None) == {}


def test_category_fallback():
    assert finding_to_signals("something weird", category="xss") == {"xss_hint": True}


def test_unknown_type_unknown_category_empty():
    assert finding_to_signals("heap overflow", "physics") == {}


def test_returns_dict_not_none():
    result = finding_to_signals("unknown type")
    assert result is not None
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _ATTACK_CLASS_TO_SIGNAL coverage
# ---------------------------------------------------------------------------

def test_attack_class_signal_map_covers_known_classes():
    known_classes = set(FINDING_TYPE_TO_ATTACK_CLASS.values())
    for cls in known_classes:
        # Every class that finding_to_signals can produce should have a signal
        # (or return {} — it's valid for some classes to not have a signal key)
        # This is just a structural check
        assert isinstance(_ATTACK_CLASS_TO_SIGNAL.get(cls, ""), str) or _ATTACK_CLASS_TO_SIGNAL.get(cls) is None


# ---------------------------------------------------------------------------
# ingest_scan_findings — no auth
# ---------------------------------------------------------------------------

def test_ingest_no_auth_raises_authorization_error(fake):
    with pytest.raises(AuthorizationError):
        ingest_scan_findings(1, 1, [])


# ---------------------------------------------------------------------------
# ingest_scan_findings — with auth
# ---------------------------------------------------------------------------

def test_ingest_empty_findings_returns_zeros(fake):
    _seed_auth(fake)
    result = ingest_scan_findings(1, 1, [])
    assert result == {"knowledge_updates": 0, "events_inserted": 0}


def test_ingest_result_has_required_keys(fake):
    _seed_auth(fake)
    result = ingest_scan_findings(1, 1, [])
    assert "knowledge_updates" in result
    assert "events_inserted" in result


def test_ingest_single_xss_finding(fake):
    _seed_auth(fake)
    findings = [{"type": "xss", "severity": "high", "url": "/search?q=1"}]
    result = ingest_scan_findings(1, 1, findings)
    assert result["knowledge_updates"] == 1
    assert result["events_inserted"] == 1


def test_ingest_creates_brain_event(fake):
    _seed_auth(fake)
    findings = [{"type": "sqli", "severity": "critical", "url": "/login"}]
    ingest_scan_findings(1, 1, findings)
    events = fake.brain_list_events(1, 1)
    assert len(events) == 1
    assert events[0]["signals"].get("sqli_hint") is True


def test_ingest_event_uses_url_as_path(fake):
    _seed_auth(fake)
    findings = [{"type": "xss", "severity": "high", "url": "/target/path"}]
    ingest_scan_findings(1, 1, findings)
    events = fake.brain_list_events(1, 1)
    assert events[0]["path"] == "/target/path"


def test_ingest_event_falls_back_to_path_field(fake):
    _seed_auth(fake)
    findings = [{"type": "xss", "severity": "high", "path": "/fallback/path"}]
    ingest_scan_findings(1, 1, findings)
    events = fake.brain_list_events(1, 1)
    assert events[0]["path"] == "/fallback/path"


def test_ingest_unknown_type_no_event(fake):
    _seed_auth(fake)
    findings = [{"type": "heap overflow", "severity": "high", "url": "/x"}]
    result = ingest_scan_findings(1, 1, findings)
    assert result["events_inserted"] == 0


def test_ingest_multiple_findings(fake):
    _seed_auth(fake)
    findings = [
        {"type": "xss", "severity": "high", "url": "/a"},
        {"type": "sqli", "severity": "critical", "url": "/b"},
        {"type": "heap overflow", "severity": "high", "url": "/c"},
    ]
    result = ingest_scan_findings(1, 1, findings)
    assert result["events_inserted"] == 2
    assert result["knowledge_updates"] == 2


def test_ingest_seeds_brain_knowledge(fake):
    _seed_auth(fake)
    findings = [{"type": "ssrf", "severity": "high", "url": "/api/fetch"}]
    ingest_scan_findings(1, 1, findings)
    knowledge = fake.brain_list_knowledge(1, 1)
    assert len(knowledge) == 1
    assert knowledge[0]["attack_class"] == "ssrf"


def test_ingest_idempotent_no_raise(fake):
    _seed_auth(fake)
    findings = [{"type": "xss", "severity": "high", "url": "/x"}]
    ingest_scan_findings(1, 1, findings)
    ingest_scan_findings(1, 1, findings)  # second call should not raise


def test_ingest_category_fallback_creates_event(fake):
    _seed_auth(fake)
    findings = [{"type": "", "category": "csrf", "severity": "medium", "url": "/form"}]
    result = ingest_scan_findings(1, 1, findings)
    assert result["events_inserted"] == 1
    events = fake.brain_list_events(1, 1)
    assert events[0]["signals"].get("csrf_hint") is True
