"""
Tests for the ConfirmationRecord, WSTG IDs, and confirmation-gate logic
introduced in core/finding.py Phase 2.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.finding import (
    classify_finding,
    wstg_id_for,
    WSTG_IDS,
    ConfirmationRecord,
    TIER_CONFIRMED,
    TIER_POSSIBLE,
)


# ---------------------------------------------------------------------------
# wstg_id_for
# ---------------------------------------------------------------------------

class TestWstgIdFor:
    def test_sql_injection(self):
        assert wstg_id_for("SQL Injection") == "WSTG-INPV-05"

    def test_error_based_specific_beats_generic(self):
        assert wstg_id_for("Error-Based SQL Injection") == "WSTG-INPV-05"

    def test_xss(self):
        assert wstg_id_for("Reflected XSS") == "WSTG-INPV-01"

    def test_stored_xss_specific(self):
        assert wstg_id_for("Stored XSS") == "WSTG-INPV-02"

    def test_ssrf(self):
        assert wstg_id_for("SSRF") == "WSTG-INPV-19"

    def test_unknown_returns_none(self):
        assert wstg_id_for("Unknown Scanner Finding") is None

    def test_empty_string(self):
        assert wstg_id_for("") is None

    def test_clickjacking(self):
        assert wstg_id_for("Clickjacking") == "WSTG-CLNT-09"


# ---------------------------------------------------------------------------
# Confirmation record injection in classify_finding
# ---------------------------------------------------------------------------

class TestConfirmationRecord:
    def _confirmed_finding(self, **kwargs):
        base = {
            "type": "SQL Injection",
            "severity": "High",
            "confidence": "confirmed",
            "evidence": "DB error: syntax error near quote",
        }
        base.update(kwargs)
        return classify_finding(base)

    def test_confirmed_finding_gets_confirmation(self):
        f = self._confirmed_finding()
        assert f["confidence"] == TIER_CONFIRMED
        assert "confirmation" in f
        conf = f["confirmation"]
        assert conf["reproduced"] is True
        assert conf["method"] in ("re-proof", "inspection", "tool", "oob")

    def test_inspection_finding_gets_inspection_method(self):
        f = classify_finding({
            "type": "Missing Security Header",
            "severity": "Low",
            "confidence": "confirmed",
            "evidence": "",
            "evidence_kind": "inspection",
        })
        assert f["confidence"] == TIER_CONFIRMED
        conf = f["confirmation"]
        assert conf["method"] == "inspection"
        assert conf["reproduced"] is True

    def test_pre_existing_confirmation_is_preserved(self):
        custom_conf = {
            "method": "tool",
            "oracle": "dalfox confirmed XSS",
            "evidence": "[POC] ...",
            "reproduced": True,
            "corroborating_tool": "dalfox",
        }
        f = classify_finding({
            "type": "Reflected XSS",
            "severity": "High",
            "confidence": "confirmed",
            "evidence": "canary reflected",
            "confirmation": custom_conf,
        })
        assert f["confirmation"]["corroborating_tool"] == "dalfox"
        assert f["confirmation"]["method"] == "tool"

    def test_reproduced_false_demotes_to_possible(self):
        """A finding with confirmation.reproduced=False is downgraded."""
        f = classify_finding({
            "type": "Reflected XSS",
            "severity": "High",
            "confidence": "confirmed",
            "evidence": "some evidence",
            "confirmation": {
                "method": "re-proof",
                "oracle": "attempted but not confirmed",
                "evidence": "probe sent",
                "reproduced": False,
            },
        })
        assert f["confidence"] == TIER_POSSIBLE
        assert f["verified"] is False

    def test_possible_finding_has_no_confirmation(self):
        f = classify_finding({
            "type": "Potential SQL Injection",
            "severity": "Low",
            "confidence": "possible",
            "evidence": "heuristic flag",
        })
        assert f["confidence"] == TIER_POSSIBLE
        # No confirmation record injected for non-confirmed findings
        assert "confirmation" not in f or f.get("confirmation") is None

    def test_wstg_id_set_on_confirmed(self):
        f = self._confirmed_finding(type="SQL Injection")
        assert f["wstg_id"] == "WSTG-INPV-05"

    def test_wstg_id_set_on_possible(self):
        f = classify_finding({
            "type": "Potential SQL Injection",
            "severity": "Low",
            "evidence": "heuristic",
        })
        # WSTG should still be attached even for possible findings
        assert f["wstg_id"] == "WSTG-INPV-05"

    def test_wstg_id_none_for_unknown(self):
        f = classify_finding({
            "type": "Custom Finding",
            "severity": "Low",
            "evidence": "something",
        })
        assert f["wstg_id"] is None


# ---------------------------------------------------------------------------
# ConfirmationRecord dataclass
# ---------------------------------------------------------------------------

class TestConfirmationRecordDataclass:
    def test_instantiation(self):
        rec = ConfirmationRecord(
            method="re-proof",
            oracle="test oracle",
            evidence="test evidence",
            reproduced=True,
        )
        assert rec.method == "re-proof"
        assert rec.corroborating_tool is None
        assert rec.wstg_id is None

    def test_with_tool(self):
        rec = ConfirmationRecord(
            method="tool",
            oracle="sqlmap confirmed",
            evidence="sqlmap output",
            reproduced=True,
            corroborating_tool="sqlmap",
            wstg_id="WSTG-INPV-05",
        )
        assert rec.corroborating_tool == "sqlmap"
        assert rec.wstg_id == "WSTG-INPV-05"
