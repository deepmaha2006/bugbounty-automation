"""
Phase 16: virtual_patch.py + apply_waf_rule/remove_waf_rule connector jobs +
approval gate (approve_action/reject_action) + auto_remediate tier.

Covers:
  - generate_patch: patchable classes produce VirtualPatch; unpatachable → None
  - rule_id_for: deterministic, stable, prefixed
  - patches_for: deduplication
  - WAF rule specs: xss/sqli/path_traversal/scanner_probe
  - PATCHABLE_CLASSES, APPROVAL_GATED_ACTION_TYPES constants
  - decide() at auto_remediate → apply_waf_rule proposals for patchable attacks
  - apply_action(): apply_waf_rule lands as 'applied'
  - approval gate: approve_action / reject_action
  - approve_action: only 'proposed' transitions; audit log entry
  - reject_action: 'proposed' → 'failed'; audit log entry
  - Connector: apply_waf_rule / remove_waf_rule handlers exist + return result dict
  - Connector: apply_waf_rule refuses empty rule_id
  - Full cycle: detect → decide (auto_remediate) → apply → approve
"""
import os
import tempfile
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detection(attack_class="xss", src_ip="1.2.3.4", path="/search",
                    asset_id=1, org_id=1, incident_id=1):
    from brain.sensors import Event
    from brain.detection import Detection, event_fingerprint
    ev = Event(asset_id=asset_id, org_id=org_id,
               ts=datetime.now(timezone.utc),
               src_ip=src_ip, path=path, signals={})
    fp = event_fingerprint(asset_id, org_id, attack_class, src_ip)
    return Detection(asset_id=asset_id, org_id=org_id,
                     attack_class=attack_class, fingerprint=fp,
                     event=ev, incident_id=incident_id)


def _auth(fake, asset_id=1, org_id=1):
    fake.record_asset_authorization(
        organization_id=org_id, asset_id=asset_id,
        authorized_by_user_id=1, method="engagement_letter",
        status="authorized", expires_at=None,
    )


def _set_tier(asset_id, org_id, tier_value):
    from brain.autonomy import set_policy, AutonomyPolicy, AutonomyTier
    set_policy(AutonomyPolicy(asset_id=asset_id, org_id=org_id,
                               tier=AutonomyTier(tier_value)))


def _connector():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "connector_agent",
        pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# VirtualPatch generation
# ---------------------------------------------------------------------------

class TestGeneratePatch:
    def test_xss_produces_block_pattern(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("xss")
        vp = generate_patch(det)
        assert vp is not None
        assert vp.rule_spec["type"] == "block_pattern"
        assert "script" in vp.rule_spec["pattern"].lower() or "script" in vp.rule_spec["pattern"]

    def test_sqli_produces_block_pattern(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("sql_injection")
        vp = generate_patch(det)
        assert vp is not None
        assert vp.rule_spec["type"] == "block_pattern"

    def test_path_traversal_produces_block_pattern(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("path_traversal")
        vp = generate_patch(det)
        assert vp is not None
        assert vp.rule_spec["type"] == "block_pattern"

    def test_scanner_probe_produces_rate_limit(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("scanner_probe")
        vp = generate_patch(det)
        assert vp is not None
        assert vp.rule_spec["type"] == "rate_limit"

    def test_unknown_class_returns_none(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("custom_attack")
        assert generate_patch(det) is None

    def test_rollback_spec_has_rule_id(self):
        from brain.virtual_patch import generate_patch
        vp = generate_patch(_make_detection("xss"))
        assert "rule_id" in vp.rollback_spec
        assert vp.rollback_spec["rule_id"] == vp.rule_id

    def test_patch_carries_asset_org(self):
        from brain.virtual_patch import generate_patch
        det = _make_detection("xss", asset_id=5, org_id=3)
        vp = generate_patch(det)
        assert vp.asset_id == 5
        assert vp.org_id == 3


# ---------------------------------------------------------------------------
# rule_id_for
# ---------------------------------------------------------------------------

class TestRuleIdFor:
    def test_deterministic(self):
        from brain.virtual_patch import rule_id_for
        r1 = rule_id_for(1, 1, "xss", "/search")
        r2 = rule_id_for(1, 1, "xss", "/search")
        assert r1 == r2

    def test_prefixed(self):
        from brain.virtual_patch import rule_id_for
        assert rule_id_for(1, 1, "xss", "/").startswith("hydrax-")

    def test_different_path_different_id(self):
        from brain.virtual_patch import rule_id_for
        r1 = rule_id_for(1, 1, "xss", "/a")
        r2 = rule_id_for(1, 1, "xss", "/b")
        assert r1 != r2

    def test_different_class_different_id(self):
        from brain.virtual_patch import rule_id_for
        r1 = rule_id_for(1, 1, "xss", "/a")
        r2 = rule_id_for(1, 1, "sqli", "/a")
        assert r1 != r2


# ---------------------------------------------------------------------------
# patches_for + deduplication
# ---------------------------------------------------------------------------

class TestPatchesFor:
    def test_empty_returns_empty(self):
        from brain.virtual_patch import patches_for
        assert patches_for([]) == []

    def test_duplicate_detections_deduplicated(self):
        from brain.virtual_patch import patches_for
        det = _make_detection("xss")
        patches = patches_for([det, det])
        assert len(patches) == 1

    def test_two_different_classes_two_patches(self):
        from brain.virtual_patch import patches_for
        d1 = _make_detection("xss", path="/a")
        d2 = _make_detection("sql_injection", path="/b")
        patches = patches_for([d1, d2])
        assert len(patches) == 2

    def test_unpatchable_excluded(self):
        from brain.virtual_patch import patches_for
        d1 = _make_detection("xss")
        d2 = _make_detection("unknown_type")
        patches = patches_for([d1, d2])
        assert len(patches) == 1


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_patchable_classes_contains_xss(self):
        from brain.virtual_patch import PATCHABLE_CLASSES
        assert "xss" in PATCHABLE_CLASSES
        assert "sql_injection" in PATCHABLE_CLASSES
        assert "path_traversal" in PATCHABLE_CLASSES
        assert "scanner_probe" in PATCHABLE_CLASSES

    def test_approval_gated_contains_edit_types(self):
        from brain.virtual_patch import APPROVAL_GATED_ACTION_TYPES
        assert "edit_source" in APPROVAL_GATED_ACTION_TYPES
        assert "edit_config" in APPROVAL_GATED_ACTION_TYPES


# ---------------------------------------------------------------------------
# decide() at auto_remediate tier
# ---------------------------------------------------------------------------

class TestDecideAutoRemediate:
    def setup_method(self):
        from brain.autonomy import KILL_SWITCH
        KILL_SWITCH.disengage()
        from brain.decision import _RATE_BRAKE, configure_allowlist
        _RATE_BRAKE.reset(1, 1)
        configure_allowlist([])

    def test_auto_remediate_patchable_produces_waf_rule(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_remediate")
        det = _make_detection("xss", src_ip="2.2.2.2")
        proposals = decide(1, 1, [det])
        assert len(proposals) == 1
        assert proposals[0].action_type == "apply_waf_rule"
        assert "rule_id" in proposals[0].params

    def test_auto_contain_patchable_still_block_source(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        det = _make_detection("xss", src_ip="3.3.3.3")
        proposals = decide(1, 1, [det])
        assert proposals[0].action_type == "block_source"

    def test_auto_remediate_unpatchable_falls_back_to_block_source(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_remediate")
        det = _make_detection("unknown_class", src_ip="4.4.4.4")
        proposals = decide(1, 1, [det])
        # unknown class not in PATCHABLE_CLASSES → block_source fallback
        if proposals:
            assert proposals[0].action_type == "block_source"

    def test_waf_rule_proposal_carries_rule_spec(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_remediate")
        det = _make_detection("sql_injection", src_ip="5.5.5.5")
        proposals = decide(1, 1, [det])
        assert "rule_spec" in proposals[0].params
        assert proposals[0].params["rule_spec"]["type"] == "block_pattern"


# ---------------------------------------------------------------------------
# apply_action: apply_waf_rule lands as 'applied'
# ---------------------------------------------------------------------------

class TestApplyWafRuleAction:
    def test_apply_waf_rule_status_applied(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        from brain.virtual_patch import rule_id_for
        rid = rule_id_for(1, 1, "xss", "/search")
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="apply_waf_rule",
            params={"rule_id": rid, "rule_spec": {"type": "block_pattern", "pattern": "<script"},
                    "attack_class": "xss"},
            tier=AutonomyTier.AUTO_REMEDIATE,
            ttl_seconds=3600,
        )
        aid = apply_action(1, 1, prop)
        a = fake.brain_get_action(aid, 1)
        assert a["status"] == "applied"

    def test_edit_source_lands_as_proposed(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="edit_source",
            params={"file": "app.py", "change": "sanitize_input"},
            tier=AutonomyTier.AUTO_REMEDIATE,
            ttl_seconds=3600,
        )
        aid = apply_action(1, 1, prop)
        assert fake.brain_get_action(aid, 1)["status"] == "proposed"


# ---------------------------------------------------------------------------
# Approval gate: approve_action / reject_action
# ---------------------------------------------------------------------------

class TestApprovalGate:
    def _make_proposed(self, fake, action_type="edit_source"):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type=action_type,
            params={"file": "config.py"},
            tier=AutonomyTier.AUTO_REMEDIATE,
            ttl_seconds=3600,
        )
        return apply_action(1, 1, prop)

    def test_approve_proposed_action(self, fake):
        from brain.response import approve_action
        aid = self._make_proposed(fake)
        assert approve_action(aid, 1, "alice@example.com") is True
        assert fake.brain_get_action(aid, 1)["status"] == "approved"

    def test_approve_logs_to_incident_log(self, fake):
        from brain.response import approve_action
        from brain.incident_log import INCIDENT_LOG
        aid = self._make_proposed(fake)
        approve_action(aid, 1, "bob@example.com")
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="approval")
        assert any(e["payload"].get("action_id") == aid for e in entries)

    def test_approve_approver_stored(self, fake):
        from brain.response import approve_action
        aid = self._make_proposed(fake)
        approve_action(aid, 1, "carol@example.com")
        a = fake.brain_get_action(aid, 1)
        assert a["approver"] == "carol@example.com"

    def test_approve_nonexistent_returns_false(self, fake):
        from brain.response import approve_action
        assert approve_action(999, 1, "nobody") is False

    def test_approve_already_approved_returns_false(self, fake):
        from brain.response import approve_action
        aid = self._make_proposed(fake)
        approve_action(aid, 1, "first@example.com")
        assert approve_action(aid, 1, "second@example.com") is False

    def test_reject_proposed_action(self, fake):
        from brain.response import reject_action
        aid = self._make_proposed(fake)
        assert reject_action(aid, 1, "dave@example.com", reason="too risky") is True
        assert fake.brain_get_action(aid, 1)["status"] == "failed"

    def test_reject_logs_to_incident_log(self, fake):
        from brain.response import reject_action
        from brain.incident_log import INCIDENT_LOG
        aid = self._make_proposed(fake)
        reject_action(aid, 1, "eve@example.com", reason="false positive")
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="rejection")
        assert any(e["payload"].get("action_id") == aid for e in entries)

    def test_reject_reason_in_log(self, fake):
        from brain.response import reject_action
        from brain.incident_log import INCIDENT_LOG
        aid = self._make_proposed(fake)
        reject_action(aid, 1, "frank@example.com", reason="FP confirmed")
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="rejection")
        match = [e for e in entries if e["payload"].get("action_id") == aid]
        assert match[-1]["payload"]["reason"] == "FP confirmed"

    def test_reject_nonexistent_returns_false(self, fake):
        from brain.response import reject_action
        assert reject_action(999, 1, "nobody") is False

    def test_reject_applied_action_returns_false(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, reject_action
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "9.9.9.9"},
                              tier=AutonomyTier.AUTO_CONTAIN)
        aid = apply_action(1, 1, prop)
        # block_source lands as 'applied', not 'proposed' → reject should fail
        assert reject_action(aid, 1, "nobody") is False


# ---------------------------------------------------------------------------
# Connector: apply_waf_rule / remove_waf_rule
# ---------------------------------------------------------------------------

class TestConnectorWafJobs:
    def test_apply_waf_rule_in_handlers(self):
        mod = _connector()
        assert "apply_waf_rule" in mod.JOB_HANDLERS
        assert "remove_waf_rule" in mod.JOB_HANDLERS

    def test_apply_waf_rule_returns_result_dict(self):
        mod = _connector()
        result = mod._job_apply_waf_rule({
            "rule_id": "hydrax-test123",
            "rule_spec": {"type": "block_pattern", "pattern": "<script",
                          "location": "query", "path": "/"},
            "rollback_token": "tok1",
        })
        assert "applied" in result
        assert result.get("rule_id") == "hydrax-test123"
        assert result.get("rollback_token") == "tok1"

    def test_apply_waf_rule_refuses_empty_rule_id(self):
        mod = _connector()
        result = mod._job_apply_waf_rule({"rule_id": "", "rollback_token": "t"})
        assert result["applied"] is False

    def test_apply_waf_rule_writes_file_when_dir_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HYDRAX_WAF_DIR", str(tmp_path))
        mod = _connector()
        result = mod._job_apply_waf_rule({
            "rule_id": "hydrax-testwrite",
            "rule_spec": {"type": "block_pattern", "pattern": "test",
                          "location": "query", "path": "/"},
            "rollback_token": "w",
        })
        assert result["applied"] is True
        assert (tmp_path / "hydrax-testwrite.conf").exists()

    def test_remove_waf_rule_returns_result_dict(self):
        mod = _connector()
        result = mod._job_remove_waf_rule({"rule_id": "hydrax-gone", "rollback_token": "r"})
        assert "removed" in result
        assert result.get("rollback_token") == "r"

    def test_remove_waf_rule_deletes_file_when_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HYDRAX_WAF_DIR", str(tmp_path))
        rule_file = tmp_path / "hydrax-delme.conf"
        rule_file.write_text("# old rule\n")
        mod = _connector()
        result = mod._job_remove_waf_rule({"rule_id": "hydrax-delme", "rollback_token": "d"})
        assert result["removed"] is True
        assert not rule_file.exists()

    def test_remove_waf_rule_refuses_empty_rule_id(self):
        mod = _connector()
        result = mod._job_remove_waf_rule({"rule_id": "", "rollback_token": "r"})
        assert result["removed"] is False


# ---------------------------------------------------------------------------
# Full cycle: detect → decide (auto_remediate) → apply → approve
# ---------------------------------------------------------------------------

class TestFullAutoRemediateCycle:
    def setup_method(self):
        from brain.autonomy import KILL_SWITCH
        KILL_SWITCH.disengage()
        from brain.decision import _RATE_BRAKE, configure_allowlist
        _RATE_BRAKE.reset(1, 1)
        configure_allowlist([])

    def test_auto_remediate_waf_rule_cycle(self, fake):
        from brain.detection import detect
        from brain.decision import decide
        from brain.response import apply_action
        from brain.sensors import Event

        _auth(fake)
        _set_tier(1, 1, "auto_remediate")

        ev = Event(asset_id=1, org_id=1,
                   ts=datetime.now(timezone.utc),
                   src_ip="66.66.66.66", path="/?q=<script>alert(1)",
                   signals={"xss_hint": True})
        ev.asset_id = 1
        ev.org_id = 1

        detections = detect(1, 1, [ev])
        proposals = decide(1, 1, detections)
        assert any(p.action_type == "apply_waf_rule" for p in proposals)

        action_ids = [apply_action(1, 1, p) for p in proposals]
        waf_actions = [a for a in fake.brain_actions
                       if a.get("type") == "apply_waf_rule"]
        assert len(waf_actions) >= 1
        assert waf_actions[0]["status"] == "applied"

    def test_edit_source_requires_approval(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, approve_action

        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="edit_source",
            params={"file": "views.py", "change": "escape(output)"},
            tier=AutonomyTier.AUTO_REMEDIATE,
            ttl_seconds=86400,
        )
        aid = apply_action(1, 1, prop)
        # Must be 'proposed' — not auto-applied
        assert fake.brain_get_action(aid, 1)["status"] == "proposed"

        # Human approval transitions it
        assert approve_action(aid, 1, "security-lead@example.com") is True
        assert fake.brain_get_action(aid, 1)["status"] == "approved"
