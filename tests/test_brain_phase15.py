"""
Phase 15: brain/decision.py + brain/response.py + containment connector jobs.

Covers:
  - is_self_lockout: loopback, empty, allowlist
  - decide(): observe tier → no proposals; auto_contain → block_source proposals
  - decide(): kill switch → no proposals
  - decide(): self-lockout IPs skipped with audit log entry
  - decide(): FP rate brake downgrade to recommend
  - apply_action(): writes brain_actions with correct status
  - recommend actions land as 'proposed' (not 'applied')
  - rollback_action(): flips status, appends rollback log entry
  - rollback_action(): idempotent — already-rolled-back returns False
  - rollback_all(): rolls back all applied/proposed for asset
  - expire_ttl_actions(): rolls back past-TTL actions only
  - connector: block_source, unblock_source, kill_session handlers
  - connector: self-lockout guard in block_source
  - full decision → apply → rollback cycle
"""
import secrets
from datetime import datetime, timedelta, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detection(attack_class="xss", src_ip="1.2.3.4", asset_id=1, org_id=1,
                    incident_id=1):
    from brain.sensors import Event
    from brain.detection import Detection, event_fingerprint
    ev = Event(asset_id=asset_id, org_id=org_id,
               ts=datetime.now(timezone.utc),
               src_ip=src_ip, path="/test", signals={})
    fp = event_fingerprint(asset_id, org_id, attack_class, src_ip)
    return Detection(asset_id=asset_id, org_id=org_id, attack_class=attack_class,
                     fingerprint=fp, event=ev, incident_id=incident_id)


def _auth(fake, asset_id=1, org_id=1):
    fake.record_asset_authorization(
        organization_id=org_id, asset_id=asset_id,
        authorized_by_user_id=1, method="engagement_letter",
        status="authorized", expires_at=None,
    )


def _set_tier(asset_id, org_id, tier_value):
    from brain.autonomy import set_policy, AutonomyPolicy, AutonomyTier
    tier = AutonomyTier(tier_value)
    set_policy(AutonomyPolicy(asset_id=asset_id, org_id=org_id, tier=tier))


# ---------------------------------------------------------------------------
# is_self_lockout
# ---------------------------------------------------------------------------

class TestSelfLockout:
    def setup_method(self):
        from brain.decision import configure_allowlist
        configure_allowlist([])

    def test_loopback_blocked(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout("127.0.0.1") is True

    def test_loopback_prefix_blocked(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout("127.0.0.2") is True

    def test_ipv6_loopback_blocked(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout("::1") is True

    def test_empty_string_blocked(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout("") is True

    def test_none_blocked(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout(None) is True

    def test_normal_ip_allowed(self):
        from brain.decision import is_self_lockout
        assert is_self_lockout("1.2.3.4") is False

    def test_owner_allowlist_blocked(self):
        from brain.decision import configure_allowlist, is_self_lockout
        configure_allowlist(["10.0.0.1"])
        assert is_self_lockout("10.0.0.1") is True

    def test_non_allowlist_ip_allowed(self):
        from brain.decision import configure_allowlist, is_self_lockout
        configure_allowlist(["10.0.0.1"])
        assert is_self_lockout("10.0.0.2") is False


# ---------------------------------------------------------------------------
# decide() — tier-based behavior
# ---------------------------------------------------------------------------

class TestDecide:
    def setup_method(self):
        from brain.autonomy import KILL_SWITCH, remove_policy
        KILL_SWITCH.disengage()
        try:
            remove_policy(1, 1)
            remove_policy(2, 1)
        except Exception:
            pass
        from brain.decision import _RATE_BRAKE, configure_allowlist
        _RATE_BRAKE.reset(1, 1)
        _RATE_BRAKE.reset(2, 1)
        configure_allowlist([])

    def test_observe_tier_no_proposals(self):
        from brain.decision import decide
        _set_tier(1, 1, "observe")
        det = _make_detection()
        proposals = decide(1, 1, [det])
        assert proposals == []

    def test_auto_contain_produces_block_source(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        det = _make_detection(src_ip="5.5.5.5")
        proposals = decide(1, 1, [det])
        assert len(proposals) == 1
        assert proposals[0].action_type == "block_source"
        assert proposals[0].params["src_ip"] == "5.5.5.5"

    def test_recommend_tier_produces_recommend_action(self):
        from brain.decision import decide
        _set_tier(1, 1, "recommend")
        det = _make_detection(src_ip="6.6.6.6")
        proposals = decide(1, 1, [det])
        assert len(proposals) == 1
        assert proposals[0].action_type == "block_source"

    def test_kill_switch_blocks_all_proposals(self):
        from brain.autonomy import KILL_SWITCH
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        KILL_SWITCH.engage()
        proposals = decide(1, 1, [_make_detection(src_ip="7.7.7.7")])
        assert proposals == []
        KILL_SWITCH.disengage()

    def test_self_lockout_ip_skipped(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        det = _make_detection(src_ip="127.0.0.1")
        proposals = decide(1, 1, [det])
        assert proposals == []

    def test_self_lockout_logged_to_incident_log(self):
        from brain.decision import decide
        from brain.incident_log import INCIDENT_LOG
        _set_tier(1, 1, "auto_contain")
        decide(1, 1, [_make_detection(src_ip="127.0.0.1")])
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="decision")
        lockout_entries = [e for e in entries if
                           e["payload"].get("reason") == "self_lockout_guard"]
        assert len(lockout_entries) >= 1

    def test_fp_rate_brake_downgrade(self):
        from brain.decision import decide, _RATE_BRAKE
        from brain.autonomy import set_policy, AutonomyPolicy, AutonomyTier
        # fp_block_max_per_min = 1
        pol = AutonomyPolicy(asset_id=2, org_id=1,
                             tier=AutonomyTier.AUTO_CONTAIN, fp_block_max_per_min=1)
        set_policy(pol)
        _RATE_BRAKE.reset(2, 1)

        d1 = _make_detection(src_ip="8.8.8.1", asset_id=2)
        d2 = _make_detection(src_ip="8.8.8.2", asset_id=2)
        proposals = decide(2, 1, [d1, d2])

        assert len(proposals) == 2
        types = {p.action_type for p in proposals}
        assert "block_source" in types
        assert "recommend" in types  # second one downgraded

    def test_rollback_token_unique_per_proposal(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        dets = [_make_detection(src_ip=f"9.9.9.{i}") for i in range(3)]
        proposals = decide(1, 1, dets)
        tokens = [p.rollback_token for p in proposals]
        assert len(set(tokens)) == len(tokens)

    def test_proposals_carry_ttl(self):
        from brain.decision import decide
        _set_tier(1, 1, "auto_contain")
        proposals = decide(1, 1, [_make_detection(src_ip="3.3.3.3")],
                           ttl_seconds=300)
        assert proposals[0].ttl_seconds == 300


# ---------------------------------------------------------------------------
# apply_action()
# ---------------------------------------------------------------------------

class TestApplyAction:
    def test_block_source_lands_as_applied(self, fake):
        from brain.decision import decide, ProposedAction, AutonomyTier
        from brain.response import apply_action
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="block_source",
            params={"src_ip": "2.2.2.2", "attack_class": "xss"},
            tier=AutonomyTier.AUTO_CONTAIN,
            ttl_seconds=3600,
        )
        action_id = apply_action(1, 1, prop)
        assert action_id is not None
        a = fake.brain_get_action(action_id, 1)
        assert a["status"] == "applied"

    def test_recommend_lands_as_proposed(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="recommend",
            params={"src_ip": "2.2.2.3", "attack_class": "sqli"},
            tier=AutonomyTier.RECOMMEND,
            ttl_seconds=3600,
        )
        action_id = apply_action(1, 1, prop)
        a = fake.brain_get_action(action_id, 1)
        assert a["status"] == "proposed"

    def test_rollback_token_stored(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        token = secrets.token_hex(16)
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="block_source",
            params={"src_ip": "2.2.2.4"},
            tier=AutonomyTier.AUTO_CONTAIN,
            rollback_token=token,
        )
        action_id = apply_action(1, 1, prop)
        a = fake.brain_get_action(action_id, 1)
        assert a["rollback_token"] == token

    def test_apply_appends_action_log(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        from brain.incident_log import INCIDENT_LOG
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="block_source",
            params={"src_ip": "3.3.3.3"},
            tier=AutonomyTier.AUTO_CONTAIN,
        )
        apply_action(1, 1, prop)
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="action")
        assert any(e["payload"].get("action_type") == "block_source" for e in entries)

    def test_expires_at_stored_in_params(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action
        prop = ProposedAction(
            asset_id=1, org_id=1, incident_id=1,
            action_type="block_source",
            params={"src_ip": "4.4.4.4"},
            tier=AutonomyTier.AUTO_CONTAIN,
            ttl_seconds=600,
        )
        action_id = apply_action(1, 1, prop)
        a = fake.brain_get_action(action_id, 1)
        assert "expires_at" in a["params"]


# ---------------------------------------------------------------------------
# rollback_action()
# ---------------------------------------------------------------------------

class TestRollbackAction:
    def test_rolls_back_applied_action(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, rollback_action
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "5.5.5.5"},
                              tier=AutonomyTier.AUTO_CONTAIN)
        aid = apply_action(1, 1, prop)
        assert rollback_action(aid, 1) is True
        assert fake.brain_get_action(aid, 1)["status"] == "rolled_back"

    def test_rollback_appends_rollback_log(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, rollback_action
        from brain.incident_log import INCIDENT_LOG
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "6.6.6.6"},
                              tier=AutonomyTier.AUTO_CONTAIN)
        aid = apply_action(1, 1, prop)
        rollback_action(aid, 1)
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="rollback")
        assert any(e["payload"].get("action_id") == aid for e in entries)

    def test_double_rollback_is_idempotent(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, rollback_action
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "7.7.7.7"},
                              tier=AutonomyTier.AUTO_CONTAIN)
        aid = apply_action(1, 1, prop)
        assert rollback_action(aid, 1) is True
        assert rollback_action(aid, 1) is False  # already rolled_back

    def test_rollback_nonexistent_returns_false(self, fake):
        from brain.response import rollback_action
        assert rollback_action(999, 1) is False


# ---------------------------------------------------------------------------
# rollback_all()
# ---------------------------------------------------------------------------

class TestRollbackAll:
    def test_rolls_back_all_applied(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, rollback_all
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                                  action_type="block_source",
                                  params={"src_ip": ip},
                                  tier=AutonomyTier.AUTO_CONTAIN)
            apply_action(1, 1, prop)
        count = rollback_all(1, 1)
        assert count == 3
        for a in fake.brain_actions:
            if a["asset_id"] == 1 and a["org_id"] == 1:
                assert a["status"] == "rolled_back"

    def test_rollback_all_empty_returns_zero(self, fake):
        from brain.response import rollback_all
        assert rollback_all(99, 1) == 0

    def test_rollback_all_only_affects_target_asset(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, rollback_all
        p1 = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                            action_type="block_source",
                            params={"src_ip": "11.0.0.1"},
                            tier=AutonomyTier.AUTO_CONTAIN)
        p2 = ProposedAction(asset_id=2, org_id=1, incident_id=1,
                            action_type="block_source",
                            params={"src_ip": "11.0.0.2"},
                            tier=AutonomyTier.AUTO_CONTAIN)
        a1 = apply_action(1, 1, p1)
        a2 = apply_action(2, 1, p2)
        rollback_all(1, 1)  # only asset 1
        assert fake.brain_get_action(a1, 1)["status"] == "rolled_back"
        assert fake.brain_get_action(a2, 1)["status"] == "applied"


# ---------------------------------------------------------------------------
# expire_ttl_actions()
# ---------------------------------------------------------------------------

class TestExpireTTL:
    def test_past_ttl_rolled_back(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, expire_ttl_actions
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "20.0.0.1"},
                              tier=AutonomyTier.AUTO_CONTAIN,
                              ttl_seconds=3600)
        aid = apply_action(1, 1, prop)
        # Manually backdate expires_at
        for a in fake.brain_actions:
            if a["id"] == aid:
                a["params"]["expires_at"] = "2000-01-01T00:00:00+00:00"
        count = expire_ttl_actions(1, 1)
        assert count == 1
        assert fake.brain_get_action(aid, 1)["status"] == "rolled_back"

    def test_future_ttl_not_rolled_back(self, fake):
        from brain.decision import ProposedAction, AutonomyTier
        from brain.response import apply_action, expire_ttl_actions
        prop = ProposedAction(asset_id=1, org_id=1, incident_id=1,
                              action_type="block_source",
                              params={"src_ip": "21.0.0.1"},
                              tier=AutonomyTier.AUTO_CONTAIN,
                              ttl_seconds=3600)
        aid = apply_action(1, 1, prop)
        count = expire_ttl_actions(1, 1)
        assert count == 0
        assert fake.brain_get_action(aid, 1)["status"] == "applied"


# ---------------------------------------------------------------------------
# Connector: block_source, unblock_source, kill_session
# ---------------------------------------------------------------------------

class TestConnectorContainmentJobs:
    def _handler(self, name):
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location(
            "connector_agent",
            pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, name)

    def test_block_source_in_handlers(self):
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location(
            "connector_agent",
            pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert "block_source" in mod.JOB_HANDLERS
        assert "unblock_source" in mod.JOB_HANDLERS
        assert "kill_session" in mod.JOB_HANDLERS

    def test_block_source_returns_result_dict(self):
        fn = self._handler("_job_block_source")
        result = fn({"src_ip": "192.168.99.1", "rollback_token": "abc123"})
        assert "blocked" in result
        assert result.get("rollback_token") == "abc123"

    def test_block_source_refuses_loopback(self):
        fn = self._handler("_job_block_source")
        result = fn({"src_ip": "127.0.0.1", "rollback_token": "tok"})
        assert result["blocked"] is False
        assert "self-lockout" in result.get("error", "")

    def test_block_source_refuses_empty_ip(self):
        fn = self._handler("_job_block_source")
        result = fn({"src_ip": "", "rollback_token": "tok"})
        assert result["blocked"] is False

    def test_unblock_source_returns_result_dict(self):
        fn = self._handler("_job_unblock_source")
        result = fn({"src_ip": "192.168.99.2", "rollback_token": "xyz"})
        assert "unblocked" in result
        assert result.get("rollback_token") == "xyz"

    def test_unblock_source_refuses_empty_ip(self):
        fn = self._handler("_job_unblock_source")
        result = fn({"src_ip": "", "rollback_token": ""})
        assert result["unblocked"] is False

    def test_kill_session_returns_result_dict(self):
        fn = self._handler("_job_kill_session")
        result = fn({"src_ip": "192.168.99.3", "dst_port": 80})
        assert "killed" in result
        assert result.get("src_ip") == "192.168.99.3"

    def test_kill_session_refuses_empty_ip(self):
        fn = self._handler("_job_kill_session")
        result = fn({"src_ip": "", "dst_port": 80})
        assert result["killed"] is False


# ---------------------------------------------------------------------------
# Full cycle: detect → decide → apply → rollback
# ---------------------------------------------------------------------------

class TestFullCycle:
    def setup_method(self):
        from brain.autonomy import KILL_SWITCH
        KILL_SWITCH.disengage()
        from brain.decision import _RATE_BRAKE, configure_allowlist
        _RATE_BRAKE.reset(1, 1)
        configure_allowlist([])

    def test_detect_decide_apply_rollback(self, fake):
        from brain.detection import detect
        from brain.decision import decide
        from brain.response import apply_action, rollback_all
        from brain.sensors import Event

        _auth(fake)
        _set_tier(1, 1, "auto_contain")

        ev = Event(asset_id=1, org_id=1,
                   ts=datetime.now(timezone.utc),
                   src_ip="55.55.55.55", path="/?id=1 UNION SELECT",
                   signals={"sqli_hint": True})
        ev.asset_id = 1
        ev.org_id = 1

        detections = detect(1, 1, [ev])
        assert len(detections) >= 1

        proposals = decide(1, 1, detections)
        assert len(proposals) >= 1

        action_ids = [apply_action(1, 1, p) for p in proposals]
        assert len(fake.brain_actions) >= 1
        for aid in action_ids:
            assert fake.brain_get_action(aid, 1)["status"] == "applied"

        count = rollback_all(1, 1)
        assert count >= 1
        for aid in action_ids:
            assert fake.brain_get_action(aid, 1)["status"] == "rolled_back"
