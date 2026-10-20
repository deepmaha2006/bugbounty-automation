"""
Phase 14: brain/detection.py + brain/correlation.py tests.

Covers:
  - classify_event: signal → attack_class mapping, None for benign events
  - event_fingerprint: deterministic, 32-char hex
  - severity_for: high/medium/low mapping
  - detect(): authorization gate, incident upsert, INCIDENT_LOG entry, observe mode
  - correlate(): campaign grouping by src_ip + attack_class + window
  - brain_list_events API (FakeDB)
"""
import json
from datetime import datetime, timedelta, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(signals=None, src_ip="1.2.3.4", path="/test", method="GET", status=200):
    from brain.sensors import Event
    return Event(
        asset_id=0, org_id=0,
        ts=datetime.now(timezone.utc),
        src_ip=src_ip, method=method, path=path, status=status,
        signals=signals or {},
    )


def _auth(fake, asset_id=1, org_id=1):
    fake.record_asset_authorization(
        organization_id=org_id, asset_id=asset_id,
        authorized_by_user_id=1, method="engagement_letter",
        status="authorized", expires_at=None,
    )


# ---------------------------------------------------------------------------
# classify_event
# ---------------------------------------------------------------------------

class TestClassifyEvent:
    def test_xss_hint(self):
        from brain.detection import classify_event
        ev = _make_event({"xss_hint": True})
        assert classify_event(ev) == "xss"

    def test_sqli_hint(self):
        from brain.detection import classify_event
        ev = _make_event({"sqli_hint": True})
        assert classify_event(ev) == "sql_injection"

    def test_path_traversal(self):
        from brain.detection import classify_event
        ev = _make_event({"path_traversal": True})
        assert classify_event(ev) == "path_traversal"

    def test_scanner_probe(self):
        from brain.detection import classify_event
        ev = _make_event({"scanner_signature": True})
        assert classify_event(ev) == "scanner_probe"

    def test_no_signals_returns_none(self):
        from brain.detection import classify_event
        ev = _make_event({})
        assert classify_event(ev) is None

    def test_unparsed_only_returns_none(self):
        from brain.detection import classify_event
        ev = _make_event({"unparsed": True})
        assert classify_event(ev) is None

    def test_first_signal_wins(self):
        from brain.detection import classify_event
        # path_traversal and sqli_hint both set; whichever is first in SIGNAL_TO_ATTACK_CLASS wins
        ev = _make_event({"path_traversal": True, "sqli_hint": True})
        result = classify_event(ev)
        assert result in ("path_traversal", "sql_injection")


# ---------------------------------------------------------------------------
# event_fingerprint
# ---------------------------------------------------------------------------

class TestEventFingerprint:
    def test_deterministic(self):
        from brain.detection import event_fingerprint
        fp1 = event_fingerprint(1, 1, "xss", "1.2.3.4")
        fp2 = event_fingerprint(1, 1, "xss", "1.2.3.4")
        assert fp1 == fp2

    def test_32_chars(self):
        from brain.detection import event_fingerprint
        assert len(event_fingerprint(1, 1, "sqli", "10.0.0.1")) == 32

    def test_different_ip_different_fp(self):
        from brain.detection import event_fingerprint
        fp1 = event_fingerprint(1, 1, "xss", "1.1.1.1")
        fp2 = event_fingerprint(1, 1, "xss", "2.2.2.2")
        assert fp1 != fp2

    def test_different_attack_class_different_fp(self):
        from brain.detection import event_fingerprint
        fp1 = event_fingerprint(1, 1, "xss", "1.1.1.1")
        fp2 = event_fingerprint(1, 1, "sqli", "1.1.1.1")
        assert fp1 != fp2

    def test_none_ip_stable(self):
        from brain.detection import event_fingerprint
        fp = event_fingerprint(1, 1, "scanner_probe", None)
        assert len(fp) == 32


# ---------------------------------------------------------------------------
# severity_for
# ---------------------------------------------------------------------------

class TestSeverityFor:
    def test_sql_injection_high(self):
        from brain.detection import severity_for
        assert severity_for("sql_injection") == "high"

    def test_path_traversal_high(self):
        from brain.detection import severity_for
        assert severity_for("path_traversal") == "high"

    def test_xss_medium(self):
        from brain.detection import severity_for
        assert severity_for("xss") == "medium"

    def test_scanner_probe_low(self):
        from brain.detection import severity_for
        assert severity_for("scanner_probe") == "low"

    def test_unknown_class_low(self):
        from brain.detection import severity_for
        assert severity_for("something_new") == "low"


# ---------------------------------------------------------------------------
# detect()
# ---------------------------------------------------------------------------

class TestDetect:
    def test_refuses_without_authorization(self, fake):
        from brain.detection import detect
        from brain.sensors import AuthorizationError
        events = [_make_event({"xss_hint": True})]
        with pytest.raises(AuthorizationError):
            detect(99, 1, events)

    def test_benign_events_produce_no_detections(self, fake):
        from brain.detection import detect
        _auth(fake)
        events = [_make_event({}), _make_event({"unparsed": True})]
        detections = detect(1, 1, events)
        assert detections == []
        assert len(fake.brain_incidents) == 0

    def test_xss_event_creates_incident(self, fake):
        from brain.detection import detect
        _auth(fake)
        events = [_make_event({"xss_hint": True})]
        detections = detect(1, 1, events)
        assert len(detections) == 1
        assert detections[0].attack_class == "xss"
        assert len(fake.brain_incidents) == 1

    def test_duplicate_events_upsert_not_insert(self, fake):
        from brain.detection import detect
        _auth(fake)
        ev = _make_event({"sqli_hint": True})
        detect(1, 1, [ev, ev])  # same fingerprint twice
        assert len(fake.brain_incidents) == 1

    def test_multiple_attack_classes_multiple_incidents(self, fake):
        from brain.detection import detect
        _auth(fake)
        events = [
            _make_event({"xss_hint": True}, src_ip="1.1.1.1"),
            _make_event({"sqli_hint": True}, src_ip="2.2.2.2"),
            _make_event({"path_traversal": True}, src_ip="3.3.3.3"),
        ]
        detections = detect(1, 1, events)
        assert len(detections) == 3
        assert len(fake.brain_incidents) == 3

    def test_incident_severity_correct(self, fake):
        from brain.detection import detect
        _auth(fake)
        detect(1, 1, [_make_event({"sqli_hint": True})])
        assert fake.brain_incidents[0]["severity"] == "high"

    def test_detection_appended_to_incident_log(self, fake):
        from brain.detection import detect
        from brain.incident_log import INCIDENT_LOG
        _auth(fake)
        detect(1, 1, [_make_event({"xss_hint": True})])
        entries = INCIDENT_LOG.list(asset_id=1, org_id=1, entry_type="detection")
        assert len(entries) >= 1
        assert entries[-1]["payload"]["attack_class"] == "xss"

    def test_observe_mode_no_actions(self, fake):
        from brain.detection import detect
        _auth(fake)
        detect(1, 1, [_make_event({"sqli_hint": True})])
        assert len(fake.brain_actions) == 0

    def test_detection_returns_incident_id(self, fake):
        from brain.detection import detect
        _auth(fake)
        detections = detect(1, 1, [_make_event({"path_traversal": True})])
        assert detections[0].incident_id is not None
        assert isinstance(detections[0].incident_id, int)

    def test_detection_fills_asset_id_org_id(self, fake):
        from brain.detection import detect
        _auth(fake, asset_id=7, org_id=3)
        detections = detect(7, 3, [_make_event({"scanner_signature": True})])
        assert detections[0].asset_id == 7
        assert detections[0].org_id == 3


# ---------------------------------------------------------------------------
# correlate()
# ---------------------------------------------------------------------------

def _make_detection(attack_class, src_ip, ts_offset_s=0, asset_id=1, org_id=1):
    from brain.detection import Detection, event_fingerprint
    ev = _make_event(src_ip=src_ip)
    ev.ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=ts_offset_s)
    fp = event_fingerprint(asset_id, org_id, attack_class, src_ip)
    return Detection(asset_id=asset_id, org_id=org_id, attack_class=attack_class,
                     fingerprint=fp, event=ev, incident_id=1)


class TestCorrelate:
    def test_empty_returns_empty(self):
        from brain.correlation import correlate
        assert correlate([]) == []

    def test_single_detection_one_campaign(self):
        from brain.correlation import correlate
        d = _make_detection("xss", "1.1.1.1")
        campaigns = correlate([d])
        assert len(campaigns) == 1
        assert campaigns[0].attack_class == "xss"
        assert campaigns[0].count == 1

    def test_same_ip_same_class_within_window_merged(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1", ts_offset_s=0)
        d2 = _make_detection("xss", "1.1.1.1", ts_offset_s=60)
        campaigns = correlate([d1, d2], window_seconds=300)
        assert len(campaigns) == 1
        assert campaigns[0].count == 2

    def test_same_ip_different_class_separate_campaigns(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1")
        d2 = _make_detection("sqli", "1.1.1.1")
        campaigns = correlate([d1, d2])
        assert len(campaigns) == 2

    def test_different_ips_separate_campaigns(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1")
        d2 = _make_detection("xss", "2.2.2.2")
        campaigns = correlate([d1, d2])
        assert len(campaigns) == 2

    def test_outside_window_starts_fresh_campaign(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1", ts_offset_s=0)
        d2 = _make_detection("xss", "1.1.1.1", ts_offset_s=700)
        campaigns = correlate([d1, d2], window_seconds=300)
        assert len(campaigns) == 2

    def test_sorted_most_recent_first(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1", ts_offset_s=0)
        d2 = _make_detection("sqli", "2.2.2.2", ts_offset_s=100)
        campaigns = correlate([d1, d2])
        assert campaigns[0].attack_class == "sqli"

    def test_campaign_paths_accumulated(self):
        from brain.correlation import correlate, Campaign
        from brain.detection import Detection, event_fingerprint
        from brain.sensors import Event

        def _det(path, src_ip="1.1.1.1"):
            ev = Event(asset_id=1, org_id=1,
                       ts=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                       src_ip=src_ip, path=path)
            fp = event_fingerprint(1, 1, "xss", src_ip)
            return Detection(asset_id=1, org_id=1, attack_class="xss",
                             fingerprint=fp, event=ev, incident_id=1)

        campaigns = correlate([_det("/a"), _det("/b"), _det("/c")])
        assert len(campaigns) == 1
        assert set(campaigns[0].paths) == {"/a", "/b", "/c"}

    def test_campaign_fingerprints_deduplicated(self):
        from brain.correlation import correlate
        d1 = _make_detection("xss", "1.1.1.1", ts_offset_s=0)
        d2 = _make_detection("xss", "1.1.1.1", ts_offset_s=10)
        campaigns = correlate([d1, d2])
        # same fingerprint (same ip+class) should not be duplicated
        assert len(campaigns[0].fingerprints) == 1


# ---------------------------------------------------------------------------
# brain_list_events (FakeDB)
# ---------------------------------------------------------------------------

class TestBrainListEvents:
    def test_empty_returns_empty(self, fake):
        assert fake.brain_list_events(1, 1) == []

    def test_returns_only_matching_asset(self, fake):
        fake.brain_insert_event(asset_id=1, org_id=1, src_ip="1.1.1.1",
                                method="GET", path="/a", status=200, signals={})
        fake.brain_insert_event(asset_id=2, org_id=1, src_ip="2.2.2.2",
                                method="GET", path="/b", status=200, signals={})
        rows = fake.brain_list_events(1, 1)
        assert len(rows) == 1
        assert rows[0]["asset_id"] == 1

    def test_limit_respected(self, fake):
        for i in range(10):
            fake.brain_insert_event(asset_id=1, org_id=1, src_ip=f"1.1.1.{i}",
                                    method="GET", path="/x", status=200, signals={})
        rows = fake.brain_list_events(1, 1, limit=5)
        assert len(rows) == 5


# ---------------------------------------------------------------------------
# Full ingest → detect → correlate pipeline test
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_ingest_detect_correlate(self, fake):
        from brain.sensors import ingest_connector_telemetry
        from brain.detection import detect
        from brain.correlation import correlate

        _auth(fake)

        telemetry = {
            "hostname": "test", "collected_at": "2024-01-01T00:00:00+00:00",
            "log_entries": [
                {"source_file": "access.log",
                 "line": '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /?id=1 UNION SELECT HTTP/1.0" 200 10',
                 "collected_at": "2024-01-01T00:00:00+00:00"},
                {"source_file": "access.log",
                 "line": '1.2.3.4 - - [10/Oct/2000:13:55:37 -0700] "GET /?q=<script>alert(1) HTTP/1.0" 200 10',
                 "collected_at": "2024-01-01T00:00:00+00:00"},
                {"source_file": "access.log",
                 "line": '5.5.5.5 - - [10/Oct/2000:13:55:38 -0700] "GET /../etc/passwd HTTP/1.0" 403 0',
                 "collected_at": "2024-01-01T00:00:00+00:00"},
            ],
        }

        events = ingest_connector_telemetry(1, 1, telemetry)
        assert len(events) == 3

        detections = detect(1, 1, events)
        # Each attack-class/src_ip pair → one incident (1.2.3.4 has sqli+xss, 5.5.5.5 has traversal)
        assert len(detections) >= 2
        assert len(fake.brain_incidents) >= 2

        campaigns = correlate(detections)
        # Multiple campaigns possible; no actions taken
        assert len(fake.brain_actions) == 0
        assert all(c.count >= 1 for c in campaigns)
