"""
Phase 13: collect_telemetry connector job + brain/sensors.py tests.

Covers:
  - _job_collect_telemetry: reads log files, caps max_lines, handles I/O errors
  - parse_log_line: Apache/Nginx combined format, JSON format, fallback
  - Signal detection: path traversal, SQLi hints, XSS hints, scanner UA
  - ingest_connector_telemetry: authorization gate, saves to brain_events, observe mode
  - Full flow: connector job result → ingest → brain_events row
"""
import json
import os
import tempfile
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Connector: _job_collect_telemetry
# ---------------------------------------------------------------------------

class TestJobCollectTelemetry:
    """Tests for the collect_telemetry connector job handler."""

    def _handler(self):
        # Import directly from connector module (no platform deps needed for this handler)
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location(
            "connector_agent",
            pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._job_collect_telemetry

    def test_returns_expected_keys(self):
        handler = self._handler()
        result = handler({"log_files": []})
        assert "hostname" in result
        assert "collected_at" in result
        assert "log_entries" in result
        assert isinstance(result["log_entries"], list)

    def test_reads_file_lines(self):
        handler = self._handler()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.0" 200 100\n')
            f.write('127.0.0.1 - - [10/Oct/2000:13:55:37 -0700] "POST /b HTTP/1.0" 404 50\n')
            fname = f.name
        try:
            result = handler({"log_files": [fname]})
        finally:
            os.unlink(fname)
        entries = [e for e in result["log_entries"] if "error" not in e]
        assert len(entries) == 2
        assert entries[0]["source_file"] == fname
        assert entries[0]["line"].startswith("127.0.0.1")

    def test_max_lines_cap(self):
        handler = self._handler()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(10):
                f.write(f"line {i}\n")
            fname = f.name
        try:
            result = handler({"log_files": [fname], "max_lines_per_file": 3})
        finally:
            os.unlink(fname)
        entries = [e for e in result["log_entries"] if "error" not in e]
        assert len(entries) == 3
        assert "line 9" in entries[-1]["line"]  # last 3 lines

    def test_hard_cap_at_1000(self):
        handler = self._handler()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(1500):
                f.write(f"line {i}\n")
            fname = f.name
        try:
            result = handler({"log_files": [fname], "max_lines_per_file": 9999})
        finally:
            os.unlink(fname)
        entries = [e for e in result["log_entries"] if "error" not in e]
        assert len(entries) <= 1000

    def test_io_error_recorded_not_raised(self):
        handler = self._handler()
        result = handler({"log_files": ["/nonexistent/path/nowhere.log"]})
        assert len(result["log_entries"]) == 1
        assert "error" in result["log_entries"][0]

    def test_collect_telemetry_in_job_handlers(self):
        """collect_telemetry must be in JOB_HANDLERS allowlist."""
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location(
            "connector_agent",
            pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert "collect_telemetry" in mod.JOB_HANDLERS

    def test_empty_log_files_returns_empty_entries(self):
        handler = self._handler()
        result = handler({})
        assert result["log_entries"] == []


# ---------------------------------------------------------------------------
# brain/sensors.py — parse_log_line
# ---------------------------------------------------------------------------

class TestParseLogLine:
    def _parse(self, line, source=""):
        from brain.sensors import parse_log_line
        return parse_log_line(line, source)

    def test_blank_returns_none(self):
        assert self._parse("") is None
        assert self._parse("   ") is None

    def test_combined_format_basic(self):
        line = '1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326'
        ev = self._parse(line)
        assert ev is not None
        assert ev.src_ip == "1.2.3.4"
        assert ev.method == "GET"
        assert ev.path == "/index.html"
        assert ev.status == 200

    def test_combined_format_with_referer_and_ua(self):
        line = ('127.0.0.1 - - [10/Oct/2000:14:00:00 +0000] '
                '"POST /login HTTP/1.1" 302 0 "http://example.com" "Mozilla/5.0"')
        ev = self._parse(line)
        assert ev.method == "POST"
        assert ev.path == "/login"
        assert ev.status == 302

    def test_combined_format_ts_parsed(self):
        line = '1.1.1.1 - - [15/Mar/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100'
        ev = self._parse(line)
        assert ev.ts.month == 3
        assert ev.ts.day == 15
        assert ev.ts.year == 2024

    def test_json_log_format(self):
        obj = {"time": "2024-01-01T12:00:00+00:00", "method": "GET",
               "path": "/api/users", "status": 200, "ip": "10.0.0.1"}
        ev = self._parse(json.dumps(obj))
        assert ev is not None
        assert ev.method == "GET"
        assert ev.path == "/api/users"
        assert ev.status == 200
        assert ev.src_ip == "10.0.0.1"

    def test_json_log_alternate_keys(self):
        obj = {"timestamp": "2024-01-01T12:00:00Z", "url": "/search",
               "statusCode": 404, "remote_addr": "192.168.1.1"}
        ev = self._parse(json.dumps(obj))
        assert ev.path == "/search"
        assert ev.status == 404
        assert ev.src_ip == "192.168.1.1"

    def test_fallback_for_unknown_format(self):
        ev = self._parse("Some totally unknown log line format here")
        assert ev is not None
        assert ev.signals.get("unparsed") is True
        assert ev.raw_line == "Some totally unknown log line format here"

    def test_source_file_stored_in_signals(self):
        line = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100'
        ev = self._parse(line, source="/var/log/nginx/access.log")
        assert ev.signals.get("log_source") == "/var/log/nginx/access.log"

    def test_returned_asset_id_is_zero(self):
        """parse_log_line leaves asset_id=0; ingest fills it in."""
        line = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100'
        ev = self._parse(line)
        assert ev.asset_id == 0
        assert ev.org_id == 0


# ---------------------------------------------------------------------------
# Signal detection
# ---------------------------------------------------------------------------

class TestSignalDetection:
    def _signals(self, path, ua=None):
        from brain.sensors import _detect_signals
        return _detect_signals(path, ua)

    def test_path_traversal_dotdot(self):
        assert self._signals("/../etc/passwd")["path_traversal"] is True

    def test_path_traversal_encoded(self):
        assert self._signals("/%2e%2e/etc/passwd")["path_traversal"] is True

    def test_sqli_union_select(self):
        assert self._signals("/?id=1+UNION+SELECT+1,2,3")["sqli_hint"] is True

    def test_sqli_comment(self):
        assert self._signals("/?name=admin'--")["sqli_hint"] is True

    def test_xss_script_tag(self):
        assert self._signals("/?q=<script>alert(1)</script>")["xss_hint"] is True

    def test_xss_encoded(self):
        assert self._signals("/?q=%3cscript%3e")["xss_hint"] is True

    def test_scanner_ua_sqlmap(self):
        assert self._signals("/", ua="sqlmap/1.7")["scanner_signature"] is True

    def test_scanner_ua_nikto(self):
        assert self._signals("/", ua="Mozilla/5.0 (Nikto/2.1)")["scanner_signature"] is True

    def test_no_signals_on_clean_request(self):
        sigs = self._signals("/index.html", ua="Mozilla/5.0")
        assert not sigs.get("path_traversal")
        assert not sigs.get("sqli_hint")
        assert not sigs.get("xss_hint")
        assert not sigs.get("scanner_signature")

    def test_multiple_signals_combined(self):
        sigs = self._signals("/?q=<script>%2e%2e/etc")
        assert sigs.get("xss_hint")
        assert sigs.get("path_traversal")


# ---------------------------------------------------------------------------
# brain/sensors.py — ingest_connector_telemetry
# ---------------------------------------------------------------------------

class TestIngestConnectorTelemetry:
    def _telemetry(self, lines, source="/var/log/access.log"):
        return {
            "hostname": "test-host",
            "collected_at": "2024-01-01T00:00:00+00:00",
            "log_entries": [
                {"source_file": source, "line": l, "collected_at": "2024-01-01T00:00:00+00:00"}
                for l in lines
            ],
        }

    def _auth_row(self, fake, asset_id=1, org_id=1):
        fake.record_asset_authorization(
            organization_id=org_id, asset_id=asset_id,
            authorized_by_user_id=1, method="engagement_letter",
            status="authorized", expires_at=None,
        )

    def test_refuses_without_authorization(self, fake):
        from brain.sensors import ingest_connector_telemetry, AuthorizationError
        with pytest.raises(AuthorizationError):
            ingest_connector_telemetry(99, 1, self._telemetry(["line 1"]))

    def test_saves_events_to_brain_events(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        lines = [
            '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.0" 200 100',
            '5.6.7.8 - - [10/Oct/2000:13:55:37 -0700] "POST /login HTTP/1.0" 302 0',
        ]
        events = ingest_connector_telemetry(1, 1, self._telemetry(lines))
        assert len(events) == 2
        assert len(fake.brain_events) == 2

    def test_event_asset_id_filled_in(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake, asset_id=5, org_id=1)
        lines = ['1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 10']
        events = ingest_connector_telemetry(5, 1, self._telemetry(lines))
        assert events[0].asset_id == 5
        assert events[0].org_id == 1

    def test_connector_io_errors_skipped(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        telemetry = {
            "hostname": "test",
            "collected_at": "2024-01-01T00:00:00+00:00",
            "log_entries": [
                {"source_file": "/bad/file.log", "error": "Permission denied"},
                {"source_file": "/good.log",
                 "line": '1.1.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 10',
                 "collected_at": "2024-01-01T00:00:00+00:00"},
            ],
        }
        events = ingest_connector_telemetry(1, 1, telemetry)
        assert len(events) == 1
        assert len(fake.brain_events) == 1

    def test_blank_lines_skipped(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        events = ingest_connector_telemetry(1, 1, self._telemetry(["", "   "]))
        assert len(events) == 0
        assert len(fake.brain_events) == 0

    def test_signals_propagated_to_brain_events(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        lines = ['1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /?q=<script>alert(1) HTTP/1.0" 200 10']
        ingest_connector_telemetry(1, 1, self._telemetry(lines))
        assert fake.brain_events[0]["signals"].get("xss_hint") is True

    def test_returns_list_of_event_objects(self, fake):
        from brain.sensors import ingest_connector_telemetry, Event
        self._auth_row(fake)
        lines = ['5.5.5.5 - - [10/Oct/2000:13:55:36 -0700] "GET /admin HTTP/1.0" 403 0']
        events = ingest_connector_telemetry(1, 1, self._telemetry(lines))
        assert len(events) == 1
        assert isinstance(events[0], Event)

    def test_empty_telemetry_returns_empty(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        events = ingest_connector_telemetry(1, 1, {"log_entries": []})
        assert events == []

    def test_json_log_lines_ingested(self, fake):
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        obj = {"time": "2024-01-01T12:00:00+00:00", "method": "GET",
               "path": "/api", "status": 200, "ip": "9.9.9.9"}
        telemetry = {
            "hostname": "test", "collected_at": "2024-01-01T00:00:00+00:00",
            "log_entries": [{"source_file": "app.log",
                             "line": json.dumps(obj),
                             "collected_at": "2024-01-01T00:00:00+00:00"}],
        }
        events = ingest_connector_telemetry(1, 1, telemetry)
        assert len(events) == 1
        assert fake.brain_events[0]["method"] == "GET"

    def test_observe_mode_no_action_taken(self, fake):
        """Phase 13: ingesting events must NEVER create brain_actions."""
        from brain.sensors import ingest_connector_telemetry
        self._auth_row(fake)
        lines = [
            '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /?id=1 UNION SELECT 1 HTTP/1.0" 200 10',
        ]
        ingest_connector_telemetry(1, 1, self._telemetry(lines))
        # Events were saved, but zero actions — observe mode only
        assert len(fake.brain_events) == 1
        assert len(fake.brain_actions) == 0


# ---------------------------------------------------------------------------
# Full connector-to-ingest flow test
# ---------------------------------------------------------------------------

class TestConnectorToIngestFlow:
    def test_full_flow(self, fake):
        """Write a temp log file, run collect_telemetry, then ingest the result."""
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location(
            "connector_agent",
            pathlib.Path(__file__).parent.parent / "connector" / "agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from brain.sensors import ingest_connector_telemetry

        # Authorize the asset
        fake.record_asset_authorization(
            organization_id=1, asset_id=3,
            authorized_by_user_id=1, method="engagement_letter",
            status="authorized", expires_at=None,
        )

        # Write a temp log with 3 access lines
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write('1.1.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 100\n')
            f.write('2.2.2.2 - - [10/Oct/2000:13:55:37 -0700] "GET /?id=1 UNION SELECT HTTP/1.0" 200 10\n')
            f.write('3.3.3.3 - - [10/Oct/2000:13:55:38 -0700] "GET /../etc/passwd HTTP/1.0" 403 0\n')
            fname = f.name

        try:
            telemetry_result = mod._job_collect_telemetry({"log_files": [fname]})
        finally:
            os.unlink(fname)

        events = ingest_connector_telemetry(3, 1, telemetry_result)

        assert len(events) == 3
        assert len(fake.brain_events) == 3

        # Attack signals should be detected
        sigs = [e.signals for e in events]
        assert any(s.get("sqli_hint") for s in sigs)
        assert any(s.get("path_traversal") for s in sigs)

        # No actions — observe mode
        assert len(fake.brain_actions) == 0
