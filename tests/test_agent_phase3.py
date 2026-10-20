"""
Phase 3 tests — AgentSupervisor orchestration.

All hermetic: no network, no Postgres, no Tk display required.

Covers:
  - UnsafeScanTargetError raised on loopback target
  - Preflight-based skip when an agent has missing required tools
  - Successful agent run → ScanResult aggregated into ScanReport
  - Legacy event types emitted (scanners_queued, scanner_start, scanner_done, progress)
  - Agent lifecycle events emitted (queued, preflight, running, done/skipped)
  - stop_event halts execution early
  - Empty-report path when no agents survive preflight
"""

import threading
import pytest

from agents.base import (
    AgentManifest, AgentContext, ScanAgent, ToolReport, ToolRequirement,
)
from agents.supervisor import AgentSupervisor
from core.models import Finding, ScanReport
from utils.ssrf_guard import UnsafeScanTargetError


# ---------------------------------------------------------------------------
# Minimal stub agents
# ---------------------------------------------------------------------------

class _OkAgent(ScanAgent):
    manifest = AgentManifest(
        key="stub_ok",
        name="Stub OK",
        category="Test",
        target_kinds=frozenset({"url"}),
        tools=(),
        payload_sets=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext):
        return [
            Finding(severity="Low", type="Test", description="stub",
                    scan_type="stub_ok"),
        ]


class _SkipAgent(ScanAgent):
    """Agent whose preflight always reports a required tool as missing."""

    manifest = AgentManifest(
        key="stub_skip",
        name="Stub Skip",
        category="Test",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(
                name="ghost_tool_xyz",
                check_cmd=("ghost_tool_xyz", "--version"),
                install=(),
                optional=False,
            ),
        ),
        payload_sets=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext):
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_supervisor(target, agents_map, stop=None, keys=None):
    """Build a supervisor with a fake AGENT_MAP injected via monkeypatching."""
    from agents import supervisor as sv_mod
    import agents.registry as reg_mod
    import agents.toolchain as tc_mod

    if stop is None:
        stop = threading.Event()
    if keys is None:
        keys = list(agents_map.keys())

    events = []

    def emit(evt):
        events.append(evt)

    sup = AgentSupervisor(
        target=target,
        scope=None,
        selected_keys=keys,
        emit=emit,
        stop=stop,
    )
    return sup, events


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

class TestSupervisorSSRFGuard:
    def test_loopback_raises(self, monkeypatch):
        # Patch AGENT_MAP so supervisor won't complain about missing keys
        import agents.registry as reg
        monkeypatch.setattr(reg, "AGENT_MAP", {})

        sup, events = _make_supervisor("http://127.0.0.1/", {})
        with pytest.raises(UnsafeScanTargetError):
            sup.run()

    def test_localhost_raises(self, monkeypatch):
        import agents.registry as reg
        monkeypatch.setattr(reg, "AGENT_MAP", {})

        sup, events = _make_supervisor("http://localhost/", {})
        with pytest.raises(UnsafeScanTargetError):
            sup.run()


# ---------------------------------------------------------------------------
# Preflight skip path
# ---------------------------------------------------------------------------

class TestSupervisorPreflight:
    def test_agent_with_missing_required_tool_is_skipped(self, monkeypatch):
        skip_agent = _SkipAgent()
        import agents.registry as reg
        monkeypatch.setattr(reg, "AGENT_MAP", {"stub_skip": skip_agent})

        # Mock discovery so we don't need a real network
        import agents.supervisor as sv_mod
        def _fake_discovery(self_sup):
            return {"urls": ["https://example.com"]}
        monkeypatch.setattr(sv_mod.AgentSupervisor, "_run_discovery", _fake_discovery)

        # Bypass SSRF guard for this test
        monkeypatch.setattr(sv_mod, "assert_safe_scan_target", lambda url: None)

        sup, events = _make_supervisor("https://example.com", {"stub_skip": skip_agent})
        report = sup.run()

        # No ScanResults because the only agent was skipped
        assert report.total_findings == 0

        lifecycle_events = [e for e in events if e[0] == "agent_lifecycle"]
        skipped = [e for e in lifecycle_events if e[2] == "skipped"]
        assert len(skipped) == 1
        assert "stub_skip" == skipped[0][1]

    def test_empty_report_when_no_agents_registered(self, monkeypatch):
        import agents.registry as reg
        import agents.supervisor as sv_mod
        monkeypatch.setattr(reg, "AGENT_MAP", {})
        monkeypatch.setattr(sv_mod, "assert_safe_scan_target", lambda url: None)

        sup, events = _make_supervisor("https://example.com", {}, keys=[])
        report = sup.run()
        assert isinstance(report, ScanReport)
        assert report.total_findings == 0


# ---------------------------------------------------------------------------
# Successful run
# ---------------------------------------------------------------------------

class TestSupervisorSuccessPath:
    def _run_with_ok_agent(self, monkeypatch):
        ok_agent = _OkAgent()
        import agents.registry as reg
        import agents.supervisor as sv_mod
        monkeypatch.setattr(reg, "AGENT_MAP", {"stub_ok": ok_agent})
        monkeypatch.setattr(sv_mod, "assert_safe_scan_target", lambda url: None)

        def _fake_discovery(self_sup):
            return {"urls": ["https://example.com"]}
        monkeypatch.setattr(sv_mod.AgentSupervisor, "_run_discovery", _fake_discovery)

        sup, events = _make_supervisor("https://example.com", {"stub_ok": ok_agent})
        report = sup.run()
        return report, events

    def test_finding_aggregated_into_report(self, monkeypatch):
        report, _ = self._run_with_ok_agent(monkeypatch)
        assert report.total_findings == 1
        assert report.results[0].scanner_key == "stub_ok"

    def test_legacy_scanner_start_event_emitted(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        starts = [e for e in events if e[0] == "scanner_start"]
        assert any(e[1] == "stub_ok" for e in starts)

    def test_legacy_scanner_done_event_emitted(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        dones = [e for e in events if e[0] == "scanner_done"]
        assert any(e[1] == "stub_ok" for e in dones)
        # (key, name, count, duration)
        done = next(e for e in dones if e[1] == "stub_ok")
        assert done[3] == 1  # 1 finding

    def test_scanners_queued_event_emitted(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        queued = [e for e in events if e[0] == "scanners_queued"]
        assert queued
        keys = [pair[0] for pair in queued[0][1]]
        assert "stub_ok" in keys

    def test_progress_event_emitted(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        progress = [e for e in events if e[0] == "progress"]
        assert progress
        assert progress[-1][1] == pytest.approx(1.0)

    def test_agent_lifecycle_running_and_done(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        lc = [e for e in events if e[0] == "agent_lifecycle" and e[1] == "stub_ok"]
        phases = [e[2] for e in lc]
        assert "running" in phases
        assert "done" in phases

    def test_finding_lifecycle_event_per_finding(self, monkeypatch):
        _, events = self._run_with_ok_agent(monkeypatch)
        findings = [e for e in events if e[0] == "agent_lifecycle" and e[2] == "finding"]
        assert len(findings) == 1
        assert isinstance(findings[0][3], Finding)


# ---------------------------------------------------------------------------
# Stop event
# ---------------------------------------------------------------------------

class TestSupervisorStop:
    def test_stop_event_skips_findings(self, monkeypatch):
        ok_agent = _OkAgent()
        import agents.registry as reg
        import agents.supervisor as sv_mod
        monkeypatch.setattr(reg, "AGENT_MAP", {"stub_ok": ok_agent})
        monkeypatch.setattr(sv_mod, "assert_safe_scan_target", lambda url: None)

        def _fake_discovery(self_sup):
            return {"urls": ["https://example.com"]}
        monkeypatch.setattr(sv_mod.AgentSupervisor, "_run_discovery", _fake_discovery)

        stop = threading.Event()
        stop.set()  # pre-set

        events = []
        sup = sv_mod.AgentSupervisor(
            target="https://example.com",
            scope=None,
            selected_keys=["stub_ok"],
            emit=lambda e: events.append(e),
            stop=stop,
        )
        # ScanAborted propagates; we just want it not to hang
        from core.scan_context import ScanAborted
        with pytest.raises(ScanAborted):
            sup.run()
