"""
Phase 1 agent architecture tests.

Verifies:
- AGENT_MAP keys exactly match SCANNER_MAP keys (back-compat invariant)
- XSSAgent is a proper ScanAgent (not a LegacyAdapter)
- XSSAgent manifest correctness
- All agents pass preflight() without crashing (returns a ToolReport)
- LegacyAdapter preflight always reports can_run == True
- toolchain.preflight_all returns one ToolReport per agent
- ToolReport.can_run reflects missing vs. present correctly
- AgentContext and base dataclasses are importable and usable

All tests are hermetic — no network, no external tools, no Postgres.
"""

import threading
from pathlib import Path

import pytest

from agents.base import (
    AgentContext,
    AgentManifest,
    ScanAgent,
    ToolReport,
    ToolRequirement,
    _tool_present,
)
from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.xss_agent import XSSAgent
import agents.toolchain as toolchain
from config.settings import SCANNER_MAP
from config.scope import ScopeConfig


# ---------------------------------------------------------------------------
# Registry invariants
# ---------------------------------------------------------------------------

class TestRegistryKeys:
    def test_agent_map_keys_equal_scanner_map_keys(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_all_values_are_scan_agents(self):
        for key, agent in AGENT_MAP.items():
            assert isinstance(agent, ScanAgent), f"{key} is not a ScanAgent"

    def test_xss_is_proper_agent_not_legacy(self):
        assert isinstance(AGENT_MAP["xss"], XSSAgent)
        assert not isinstance(AGENT_MAP["xss"], LegacyAdapter)

    def test_legacy_keys_are_legacy_adapters(self):
        # Phase 1 + Phase 4 + Phase 8 proper agents are excluded;
        # everything else must still be a LegacyAdapter.
        proper = {
            "xss", "sqli", "csrf", "ssrf", "rce",
            "file_upload", "open_redirect", "clickjack",
            "bac", "auth_session", "business_logic", "sec_misconfig", "sub_takeover",
            "info_disclosure", "cloud", "recon", "ddos",
            "api", "proto_pollution", "xml", "websocket",
            "llm", "mobile", "cache", "smuggling",
            "nuclei", "nmap", "sqlmap",
        }
        for key, agent in AGENT_MAP.items():
            if key not in proper:
                assert isinstance(agent, LegacyAdapter), (
                    f"{key} should be a LegacyAdapter but is {type(agent).__name__}"
                )

    def test_rebuild_registry_is_idempotent(self):
        before = set(AGENT_MAP.keys())
        build_registry()
        after = set(AGENT_MAP.keys())
        assert before == after


# ---------------------------------------------------------------------------
# XSSAgent manifest
# ---------------------------------------------------------------------------

class TestXSSAgentManifest:
    def setup_method(self):
        self.agent = XSSAgent()

    def test_key(self):
        assert self.agent.manifest.key == "xss"

    def test_name_non_empty(self):
        assert self.agent.manifest.name

    def test_category_non_empty(self):
        assert self.agent.manifest.category

    def test_url_in_target_kinds(self):
        assert "url" in self.agent.manifest.target_kinds

    def test_default_true(self):
        assert self.agent.manifest.default is True

    def test_payload_sets_declared(self):
        assert len(self.agent.manifest.payload_sets) > 0

    def test_no_external_tools_required(self):
        assert len(self.agent.manifest.tools) == 0


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

class TestPreflight:
    def test_xss_preflight_can_run(self):
        report = AGENT_MAP["xss"].preflight()
        assert isinstance(report, ToolReport)
        assert report.can_run is True

    def test_legacy_adapter_preflight_always_passes(self):
        for key, agent in AGENT_MAP.items():
            if isinstance(agent, LegacyAdapter):
                report = agent.preflight()
                assert report.can_run is True, (
                    f"LegacyAdapter for '{key}' should always pass preflight"
                )

    def test_preflight_all_returns_all_keys(self):
        agents = list(AGENT_MAP.values())
        reports = toolchain.preflight_all(agents)
        assert set(reports.keys()) == set(AGENT_MAP.keys())

    def test_preflight_all_values_are_tool_reports(self):
        reports = toolchain.preflight_all(list(AGENT_MAP.values()))
        for key, rep in reports.items():
            assert isinstance(rep, ToolReport), f"Expected ToolReport for {key}"


# ---------------------------------------------------------------------------
# ToolReport logic
# ---------------------------------------------------------------------------

class TestToolReport:
    def test_no_missing_can_run(self):
        r = ToolReport(agent_key="test", present=["a"], missing=[], optional_missing=[])
        assert r.can_run is True

    def test_missing_required_cannot_run(self):
        r = ToolReport(agent_key="test", present=[], missing=["b"], optional_missing=[])
        assert r.can_run is False

    def test_optional_missing_still_can_run(self):
        r = ToolReport(agent_key="test", present=[], missing=[], optional_missing=["c"])
        assert r.can_run is True


# ---------------------------------------------------------------------------
# ToolRequirement preflight helper
# ---------------------------------------------------------------------------

class TestToolPresent:
    def test_empty_check_cmd_is_present(self):
        # No binary to check → tool counts as always available.
        assert _tool_present(()) is True
        assert _tool_present([]) is True

    def test_nonexistent_binary_is_absent(self):
        assert _tool_present(("__nonexistent_binary_xyz__",)) is False

    def test_python_binary_is_present(self):
        import sys
        assert _tool_present((sys.executable, "--version")) is True


# ---------------------------------------------------------------------------
# LegacyAdapter manifest mirrors SCANNER_META
# ---------------------------------------------------------------------------

class TestLegacyAdapterManifest:
    def test_manifest_key_matches_registry_key(self):
        for key, agent in AGENT_MAP.items():
            assert agent.manifest.key == key

    def test_legacy_manifest_has_name(self):
        for key, agent in AGENT_MAP.items():
            if isinstance(agent, LegacyAdapter):
                assert agent.manifest.name, f"LegacyAdapter for '{key}' has no name"


# ---------------------------------------------------------------------------
# AgentContext can be constructed
# ---------------------------------------------------------------------------

class TestAgentContext:
    def test_can_construct(self):
        scope = ScopeConfig()
        ctx = AgentContext(
            target="https://example.com",
            scope=scope,
            stop=threading.Event(),
            rate_limiter=None,
            http_client=None,
            emit=lambda *a, **kw: None,
            workdir=Path("/tmp"),
        )
        assert ctx.target == "https://example.com"
        assert ctx.discovered_targets == []
        assert ctx.discovery_summary == {}
