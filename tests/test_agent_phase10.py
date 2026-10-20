"""
Phase 10 tests — proper agents for Advanced & Modern Threats scanners.

This completes the agent promotion work: every scanner in SCANNER_MAP is now
a proper ScanAgent; no LegacyAdapters remain.

Verifies:
  - All 8 new proper agents are in AGENT_MAP (not LegacyAdapter)
  - Manifest fields: key, name, category, intensity, default
  - smuggling has default=False; all others default=True
  - mobile has intensity='passive'; all others 'active'
  - Zero tool requirements (all pure-Python scanners)
  - Registry invariant preserved: AGENT_MAP.keys() == SCANNER_MAP.keys()
  - No LegacyAdapters remain anywhere in AGENT_MAP
  - run_checks registration

All hermetic — no network, no Postgres, no Tk display.
"""

import pytest

from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.base import ScanAgent
from agents.toolchain import preflight
from config.settings import SCANNER_MAP


PHASE10_AGENTS = {
    "api", "proto_pollution", "xml", "websocket",
    "llm", "mobile", "cache", "smuggling",
}


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

class TestPhase10Registry:
    def test_all_phase10_agents_present(self):
        for key in PHASE10_AGENTS:
            assert key in AGENT_MAP, f"Missing agent: {key}"

    def test_phase10_agents_are_not_legacy_adapters(self):
        for key in PHASE10_AGENTS:
            assert not isinstance(AGENT_MAP[key], LegacyAdapter), \
                f"{key} should be a proper ScanAgent, not LegacyAdapter"

    def test_phase10_agents_are_scan_agents(self):
        for key in PHASE10_AGENTS:
            assert isinstance(AGENT_MAP[key], ScanAgent)

    def test_registry_key_invariant_preserved(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_registry_idempotent(self):
        build_registry()
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_no_legacy_adapters_remain(self):
        """Phase 10 completes the promotion — zero LegacyAdapters should remain."""
        for key, agent in AGENT_MAP.items():
            assert not isinstance(agent, LegacyAdapter), \
                f"{key} is still a LegacyAdapter after Phase 10"


# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------

EXPECTED_MANIFESTS = {
    "api":            ("API Security",               "Advanced & Modern Threats", "active",  True),
    "proto_pollution":("Prototype Pollution",        "Advanced & Modern Threats", "active",  True),
    "xml":            ("XML / XXE",                  "Advanced & Modern Threats", "active",  True),
    "websocket":      ("WebSocket Security",         "Advanced & Modern Threats", "active",  True),
    "llm":            ("AI / LLM Security",          "Advanced & Modern Threats", "active",  True),
    "mobile":         ("Exposed Secrets & Endpoints","Advanced & Modern Threats", "passive", True),
    "cache":          ("Web Cache Poisoning",        "Advanced & Modern Threats", "active",  True),
    "smuggling":      ("Request Smuggling",          "Advanced & Modern Threats", "active",  False),
}


class TestPhase10Manifests:
    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_name(self, key, expected):
        assert AGENT_MAP[key].manifest.name == expected[0]

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_category(self, key, expected):
        assert AGENT_MAP[key].manifest.category == expected[1]

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_intensity(self, key, expected):
        assert AGENT_MAP[key].manifest.intensity == expected[2]

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_default(self, key, expected):
        assert AGENT_MAP[key].manifest.default is expected[3]

    def test_smuggling_is_not_default(self):
        assert AGENT_MAP["smuggling"].manifest.default is False

    def test_mobile_is_passive(self):
        assert AGENT_MAP["mobile"].manifest.intensity == "passive"

    def test_all_phase10_accept_url(self):
        for key in PHASE10_AGENTS:
            assert "url" in AGENT_MAP[key].manifest.target_kinds


# ---------------------------------------------------------------------------
# No tool requirements on any Phase 10 agent
# ---------------------------------------------------------------------------

class TestPhase10ToolRequirements:
    def test_all_phase10_agents_have_no_tools(self):
        for key in PHASE10_AGENTS:
            assert len(AGENT_MAP[key].manifest.tools) == 0, \
                f"{key} should have no tool requirements"


# ---------------------------------------------------------------------------
# Preflight: all can_run=True
# ---------------------------------------------------------------------------

class TestPhase10Preflight:
    def test_all_phase10_agents_can_run(self):
        for key in PHASE10_AGENTS:
            report = preflight(AGENT_MAP[key])
            assert report.can_run is True, \
                f"{key} preflight can_run=False (missing: {report.missing})"


# ---------------------------------------------------------------------------
# Full registry completeness — every SCANNER_MAP key is a proper ScanAgent
# ---------------------------------------------------------------------------

class TestFullRegistryCompleteness:
    def test_every_scanner_map_key_has_proper_agent(self):
        """Promotion is complete: SCANNER_MAP ↔ AGENT_MAP, zero LegacyAdapters."""
        for key in SCANNER_MAP:
            agent = AGENT_MAP.get(key)
            assert agent is not None, f"{key} missing from AGENT_MAP"
            assert not isinstance(agent, LegacyAdapter), \
                f"{key} is still a LegacyAdapter"
            assert isinstance(agent, ScanAgent), \
                f"{key} is not a ScanAgent"

    def test_total_proper_agent_count(self):
        """All scanner keys (len(SCANNER_MAP)) should now be proper agents."""
        proper = [k for k, a in AGENT_MAP.items()
                  if not isinstance(a, LegacyAdapter)]
        assert len(proper) == len(SCANNER_MAP), \
            f"Expected {len(SCANNER_MAP)} proper agents, got {len(proper)}"


# ---------------------------------------------------------------------------
# run_checks registration
# ---------------------------------------------------------------------------

class TestPhase10RunChecks:
    def test_new_modules_in_agent_modules_list(self):
        import run_checks
        for mod in (
            "agents.api_agent", "agents.proto_pollution_agent", "agents.xml_agent",
            "agents.websocket_agent", "agents.llm_agent", "agents.mobile_agent",
            "agents.cache_agent", "agents.smuggling_agent",
        ):
            assert mod in run_checks.AGENT_MODULES, f"{mod} missing from AGENT_MODULES"
