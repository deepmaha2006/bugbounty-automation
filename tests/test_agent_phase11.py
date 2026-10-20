"""
Phase 11 tests — dedicated Kali tool agents (nuclei, nmap, sqlmap).

These are the first agents with REQUIRED (non-optional) ToolRequirements.
In CI (sandbox), nuclei/nmap/sqlmap are absent, so preflight.can_run=False
for all three — exercising the blocked-agent path in AgentSupervisor for the
first time with real tool gates.

Verifies:
  - All 3 new agents are in AGENT_MAP as proper ScanAgents (not LegacyAdapter)
  - AGENT_MAP.keys() == SCANNER_MAP.keys() invariant holds (now 28 keys)
  - Manifest fields: key, name, category='Kali Power Tools', intensity='active',
    default=False
  - Each agent declares exactly 1 required (non-optional) ToolRequirement
  - ToolRequirement.optional is False for every tool in these agents
  - preflight returns a ToolReport with can_run determined by tool presence
  - run_checks registration for all 3 new modules
  - SCANNER_MAP contains the 3 new keys ('nuclei', 'nmap', 'sqlmap')

All hermetic — no network, no Postgres, no Tk display.
"""

import pytest

from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.base import ScanAgent, ToolReport
from agents.toolchain import preflight
from config.settings import SCANNER_MAP


PHASE11_AGENTS = {"nuclei", "nmap", "sqlmap"}


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

class TestPhase11Registry:
    def test_all_phase11_agents_present(self):
        for key in PHASE11_AGENTS:
            assert key in AGENT_MAP, f"Missing agent: {key}"

    def test_phase11_agents_are_not_legacy_adapters(self):
        for key in PHASE11_AGENTS:
            assert not isinstance(AGENT_MAP[key], LegacyAdapter), \
                f"{key} should be a proper ScanAgent, not LegacyAdapter"

    def test_phase11_agents_are_scan_agents(self):
        for key in PHASE11_AGENTS:
            assert isinstance(AGENT_MAP[key], ScanAgent)

    def test_registry_key_invariant_preserved(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_total_agent_count_is_28(self):
        assert len(AGENT_MAP) == 28, \
            f"Expected 28 agents (25 Phase-1-10 + 3 Phase-11), got {len(AGENT_MAP)}"

    def test_registry_idempotent(self):
        build_registry()
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())


# ---------------------------------------------------------------------------
# SCANNER_MAP contains the new keys
# ---------------------------------------------------------------------------

class TestPhase11ScannerMap:
    def test_nuclei_in_scanner_map(self):
        assert "nuclei" in SCANNER_MAP

    def test_nmap_in_scanner_map(self):
        assert "nmap" in SCANNER_MAP

    def test_sqlmap_in_scanner_map(self):
        assert "sqlmap" in SCANNER_MAP


# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------

EXPECTED_MANIFESTS = {
    "nuclei": ("Nuclei",         "Kali Power Tools", "active", False),
    "nmap":   ("Nmap Port Scan", "Kali Power Tools", "active", False),
    "sqlmap": ("sqlmap",         "Kali Power Tools", "active", False),
}


class TestPhase11Manifests:
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

    def test_all_phase11_are_not_default(self):
        for key in PHASE11_AGENTS:
            assert AGENT_MAP[key].manifest.default is False, \
                f"{key} should default=False (requires explicit opt-in)"

    def test_all_phase11_accept_url(self):
        for key in PHASE11_AGENTS:
            assert "url" in AGENT_MAP[key].manifest.target_kinds

    def test_nmap_also_accepts_domain(self):
        assert "domain" in AGENT_MAP["nmap"].manifest.target_kinds


# ---------------------------------------------------------------------------
# Required (non-optional) ToolRequirements — first in the codebase
# ---------------------------------------------------------------------------

class TestPhase11ToolRequirements:
    def test_each_agent_has_exactly_one_tool(self):
        for key in PHASE11_AGENTS:
            tools = AGENT_MAP[key].manifest.tools
            assert len(tools) == 1, \
                f"{key} should declare exactly 1 ToolRequirement, got {len(tools)}"

    def test_all_tools_are_required_not_optional(self):
        for key in PHASE11_AGENTS:
            for req in AGENT_MAP[key].manifest.tools:
                assert req.optional is False, \
                    f"{key}.{req.name} optional=True but should be False (required)"

    def test_tool_names_match_keys(self):
        expected = {"nuclei": "nuclei", "nmap": "nmap", "sqlmap": "sqlmap"}
        for key, tool_name in expected.items():
            req = AGENT_MAP[key].manifest.tools[0]
            assert req.name == tool_name

    def test_all_tools_have_install_instructions(self):
        for key in PHASE11_AGENTS:
            req = AGENT_MAP[key].manifest.tools[0]
            assert len(req.install) > 0, \
                f"{key}.{req.name} has no install instructions"

    def test_nuclei_install_uses_go(self):
        req = AGENT_MAP["nuclei"].manifest.tools[0]
        pms = [pm for pm, _ in req.install]
        assert "go" in pms, "nuclei should install via 'go install'"

    def test_nmap_install_uses_apt(self):
        req = AGENT_MAP["nmap"].manifest.tools[0]
        pms = [pm for pm, _ in req.install]
        assert "apt" in pms, "nmap should install via apt"

    def test_sqlmap_install_has_apt_and_pip(self):
        req = AGENT_MAP["sqlmap"].manifest.tools[0]
        pms = [pm for pm, _ in req.install]
        assert "apt" in pms and "pip" in pms, \
            "sqlmap should offer both apt and pip install paths"


# ---------------------------------------------------------------------------
# Preflight: can_run reflects real tool presence
# ---------------------------------------------------------------------------

class TestPhase11Preflight:
    def test_preflight_returns_tool_report(self):
        for key in PHASE11_AGENTS:
            report = preflight(AGENT_MAP[key])
            assert isinstance(report, ToolReport), \
                f"{key} preflight should return ToolReport"

    def test_preflight_missing_tools_listed_when_absent(self):
        """In CI the kali tools are absent; preflight.missing should contain them."""
        import shutil
        for key in PHASE11_AGENTS:
            req = AGENT_MAP[key].manifest.tools[0]
            tool_on_path = shutil.which(req.name) is not None
            report = preflight(AGENT_MAP[key])
            if not tool_on_path:
                assert report.can_run is False, \
                    f"{key} tool absent but can_run=True"
                assert req.name in report.missing, \
                    f"{key} tool absent but not in report.missing"

    def test_preflight_can_run_when_tool_present(self):
        """If a tool happens to be installed, can_run must be True."""
        import shutil
        for key in PHASE11_AGENTS:
            req = AGENT_MAP[key].manifest.tools[0]
            if shutil.which(req.name) is not None:
                report = preflight(AGENT_MAP[key])
                assert report.can_run is True, \
                    f"{key} tool present but can_run=False"


# ---------------------------------------------------------------------------
# run_checks registration
# ---------------------------------------------------------------------------

class TestPhase11RunChecks:
    def test_new_modules_in_agent_modules_list(self):
        import run_checks
        for mod in ("agents.nuclei_agent", "agents.nmap_agent", "agents.sqlmap_agent"):
            assert mod in run_checks.AGENT_MODULES, f"{mod} missing from AGENT_MODULES"

    def test_kali_scanners_module_importable(self):
        import scanners.kali_scanners  # noqa: F401

    def test_scanner_stubs_instantiable(self):
        from scanners.kali_scanners import NucleiScanner, NmapScanner, SqlmapScanner
        NucleiScanner()
        NmapScanner()
        SqlmapScanner()
