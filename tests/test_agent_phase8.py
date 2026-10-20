"""
Phase 8 tests — proper agents for Access Control & Auth scanners.

Verifies:
  - All 5 new proper agents are in AGENT_MAP (not LegacyAdapter)
  - Manifest fields: key, name, category, intensity, target_kinds
  - sub_takeover and sec_misconfig declare optional tool requirements
  - Optional tools do not block can_run (preflight still returns can_run=True)
  - Registry invariant preserved: AGENT_MAP.keys() == SCANNER_MAP.keys()
  - run_checks registration: all 5 new modules in AGENT_MODULES

All hermetic — no network, no Postgres, no Tk display.
"""

import pytest

from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.base import ScanAgent
from agents.toolchain import preflight
from config.settings import SCANNER_MAP


# ---------------------------------------------------------------------------
# New proper agents in this phase
# ---------------------------------------------------------------------------

PHASE8_AGENTS = {
    "bac", "auth_session", "business_logic", "sec_misconfig", "sub_takeover",
}

PHASE8_ALL_PROPER = {
    "xss", "sqli", "csrf", "ssrf", "rce",
    "file_upload", "open_redirect", "clickjack",
} | PHASE8_AGENTS


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

class TestPhase8Registry:
    def test_all_phase8_agents_present(self):
        for key in PHASE8_AGENTS:
            assert key in AGENT_MAP, f"Missing agent: {key}"

    def test_phase8_agents_are_not_legacy_adapters(self):
        for key in PHASE8_AGENTS:
            agent = AGENT_MAP[key]
            assert not isinstance(agent, LegacyAdapter), \
                f"{key} should be a proper ScanAgent, not LegacyAdapter"

    def test_phase8_agents_are_scan_agents(self):
        for key in PHASE8_AGENTS:
            assert isinstance(AGENT_MAP[key], ScanAgent), \
                f"{key} must be a ScanAgent instance"

    def test_registry_key_invariant_preserved(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_registry_idempotent_after_phase8(self):
        build_registry()
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())


# ---------------------------------------------------------------------------
# Per-agent manifest checks
# ---------------------------------------------------------------------------

EXPECTED_MANIFESTS = {
    "bac":            ("Broken Access Control",      "Access Control & Misconfiguration", "active"),
    "auth_session":   ("Auth & Session Management",  "Authentication & Business Logic",    "active"),
    "business_logic": ("Business Logic",             "Authentication & Business Logic",    "active"),
    "sec_misconfig":  ("Security Misconfiguration",  "Access Control & Misconfiguration", "passive"),
    "sub_takeover":   ("Subdomain Takeover",         "Access Control & Misconfiguration", "passive"),
}


class TestPhase8Manifests:
    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_name(self, key, expected):
        name, _, _ = expected
        assert AGENT_MAP[key].manifest.name == name

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_category(self, key, expected):
        _, category, _ = expected
        assert AGENT_MAP[key].manifest.category == category

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_intensity(self, key, expected):
        _, _, intensity = expected
        assert AGENT_MAP[key].manifest.intensity == intensity

    def test_all_phase8_agents_have_url_target_kind(self):
        for key in PHASE8_AGENTS:
            m = AGENT_MAP[key].manifest
            assert "url" in m.target_kinds, f"{key} must accept 'url' targets"

    def test_sub_takeover_also_accepts_domain_target(self):
        m = AGENT_MAP["sub_takeover"].manifest
        assert "domain" in m.target_kinds

    def test_all_phase8_agents_default_field_is_bool(self):
        for key in PHASE8_AGENTS:
            m = AGENT_MAP[key].manifest
            assert isinstance(m.default, bool), f"{key}.manifest.default must be bool"


# ---------------------------------------------------------------------------
# Tool requirements — sec_misconfig and sub_takeover have optional tools
# ---------------------------------------------------------------------------

class TestPhase8ToolRequirements:
    def test_sec_misconfig_declares_nikto(self):
        tools = {t.name for t in AGENT_MAP["sec_misconfig"].manifest.tools}
        assert "nikto" in tools

    def test_sec_misconfig_nikto_is_optional(self):
        for req in AGENT_MAP["sec_misconfig"].manifest.tools:
            if req.name == "nikto":
                assert req.optional is True

    def test_sub_takeover_declares_subfinder(self):
        tools = {t.name for t in AGENT_MAP["sub_takeover"].manifest.tools}
        assert "subfinder" in tools

    def test_sub_takeover_declares_amass(self):
        tools = {t.name for t in AGENT_MAP["sub_takeover"].manifest.tools}
        assert "amass" in tools

    def test_sub_takeover_tools_are_optional(self):
        for req in AGENT_MAP["sub_takeover"].manifest.tools:
            assert req.optional is True, f"sub_takeover.{req.name} must be optional"

    def test_bac_has_no_tool_requirements(self):
        assert len(AGENT_MAP["bac"].manifest.tools) == 0

    def test_auth_session_has_no_tool_requirements(self):
        assert len(AGENT_MAP["auth_session"].manifest.tools) == 0

    def test_business_logic_has_no_tool_requirements(self):
        assert len(AGENT_MAP["business_logic"].manifest.tools) == 0

    def test_sec_misconfig_nikto_has_apt_install_recipe(self):
        for req in AGENT_MAP["sec_misconfig"].manifest.tools:
            if req.name == "nikto":
                install_d = req.install_dict()
                assert "apt" in install_d

    def test_sub_takeover_subfinder_has_go_install_recipe(self):
        for req in AGENT_MAP["sub_takeover"].manifest.tools:
            if req.name == "subfinder":
                install_d = req.install_dict()
                assert "go" in install_d


# ---------------------------------------------------------------------------
# Preflight: optional-only tools → can_run = True even when absent
# ---------------------------------------------------------------------------

class TestPhase8Preflight:
    def test_all_phase8_agents_can_run_after_preflight(self):
        """Agents with only optional tools must report can_run=True."""
        for key in PHASE8_AGENTS:
            report = preflight(AGENT_MAP[key])
            assert report.can_run is True, \
                f"{key} preflight reports can_run=False (missing required tools: {report.missing})"

    def test_preflight_missing_optional_tools_go_to_optional_missing(self):
        """When nikto/subfinder/amass are absent, they land in optional_missing not missing."""
        for key in ("sec_misconfig", "sub_takeover"):
            report = preflight(AGENT_MAP[key])
            assert report.missing == [], \
                f"{key}: required tools missing: {report.missing}"


# ---------------------------------------------------------------------------
# run_checks registration
# ---------------------------------------------------------------------------

class TestPhase8RunChecks:
    def test_new_agent_modules_in_agent_modules_list(self):
        import run_checks
        for mod in (
            "agents.bac_agent", "agents.auth_session_agent",
            "agents.business_logic_agent", "agents.sec_misconfig_agent",
            "agents.sub_takeover_agent",
        ):
            assert mod in run_checks.AGENT_MODULES, f"{mod} missing from AGENT_MODULES"
