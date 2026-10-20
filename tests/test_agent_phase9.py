"""
Phase 9 tests — proper agents for Network, Cloud & Recon scanners.

Verifies:
  - All 4 new proper agents are in AGENT_MAP (not LegacyAdapter)
  - Manifest fields: key, name, category, intensity, target_kinds, default
  - recon declares 3 optional tool requirements (nmap, whatweb, dnsrecon)
  - ddos has default=False (excluded from full preset)
  - Optional tools do not block can_run
  - Registry invariant preserved: AGENT_MAP.keys() == SCANNER_MAP.keys()
  - run_checks registration

All hermetic — no network, no Postgres, no Tk display.
"""

import pytest

from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.base import ScanAgent
from agents.toolchain import preflight
from config.settings import SCANNER_MAP


PHASE9_AGENTS = {"info_disclosure", "cloud", "recon", "ddos"}

ALL_PROPER = {
    "xss", "sqli", "csrf", "ssrf", "rce",
    "file_upload", "open_redirect", "clickjack",
    "bac", "auth_session", "business_logic", "sec_misconfig", "sub_takeover",
} | PHASE9_AGENTS


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

class TestPhase9Registry:
    def test_all_phase9_agents_present(self):
        for key in PHASE9_AGENTS:
            assert key in AGENT_MAP, f"Missing agent: {key}"

    def test_phase9_agents_are_not_legacy_adapters(self):
        for key in PHASE9_AGENTS:
            assert not isinstance(AGENT_MAP[key], LegacyAdapter), \
                f"{key} should be a proper ScanAgent, not LegacyAdapter"

    def test_phase9_agents_are_scan_agents(self):
        for key in PHASE9_AGENTS:
            assert isinstance(AGENT_MAP[key], ScanAgent)

    def test_registry_key_invariant_preserved(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_registry_idempotent(self):
        build_registry()
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())


# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------

EXPECTED_MANIFESTS = {
    "info_disclosure": ("Information Disclosure", "Network, Cloud & Recon", "active",  True),
    "cloud":           ("Cloud Security",         "Network, Cloud & Recon", "active",  True),
    "recon":           ("Passive Reconnaissance", "Network, Cloud & Recon", "passive", True),
    "ddos":            ("DDoS Resilience",        "Network, Cloud & Recon", "active",  False),
}


class TestPhase9Manifests:
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

    def test_ddos_is_not_default(self):
        assert AGENT_MAP["ddos"].manifest.default is False

    def test_all_phase9_accept_url(self):
        for key in PHASE9_AGENTS:
            assert "url" in AGENT_MAP[key].manifest.target_kinds

    def test_recon_also_accepts_domain(self):
        assert "domain" in AGENT_MAP["recon"].manifest.target_kinds


# ---------------------------------------------------------------------------
# Tool requirements for recon
# ---------------------------------------------------------------------------

class TestPhase9ToolRequirements:
    def test_recon_declares_nmap(self):
        names = {r.name for r in AGENT_MAP["recon"].manifest.tools}
        assert "nmap" in names

    def test_recon_declares_whatweb(self):
        names = {r.name for r in AGENT_MAP["recon"].manifest.tools}
        assert "whatweb" in names

    def test_recon_declares_dnsrecon(self):
        names = {r.name for r in AGENT_MAP["recon"].manifest.tools}
        assert "dnsrecon" in names

    def test_recon_all_tools_optional(self):
        for req in AGENT_MAP["recon"].manifest.tools:
            assert req.optional is True, f"recon.{req.name} must be optional"

    def test_recon_nmap_has_apt_install_recipe(self):
        for req in AGENT_MAP["recon"].manifest.tools:
            if req.name == "nmap":
                assert "apt" in req.install_dict()

    def test_info_disclosure_has_no_tools(self):
        assert len(AGENT_MAP["info_disclosure"].manifest.tools) == 0

    def test_cloud_has_no_tools(self):
        assert len(AGENT_MAP["cloud"].manifest.tools) == 0

    def test_ddos_has_no_tools(self):
        assert len(AGENT_MAP["ddos"].manifest.tools) == 0


# ---------------------------------------------------------------------------
# Preflight: all can_run=True
# ---------------------------------------------------------------------------

class TestPhase9Preflight:
    def test_all_phase9_agents_can_run(self):
        for key in PHASE9_AGENTS:
            report = preflight(AGENT_MAP[key])
            assert report.can_run is True, \
                f"{key} preflight can_run=False (missing: {report.missing})"

    def test_recon_optional_tools_land_in_optional_missing_not_missing(self):
        report = preflight(AGENT_MAP["recon"])
        assert report.missing == [], f"recon has required tools missing: {report.missing}"


# ---------------------------------------------------------------------------
# Phase 1 legacy-adapter list update check
# ---------------------------------------------------------------------------

class TestPhase9LegacyAdaptersUpdated:
    def test_phase9_keys_not_legacy_adapters(self):
        for key in PHASE9_AGENTS:
            assert not isinstance(AGENT_MAP[key], LegacyAdapter), \
                f"{key} is still a LegacyAdapter after Phase 9"


# ---------------------------------------------------------------------------
# run_checks registration
# ---------------------------------------------------------------------------

class TestPhase9RunChecks:
    def test_new_modules_in_agent_modules_list(self):
        import run_checks
        for mod in (
            "agents.info_disclosure_agent", "agents.cloud_agent",
            "agents.recon_agent", "agents.ddos_agent",
        ):
            assert mod in run_checks.AGENT_MODULES, f"{mod} missing from AGENT_MODULES"
