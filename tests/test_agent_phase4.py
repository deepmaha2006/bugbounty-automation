"""
Phase 4 tests — proper agents for Web Application Security scanners.

Verifies:
  - All 7 new proper agents are in AGENT_MAP (not LegacyAdapter)
  - Manifest fields: key, name, category, intensity, target_kinds
  - Payload sets declared match payload files that can actually load them
  - Registry invariant still holds: AGENT_MAP.keys() == SCANNER_MAP.keys()
  - All agents can_run after preflight (no tools required)

All hermetic — no network, no Postgres, no Tk display.
"""

import pytest

from agents.registry import AGENT_MAP, build_registry
from agents._legacy_adapter import LegacyAdapter
from agents.base import ScanAgent
from agents.toolchain import preflight
from config.settings import SCANNER_MAP


# ---------------------------------------------------------------------------
# Expected proper agents (Phase 1 + Phase 4)
# ---------------------------------------------------------------------------

PROPER_AGENTS = {
    "xss", "sqli", "csrf", "ssrf", "rce",
    "file_upload", "open_redirect", "clickjack",
}


class TestPhase4Registry:
    def test_all_proper_agents_present(self):
        for key in PROPER_AGENTS:
            assert key in AGENT_MAP, f"Missing agent: {key}"

    def test_proper_agents_are_not_legacy_adapters(self):
        for key in PROPER_AGENTS:
            agent = AGENT_MAP[key]
            assert not isinstance(agent, LegacyAdapter), \
                f"{key} should be a proper ScanAgent, not LegacyAdapter"

    def test_registry_key_invariant_preserved(self):
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())

    def test_registry_idempotent(self):
        build_registry()
        assert set(AGENT_MAP.keys()) == set(SCANNER_MAP.keys())


# ---------------------------------------------------------------------------
# Per-agent manifest checks
# ---------------------------------------------------------------------------

EXPECTED_MANIFESTS = {
    "sqli":          ("SQL Injection", "Web Application Security", "active"),
    "csrf":          ("CSRF", "Web Application Security", "active"),
    "ssrf":          ("SSRF", "Web Application Security", "active"),
    "rce":           ("RCE & Command Injection", "Web Application Security", "active"),
    "file_upload":   ("File Upload", "Web Application Security", "active"),
    "open_redirect": ("Open Redirect", "Web Application Security", "active"),
    "clickjack":     ("Clickjacking", "Web Application Security", "passive"),
}


class TestPhase4Manifests:
    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_name(self, key, expected):
        name, category, intensity = expected
        assert AGENT_MAP[key].manifest.name == name

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_category(self, key, expected):
        name, category, intensity = expected
        assert AGENT_MAP[key].manifest.category == category

    @pytest.mark.parametrize("key,expected", list(EXPECTED_MANIFESTS.items()))
    def test_manifest_intensity(self, key, expected):
        name, category, intensity = expected
        assert AGENT_MAP[key].manifest.intensity == intensity

    def test_all_proper_agents_default_field_set(self):
        for key in PROPER_AGENTS:
            m = AGENT_MAP[key].manifest
            assert isinstance(m.default, bool), f"{key}.manifest.default must be bool"

    def test_target_kinds_url_for_web_agents(self):
        for key in PROPER_AGENTS:
            m = AGENT_MAP[key].manifest
            assert "url" in m.target_kinds, f"{key} must accept 'url' targets"


# ---------------------------------------------------------------------------
# Payload bundle files
# ---------------------------------------------------------------------------

class TestPhase4PayloadBundles:
    def test_sqli_payload_bundles_load(self):
        from agents.payloads.sqli import get_payloads, BUNDLES
        for name in ("error", "boolean", "time", "union"):
            payloads = get_payloads(name)
            assert isinstance(payloads, list), f"sqli/{name} must be a list"
            assert payloads, f"sqli/{name} must be non-empty"

    def test_ssrf_payload_bundle_loads(self):
        from agents.payloads.ssrf import get_payloads
        payloads = get_payloads("internal")
        assert isinstance(payloads, list) and payloads

    def test_rce_payload_bundles_load(self):
        from agents.payloads.rce import get_payloads
        for name in ("cmd", "ssti"):
            payloads = get_payloads(name)
            assert isinstance(payloads, list), f"rce/{name} must be a list"
            assert payloads, f"rce/{name} must be non-empty"

    def test_open_redirect_payload_bundle_loads(self):
        from agents.payloads.open_redirect import get_payloads
        payloads = get_payloads("redirect")
        assert isinstance(payloads, list) and payloads

    def test_unknown_bundle_returns_empty_list(self):
        from agents.payloads.sqli import get_payloads
        assert get_payloads("nonexistent") == []

    def test_manifest_payload_sets_match_bundle_files(self):
        """Every payload_set declared in a manifest must load non-empty."""
        bundle_loaders = {
            "xss":          "agents.payloads.xss",
            "sqli":         "agents.payloads.sqli",
            "ssrf":         "agents.payloads.ssrf",
            "rce":          "agents.payloads.rce",
            "open_redirect":"agents.payloads.open_redirect",
        }
        import importlib
        for key, modpath in bundle_loaders.items():
            mod = importlib.import_module(modpath)
            agent_payload_sets = AGENT_MAP[key].manifest.payload_sets
            for bundle_name in agent_payload_sets:
                result = mod.get_payloads(bundle_name)
                assert result, f"{modpath}.get_payloads({bundle_name!r}) returned empty"


# ---------------------------------------------------------------------------
# Preflight — all new proper agents must be runnable (no required tools)
# ---------------------------------------------------------------------------

class TestPhase4Preflight:
    @pytest.mark.parametrize("key", sorted(PROPER_AGENTS))
    def test_agent_can_run(self, key):
        report = preflight(AGENT_MAP[key])
        assert report.can_run, \
            f"{key} preflight reports not-ready; missing={report.missing}"

    def test_no_new_agent_has_missing_required_tools(self):
        not_ready = [
            k for k in PROPER_AGENTS
            if not preflight(AGENT_MAP[k]).can_run
        ]
        assert not_ready == []
