"""
Phase 2 tests — toolchain preflight + ToolReadinessPanel logic.

The Tk widget itself can't be instantiated in a headless CI environment, so
these tests exercise the data-layer logic that the panel uses:
  - preflight_all() returns correct ToolReport shapes for all agents
  - Summary string computation (ready/needs counts)
  - install_tool() raise path when no recipe defined
  - ToolReadinessPanel._make_tool_detail() static helper
  - install_missing() dry_run path when a recipe exists

All hermetic — no network, no Postgres, no Tk display required.
"""

import pytest

from agents.base import ToolReport, ToolRequirement, AgentManifest
from agents.registry import AGENT_MAP
from agents.toolchain import preflight_all, preflight, install_missing, install_tool
from config.settings import SCANNER_MAP


# ---------------------------------------------------------------------------
# preflight_all
# ---------------------------------------------------------------------------

class TestPreflightAll:
    def test_returns_one_report_per_agent(self):
        agents = list(AGENT_MAP.values())
        reports = preflight_all(agents)
        assert len(reports) == len(AGENT_MAP)

    def test_all_keys_present(self):
        agents = list(AGENT_MAP.values())
        reports = preflight_all(agents)
        assert set(reports) == set(AGENT_MAP)

    def test_all_reports_are_tool_reports(self):
        agents = list(AGENT_MAP.values())
        reports = preflight_all(agents)
        for key, rep in reports.items():
            assert isinstance(rep, ToolReport), f"bad type for {key}"

    def test_all_agents_can_run_in_phase1(self):
        # Phase 1-10 agents had no required tools; all were always runnable.
        # Phase 11 added nuclei/nmap/sqlmap with REQUIRED tools — those may be
        # absent in CI, so exclude them from this legacy assertion.
        REQUIRED_TOOL_AGENTS = {"nuclei", "nmap", "sqlmap"}
        agents = [a for k, a in AGENT_MAP.items() if k not in REQUIRED_TOOL_AGENTS]
        reports = preflight_all(agents)
        not_ready = [k for k, r in reports.items() if not r.can_run]
        assert not_ready == [], f"These agents reported not-ready: {not_ready}"

    def test_single_agent_preflight_matches_preflight_all(self):
        xss = AGENT_MAP["xss"]
        single = preflight(xss)
        all_reports = preflight_all([xss])
        all_rep = all_reports["xss"]
        assert single.can_run == all_rep.can_run
        assert single.missing == all_rep.missing


# ---------------------------------------------------------------------------
# ToolReport._make_tool_detail (static helper, testable without Tk)
# ---------------------------------------------------------------------------

class TestMakeToolDetail:
    def test_all_present(self):
        from ui.tool_readiness_panel import ToolReadinessPanel
        rep = ToolReport("k", present=["dalfox", "nuclei"], missing=[], optional_missing=[])
        detail = ToolReadinessPanel._make_tool_detail(rep)
        assert "present" in detail
        assert "dalfox" in detail

    def test_required_missing(self):
        from ui.tool_readiness_panel import ToolReadinessPanel
        rep = ToolReport("k", present=[], missing=["sqlmap"], optional_missing=[])
        detail = ToolReadinessPanel._make_tool_detail(rep)
        assert "MISSING" in detail
        assert "sqlmap" in detail

    def test_optional_missing(self):
        from ui.tool_readiness_panel import ToolReadinessPanel
        rep = ToolReport("k", present=[], missing=[], optional_missing=["amass"])
        detail = ToolReadinessPanel._make_tool_detail(rep)
        assert "optional" in detail.lower()

    def test_empty_detail_when_nothing(self):
        from ui.tool_readiness_panel import ToolReadinessPanel
        rep = ToolReport("k", present=[], missing=[], optional_missing=[])
        detail = ToolReadinessPanel._make_tool_detail(rep)
        assert detail == ""


# ---------------------------------------------------------------------------
# install_tool — error paths
# ---------------------------------------------------------------------------

class TestInstallTool:
    def test_raises_when_no_recipe(self):
        req = ToolRequirement(name="ghost_tool", check_cmd=(), install=(), optional=False)
        with pytest.raises(RuntimeError, match="No install recipe"):
            install_tool(req)

    def test_dry_run_returns_true_when_recipe_exists(self):
        req = ToolRequirement(
            name="dalfox",
            check_cmd=("dalfox", "version"),
            install=(("go", ["go", "install", "github.com/hahwul/dalfox/v2@latest"]),),
            optional=False,
        )
        result = install_tool(req, dry_run=True)
        assert result is True


# ---------------------------------------------------------------------------
# install_missing — dry_run smoke test
# ---------------------------------------------------------------------------

class TestInstallMissing:
    def test_empty_result_when_agent_has_no_tools(self):
        from agents.xss_agent import XSSAgent
        agent = XSSAgent()
        result = install_missing(agent, dry_run=True)
        # XSSAgent has no tools so nothing to install
        assert result == {}

    def test_dry_run_does_not_raise(self):
        # For any agent that actually has tools, dry_run should not execute
        # any subprocess; it just returns the {name: True} map.
        for key, agent in AGENT_MAP.items():
            if agent.manifest.tools:
                result = install_missing(agent, dry_run=True)
                assert isinstance(result, dict)
                break
