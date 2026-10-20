"""
Hermetic tests for utils/corroboration.py.
All subprocess calls and tool_available checks are mocked.
"""

import sys
import os
import subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

from utils.corroboration import (
    corroborate_xss,
    corroborate_sqli,
    corroborate_misconfig,
    corroborate_with_httpx,
)


# ---------------------------------------------------------------------------
# corroborate_xss
# ---------------------------------------------------------------------------

class TestCorroborateXss:
    def test_returns_none_when_dalfox_not_installed(self):
        with patch("utils.corroboration.tool_available", return_value=False):
            result = corroborate_xss("http://target.com/search", "q")
        assert result is None

    def test_returns_confirmation_when_poc_found(self):
        mock_result = MagicMock()
        mock_result.stdout = "[POC] http://target.com/search?q=<script>alert(1)</script>\n"
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result):
            result = corroborate_xss("http://target.com/search", "q")
        assert result is not None
        assert result["reproduced"] is True
        assert result["corroborating_tool"] == "dalfox"
        assert result["method"] == "tool"
        assert "[POC]" in result["evidence"]

    def test_returns_none_when_no_poc(self):
        mock_result = MagicMock()
        mock_result.stdout = "No XSS found\n"
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result):
            result = corroborate_xss("http://target.com/search", "q")
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="dalfox", timeout=60)):
            result = corroborate_xss("http://target.com/search", "q")
        assert result is None

    def test_returns_none_on_file_not_found(self):
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run",
                   side_effect=FileNotFoundError("dalfox not found")):
            result = corroborate_xss("http://target.com/search", "q")
        assert result is None


# ---------------------------------------------------------------------------
# corroborate_sqli
# ---------------------------------------------------------------------------

class TestCorroborateSqli:
    def test_returns_none_when_sqlmap_not_installed(self):
        with patch("utils.corroboration.tool_available", return_value=False):
            result = corroborate_sqli("http://target.com/login")
        assert result is None

    def test_returns_confirmation_when_vulnerable(self):
        mock_result = MagicMock()
        mock_result.stdout = (
            "[INFO] GET parameter 'id' is vulnerable\n"
            "[INFO] sqlmap identified the following injection point(s)\n"
        )
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result), \
             patch("utils.corroboration.shutil.rmtree"):
            result = corroborate_sqli("http://target.com/login?id=1")
        assert result is not None
        assert result["reproduced"] is True
        assert result["corroborating_tool"] == "sqlmap"
        assert "is vulnerable" in result["evidence"]

    def test_returns_none_when_not_vulnerable(self):
        mock_result = MagicMock()
        mock_result.stdout = "[INFO] all tested parameters do not appear to be injectable\n"
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result), \
             patch("utils.corroboration.shutil.rmtree"):
            result = corroborate_sqli("http://target.com/login?id=1")
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="sqlmap", timeout=120)), \
             patch("utils.corroboration.shutil.rmtree"):
            result = corroborate_sqli("http://target.com/login")
        assert result is None


# ---------------------------------------------------------------------------
# corroborate_misconfig
# ---------------------------------------------------------------------------

class TestCorroborateMisconfig:
    def test_returns_empty_when_nuclei_not_installed(self):
        with patch("utils.corroboration.tool_available", return_value=False):
            result = corroborate_misconfig("http://target.com")
        assert result == []

    def test_returns_confirmation_list_from_nuclei_findings(self):
        mock_findings = [
            {
                "type": "Apache Path Traversal",
                "severity": "High",
                "evidence": "template match",
                "url": "http://target.com/",
            }
        ]
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.run_nuclei", return_value=mock_findings):
            result = corroborate_misconfig("http://target.com")
        assert len(result) == 1
        assert result[0]["corroborating_tool"] == "nuclei"
        assert result[0]["reproduced"] is True

    def test_returns_empty_when_nuclei_finds_nothing(self):
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.run_nuclei", return_value=[]):
            result = corroborate_misconfig("http://target.com")
        assert result == []


# ---------------------------------------------------------------------------
# corroborate_with_httpx
# ---------------------------------------------------------------------------

class TestCorroborateWithHttpx:
    def test_returns_none_when_httpx_not_installed(self):
        with patch("utils.corroboration.tool_available", return_value=False):
            result = corroborate_with_httpx("http://target.com")
        assert result is None

    def test_returns_confirmation_with_httpx_output(self):
        mock_result = MagicMock()
        mock_result.stdout = '{"url":"http://target.com","status_code":200}\n'
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result):
            result = corroborate_with_httpx("http://target.com")
        assert result is not None
        assert result["corroborating_tool"] == "httpx"
        assert result["reproduced"] is True

    def test_returns_none_when_no_output(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        with patch("utils.corroboration.tool_available", return_value=True), \
             patch("utils.corroboration.subprocess.run", return_value=mock_result):
            result = corroborate_with_httpx("http://target.com")
        assert result is None
