"""
Hermetic tests for the benchmark runner.
No real targets required — all scanning is mocked.
"""

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.runner import (
    _compute_metrics,
    _type_match,
    _confirmed,
    _is_reachable,
    run_benchmark,
)


# ---------------------------------------------------------------------------
# _type_match
# ---------------------------------------------------------------------------

class TestTypeMatch:
    def test_exact_match(self):
        assert _type_match("SQL Injection", "SQL Injection")

    def test_case_insensitive(self):
        assert _type_match("Reflected XSS", "reflected xss")

    def test_substring_match(self):
        assert _type_match("Error-Based SQL Injection", "SQL Injection")

    def test_none_truth_type_always_matches(self):
        assert _type_match("Anything", None)

    def test_no_match(self):
        assert not _type_match("CSRF", "SQL Injection")


# ---------------------------------------------------------------------------
# _confirmed
# ---------------------------------------------------------------------------

class TestConfirmed:
    def test_filters_to_confirmed_only(self):
        findings = [
            {"type": "XSS", "confidence": "confirmed"},
            {"type": "SQLi", "confidence": "possible"},
            {"type": "SSRF", "confidence": "info"},
            {"type": "RCE", "confidence": "confirmed"},
        ]
        result = _confirmed(findings)
        assert len(result) == 2
        assert all(f["confidence"] == "confirmed" for f in result)

    def test_empty_list(self):
        assert _confirmed([]) == []


# ---------------------------------------------------------------------------
# _compute_metrics
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    def test_true_positive(self):
        findings = [{"type": "SQL Injection", "confidence": "confirmed",
                     "url": "http://localhost:3000/rest/user/login"}]
        known_vuln = [{"endpoint": "/rest/user/login", "type": "SQL Injection"}]
        tp, fp, fn, tn = _compute_metrics(
            findings, known_vuln, [], "http://localhost:3000"
        )
        assert tp >= 1

    def test_false_negative(self):
        findings = []  # scanner found nothing
        known_vuln = [{"endpoint": "/vuln", "type": "SQL Injection"}]
        tp, fp, fn, tn = _compute_metrics(
            findings, known_vuln, [], "http://localhost:3000"
        )
        assert fn >= 1
        assert tp == 0

    def test_static_spa_zero_findings_gives_tn(self):
        findings = []
        known_clean = [{"endpoint": "/", "type": None}]
        tp, fp, fn, tn = _compute_metrics(
            findings, [], known_clean, "https://www.saucedemo.com"
        )
        assert fp == 0
        assert tn >= 1

    def test_static_spa_confirmed_finding_is_fp(self):
        findings = [{"type": "SQL Injection", "confidence": "confirmed",
                     "url": "https://www.saucedemo.com/"}]
        known_clean = [{"endpoint": "/", "type": None}]
        tp, fp, fn, tn = _compute_metrics(
            findings, [], known_clean, "https://www.saucedemo.com"
        )
        assert fp >= 1


# ---------------------------------------------------------------------------
# run_benchmark — mocked scanning
# ---------------------------------------------------------------------------

class TestRunBenchmarkHermetic:
    def test_all_unreachable_returns_true(self, tmp_path):
        """When all targets are unreachable and skip_if_unreachable=true, benchmark passes."""
        gt = tmp_path / "ground_truth.yaml"
        gt.write_text("""
targets:
  - name: fake_target
    url: "http://127.0.0.1:19999"
    skip_if_unreachable: true
    known_vulnerable: []
    known_clean: []
""", encoding="utf-8")

        with patch("benchmark.runner._is_reachable", return_value=False):
            passed = run_benchmark(ground_truth_path=gt)

        assert passed is True

    def test_zero_confirmed_on_negative_set_passes(self, tmp_path):
        """Scanner returns zero confirmed findings on static-SPA negative set → PASS."""
        gt = tmp_path / "ground_truth.yaml"
        gt.write_text("""
targets:
  - name: spa_negative
    url: "http://localhost:9999"
    skip_if_unreachable: false
    known_vulnerable: []
    known_clean:
      - endpoint: "/"
        type: null
""", encoding="utf-8")

        with patch("benchmark.runner._is_reachable", return_value=True), \
             patch("benchmark.runner._scan_target", return_value=[]):
            passed = run_benchmark(ground_truth_path=gt)

        assert passed is True

    def test_confirmed_on_negative_set_fails(self, tmp_path):
        """Scanner returns a confirmed finding on static-SPA negative set → FAIL."""
        gt = tmp_path / "ground_truth.yaml"
        gt.write_text("""
targets:
  - name: spa_negative
    url: "http://localhost:9999"
    skip_if_unreachable: false
    known_vulnerable: []
    known_clean:
      - endpoint: "/"
        type: null
""", encoding="utf-8")

        confirmed_finding = {
            "type": "SQL Injection",
            "confidence": "confirmed",
            "url": "http://localhost:9999/",
        }

        with patch("benchmark.runner._is_reachable", return_value=True), \
             patch("benchmark.runner._scan_target", return_value=[confirmed_finding]):
            passed = run_benchmark(ground_truth_path=gt)

        assert passed is False

    def test_precision_calculation_high_precision(self, tmp_path):
        """TP findings on known-vulnerable → high precision → gate passes."""
        gt = tmp_path / "ground_truth.yaml"
        gt.write_text("""
targets:
  - name: test_target
    url: "http://localhost:9999"
    skip_if_unreachable: false
    known_vulnerable:
      - endpoint: "/vuln"
        type: "SQL Injection"
        param: "id"
    known_clean: []
""", encoding="utf-8")

        tp_finding = {
            "type": "SQL Injection",
            "confidence": "confirmed",
            "url": "http://localhost:9999/vuln",
        }

        with patch("benchmark.runner._is_reachable", return_value=True), \
             patch("benchmark.runner._scan_target", return_value=[tp_finding]):
            passed = run_benchmark(ground_truth_path=gt)

        # TP=1, FP=0 → precision=1.0 ≥ 0.95 → gate passes
        assert passed is True

    def test_results_md_written(self, tmp_path):
        """runner.py writes RESULTS.md into benchmark/."""
        gt = tmp_path / "ground_truth.yaml"
        gt.write_text("""
targets:
  - name: fake
    url: "http://127.0.0.1:19998"
    skip_if_unreachable: true
    known_vulnerable: []
    known_clean: []
""", encoding="utf-8")

        # Patch the output path to go into tmp_path
        results_path = tmp_path / "RESULTS.md"
        with patch("benchmark.runner._is_reachable", return_value=False), \
             patch("benchmark.runner._HERE", tmp_path):
            from benchmark import runner as bm
            orig_here = bm._HERE
            bm._HERE = tmp_path
            try:
                bm.run_benchmark(ground_truth_path=gt)
            finally:
                bm._HERE = orig_here

        assert results_path.exists()
        text = results_path.read_text(encoding="utf-8")
        assert "HydraX Benchmark Results" in text
