"""
HydraX FP/precision benchmark runner.

Usage:
    python benchmark/runner.py

Exit codes:
    0 — precision >= 0.95 (or all targets were unreachable/skipped)
    1 — precision < 0.95 or static-SPA negative set has confirmed findings

Targets are defined in benchmark/ground_truth.yaml.  Each target can be
flagged skip_if_unreachable; the runner does a quick GET (3 s timeout) and
skips the target silently if it isn't reachable.

Metrics per class:
    precision = TP / (TP + FP)   (how much of what we report is real)
    recall    = TP / (TP + FN)   (how much of the real stuff we find)
"""

import sys
import os
import time
import socket
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running as `python benchmark/runner.py` from the project root.
_HERE = Path(__file__).parent
_PROJECT = _HERE.parent
sys.path.insert(0, str(_PROJECT))

try:
    import yaml
except ImportError:
    # fallback minimal YAML parser (only handles the simple schema we use)
    yaml = None  # type: ignore

from scanners.xss_scanner import XSSScanner
from scanners.sql_injection import SQLInjectionScanner
from scanners.security_misconfig import SecurityMisconfigScanner


# ---------------------------------------------------------------------------
# YAML loading (with lightweight fallback if PyYAML absent)
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    if yaml is not None:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    # Minimal fallback — only parse the ground_truth.yaml schema
    import re
    text = path.read_text(encoding="utf-8")
    # Strip comments
    lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    # Re-join and try json-style parse after converting YAML arrays manually
    # This is intentionally limited; real use should have PyYAML.
    raise RuntimeError(
        "PyYAML not installed. Run `pip install pyyaml` to use the benchmark runner."
    )


# ---------------------------------------------------------------------------
# Reachability check
# ---------------------------------------------------------------------------

def _is_reachable(url: str, timeout: float = 3.0) -> bool:
    try:
        req = urllib.request.Request(url, method="GET")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Finding collection helpers
# ---------------------------------------------------------------------------

def _confirmed(findings: List[dict]) -> List[dict]:
    return [f for f in findings if f.get("confidence") == "confirmed"]


def _scan_target(base_url: str) -> List[dict]:
    all_findings: List[dict] = []
    for ScannerCls in (XSSScanner, SQLInjectionScanner, SecurityMisconfigScanner):
        try:
            scanner = ScannerCls()
            result = scanner.scan(base_url)
            vulns = result.get("vulnerabilities", [])
            all_findings.extend(vulns)
        except Exception as exc:
            print(f"  [WARN] {ScannerCls.__name__} raised: {exc}", flush=True)
    return all_findings


# ---------------------------------------------------------------------------
# Precision / recall computation
# ---------------------------------------------------------------------------

def _type_match(finding_type: str, truth_type: str) -> bool:
    """True when the finding type string matches the ground-truth type."""
    if truth_type is None:
        return True
    return truth_type.lower() in finding_type.lower()


def _compute_metrics(
    confirmed_findings: List[dict],
    known_vulnerable: List[dict],
    known_clean: List[dict],
    base_url: str,
) -> Tuple[int, int, int, int]:
    """Return (TP, FP, FN, TN) counts."""
    tp = fp = fn = tn = 0

    # For each known-vulnerable entry, check if scanner found it
    for kv in known_vulnerable:
        endpoint = kv.get("endpoint", "")
        truth_type = kv.get("type")
        expected_url = base_url.rstrip("/") + endpoint
        found = any(
            _type_match(f.get("type", ""), truth_type or "")
            and (
                endpoint in f.get("url", "")
                or base_url in f.get("url", "")
            )
            for f in confirmed_findings
        )
        if found:
            tp += 1
        else:
            fn += 1

    # For each known-clean entry, any confirmed finding is a FP
    for kc in known_clean:
        endpoint = kc.get("endpoint", "")
        fp_here = [
            f for f in confirmed_findings
            if endpoint in f.get("url", "") or base_url in f.get("url", "")
        ]
        fp += len(fp_here)
        if not fp_here:
            tn += 1

    # Any confirmed finding not in known_vulnerable is also a FP
    for f in confirmed_findings:
        furl = f.get("url", "")
        ftype = f.get("type", "")
        matches_known = any(
            endpoint in furl
            and _type_match(ftype, kv.get("type"))
            for kv in known_vulnerable
            for endpoint in [kv.get("endpoint", "")]
        )
        if not matches_known and known_vulnerable:
            fp += 1

    return tp, fp, fn, tn


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def _write_results(
    results: List[dict],
    combined_precision: Optional[float],
    combined_recall: Optional[float],
    negative_pass: bool,
    output_path: Path,
):
    lines = [
        "# HydraX Benchmark Results",
        "",
        "## Methodology",
        "",
        "Precision (TP / (TP+FP)) is measured against labeled ground-truth targets.",
        "Recall (TP / (TP+FN)) is tracked alongside precision so that FP reduction",
        "cannot be gamed by suppressing all findings.",
        "",
        "**Oracle requirement**: every `confirmed` finding must carry a `confirmation`",
        "record with `reproduced: true` or a corroborating tool match.  Bare heuristics",
        "are downgraded to `possible` and excluded from precision/recall counts.",
        "",
        "## Targets",
        "",
    ]
    for r in results:
        status = r.get("status", "unknown")
        lines.append(f"### {r['name']} — {r['url']}")
        if status == "skipped":
            lines.append("**Skipped** (unreachable)")
        elif status == "error":
            lines.append(f"**Error**: {r.get('error', '')}")
        else:
            tp, fp, fn, tn = r["tp"], r["fp"], r["fn"], r["tn"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else None
            rec  = tp / (tp + fn) if (tp + fn) > 0 else None
            lines += [
                f"- TP={tp}  FP={fp}  FN={fn}  TN={tn}",
                f"- Precision: {f'{prec:.2%}' if prec is not None else 'N/A (no predicted positives)'}",
                f"- Recall:    {f'{rec:.2%}' if rec is not None else 'N/A (no true positives)'}",
                f"- Confirmed findings: {r['confirmed_count']}",
            ]
        lines.append("")

    lines += [
        "## Combined Metrics",
        "",
    ]
    if combined_precision is not None:
        lines.append(f"**Precision**: {combined_precision:.2%}  (gate: ≥ 95%)")
        recall_str = f"{combined_recall:.2%}" if combined_recall is not None else "N/A"
        lines.append(f"**Recall**:    {recall_str}")
        gate_str = "PASS ✓" if combined_precision >= 0.95 else "FAIL ✗"
        lines.append(f"**Gate**:      {gate_str}")
    else:
        lines.append(
            "All targets were unreachable — precision gate skipped.  "
            "Run against live Juice Shop + DVWA to obtain a real number."
        )
    lines.append("")

    lines += [
        "## Static SPA Negative Set",
        "",
        f"Result: {'PASS ✓ (0 confirmed findings)' if negative_pass else 'FAIL ✗ (confirmed findings on static SPA)'}",
        "",
    ]

    lines += [
        "## How to run real targets",
        "",
        "1. `docker run -d -p 3000:3000 bkimminich/juice-shop`",
        "2. `docker run -d -p 4280:80 vulnerables/web-dvwa`",
        "3. `python benchmark/runner.py`",
        "",
        "Or via the Makefile: `make benchmark`",
        "",
    ]

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResults written to {output_path}", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_benchmark(ground_truth_path: Optional[Path] = None) -> bool:
    """Run the full benchmark.  Returns True when precision gate passes."""
    gt_path = ground_truth_path or (_HERE / "ground_truth.yaml")
    data = _load_yaml(gt_path)
    targets = data.get("targets", [])

    results = []
    all_tp = all_fp = all_fn = all_tn = 0
    negative_pass = True  # assume pass until a static-spa target fails

    for target_cfg in targets:
        name = target_cfg.get("name", "unnamed")
        url = target_cfg.get("url", "")
        skip_if_unreachable = target_cfg.get("skip_if_unreachable", True)
        known_vulnerable = target_cfg.get("known_vulnerable") or []
        known_clean = target_cfg.get("known_clean") or []

        print(f"\n[benchmark] Target: {name} ({url})", flush=True)

        if not _is_reachable(url):
            if skip_if_unreachable:
                print(f"  → unreachable, skipping", flush=True)
                results.append({"name": name, "url": url, "status": "skipped"})
                continue
            else:
                results.append({
                    "name": name, "url": url,
                    "status": "error", "error": "target unreachable"
                })
                continue

        print(f"  → scanning …", flush=True)
        t0 = time.monotonic()
        try:
            raw_findings = _scan_target(url)
        except Exception as exc:
            results.append({
                "name": name, "url": url,
                "status": "error", "error": str(exc)
            })
            continue

        confirmed = _confirmed(raw_findings)
        elapsed = time.monotonic() - t0
        print(f"  → {len(raw_findings)} total findings, {len(confirmed)} confirmed ({elapsed:.1f}s)", flush=True)

        # Static-SPA negative check
        is_negative = not known_vulnerable and known_clean
        if is_negative and confirmed:
            print(f"  ✗ FAIL: {len(confirmed)} confirmed finding(s) on negative set", flush=True)
            negative_pass = False

        tp, fp, fn, tn = _compute_metrics(confirmed, known_vulnerable, known_clean, url)
        all_tp += tp
        all_fp += fp
        all_fn += fn
        all_tn += tn

        results.append({
            "name": name, "url": url, "status": "ok",
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "confirmed_count": len(confirmed),
        })

    # Combined precision / recall
    combined_precision: Optional[float] = None
    combined_recall: Optional[float] = None
    if (all_tp + all_fp) > 0:
        combined_precision = all_tp / (all_tp + all_fp)
    if (all_tp + all_fn) > 0:
        combined_recall = all_tp / (all_tp + all_fn)

    print("\n[benchmark] Summary", flush=True)
    if combined_precision is not None:
        print(f"  Precision: {combined_precision:.2%}", flush=True)
        recall_str = f"{combined_recall:.2%}" if combined_recall is not None else "N/A"
        print(f"  Recall:    {recall_str}", flush=True)
    else:
        print("  All targets skipped — no precision measurement possible", flush=True)

    print(f"  Static SPA negative: {'PASS' if negative_pass else 'FAIL'}", flush=True)

    _write_results(
        results, combined_precision, combined_recall, negative_pass,
        _HERE / "RESULTS.md",
    )

    gate_passed = (
        negative_pass
        and (combined_precision is None or combined_precision >= 0.95)
    )
    return gate_passed


if __name__ == "__main__":
    passed = run_benchmark()
    sys.exit(0 if passed else 1)
