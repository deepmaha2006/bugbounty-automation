"""Demo: exercise the real remediation engine ("brain") end to end.

    python scripts/brain_demo.py

Safe to run: the learn-loop step works on a TEMPORARY copy of the KB and a
temporary unresolved store, so config/remediation_kb.yaml and
webapp/data/brain/ are never modified. Step 4 talks only to a local app on
127.0.0.1 and only if HYDRAX_DEMO_TOKEN (a bearer token) is set.
"""
import copy
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore")                       # JWT-unset notice etc.
try:
    sys.stdout.reconfigure(encoding="utf-8")             # Windows consoles
except Exception:  # noqa: BLE001
    pass

import logging  # noqa: E402
logging.disable(logging.WARNING)                         # keep the demo output clean

from webapp.services import remediation_kb as kbm       # noqa: E402
from webapp.services import remediation_service as rs   # noqa: E402

LINE = "─" * 78


def header(title):
    print(f"\n{LINE}\n{title}\n{LINE}")


def show(report, label=""):
    parts = rs.score_risk(report["severity"],
                          kbm_exploit(report), report["confidence"],
                          report["_exposure"], report["kind"])
    base = rs.SEVERITY_BASE[parts["severity"]]
    ex = rs.EXPLOIT_MOD[parts["exploitability"]]
    co = rs.CONFIDENCE_MOD[parts["confidence"]]
    xp = rs.EXPOSURE_MOD[parts["exposure"]]
    print(f"{label}")
    print(f"  key          : {report['key']}   (resolved_by={report['resolved_by']}, "
          f"kind={report['kind']}, unresolved={report['unresolved']})")
    print(f"  cwe / owasp  : {report['cwe']} / {report['owasp']}")
    print(f"  math         : base {base} + exploit {ex:+d} + confidence {co:+d} "
          f"+ exposure {xp:+d} = {base + ex + co + xp} → clamp → {report['risk_score']}")
    print(f"  priority     : {report['priority']}")
    print(f"  rationale    : {report['rationale']}")
    print(f"  triage       : {report['triage_note'][:110]}{'…' if len(report['triage_note']) > 110 else ''}")


_EXPLOIT_CACHE = {}


def kbm_exploit(report):
    """Exploitability word the engine used for this entry (for the math line)."""
    if report["unresolved"]:
        return "Medium"
    entry = kbm.get_kb()["entries"].get(report["key"]) or _EXPLOIT_CACHE.get(report["key"])
    text = entry["exploitability"] if entry else "Medium"
    return next((w for w in kbm.EXPLOITABILITY if str(text).startswith(w)), "Medium")


def resolve(finding, context):
    r = rs.resolve(finding, context)
    r["_exposure"] = context.get("exposure", "unknown")
    return r


def main():
    tmp = Path(tempfile.mkdtemp(prefix="brain_demo_"))
    rs.UNRESOLVED_PATH = tmp / "unresolved.json"        # never touch webapp/data/
    web = {"exposure": "internet_facing"}

    # ------------------------------------------------------------------ 1
    header("1. RESOLVE + SCORE")
    samples = [
        ("Critical SQL injection (confirmed, internet-facing)",
         {"type": "Union-based SQL Injection", "severity": "Critical", "confidence": "confirmed"}, web),
        ("Medium missing security header",
         {"type": "Missing Security Header", "severity": "Medium", "confidence": "confirmed"}, web),
        ("Info signal fed as Critical (shows the P3 cap)",
         {"type": "Technology Fingerprint", "severity": "Critical", "confidence": "confirmed"}, web),
        ("IDOR needing verification, internal asset",
         {"type": "Potential IDOR", "severity": "High", "confidence": "needs_verification"},
         {"exposure": "internal"}),
        ("No type string — category + CWE only",
         {"type": "", "category": "ssrf", "cwe": "CWE-918", "severity": "High"}, web),
    ]
    for label, finding, ctx in samples:
        show(resolve(finding, ctx), f"\n▶ {label}")

    # ------------------------------------------------------------------ 2
    header("2. CORRELATE")
    scan = [
        {"type": "Missing Security Header", "severity": "Medium", "confidence": "confirmed"},
        {"type": "Missing Security Header", "severity": "Medium", "confidence": "confirmed"},
        {"type": "Server Information Disclosure", "severity": "Low", "confidence": "confirmed"},
        {"type": "Session Cookie Missing HttpOnly Flag", "severity": "Medium", "confidence": "confirmed"},
        {"type": "Session Cookie Missing Secure Flag", "severity": "Medium", "confidence": "confirmed"},
        {"type": "Technology Stack Fingerprinting", "severity": "Info", "confidence": "confirmed"},
        {"type": "API Endpoint Detected", "severity": "Info", "confidence": "confirmed"},
        {"type": "Stored XSS", "severity": "Critical", "confidence": "confirmed"},
    ]
    out = rs.analyze_scan(scan, web)
    print(f"{len(out['reports'])} findings → {len(out['issues'])} correlated issues:")
    for i in out["issues"]:
        print(f"  [{i['priority']}] {i['title']:<34} risk {i['risk_score']:>3}  "
              f"members={i['count']}  {i['member_titles']}")
    print("\nTop Priorities (findings by risk, then issues):")
    for t in out["top_priorities"]:
        print(f"  [{t['priority']}] {t['risk_score']:>3}  {t['kind']:<7} {t['title']}")

    # ------------------------------------------------------------------ 3
    header("3. LEARN LOOP (temporary KB copy — the real KB is not modified)")
    kb_copy = tmp / "remediation_kb.yaml"
    shutil.copyfile(kbm.KB_PATH, kb_copy)
    real_before = kbm.KB_PATH.read_bytes()

    unknown = {"type": "Exposed Grafana Dashboard", "category": "sec_misconfig",
               "severity": "High", "confidence": "confirmed"}
    first = rs.resolve(unknown, web, kb=kbm.load_kb(kb_copy))
    print(f"(a) first resolve   → key={first['key']}  resolved_by={first['resolved_by']}  "
          f"unresolved={first['unresolved']}")
    [rec] = [u for u in rs.list_unresolved() if u["type"] == unknown["type"]]
    print(f"(b) unresolved store → signature={rec['signature']!r} count={rec['count']} "
          f"first_seen={rec['first_seen']}")
    d = rec["draft"]
    print(f"    nearest KB hints → {rec['nearest'] or 'none'}   draft_source={rec['draft_source']}")
    print(f"    auto-draft       → key={d['key']!r} aliases={d['aliases']} category={d['category']!r} "
          f"tags={d['tags']}")
    print(f"    draft valid yet? → {not kbm.validate_entry(d)}  "
          f"({len(kbm.validate_entry(d))} fields still to complete)")

    # An analyst completes the draft (content kept deliberately short).
    entry = copy.deepcopy(kbm.load_kb(kb_copy)["entries"]["sec_misconfig.debug_mode_enabled"])
    entry.update({
        # The analyst files it under the right category when completing the draft.
        "key": "sec_misconfig.exposed_grafana_dashboard", "aliases": d["aliases"],
        "category": "sec_misconfig", "cwe": "CWE-306",
        "severity_guidance": "High — raise to Critical if anonymous users can view or edit dashboards.",
        "exploitability": "High — reachable with a browser if anonymous access is enabled.",
        "why_it_matters": "A monitoring dashboard reachable without login exposes internal metrics and hostnames.",
        "detection_signal": "The dashboard's UI or API responds without authentication.",
        "false_positive_check": "Confirm the dashboard is reachable without a session and shows real data.",
        "remediation": {
            "immediate_mitigation": "Restrict the dashboard to the VPN or an allow-listed network.",
            "short_term_fix": "Disable anonymous access and require SSO for the dashboard.",
            "long_term_hardening": "Keep monitoring tools off the public internet by policy.",
            "code_fix_examples": {}, "config_examples": {},
        },
        "verification": "Confirm an unauthenticated request is redirected to login.",
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        "tags": ["monitoring", "exposure"],
    })
    added = rs.promote_unresolved(rec["signature"], entry, path=kb_copy)
    print(f"(c) promote_unresolved → {added}")
    learned = rs.resolve(unknown, web, kb=kbm.load_kb(kb_copy))
    print(f"(d) re-resolve       → key={learned['key']}  resolved_by={learned['resolved_by']}  "
          f"unresolved={learned['unresolved']}  priority={learned['priority']} ({learned['risk_score']})")
    still = [u for u in rs.list_unresolved() if u["type"] == unknown["type"]]
    print(f"    signature cleared from store? {not still}")
    print(f"    real config/remediation_kb.yaml unchanged? {kbm.KB_PATH.read_bytes() == real_before}")

    header("3b. SMARTER MATCHING — synonyms help, unrelated titles never guess (real KB)")
    for title, extra in [("Cross-Site Scripting (Stored)", {}), ("SQLi (union based)", {}),
                         ("JSON Web Token none algorithm", {}),
                         ("Quarterly Revenue Report Generated", {"category": "sec_misconfig"})]:
        r = rs.resolve(dict({"type": title}, **extra), web)
        print(f"  {title:<40} {extra.get('category', ''):<14} → {r['resolved_by']:<8} {r['key']}")

    header("3c. FEEDBACK — analysts mark resolutions right/wrong (temporary store)")
    rs.FEEDBACK_PATH = tmp / "feedback.json"
    for ok in (True, True, True, False):
        fb = rs.record_feedback("xss.stored", ok, "Cross-Site Scripting (Stored)")
    print(f"  xss.stored feedback → correct={fb['correct']} incorrect={fb['incorrect']} "
          f"score={fb['score']}")
    print(f"  shown on the report → {rs.resolve({'type': 'Stored XSS'}, web)['feedback']}")

    header("3d. REVIEW QUEUE (what the brain keeps seeing but cannot solve yet)")
    for t in ["Kubernetes dashboard exposed publicly"] * 3 + ["Redis instance reachable without authentication"]:
        rs.resolve({"type": t}, web)
    print(rs.format_review_queue())

    # ------------------------------------------------------------------ 4
    header("4. LIVE ENDPOINT  POST /api/brain/resolve")
    base = os.environ.get("HYDRAX_DEMO_URL", "http://127.0.0.1:8000")
    token = os.environ.get("HYDRAX_DEMO_TOKEN")
    try:
        urllib.request.urlopen(f"{base}/health", timeout=2)
        up = True
    except urllib.error.HTTPError:
        up = True
    except Exception:  # noqa: BLE001
        up = False
    if not up:
        print(f"Skipped: no app responding at {base}. Start it (uvicorn webapp.main:app, "
              "needs Postgres) and set HYDRAX_DEMO_TOKEN to an operator's bearer token.")
    elif not token:
        print(f"App is up at {base}, but HYDRAX_DEMO_TOKEN is not set — skipping the "
              "authenticated call (the endpoint returns 401 without it).")
    else:
        body = json.dumps({"signal": "WAF log: repeated SQL injection probes on /login",
                           "confidence": "needs_verification",
                           "context": {"exposure": "internet_facing", "asset": "shop-web-01"}}).encode()
        req = urllib.request.Request(f"{base}/api/brain/resolve", data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                rep = json.load(resp)
            print(f"HTTP 200 → key={rep['key']} resolved_by={rep['resolved_by']} "
                  f"priority={rep['priority']} risk={rep['risk_score']}\n  {rep['rationale']}")
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}")

    # ------------------------------------------------------------------ 5
    header("5. KB SUMMARY")
    kb = kbm.load_kb()
    kinds = {}
    for e in kb["entries"].values():
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"entries: {len(kb['entries'])}  ({kinds.get('vulnerability', 0)} vulnerability, "
          f"{kinds.get('signal', 0)} signal)   aliases: {len(kb['by_alias'])}   "
          f"categories: {len(kb['by_category'])}")
    sys.path.insert(0, str(ROOT / "tests"))
    from test_kb_coverage import STAGE0_FINDING_TYPES  # noqa: E402
    misses = [t for t in STAGE0_FINDING_TYPES
              if rs.resolve({"type": t}, kb=kb)["resolved_by"] != "alias"]
    print(f"scanner finding types: {len(STAGE0_FINDING_TYPES)}   resolve by alias: "
          f"{len(STAGE0_FINDING_TYPES) - len(misses)}   misses: {misses or 'none'}")

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
