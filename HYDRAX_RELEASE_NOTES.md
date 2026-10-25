# HydraX v5.2.0 — Release Notes

**Platform:** Desktop · Python 3.9+ · CustomTkinter · Fully offline

---

## What's New in v5.2.0

### HYDRA-1 Analyst Brain (Upgraded)

- **Professional SOC Analyst Persona** — All LLM-powered analysis now runs under
  the HYDRA-1 identity: a senior adversarial intelligence analyst with OSCP/CEH/CISSP
  equivalent knowledge, MITRE ATT&CK expertise, and structured vulnerability triage.
- **Structured Triage Output** — Findings include CVSS score, CWE, OWASP mapping,
  attack chain, kill chain position, and P1–P4 remediation priority automatically.
- **Attack Chain Correlation** — Multiple findings are chained into compounded risk
  narratives, surfacing cases where a LOW + MEDIUM = CRITICAL exploit path.
- **Remediation Action Plans** — Detailed WORKAROUND + ROOT_FIX + VERIFICATION_STEPS
  generated per finding.

### UI / UX Improvements

- **Scrolling Fixed** — Global mouse wheel handler now correctly delegates scroll events
  to the nearest scrollable container. Linux `<Button-4>`/`<Button-5>` events handled.
  Scrolling is 3× faster per wheel tick.
- **Layout Collisions Eliminated** — Root grid `rowspan` corrected to prevent sidebar
  and content frame from fighting over grid rows. No more content hidden beneath panels.
- **Signature Seal (Settings)** — An animated cursive signature "Deepesh Kumar Mahawar"
  appears in Settings as a permanent platform authorship mark. It cannot be edited or
  removed from any deployed instance. Animation replays on demand.

### Security Hardening

- **SSRF Prevention in Webhooks** — Webhook URLs are now validated before dispatch.
  RFC-1918 / loopback / `.local` addresses are rejected silently, preventing webhook
  configuration from being weaponized as an SSRF vector.
- **HTTPS-Only Webhooks** — Plain HTTP webhook targets are rejected.
- **Subprocess Safety Verified** — All external tool calls confirmed to use argument-list
  subprocess (never `shell=True`). Command injection surface is zero.

### Production Deployment

- **`setup_production.py`** — One-command environment check and dependency install.
  Validates Python version, pip installs, Playwright, external tools (nmap, nikto, etc.),
  creates runtime directories, writes default config.
- **`launch.bat` / `launch.sh`** — Platform-native launch scripts. Errors redirect to
  `runtime/hydrax.log`. Automatically picks venv if present.

---

## Architecture

```
brain/
  soc_analyst_prompt.py    ← HYDRA-1 system prompts (full / triage / correlation / remediation)
  vuln_brain.py            ← Autonomous analysis engine
  autonomous_brain.py      ← Event-driven brain runner

ai/
  local_llm.py             ← LLM facade — now uses HYDRA-1 persona for all calls

ui/
  signature_widget.py      ← Animated cursive signature canvas widget
  views/settings_view.py   ← Settings page + signature seal card
  main_window.py           ← Fixed scrolling + layout grid
```

---

## Professional Naming Reference

| Code Name | What It Does |
|---|---|
| **HYDRA-1** | The autonomous SOC analyst AI brain persona |
| **VulnBrain** | Vulnerability correlation and risk scoring engine |
| **HydraBrain** | Autonomy tier controller (observe / recommend / auto-contain) |
| **Threat Cognition Engine** | The combined LLM + heuristic analysis pipeline |
| **Adversarial Intelligence** | The analysis mode that emulates attacker TTPs |
| **Kill Chain Position** | Where a finding sits in the MITRE ATT&CK kill chain |
| **Compounded Risk** | The escalated severity when findings chain together |

---

## Authorized Use Only

HydraX is designed for authorized security testing engagements only.
Always obtain written permission before scanning a target.
Unauthorized scanning is illegal. The kill switch in `brain/autonomy.py`
forces all autonomous actions to OBSERVE mode when engaged.

---

*Platform crafted by Deepesh Kumar Mahawar*
