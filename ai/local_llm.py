"""
Local LLM client — wraps the existing pentest/llm/provider.py for the
desktop brain and AI modules.

No external API keys required by default.  Configure via env vars:
  PENTEST_LLM_PROVIDER  local | openai | anthropic   (default: local)
  PENTEST_LLM_BASE_URL  Ollama URL                   (default: http://localhost:11434/v1)
  PENTEST_LLM_MODEL     model name                   (default: llama3.2)

Security: untrusted strings (target responses, page content) are always
wrapped with prompt_injection_wrap() before being sent to the model.

The default system persona is HYDRA-1 — a senior adversarial intelligence
analyst defined in brain.soc_analyst_prompt.  Every LLM call uses this
professional identity unless the caller explicitly overrides the system prompt.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

# Reuse the provider that the pentest pipeline already configured/tested.
from pentest.llm.provider import complete, is_available
from pentest.llm.provider import prompt_injection_wrap as _wrap_pair
from brain.soc_analyst_prompt import get_system_prompt

logger = logging.getLogger(__name__)

# Default system prompt used for all analysis unless overridden
_DEFAULT_SYSTEM = get_system_prompt("full")
_TRIAGE_SYSTEM  = get_system_prompt("triage")
_CHAIN_SYSTEM   = get_system_prompt("correlation")
_REMED_SYSTEM   = get_system_prompt("remediation")


class LocalLLM:
    """Thin facade over pentest/llm/provider for desktop-brain use.

    Every analysis method injects the HYDRA-1 SOC analyst identity as the
    system prompt so the model behaves as a professional adversarial analyst.

    Usage::

        from ai.local_llm import llm

        answer = llm.ask("Explain CVE-2024-1234 in one sentence.")
        analysis = llm.analyze_finding(finding_dict)
    """

    def ask(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int = 512,
    ) -> str:
        """Send a prompt to the local LLM.  Returns "" on failure.

        If *system* is empty the HYDRA-1 full analyst persona is injected
        automatically.
        """
        sys_prompt = system if system else _DEFAULT_SYSTEM
        try:
            result = complete(prompt, system=sys_prompt, max_tokens=max_tokens)
            return result or ""
        except Exception as exc:
            logger.debug("LLM unavailable: %s", exc)
            return ""

    def analyze_finding(self, finding: dict[str, Any]) -> str:
        """Ask the LLM to enrich a Finding dict with remediation context.

        Uses the triage mode of the HYDRA-1 persona for fast, structured output.
        """
        vuln_type = finding.get("type", "Unknown")
        url       = finding.get("url", "")
        severity  = finding.get("severity", "Unknown")
        evidence  = str(finding.get("evidence", ""))[:400]
        cve       = finding.get("cve", "")
        owasp     = finding.get("owasp", "")

        prompt = (
            f"VULNERABILITY FINDING TO TRIAGE:\n"
            f"  Type     : {vuln_type}\n"
            f"  Severity : {severity}\n"
            f"  URL      : {url}\n"
            f"  CVE      : {cve or 'N/A'}\n"
            f"  OWASP    : {owasp or 'N/A'}\n"
            f"  Evidence : {_wrap_pair('evidence', evidence)}\n\n"
            "Respond with the full structured triage format defined in your instructions.\n"
            "Be concise — under 200 words total."
        )
        return self.ask(prompt, system=_TRIAGE_SYSTEM, max_tokens=350)

    def triage_findings(self, findings: list[dict[str, Any]]) -> str:
        """Produce an executive SOC triage summary for a list of findings."""
        if not findings:
            return "No findings to triage."
        # Sort by severity (worst first), cap at 20 for prompt length
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_f = sorted(
            findings,
            key=lambda f: sev_rank.get(f.get("severity", "Info"), 5),
        )[:20]
        summary_lines = []
        for f in sorted_f:
            sev = f.get("severity", "?")
            typ = f.get("type", "?")
            url = f.get("url", "?")
            cve = f.get("cve", "")
            cve_str = f" [{cve}]" if cve else ""
            summary_lines.append(f"  [{sev}] {typ}{cve_str} @ {url}")

        bullet_list = "\n".join(summary_lines)
        prompt = (
            f"FINDINGS SET ({len(findings)} total, showing worst {len(sorted_f)}):\n"
            f"{bullet_list}\n\n"
            "Produce an executive SOC triage summary using the ATTACK_CHAINS → "
            "COMPOUNDED_RISK → KILL_CHAIN_COVERAGE → PRIORITY_QUEUE format.\n"
            "Max 200 words. Start with the most critical threat."
        )
        return self.ask(prompt, system=_CHAIN_SYSTEM, max_tokens=400)

    def suggest_attack_chain(
        self,
        findings: list[dict[str, Any]],
        target: str,
    ) -> str:
        """Generate a red-team attack chain narrative across confirmed findings."""
        if not findings:
            return ""
        types = list({
            f.get("type", "")
            for f in findings
            if f.get("severity") in ("Critical", "High")
        })[:8]
        if not types:
            return ""
        prompt = (
            f"TARGET: {target}\n"
            f"CONFIRMED VULNERABILITY CLASSES: {', '.join(types)}\n\n"
            "Construct a realistic multi-step kill-chain attack path exploiting "
            "these classes. Format: numbered steps (max 10), MITRE ATT&CK TTP "
            "labels where applicable, plain English, no filler. Max 200 words."
        )
        return self.ask(prompt, system=_CHAIN_SYSTEM, max_tokens=350)

    def generate_remediation_plan(self, finding: dict[str, Any]) -> str:
        """Generate a structured remediation action plan for a single finding."""
        vuln_type = finding.get("type", "Unknown")
        severity  = finding.get("severity", "Unknown")
        url       = finding.get("url", "")
        evidence  = str(finding.get("evidence", ""))[:300]

        prompt = (
            f"FINDING REQUIRING REMEDIATION:\n"
            f"  Type    : {vuln_type}\n"
            f"  Severity: {severity}\n"
            f"  URL     : {url}\n"
            f"  Evidence: {_wrap_pair('evidence', evidence)}\n\n"
            "Generate a full remediation action plan using the PRIORITY → "
            "ESTIMATED_EFFORT → WORKAROUND → ROOT_FIX → OWASP_CONTROL → "
            "VERIFICATION_STEPS → REGRESSION_TEST format.\n"
            "Max 250 words. Be specific and actionable."
        )
        return self.ask(prompt, system=_REMED_SYSTEM, max_tokens=450)

    @property
    def available(self) -> bool:
        return is_available()


# Module-level singleton — import and use directly.
llm = LocalLLM()
