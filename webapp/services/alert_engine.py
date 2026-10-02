"""Alert Engine (Phase 9, spec §9): turns a newly-detected or reopened
high-confidence Critical/High finding into a real notification attempt on
every enabled channel for its organization.

"Alert sent" here always means an actual delivery attempt was made and its
real outcome recorded (webapp.db.record_notification) — never a simulated
success. Delivery failures are caught and recorded as failed, not raised,
so one broken channel never blocks the others or the scan itself.
"""
import logging
import smtplib
import sys
from email.mime.text import MIMEText
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webapp import config, db  # noqa: E402
from utils.ssrf_guard import assert_safe_scan_target  # noqa: E402

logger = logging.getLogger("hydrax.alerts")


def maybe_alert(finding_id: int) -> None:
    """Entry point called by the scan services right after add_finding().
    No-op unless the finding is genuinely alert-worthy."""
    # finding_id alone doesn't carry organization scope here — the caller
    # already knows it belongs to a real, just-persisted finding, so a
    # direct unscoped lookup is safe (mirrors list_interrupted_scans-style
    # internal-only reads elsewhere in db.py).
    finding = db.get_finding_unscoped(finding_id)
    if not finding:
        return
    if finding["severity"] not in config.ALERTABLE_SEVERITIES:
        return
    if finding.get("confidence") != "confirmed":
        return

    alert = db.get_or_create_alert(finding["organization_id"], finding_id,
                                   finding.get("target_id"), finding["severity"])
    if not db.should_notify(alert, config.ALERT_COOLDOWN_MINUTES):
        return

    channels = db.list_notification_channels(finding["organization_id"], enabled_only=True)
    if not channels:
        return

    asset = db.get_target(finding["target_id"], finding["organization_id"]) if finding.get("target_id") else None
    payload = _build_payload(finding, asset, alert)

    for channel in channels:
        try:
            _deliver(channel, payload)
            db.record_notification(alert["id"], channel["id"], "sent")
        except Exception as e:  # noqa: BLE001 — one bad channel must not break the rest
            logger.warning("alert delivery failed (channel %s, %s): %s",
                           channel["id"], channel["channel_type"], e)
            db.record_notification(alert["id"], channel["id"], "failed", error_message=str(e))

    db.mark_alert_notified(alert["id"])


def _build_payload(finding: dict, asset: dict, alert: dict) -> dict:
    """Every field spec §9 requires in an alert."""
    asset_name = (asset or {}).get("name") or (asset or {}).get("url") or "unknown asset"
    return {
        "asset": asset_name,
        "vulnerability": finding["type"],
        "severity": finding["severity"],
        "cvss_estimated": finding.get("cvss"),
        "evidence": finding.get("evidence", ""),
        "first_detected": finding.get("discovered_at", ""),
        "affected_component": finding.get("affected_component") or finding.get("parameter") or finding["type"],
        "remediation": finding.get("remediation", ""),
        "finding_id": finding["id"],
        # The API resource for this finding (there is no web page; the
        # desktop app is the client).
        "finding_link": f"/api/findings/{finding['id']}",
    }


def _deliver(channel: dict, payload: dict) -> None:
    channel_type = channel["channel_type"]
    if channel_type == "webhook":
        _deliver_webhook(channel["config"], payload)
    elif channel_type == "slack":
        _deliver_slack(channel["config"], payload)
    elif channel_type == "teams":
        _deliver_teams(channel["config"], payload)
    elif channel_type == "email":
        _deliver_email(channel["config"], payload)
    else:
        raise ValueError(f"Unknown channel type: {channel_type}")


def _summary_text(payload: dict) -> str:
    return (f"[{payload['severity']}] {payload['vulnerability']} on {payload['asset']}\n"
           f"Affected: {payload['affected_component']}\n"
           f"First detected: {payload['first_detected']}\n"
           f"Evidence: {payload['evidence'][:300]}\n"
           f"Remediation: {payload['remediation']}\n"
           f"Details: {payload['finding_link']}")


def _deliver_webhook(config_: dict, payload: dict) -> None:
    url = config_["url"]
    # Re-checked immediately before every delivery, not only at channel-
    # creation time (webapp/routers/alerts.py) — a channel URL's DNS record
    # could be repointed at an internal address after passing that initial
    # check (DNS rebinding), the same reason webapp/services/*_scan_service.py
    # re-check scan targets right before executing rather than trusting a
    # cached result (CWE-918, WSTG-INPV-19, ASVS V5.2.5).
    assert_safe_scan_target(url)
    resp = requests.post(url, json=payload, timeout=config.ALERT_WEBHOOK_TIMEOUT_SECONDS)
    resp.raise_for_status()


def _deliver_slack(config_: dict, payload: dict) -> None:
    url = config_["url"]
    assert_safe_scan_target(url)
    resp = requests.post(url, json={"text": _summary_text(payload)},
                         timeout=config.ALERT_WEBHOOK_TIMEOUT_SECONDS)
    resp.raise_for_status()


def _deliver_teams(config_: dict, payload: dict) -> None:
    url = config_["url"]
    assert_safe_scan_target(url)
    # Teams "MessageCard" connector format.
    card = {
        "@type": "MessageCard", "@context": "http://schema.org/extensions",
        "themeColor": "d9534f" if payload["severity"] == "Critical" else "f0ad4e",
        "summary": f"{payload['severity']} vulnerability: {payload['vulnerability']}",
        "sections": [{
            "activityTitle": f"{payload['severity']}: {payload['vulnerability']}",
            "text": _summary_text(payload),
        }],
    }
    resp = requests.post(url, json=card, timeout=config.ALERT_WEBHOOK_TIMEOUT_SECONDS)
    resp.raise_for_status()


def _deliver_email(config_: dict, payload: dict) -> None:
    """Uses smtplib directly against config.SMTP_* — no real SMTP server is
    available in the sandbox this was built in, so this path is verified by
    mocking smtplib.SMTP (tests/test_phase9_alerting.py), unlike the webhook/
    Slack/Teams paths above, which are tested against a real local HTTP
    server. Flagged in docs/ROADMAP.md for real-SMTP verification."""
    to_address = config_["to"]
    msg = MIMEText(_summary_text(payload))
    msg["Subject"] = f"[HydraX] {payload['severity']}: {payload['vulnerability']} on {payload['asset']}"
    msg["From"] = config.SMTP_FROM_ADDRESS
    msg["To"] = to_address

    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=config.ALERT_WEBHOOK_TIMEOUT_SECONDS) as smtp:
        if config.SMTP_USE_TLS:
            smtp.starttls()
        if config.SMTP_USERNAME:
            smtp.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        smtp.sendmail(config.SMTP_FROM_ADDRESS, [to_address], msg.as_string())
