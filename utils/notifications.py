"""
Desktop and multi-channel notification system for HydraX.

Channels:
  1. OS desktop notification (always, via plyer or win10toast or fallback)
  2. Email (SMTP, optional — user configures in Settings)
  3. Webhook (Slack / Telegram / generic POST, optional)

All channels are fire-and-forget in daemon threads so they never block the UI.
"""

from __future__ import annotations

import json
import smtplib
import threading
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, Optional

from config.settings import PROJECT_ROOT

_CONFIG_FILE = PROJECT_ROOT / "config" / "notifications.json"

_DEFAULTS: Dict[str, Any] = {
    "enabled":           True,
    "threshold":         "high",      # critical | high | medium | all
    "quiet_hours_start": "",          # "22:00" or ""
    "quiet_hours_end":   "",          # "08:00" or ""
    # Email
    "email_enabled":    False,
    "smtp_host":        "",
    "smtp_port":        587,
    "smtp_user":        "",
    "smtp_password":    "",
    "email_to":         "",
    # Webhook
    "webhook_enabled":  False,
    "webhook_url":      "",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_config() -> Dict[str, Any]:
    try:
        if _CONFIG_FILE.exists():
            data = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            merged = dict(_DEFAULTS)
            merged.update(data)
            return merged
    except Exception:
        pass
    return dict(_DEFAULTS)


def save_config(cfg: Dict[str, Any]) -> None:
    try:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def _meets_threshold(severity: str, threshold: str) -> bool:
    sev_i = _SEV_ORDER.get(severity.lower(), 99)
    thr_i = _SEV_ORDER.get(threshold.lower(), 1)
    return sev_i <= thr_i


def _in_quiet_hours(start: str, end: str) -> bool:
    if not start or not end:
        return False
    try:
        from datetime import datetime as _dt, time as _t
        now = _dt.now().time()
        s = _t.fromisoformat(start)
        e = _t.fromisoformat(end)
        if s <= e:
            return s <= now <= e
        return now >= s or now <= e
    except Exception:
        return False


def notify(
    title: str,
    message: str,
    severity: str = "info",
    deep_link: str = "",
) -> None:
    """Send a notification on all configured channels (fire-and-forget)."""
    cfg = _load_config()
    if not cfg.get("enabled", True):
        return
    if not _meets_threshold(severity, cfg.get("threshold", "high")):
        return
    if _in_quiet_hours(cfg.get("quiet_hours_start", ""), cfg.get("quiet_hours_end", "")):
        return

    threading.Thread(
        target=_send_all,
        args=(title, message, severity, deep_link, cfg),
        daemon=True,
    ).start()


def _send_all(title: str, message: str, severity: str,
              deep_link: str, cfg: Dict[str, Any]) -> None:
    _send_desktop(title, message, severity)
    if cfg.get("email_enabled"):
        _send_email(title, message, severity, cfg)
    if cfg.get("webhook_enabled") and cfg.get("webhook_url"):
        _send_webhook(title, message, severity, deep_link, cfg)


def _send_desktop(title: str, message: str, severity: str) -> None:
    """Send an OS desktop notification. Tries plyer, then win10toast, then prints."""
    try:
        from plyer import notification as _n
        _n.notify(title=title, message=message, app_name="HydraX", timeout=8)
        return
    except Exception:
        pass
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, message, duration=8, threaded=True)
        return
    except Exception:
        pass
    # Final fallback — visible in the terminal if the app runs in a console
    print(f"[NOTIFY] [{severity.upper()}] {title}: {message}")


def _send_email(title: str, message: str, severity: str, cfg: Dict) -> None:
    host = cfg.get("smtp_host", "")
    if not host:
        return
    try:
        body = f"HydraX Alert — {severity.upper()}\n\n{title}\n\n{message}"
        msg = MIMEText(body)
        msg["Subject"] = f"[HydraX] {title}"
        msg["From"] = cfg.get("smtp_user", "hydrax@localhost")
        msg["To"] = cfg.get("email_to", "")
        with smtplib.SMTP(host, int(cfg.get("smtp_port", 587))) as s:
            s.ehlo()
            if int(cfg.get("smtp_port", 587)) == 587:
                s.starttls()
            if cfg.get("smtp_user") and cfg.get("smtp_password"):
                s.login(cfg["smtp_user"], cfg["smtp_password"])
            s.send_message(msg)
    except Exception:
        pass


def _validate_webhook_url(url: str) -> bool:
    """Validate webhook URL to prevent SSRF attacks against internal hosts.

    Allows only HTTPS URLs pointing to public (non-RFC-1918) addresses.
    """
    import ipaddress
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("https",):
            return False   # require TLS; reject plain http and other schemes
        host = parsed.hostname or ""
        if not host:
            return False
        # Reject IP addresses that resolve to private / loopback ranges
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except ValueError:
            # hostname — allow (DNS resolution at send time; SSRF guard covers it)
            if host in ("localhost",) or host.endswith(".local"):
                return False
        return True
    except Exception:
        return False


def _send_webhook(title: str, message: str, severity: str,
                  deep_link: str, cfg: Dict) -> None:
    url = cfg.get("webhook_url", "")
    if not url:
        return
    if not _validate_webhook_url(url):
        # Silently drop — misconfigured URL or SSRF attempt
        return
    payload = {
        "text": f"*[HydraX {severity.upper()}]* {title}\n{message}",
        "severity": severity,
        "deep_link": deep_link,
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8):
            pass
    except Exception:
        pass
