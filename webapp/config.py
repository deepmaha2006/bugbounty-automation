"""
Web platform configuration — single source of truth for the FastAPI layer.
"""
import os
from pathlib import Path

WEBAPP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WEBAPP_ROOT.parent

# --- Server -------------------------------------------------------------
# Binding all interfaces by default is intentional for a containerized
# deployment (Phase 17) that's expected to sit behind a reverse proxy/
# firewall, not exposed directly — env-overridable (e.g. HYDRAX_HOST=127.0.0.1
# for an operator fronting it with a local-only reverse proxy on the same
# host). nosec: B104 flags the literal default, which is a deliberate,
# documented choice here, not an oversight.
HOST = os.environ.get("HYDRAX_HOST", "0.0.0.0")  # nosec B104
PORT = int(os.environ.get("HYDRAX_PORT", "8000"))
APP_TITLE = "HydraX — Enterprise Bug Bounty Automation Platform"
APP_VERSION = "6.0.0"

# --- Storage ------------------------------------------------------------
DATA_DIR = WEBAPP_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"

# PostgreSQL configuration
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.environ.get("POSTGRES_DB", "hydrax")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")

for _d in (UPLOAD_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- Scheduler + queue (Phase 5) ------------------------------------------
REDIS_URL = os.environ.get("HYDRAX_REDIS_URL", "redis://localhost:6379/0")
# How often the beat scheduler checks for assets whose next_scan_at has
# passed — independent of any individual asset's own monitoring frequency.
SCHEDULER_CHECK_INTERVAL_SECONDS = 60

MONITORING_FREQUENCY_MINUTES = {
    "5m": 5, "15m": 15, "30m": 30, "hourly": 60,
    "daily": 60 * 24, "weekly": 60 * 24 * 7,
}

# --- Alerting (Phase 9) -----------------------------------------------------
# Only Critical/High findings ever alert (spec §9: "new high-confidence
# critical/high vulnerability"); confidence must be 'confirmed' too.
ALERTABLE_SEVERITIES = ("Critical", "High")
# Never re-notify for the same unchanged vulnerability within this window.
ALERT_COOLDOWN_MINUTES = int(os.environ.get("HYDRAX_ALERT_COOLDOWN_MINUTES", "60"))
ALERT_WEBHOOK_TIMEOUT_SECONDS = 10

SMTP_HOST = os.environ.get("HYDRAX_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("HYDRAX_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("HYDRAX_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("HYDRAX_SMTP_PASSWORD", "")
SMTP_FROM_ADDRESS = os.environ.get("HYDRAX_SMTP_FROM", "alerts@hydrax.local")
SMTP_USE_TLS = os.environ.get("HYDRAX_SMTP_USE_TLS", "1").strip().lower() in ("1", "true", "yes", "on")

# --- Company Connector (Phase 8) --------------------------------------------
# PEM-encoded Ed25519 private key the platform signs every connector job
# with. See webapp/services/connector_crypto.py::get_platform_signing_keys
# for the ephemeral dev-mode fallback when this isn't set.
JOB_SIGNING_PRIVATE_KEY_PEM = os.environ.get("HYDRAX_JOB_SIGNING_PRIVATE_KEY", "")
CONNECTOR_ENROLLMENT_TOKEN_EXPIRE_MINUTES = 30
CONNECTOR_JOB_EXPIRE_MINUTES = 10
# Heartbeat-freshness thresholds driving the live-computed connector state
# (ONLINE/DEGRADED/OFFLINE) — see webapp/db.py::connector_state.
CONNECTOR_DEGRADED_AFTER_MINUTES = 2
CONNECTOR_OFFLINE_AFTER_MINUTES = 5

# --- Auth ---------------------------------------------------------------
def _env_truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# HYDRAX_DEBUG=1 is an opt-in development flag: if the database is unreachable
# at startup, the API starts anyway (data endpoints fail) instead of exiting.
# Off by default: startup fails fast.
DEBUG = _env_truthy(os.environ.get("HYDRAX_DEBUG", ""))


def resolve_jwt_secret(secret: str, dev_mode: bool) -> dict:
    """Decide the effective JWT secret and auth state from raw inputs.

    Never mints a random secret unless the operator explicitly opts into
    development mode. Returns {"secret", "configured", "ephemeral"}:
      * An operator-provided secret always wins (never ephemeral).
      * No secret + explicit dev/test mode -> a throwaway in-process secret.
      * No secret + no dev mode -> authentication disabled (fails closed),
        so no token is ever issued or accepted under a silently rotating key.
    """
    secret = (secret or "").strip()
    if secret:
        return {"secret": secret, "configured": True, "ephemeral": False}
    if dev_mode:
        import secrets
        return {"secret": secrets.token_hex(32), "configured": True,
                "ephemeral": True}
    return {"secret": "", "configured": False, "ephemeral": False}


# HYDRAX_JWT_SECRET is the operator-provided secret for real deployments.
# HYDRAX_JWT_DEV_MODE=1 is an explicit, opt-in development/test mode that may
# use a throwaway in-process secret; it is never the default.
JWT_DEV_MODE = _env_truthy(os.environ.get("HYDRAX_JWT_DEV_MODE", ""))
_JWT_RESOLVED = resolve_jwt_secret(
    os.environ.get("HYDRAX_JWT_SECRET", ""), JWT_DEV_MODE)
JWT_SECRET = _JWT_RESOLVED["secret"]
AUTH_CONFIGURED = _JWT_RESOLVED["configured"]
JWT_EPHEMERAL = _JWT_RESOLVED["ephemeral"]

if not AUTH_CONFIGURED:
    import warnings
    warnings.warn(
        "JWT authentication is disabled: HYDRAX_JWT_SECRET is not set and "
        "HYDRAX_JWT_DEV_MODE is not enabled. No token will be issued or "
        "accepted until a secret is configured.",
        RuntimeWarning,
    )
elif JWT_EPHEMERAL:
    import warnings
    warnings.warn(
        "HYDRAX_JWT_DEV_MODE=1: using a throwaway in-process JWT secret. "
        "Tokens will invalidate on restart — local development only.",
        RuntimeWarning,
    )

JWT_ALGO = "HS256"
# Short-lived now that refresh-token rotation exists (Phase 3) — a stolen
# access token is only useful for a few minutes; long-lived sessions are
# carried by the refresh token instead.
JWT_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
MFA_PENDING_TOKEN_EXPIRE_MINUTES = 5

# --- Account lockout (Phase 3) --------------------------------------------
# Distinct from the sliding-window AuthLimiter below: that resets after
# RATE_LIMIT_WINDOW_SECONDS and is keyed by (username, ip); this is a
# persistent, user-keyed lock that survives across IPs/windows and (past the
# threshold) requires either the cool-down to elapse or an admin to clear it.
# The two are complementary, not redundant: a single-source brute force is
# capped fast by the per-(username, ip) limiter (5/15min) before it can rack
# up failures here; a distributed credential-stuffing attempt spread across
# many IPs evades that per-IP cap but still accumulates toward this
# IP-independent threshold, since login() only calls record_login_failure()
# on attempts the rate limiter actually let through.
ACCOUNT_LOCKOUT_THRESHOLD = 10
ACCOUNT_LOCKOUT_DURATION_MINUTES = 30

# --- Auth rate limiting (P2-3) -------------------------------------------
# In-memory, bounded brute-force/credential-stuffing protection for the
# login/register endpoints. No Redis/database dependency; the limiter stores
# only failure counts + window start (never passwords or tokens) and caps its
# internal tables so attacker-controlled usernames/IPs cannot grow memory
# without bound.
RATE_LIMIT_LOGIN_MAX_ATTEMPTS = 5          # failed logins per username+IP
RATE_LIMIT_REGISTER_MAX_ATTEMPTS = 10      # registration attempts per IP
RATE_LIMIT_WINDOW_SECONDS = 15 * 60        # 15-minute sliding window
RATE_LIMIT_MAX_KEYS = 10_000               # LRU cap on tracked keys

# IPs/CIDRs of reverse proxies this deployment actually sits behind (e.g.
# deploy/nginx.conf.example, which does forward X-Forwarded-For/X-Real-IP).
# _client_ip() (webapp/routers/auth.py) only trusts those headers when the
# immediate TCP peer is one of these — otherwise every request behind an
# undeclared proxy would appear to share the proxy's own IP, collapsing the
# per-IP rate limiters into one shared bucket for every real client (an
# availability bug, not a bypass, but blindly trusting the headers from ANY
# peer would be a real one: an attacker could forge X-Forwarded-For to reset
# their own rate-limit key on every request). Comma-separated; empty means
# trust nothing and always use the raw TCP peer (today's default behavior).
TRUSTED_PROXY_IPS = [ip.strip() for ip in
                     os.environ.get("HYDRAX_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()]

# --- Admin bootstrap ------------------------------------------------------
# On startup, if HYDRAX_ADMIN_USERNAME + HYDRAX_ADMIN_PASSWORD are set, the
# first admin account is created automatically. Otherwise the very first
# registered account becomes the platform administrator.
ADMIN_USERNAME = os.environ.get("HYDRAX_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("HYDRAX_ADMIN_PASSWORD", "")
ADMIN_EMAIL = os.environ.get("HYDRAX_ADMIN_EMAIL", "admin@hydrax.local")

# --- Target verification ---------------------------------------------------
# DNS TXT challenge mode. "real" (the default) performs an actual TXT lookup
# via dnspython and only verifies a target when the per-target challenge token
# is present in the target's TXT records. "simulated" is a development/lab-only
# mode that treats the stored token as present — it is only active when
# HYDRAX_VERIFY_MODE=simulated is set explicitly and is never the default.
VERIFY_MODE = os.environ.get("HYDRAX_VERIFY_MODE", "real").strip().lower()

# --- Scan scheduling (P2-7) ----------------------------------------------
# Maximum number of scans that may run concurrently in-process. Further
# submissions are queued FIFO by the shared ScanManager until a slot frees.
# Overridable with HYDRAX_MAX_CONCURRENT_SCANS; must be at least 1.
try:
    MAX_CONCURRENT_SCANS = max(
        1, int(os.environ.get("HYDRAX_MAX_CONCURRENT_SCANS", "3")))
except (TypeError, ValueError):
    MAX_CONCURRENT_SCANS = 3

# --- Scan defaults (mirrors config/settings.py) --------------------------
DEFAULT_TIMEOUT = 15
DEFAULT_THREADS = 8
VERIFY_SSL = False
