"""
HydraX — Bug Bounty Automation Platform.

FastAPI entry point (API only): mounts the API routers and initializes the
PostgreSQL database. The client is the desktop app; there is no web frontend.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import logging
import uuid

import psycopg2

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from webapp import config as wcfg
from webapp import config, db, security
from webapp.logging_config import configure_logging, request_id_var
from webapp.routers import (alerts, assets, auth, brain, connectors, dashboard, events,
                            findings, organizations, profile, remediation, reports,
                            scans, settings, verification)
from webapp.services import scan_manager

configure_logging()

# WSTG-INFO-10: an unauthenticated /openapi.json (and /docs, /redoc built
# from it) hands an attacker the platform's complete API surface — every
# route, parameter, and schema — before they've authenticated at all.
# Defaults to staying available (it's genuinely useful for legitimate
# integrators and this platform requires auth for everything that matters
# anyway) but is one env var away from being turned off for a deployment
# that wants to reduce pre-auth reconnaissance surface.
_docs_disabled = config._env_truthy(os.environ.get("HYDRAX_DISABLE_API_DOCS", ""))

app = FastAPI(
    title=config.APP_TITLE,
    version=wcfg.APP_VERSION,
    description="Automated vulnerability assessment for authorized web applications and connected infrastructure.",
    docs_url=None if _docs_disabled else "/docs",
    redoc_url=None if _docs_disabled else "/redoc",
    openapi_url=None if _docs_disabled else "/openapi.json",
)


@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    """Every log line emitted while handling this request carries the same
    request_id (spec §22) — set here before the route runs, read back by
    logging_config._ContextFilter. Echoed as a response header so a client
    or reverse proxy can correlate its own logs to this request too."""
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    token = request_id_var.set(rid)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-ID"] = rid
    return response


# Every external origin the shipped frontend actually loads from (Google
# Fonts CSS + files, Chart.js from jsdelivr) — deliberately not "*" anywhere.
_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    # 'unsafe-inline' here only (never in script-src): the shipped pages use
    # inline style="" attributes, which is a materially weaker primitive
    # than inline script — every inline <script> block was extracted to a
    # static .js file specifically so script-src doesn't need it.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    """OWASP WSTG-CONF-07 / ASVS V14.4: HTTP response security headers,
    previously entirely absent. Applied to every response — cheap, and
    there's no response path that should be exempt from any of these."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Legacy fallback for browsers that don't honor frame-ancestors yet.
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), payment=(), usb=()")
    # A no-op on a plain-HTTP response (browsers only honor HSTS over HTTPS)
    # — safe to always send, and correct once Phase 17's TLS-terminating
    # reverse proxy is in front of this.
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # API responses carry findings/audit/session data — never cache them
    # (a shared proxy or the browser's own back/forward cache is exactly the
    # kind of place this shouldn't linger).
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

_cors_origins = os.environ.get("HYDRAX_CORS_ORIGINS", "").split(",")
_cors_origins = [o.strip() for o in _cors_origins if o.strip()] or ["http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers ------------------------------------------------------------
app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(alerts.router)
app.include_router(alerts.channels_router)
app.include_router(remediation.router)
app.include_router(connectors.router)
app.include_router(scans.router)
app.include_router(verification.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(settings.router)
app.include_router(profile.router)
app.include_router(events.router)
app.include_router(brain.router)


def _bootstrap_admin():
    """Create the bootstrap admin account from environment variables.

    Lands in the platform's Default Organization — this is an operator/ops
    bootstrap path, not a company signing up for its own tenant (that's the
    register() organization_name path in webapp/routers/auth.py).
    """
    if not wcfg.ADMIN_USERNAME or not wcfg.ADMIN_PASSWORD:
        return
    if db.count_users() == 0 or db.get_user_by_username(wcfg.ADMIN_USERNAME) is None:
        existing = db.get_user_by_username(wcfg.ADMIN_USERNAME)
        if existing:
            db.promote_to_admin(existing["id"])
            return
        uid = db.create_user(wcfg.ADMIN_USERNAME, wcfg.ADMIN_EMAIL,
                             security.hash_password(wcfg.ADMIN_PASSWORD),
                             db.get_default_organization_id())
        db.promote_to_admin(uid)


@app.on_event("startup")
def _startup():
    try:
        db.init_db()
    except psycopg2.OperationalError as exc:
        # Fail fast unless HYDRAX_DEBUG=1: then start anyway so the API can
        # be exercised without a database. Admin bootstrap and scan recovery both
        # need the DB, so they're skipped; the pool is retried per request.
        if not wcfg.DEBUG:
            raise
        logging.getLogger("hydrax.main").warning(
            "DB unavailable — running in preview mode, data endpoints will fail (%s)",
            str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__)
        return
    _bootstrap_admin()
    # Recover scans left running/queued by a previous process, then start the
    # FIFO coordinator (P2-7).
    scan_manager.start()



@app.get("/health")
@app.get("/healthz")
def health():
    """Real component checks (spec §22) — DB round-trip, Redis/broker
    reachability, scan-queue coordinator liveness. Never a hardcoded 'ok'.
    503 only when the database (the one dependency nothing here can function
    without) is unreachable — 'degraded' components still return 200 so a
    load balancer doesn't pull a still-functional instance out of rotation
    over a non-critical dependency."""
    from webapp.services import health as health_service
    result = health_service.overall_health()
    status_code = 503 if result["status"] == "down" else 200
    return JSONResponse(content=result, status_code=status_code)