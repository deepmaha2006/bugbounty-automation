"""Platform health checks (CVM platform spec §22).

Each check is a small, independently callable function so it can be unit
tested without needing every dependency (DB, Redis) actually running — the
health endpoint itself is the only place that calls all of them together.
Every check is real: no component is ever reported healthy without an
actual connectivity attempt.

check_database()/check_redis() return the raw exception string on failure —
useful for direct unit testing and any future authenticated diagnostics
route — but GET /health and /healthz are UNAUTHENTICATED (load balancers and
k8s probes call them without credentials), so overall_health() strips that
detail before returning it publicly (WSTG-ERRH-01 / ASVS V7.4.1: a raw
connection-error string can leak a DB/Redis hostname, port, or username to
anyone on the network, with no auth at all). The detail is not lost — it's
logged server-side instead, where an operator can actually see it.
"""
import logging
from typing import Any, Dict

from webapp import config

logger = logging.getLogger("hydrax.health")


def check_database() -> Dict[str, Any]:
    """A real round-trip query, not just 'can we open a connection'."""
    try:
        from webapp import db
        conn = db._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
            return {"status": "ok"}
        finally:
            db._put_conn(conn)
    except Exception as e:  # noqa: BLE001
        return {"status": "down", "error": str(e)}


def check_redis() -> Dict[str, Any]:
    """The Celery broker (Phase 5) — degraded rather than down at the API
    layer if unreachable, since the API itself can still serve requests
    without it (only scheduling/async delivery is affected)."""
    try:
        import redis
        # Short timeout: a health check must fail fast, not hang the
        # /health route for seconds when the broker is simply unreachable.
        client = redis.from_url(config.REDIS_URL, socket_connect_timeout=0.5,
                                socket_timeout=0.5)
        client.ping()
        return {"status": "ok"}
    except Exception as e:  # noqa: BLE001
        return {"status": "down", "error": str(e)}


def check_scan_queue() -> Dict[str, Any]:
    """The in-process FIFO scan coordinator (Phase 1) — always 'ok' with a
    live snapshot; there's no failure mode here beyond the coordinator
    thread having died, which is itself part of the snapshot."""
    from webapp.services import scan_manager
    stats = scan_manager.stats()
    return {"status": "ok" if stats["coordinator_alive"] else "degraded", **stats}


def overall_health() -> Dict[str, Any]:
    """Aggregate status: 'ok' only if every component is 'ok'; 'degraded' if
    only non-critical components (redis/queue) are impaired; 'down' if the
    database — the one dependency nothing on this platform can function
    without — is unreachable.

    The dict this returns is what the unauthenticated /health route sends
    verbatim to the caller — see the module docstring for why every
    component's raw `error` detail is logged here and never included in it."""
    raw = {
        "database": check_database(),
        "redis": check_redis(),
        "scan_queue": check_scan_queue(),
    }
    for name, result in raw.items():
        if result.get("error"):
            logger.warning("Health check failed", extra={"component": name, "error": result["error"]})
    components = {name: {"status": result["status"]} for name, result in raw.items()}
    if components["database"]["status"] != "ok":
        overall = "down"
    elif any(c["status"] != "ok" for c in components.values()):
        overall = "degraded"
    else:
        overall = "ok"
    return {"status": overall, "version": config.APP_VERSION, "components": components}
