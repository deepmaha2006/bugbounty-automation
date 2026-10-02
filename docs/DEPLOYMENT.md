# DEPLOYMENT.md — HydraX CVM Platform

Spec §26. Not deploy-tested end-to-end in this sandbox (no Docker/Postgres/
Redis available here — the same honest caveat carried through every phase
touching real infrastructure in `docs/ROADMAP.md`). Verify each step below
against a real environment before first production use.

## Components

| Component | Image/process | Profile(s) |
|---|---|---|
| Postgres | `postgres:16-alpine` | always on |
| Redis | `redis:7-alpine` | always on |
| API (dev, hot-reload) | this repo's `Dockerfile`, bind-mounted source | `dev` |
| API (prod) | this repo's `Dockerfile`, built image | `staging`, `prod` |
| Celery worker | same image, `celery ... worker` | `staging`, `prod` |
| Celery beat | same image, `celery ... beat` | `staging`, `prod` |

```bash
cp .env.example .env       # fill in real secrets — see that file's comments
docker compose --profile dev up            # local development
docker compose --profile staging up        # staging, foreground
docker compose --profile prod up -d        # production, detached
```

## Migration tooling

There is no separate migration tool (Alembic, etc.) — `webapp/db.py::init_db()`
is itself the migration mechanism: every schema change across every phase of
this project was added as an idempotent `CREATE TABLE IF NOT EXISTS` /
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` / `ALTER TABLE ... ALTER COLUMN
... DROP NOT NULL` statement, and `init_db()` is called on every process
startup (`webapp/main.py`'s startup event). Running it against an
already-migrated database is required to be a safe no-op — this is exactly
what `scripts/ci_db_smoke_test.py` (Phase 16) verifies by calling it twice
in a row in CI.

**Before adding a new schema change**: follow the existing pattern (an
idempotent `IF NOT EXISTS`-style statement appended to `init_db()`), not a
new migration file — a second mechanism alongside this one would only be a
place for the two to drift apart.

## Backup strategy

Postgres is the only stateful component that isn't otherwise reconstructible
(Redis holds only in-flight Celery task state — safe to lose; scan report
files under `webapp/data/reports/` and `webapp/data/uploads/` are
regenerable/re-uploadable but not from the database alone, so back those up
too).

```bash
# Logical backup (portable across Postgres versions, safe with the app running)
docker compose exec postgres pg_dump -U postgres -Fc hydrax > "hydrax-$(date +%Y%m%d-%H%M%S).dump"

# Restore into a fresh database
docker compose exec -T postgres pg_restore -U postgres -d hydrax --clean --if-exists < hydrax-20260101-000000.dump
```

Recommended cadence: nightly logical `pg_dump` + the data volumes
(`webapp/data/`), retained per your organization's data-retention policy —
findings and audit-log rows are compliance-relevant (spec §18), so retention
should match whatever period your authorization/engagement agreements commit
to, not just an arbitrary "30 days." Store backups encrypted at rest and
somewhere other than the same host (SECURITY_MODEL.md §6's "secrets/
credentials never committed" principle extends to "backups of the database
containing everyone's findings shouldn't sit unencrypted next to it").

## TLS / reverse proxy

`webapp/config.py::HOST`/`PORT` and uvicorn have no TLS support — that's
intentional; see `deploy/nginx.conf.example` for a documented, not
deploy-tested reverse-proxy config terminating TLS in front of the app.
Its comments explain why the Server-Sent Events route
(`webapp/routers/events.py`) needs `proxy_buffering off` and a long read
timeout, which is easy to miss and silently breaks live scan-progress
streaming if skipped.

**Set `HYDRAX_TRUSTED_PROXY_IPS`** (`.env.example`) to this proxy's own
IP/CIDR whenever one is in front of the app. Without it, the login/register
rate limiters (`webapp/routers/auth.py::_client_ip`) see every request as
coming from the proxy's own address instead of the real client — not a
bypass (attacker-supplied `X-Forwarded-For` is never trusted from an
unlisted peer), but it does collapse every real client behind the proxy
into one shared rate-limit bucket, which is a real availability problem for
your actual users. Found and fixed during the Phase 20 security
verification — see `docs/SECURITY_VERIFICATION_REPORT.md`.

## Logging

`webapp/logging_config.py` (Phase 14) writes structured JSON to stdout by
default — correct for a container: let the container runtime/orchestrator
(Docker's own log driver, or whatever aggregates `docker compose logs`)
collect it rather than writing to a file inside the container that would be
lost on restart. `HYDRAX_LOG_LEVEL` controls verbosity (`.env.example`).

## Health checks

`GET /health` (and its `/healthz` alias) is real (Phase 14) — DB round-trip,
Redis reachability, scan-queue liveness — and returns HTTP 503 specifically
when the database is unreachable. The `Dockerfile`'s own `HEALTHCHECK`
already points at it; wire an orchestrator's liveness/readiness probe (a
Kubernetes `livenessProbe`, an ALB health check target, etc.) at the same
endpoint rather than reinventing one.
