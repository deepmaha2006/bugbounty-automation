# ARCHITECTURE.md — HydraX → Continuous Vulnerability Management Platform

> **2026-09-29 — web frontend removed.** `webapp/static/` (the browser UI) and its
> `/app` and `/static` routes were deleted; `webapp/` is now an API-only backend and the
> desktop app (`ui/`) is the client. References to website pages below are historical.

Status: living document. Written at the start of the CVM transformation (2026-09-26)
after a full inspection of the pre-existing codebase. Every claim below reflects the
actual code at that commit (`git log` baseline: "Baseline snapshot before CVM platform
transformation"), not aspiration — where something doesn't exist yet it's marked ADD.

## 1. What exists today

HydraX is currently **two independent products sharing one scanning core**, with no
shared identity, asset, or finding model between them:

```
                    ┌─────────────────────────┐
                    │   core/ scanners/        │
                    │   utils/ config/         │   <- shared scanning engine
                    │  (ScanEngine, 25 scanner │
                    │   classes, discovery,    │
                    │   HTTP client, profiles) │
                    └───────────┬─────────────┘
                    ┌───────────┴─────────────┐
                    │                          │
          ┌─────────▼─────────┐     ┌──────────▼──────────┐
          │   Desktop GUI      │     │   Web platform       │
          │   main.py + ui/    │     │   webapp/             │
          │   CustomTkinter    │     │   FastAPI + Postgres  │
          │   local, single-   │     │   single-tenant,      │
          │   user, no server  │     │   flat user/role      │
          │   writes reports/  │     │   writes to Postgres  │
          │   *.json|html      │     │                       │
          └────────────────────┘     └───────────────────────┘
```

- **Desktop GUI** (`main.py`, `ui/`): sidebar nav + view router + `queue.Queue` event
  pump. Views: dashboard, website scanner, app/APK scanner, "company scanner" (in
  reality a domain-wide *web* scan — the name predates and is unrelated to this spec's
  Company Connector concept), results, reports, settings, profile. No accounts, no
  multi-tenancy, no persistence beyond flat files in `reports/`.
- **Web platform** (`webapp/`): FastAPI app (`webapp/main.py`), routers mounted at bare
  paths (no `/api/v1` prefix) for auth/scans/verification/reports/dashboard/settings/
  profile/events(SSE). Raw `psycopg2` against Postgres, schema hand-written in
  `webapp/db.py::init_db()`. Tables today: `users, settings, profiles, targets, scans,
  findings, reports, audit_log`. `users.role` is a bare string (`user`/`admin`) — no
  organizations table, no per-tenant scoping anywhere.
- **Scanning core** (`core/`, `scanners/`, `utils/`, `config/`): `ScanEngine` runs
  scanner classes concurrently in a `ThreadPoolExecutor` with a circuit breaker;
  `Finding`/`ScanResult`/`ScanReport` dataclasses in `core/models.py` have **no**
  CVE/CWE/CVSS/status/fingerprint/occurrence_count fields; `utils/sync_rate_limiter.py`
  is a real per-host token bucket; `webapp/services/scan_manager.py` is an in-process
  FIFO scan coordinator started on FastAPI `startup` — single-process, no distributed
  queue, no cron-style recurring schedule.
- **Real-tool integration**: `webapp/services/web_scan_tools.py` +
  `webapp/services/kali_tools.py` already bridge to nuclei/sqlmap/nmap/nikto per
  `PRODUCTION_UPGRADE_PLAN.md`. This is the intended foundation for CVE/CWE-backed
  detection (spec §4), not something to build from scratch.
- **Mobile/APK support** (being removed, see below): `webapp/services/apk_service.py`,
  `ui/views/app_scanner_view.py`, `webapp/static/scanner-app.{html,js}`,
  `tools/apktool*`, `tools/jadx*`, `androguard` dependency.

## 2. Target architecture

The web platform (`webapp/`) becomes the **single product surface** for the CVM
platform. Multi-tenant SaaS features (organizations, RBAC, connectors, scheduler,
alerting, remediation workflow, audit log) are new capability built *into* `webapp/`,
not duplicated into the desktop GUI — a local single-user Tkinter app is structurally
the wrong place for multi-tenant, connector-based, continuously-scheduled monitoring.
The desktop GUI is **kept** (per §27's "don't remove working functionality unless
obsolete or APK-related") as a local ad-hoc scanning tool that talks to the same
`core/`/`scanners/` engine, but it is no longer where new platform capability lands.

```
                                   ┌──────────────────────────┐
  Desktop client    ───────────►  │   webapp/ (FastAPI)        │
  (ui/, HTTP +                    │   /api/v1/*  REST + OpenAPI│
   X-API-Key)                     └───────────┬───────────────┘
                                               │
                     ┌─────────────────────────┼─────────────────────────┐
                     │                         │                         │
             ┌───────▼───────┐        ┌────────▼────────┐       ┌────────▼────────┐
             │  Postgres      │        │  Redis + Celery  │       │  Notification    │
             │  (multi-tenant │        │  scheduler+queue  │       │  channels        │
             │  schema, §20)  │        │  (beat + workers) │       │  (email/webhook/  │
             └────────────────┘        └────────┬─────────┘       │  Slack/Teams)     │
                                                 │                  └───────────────────┘
                     ┌───────────────────────────┼───────────────────────────┐
                     │                            │                            │
             ┌───────▼────────┐          ┌────────▼────────┐          ┌────────▼─────────┐
             │  Web Scanner    │          │ Connector         │          │ Finding Processor │
             │  job (reuses    │          │ Assessment job    │          │ → Risk Engine      │
             │  core/scanners) │          │ (signed job → to  │          │ → Alert Engine     │
             │                 │          │  enrolled agent)  │          │ → Verification      │
             └─────────────────┘          └────────┬──────────┘          └────────────────────┘
                                                     │  encrypted outbound (agent-initiated)
                                            ┌────────▼─────────┐
                                            │  Company Connector │  <- installed in customer's
                                            │  (agent process)   │     authorized environment
                                            └────────────────────┘
```

Key design decision: **the connector never accepts inbound connections.** It enrolls,
then polls/holds an outbound connection to the platform for signed job assignments —
this avoids requiring customers to open inbound firewall ports into their network,
which would itself be a security regression for a security product.

## 3. Component disposition (KEEP / UPGRADE / REPLACE / REMOVE / ADD)

### REMOVE (spec §2 — do first, see PRODUCTION_READINESS.md / commit history for the executed checklist)
- `webapp/services/apk_service.py`, `ui/views/app_scanner_view.py`,
  `webapp/static/scanner-app.html`, `webapp/static/js/scanner-app.js`,
  `tests/test_apk_upload_security.py`, `tools/apktool*`, `tools/jadx*`.
- `androguard` dependency; `enable_apk_scan` setting/column/UI; `POST /scans/apk`
  endpoint + its request validation helpers in `webapp/routers/scans.py`;
  `ApkScanRequest` schema; APK nav entries in desktop GUI and static HTML pages.
- `config/profiles/mobile-api.yaml` — deleted after content review confirmed it
  targeted the APK binary itself, not just a mobile backend API.

### KEEP as-is (not obsolete, not APK-related)
- `core/scan_engine.py`, `utils/discovery.py`, `utils/http_client.py`,
  `utils/sync_rate_limiter.py`, `scanners/*` (minus nothing — none are mobile-specific),
  `webapp/security.py` (JWT + PBKDF2-HMAC-SHA256 password hashing — corrected from
  this document's original "bcrypt" during the Phase 19 WSTG audit, which was never
  accurate; see `docs/SECURITY_AUDIT_WSTG.md` F3), `webapp/services/auth_limiter.py` (login rate
  limiting), `config/scope.py` (authorized-target scope — directly reusable for
  per-asset `authorization_status`), desktop GUI shell (`ui/main_window.py` and
  non-APK views) as a local tool.

### UPGRADE (extend existing, don't rewrite)
- `core/models.py` — add CVE/CWE/CVSS/confidence/status/fingerprint/occurrence_count/
  affected_component/remediation fields to `Finding`, or add a platform-side
  `findings` table (webapp/db.py) that is the system of record and treats `core/`
  findings as raw scanner output feeding into it. Chosen approach: the latter — keep
  `core/models.py` scanner-facing and lightweight, add the full lifecycle model in the
  webapp DB layer (`webapp/models_v2.py` or equivalent), converting on ingest. This
  avoids coupling the scanner engine (also used standalone by the desktop GUI) to
  platform-only concepts like organization_id.
- `webapp/db.py` schema — add organizations, roles, assets, asset_authorizations,
  connectors, connector_credentials, connector_heartbeats, connector_jobs,
  connector_job_results, scan_jobs, finding_evidence, vulnerabilities,
  remediation_tasks, alerts, notifications, reports (per spec §20), and add
  `organization_id` to every existing security-sensitive table (`users`, `targets`→
  `assets`, `scans`, `findings`, `reports`, `audit_log`).
- `webapp/services/scan_manager.py` — replaced in function (see REPLACE) but the
  resume-on-restart behavior it implements is worth preserving conceptually in the
  new Celery-based scheduler (idempotent job re-enqueue on worker restart).
- `webapp/routers/*` — add `/api/v1` versioning prefix; add pagination/filtering/
  sorting conventions consistently; existing routers are extended, not replaced.

### REPLACE
- **In-process FIFO scan coordinator → Redis + Celery** (scheduler + queue, spec §7).
  Chosen over BullMQ because the backend is Python/FastAPI already — Celery is the
  natural fit and needs no new language runtime. Celery beat handles the configurable
  per-asset schedules (5m/15m/30m/hourly/daily/weekly); Celery workers consume typed
  queues (`web_scan`, `connector_assessment`, `asset_discovery`, `config_assessment`,
  `vuln_correlation`) matching spec §7's architecture diagram.
- **`targets` table (bare URL string) → `assets` table** with the full field set from
  spec §3 (asset_id, organization_id, asset_type, name, hostname, url, environment,
  owner, business_criticality, authorization_status, monitoring_status, timestamps).
  **Revised during Phase 2 implementation**: the physical table keeps the name
  `targets` (extended in place with every field above) rather than being renamed —
  see the "Revised decision" note under Phase 2 in `docs/ROADMAP.md` for why. It is
  exposed to the API/UI as "assets" via `webapp/routers/assets.py`.

### ADD (net-new, spec sections in parentheses)
- Organizations + multi-tenancy enforcement at the query layer (§16).
- RBAC with 4 roles + MFA + token rotation + account lockout (§17).
- Company Connector: enrollment protocol, heartbeat, signed allowlisted job model,
  connector states (§5, §6).
- Risk Engine with stored, explainable factors, not just CVSS passthrough (§10).
- Alert Engine with dedup/cooldown/ack + email/webhook/Slack/Teams delivery (§9).
- Finding fingerprinting + lifecycle state machine + occurrence_count (§8).
- Remediation workflow + automatic re-verification scan on "fix submitted" (§14, §15).
- Audit log covering the full action list in §18 (extends existing `audit_log` table
  which today only logs a subset).
- Reporting: PDF/CSV/JSON executive + technical reports (§23).
- Observability: structured logs, health checks for API/DB/queue/workers/scanners/
  connectors (§22).
- Safe test environment doc + fixtures pointing at Juice Shop/WebGoat/DVWA (§24).
- CI/CD security gates: SAST, dependency scanning, secret scanning, container
  scanning (§25), building on `.github/workflows` (currently minimal/absent — verify
  and fill in).
- `Dockerfile` for the FastAPI app + docker-compose profiles for dev/test/staging/
  prod + `.env.example` (§26) — today only a bare Postgres compose service exists.

## 4. Why the desktop GUI is not the connector

The spec's "Company Connector" (§5) is an agent installed *inside* the customer's
authorized environment that enrolls, authenticates, and executes signed jobs — this
is a new, separate artifact (a small Python service or CLI), not the existing
Tkinter desktop app. The existing `company_scanner_view.py` name is coincidental and
misleading; it performs a domain-wide **web** scan from outside the target, which is
conceptually a `WEB_APPLICATION` asset assessment, not a connector. It will be
relabeled/absorbed accordingly rather than reused as connector code.

## 5. Sequencing

See `ROADMAP.md` for the phased implementation order and current phase status.

## Remediation engine

Findings are resolved to a curated knowledge base (`config/remediation_kb.yaml`)
by `webapp/services/remediation_service.py`, which scores, triages and
correlates them into analyst reports shown in scan results, reports and the UI;
`POST /api/brain/resolve` exposes the same resolver for described events. See
[`BRAIN.md`](BRAIN.md).
