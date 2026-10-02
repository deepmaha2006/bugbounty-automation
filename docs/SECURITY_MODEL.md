# SECURITY_MODEL.md — HydraX CVM Platform

Concrete controls implementing THREAT_MODEL.md. This document says *what the code
must do*; ROADMAP.md and PRODUCTION_READINESS.md track whether it does yet.

## 1. Tenancy & data isolation

- Every security-sensitive table carries `organization_id` (spec §16, §20):
  `users, assets, asset_authorizations, connectors, connector_credentials,
  connector_heartbeats, connector_jobs, connector_job_results, scans, scan_jobs,
  findings, finding_evidence, vulnerabilities, remediation_tasks, alerts,
  notifications, audit_logs, reports`.
- All reads/writes to those tables go through a single data-access layer that derives
  `organization_id` from the authenticated session/token — **never** from a
  client-supplied query param or body field. A request that includes a conflicting
  `organization_id` in its payload is rejected, not silently overridden.
- Cross-tenant isolation is covered by explicit automated tests (spec §16, §25): for
  every resource type, assert that org A's authenticated user gets 403/404 (not the
  resource) when addressing org B's resource by ID.

## 2. Authentication

- Passwords: PBKDF2-HMAC-SHA256 (already in `webapp/security.py`, not bcrypt as
  originally written here — corrected during the Phase 19 WSTG audit), at
  600,000 iterations (raised from 120,000; ASVS V6.2.3) with the iteration count
  embedded per-hash so it can be raised again without invalidating existing
  accounts, plus opportunistic rehashing on successful login (ASVS V6.2.4). A
  12-character minimum length (ASVS V2.1.1) rather than a composition/complexity
  rule. See `docs/SECURITY_AUDIT_WSTG.md` F2/F3.
- Sessions/tokens: short-lived JWT access token + refresh token rotation (ADD — not
  present today). Refresh reuse detection: a used-and-replayed refresh token revokes
  the whole token family.
- MFA: TOTP-based, required for Admin and Security Manager roles at minimum;
  optional-but-encouraged for others (ADD).
- Account lockout / risk controls: exponential backoff already exists for login
  attempts (`webapp/services/auth_limiter.py`) — extend to a hard lockout after N
  failures with admin-visible unlock, and flag impossible-travel/new-device logins for
  audit visibility (not necessarily blocking, but logged).
- API authentication: separate long-lived API keys (hashed at rest, shown once on
  creation) for machine clients, distinct from user session tokens, each scoped to an
  organization and revocable (spec §18 requires audit of API key creation/revocation).

## 3. Authorization (RBAC)

Four roles (spec §17), enforced server-side on every mutating and every
tenant-scoped read endpoint:

| Role | Can |
|---|---|
| Admin | Everything within their organization: users, assets, connectors, monitoring config, scanning, alerts, remediation, risk acceptance, org settings |
| Security Manager | Assets, connectors, monitoring, scanning, alerts, remediation, risk acceptance — not user/role management |
| Security Analyst | View + triage findings, run scans, manage remediation tasks assigned to them — not org/user/connector admin |
| Viewer | Read-only across assets/findings/reports/dashboards |

Implementation: a single dependency/decorator checked in every route (FastAPI
`Depends`), not per-router copy-pasted logic — one place to audit, one place to fix.

## 4. Connector security (spec §6 — the platform's highest-stakes control)

- **Enrollment**: org admin generates a short-lived, single-use enrollment token in
  the platform UI; the connector process exchanges it once for a long-lived
  per-connector credential (asymmetric keypair generated on the connector, public key
  registered with the platform — private key never leaves the customer environment).
- **Job signing**: every job the platform sends is signed with the platform's job-
  signing key. Job payload: `job_id, organization_id, connector_id, job_type, scope,
  created_at, expires_at, authorization, signature`. The connector verifies signature,
  `organization_id`/`connector_id` match its own identity, `expires_at` has not
  passed, and `job_type`/`scope` are within what that connector is currently
  authorized for — rejecting and auditing anything that fails any check.
- **Allowlisted execution**: `job_type` maps to a fixed, closed set of functions
  (authorized inventory check, authorized configuration check, authorized
  vulnerability assessment, authorized security telemetry collection). No job field is
  ever passed to a shell, `eval`, or dynamic import. Adding a new job type requires a
  code change and review, not a data-driven capability.
- **Result signing**: the connector signs its result payload with its own private
  key; the platform verifies it before trusting the result.
- **State machine**: `ONLINE → DEGRADED` (missed N consecutive heartbeats) `→ OFFLINE`
  (missed timeout) and `ONLINE/DEGRADED/OFFLINE → REVOKED` (admin action, irreversible
  without re-enrollment). A revoked connector's credential is checked on every request
  — no caching window that honors a revoked credential.
- **Audit**: enrollment, every job sent, every job outcome (executed/rejected+reason),
  every heartbeat state transition, revocation — all audited with connector_id +
  organization_id.

## 5. Web scanning safety

- Non-destructive by construction: no scanner may perform state-changing writes
  against a target beyond what's needed to prove a vulnerability exists (e.g., a
  boolean/time-based SQLi probe, not a data-modifying payload). `ddos_tester.py` is
  reviewed explicitly for this (see THREAT_MODEL.md residual risks).
- SSRF self-protection: before any scanner issues a request, the resolved target IP
  is checked against a denylist (loopback, link-local incl. `169.254.169.254`,
  RFC1918, the platform's own DB/Redis/internal hosts) — re-checked per-request, not
  cached from asset creation, since DNS can change (DNS rebinding).
- Authorization re-check immediately before scan execution, not only at scheduling
  time (an asset can be de-authorized between scheduling and run).
- Evidence-based findings only: every finding requires `confidence` + `evidence` +
  `detection_method`; no finding is created from a single ambiguous signal without a
  corroborating check where feasible (spec §4: "only report a vulnerability when
  sufficient evidence exists").

## 6. Secrets management

- JWT signing secret, connector job-signing key, notification webhook
  tokens/credentials, DB credentials: sourced from environment/secrets manager, never
  committed. `.env.example` documents every required variable with placeholder values
  (ADD). `webapp/config.py::resolve_jwt_secret`'s fail-closed behavior (no default
  secret) is the pattern to replicate for every other secret.
- Logs never contain passwords, tokens, API keys, or connector private keys — enforced
  by convention + a grep-based CI check on log statements as a backstop (spec §18,
  §22).

## 7. Input validation & output encoding

- Every API input validated via Pydantic models with explicit types/constraints, not
  `dict`-typed bodies.
- All user-supplied content rendered in the frontend is encoded/escaped by default
  (no raw HTML injection from finding evidence, asset names, etc. — these fields can
  contain attacker-controlled strings scraped from a scanned target, so the dashboard
  itself must treat them as untrusted).
- File handling: no arbitrary file upload after APK removal removes the platform's
  only binary-upload surface; the one remaining upload (engagement letters) validates
  extension, magic bytes, and a hard size cap (10MB), and never executes or interprets
  uploaded content.
- HTTP response security headers (ADDED — this section was originally silent on it,
  gap closed during the Phase 19 WSTG audit): `Content-Security-Policy` scoped to
  the frontend's actual external dependencies (never a wildcard, and `script-src`
  carries no `unsafe-inline`), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY` + `frame-ancestors 'none'` (clickjacking), `Referrer-Policy:
  no-referrer`, a restrictive `Permissions-Policy`, `Strict-Transport-Security`, and
  `Cache-Control: no-store` on every `/api/*` response. See
  `docs/SECURITY_AUDIT_WSTG.md` F1.

## 8. Dependency, code, and supply-chain security (spec §21, §25)

- SAST (e.g. `bandit`/`semgrep` for Python) in CI on every PR.
- Dependency scanning (e.g. `pip-audit`/`safety`) in CI; fail on known-critical CVEs
  in direct dependencies.
- Secret scanning (e.g. `gitleaks`/`trufflehog`) in CI and as a pre-commit hook.
- Container scanning for the app image once a Dockerfile exists (spec §26).

## 9. Observability without leaking secrets (spec §22)

- Structured (JSON) logs for API/worker/connector events, correlated by
  request_id/job_id/organization_id.
- Health checks: `/healthz` (API), DB connectivity check, Redis/queue connectivity
  check, worker liveness (Celery heartbeat), scanner subprocess health where
  applicable, connector heartbeat freshness.
- Alert-delivery and scan-failure/duration/queue-depth metrics exported for the
  admin dashboard's own "system health" view — distinct from customer-facing findings.

This document will be re-checked item-by-item in `PRODUCTION_READINESS.md` at the end
of implementation, with each item marked READY / NEEDS REVIEW / BLOCKED.
