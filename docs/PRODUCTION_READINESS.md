# PRODUCTION_READINESS.md — HydraX CVM Platform

> **2026-09-29 — web frontend removed.** `webapp/static/` (the browser UI) and its
> `/app` and `/static` routes were deleted; `webapp/` is now an API-only backend and the
> desktop app (`ui/`) is the client. References to website pages below are historical.

Spec §29's final validation pass. Every component below is marked
**READY**, **NEEDS REVIEW**, or **BLOCKED**, per SECURITY_MODEL.md's closing
line: "This document will be re-checked item-by-item... with each item
marked READY / NEEDS REVIEW / BLOCKED."

**Read this legend before the tables below — it's load-bearing.** This
entire 17-phase transformation was built in a sandbox with no live
PostgreSQL, Redis, Docker, or SMTP server available. Two verification paths
were used throughout, and the distinction matters:

- **READY** = implemented, and verified either against real, unmocked
  execution (genuine Ed25519 crypto, a real local HTTP server for webhook
  delivery, real DNS resolution for the SSRF guard) or exhaustively via the
  hermetic `tests/conftest.py::FakeDB` suite (359 tests as of Phase 20,
  `python -m pytest -q`, zero known failures) *and* careful manual SQL/logic
  review.
- **NEEDS REVIEW** = implemented and reviewed with the same rigor, but its
  correctness ultimately depends on real infrastructure this sandbox
  couldn't provide (a live Postgres, a live Redis/Celery broker, a real
  Docker build, a real SMTP server, a real CI run). Nothing here is a guess
  — every one of these has a specific, named verification step in
  `docs/ROADMAP.md`'s phase-by-phase writeups (e.g.
  `scripts/ci_db_smoke_test.py` for the database layer) — it just hasn't
  been *run* yet against the real thing.
- **BLOCKED** = a genuine, currently-unimplemented gap that should be closed
  before relying on that specific capability.

Every phase's full implementation detail, including exact caveats and what
was deferred and why, lives in `docs/ROADMAP.md`. This document is the
summary judgment call, not a replacement for that detail.

**Update (Phase 19)**: a dedicated OWASP WSTG/ASVS/Top 10 audit was run
after this document was first written — full detail in
`docs/SECURITY_AUDIT_WSTG.md`. 11 real findings were fixed (password policy,
password storage work factor, a login timing side-channel, missing HTTP
security headers, error-message information disclosure in two places, an
XSS vector in generated reports, an unbounded file upload, and client-side
hardening) and are reflected in the tables below.

**Update (Phase 20)**: an independent, skeptical re-verification pass —
explicitly instructed *not* to assume Phase 19's findings were correct just
because tests passed — found and fixed **10 further issues** Phase 19
missed: two genuine race conditions (refresh-token rotation, connector job
dispatch, and a third in finding-deduplication), an SSRF vector in
notification-channel URLs Phase 19 never examined, a missing output schema
on an admin listing, a business-logic gap allowing an organization to lock
itself out of admin access, a connector-enrollment input-validation gap,
and two test-double (`FakeDB`) contract bugs — one of which meant a real
crash-causing bug in production code (`web_scan_service.py`'s finding
aggregation loop) had **zero test coverage** despite hundreds of passing
tests. Full detail, attack paths, CWE/WSTG/ASVS/Top-10 mapping, and what
remains explicitly unverified: `docs/SECURITY_VERIFICATION_REPORT.md`.

## 0. The founding mandate

**REMOVED: APK/mobile application scanning support, completely.** Verified
at the end of this phase, not just at the start: `git ls-files | xargs grep
-l -i "apk\|androguard"` across every tracked file returns only
documentation (`docs/ARCHITECTURE.md`/`ROADMAP.md`/`SECURITY_MODEL.md`
describing the removal itself, as expected), `utils/discovery.py`'s crawler
skip-list (a `.apk` binary-download extension to *not* fetch during web
crawling — unrelated to APK analysis), and one benign code comment in
`webapp/db.py`. No APK upload endpoint, no Android reverse-engineering, no
mobile scanner exists anywhere in the platform. **READY.**

## 1. Tenancy & data isolation (SECURITY_MODEL.md §1)

| Item | Status | Notes |
|---|---|---|
| `organization_id` on every security-sensitive table | READY | `organizations`/`roles` + org-scoped columns added Phase 2; every subsequent phase's new tables followed the same pattern from day one. |
| Every query derives org from session, never client input | READY | Every `db.get_X(id, organization_id)` function takes `organization_id` from the authenticated `user` dict, not a request body/query field — spot-checked across every router in Phase 13's hardening review. |
| Cross-tenant isolation has explicit automated tests | READY | Every phase from 2 onward added a cross-org 404 test for its new resource type; Phase 13's review confirmed no gaps in routers not already covered. |

## 2. Authentication (SECURITY_MODEL.md §2)

| Item | Status | Notes |
|---|---|---|
| Password hashing (PBKDF2-HMAC-SHA256, 600k iterations) | READY | Pre-existing algorithm choice (this document previously and incorrectly said "bcrypt" — corrected Phase 19), work factor raised from a decade-old 120,000 to 600,000 (ASVS V6.2.3) with a backward-compatible versioned hash format and opportunistic rehash-on-login (ASVS V6.2.4) — tested, including the legacy-hash compatibility path specifically. |
| Password policy (12-char minimum) | READY | Phase 19: raised from 6 characters, both registration and change-password, client and server side — tested. |
| Login timing side-channel (username enumeration) | READY | Phase 19: a nonexistent-user login now always pays the same PBKDF2 cost as a real one (dummy-hash comparison) — tested. |
| JWT access + refresh rotation, reuse detection | READY | Phase 3, hardened Phase 20. Reuse of a rotated-out refresh token revokes the whole token family — tested, including the race-condition fix (concurrent refresh of the same token could previously both succeed; now atomic). Never verified against real Postgres under genuine concurrent load — see `docs/SECURITY_VERIFICATION_REPORT.md` "Remaining risks" #1. |
| Role changes take effect immediately, no stale-JWT window | READY | Phase 20 review: authorization re-fetches the user's current role from the DB on every request (`current_user_from_token`), never trusts the JWT's own `role` claim — a demotion/lockout applies on the very next request. |
| MFA (TOTP) | READY | Phase 3. Two-step login with a distinct `mfa_pending` JWT claim `current_user_from_token` explicitly refuses as a bearer credential — tested. |
| Account lockout, admin-visible unlock | READY | Phase 3, tested. |
| API keys (hashed at rest, revocable, audited) | READY | Phase 3, tested. |
| Fail-closed JWT secret (no default) | READY | Pre-existing pattern (`resolve_jwt_secret`), kept and relied on by every later phase. |
| JWT algorithm confusion (`alg: none`) | READY | Phase 19 review: `jwt.decode(..., algorithms=[config.JWT_ALGO])` pins an explicit allowlist; PyJWT rejects anything else. |

## 3. Authorization / RBAC (SECURITY_MODEL.md §3)

| Item | Status | Notes |
|---|---|---|
| 4 roles, single `Depends`-based enforcement point | READY | Phase 3. `require_admin`/`require_operator`/`require_viewer`/`require_user` — no per-router copy-pasted role logic. |
| Every mutating/tenant-scoped route actually gated | READY | Spot-checked in Phase 13; full 71-route inventory re-verified in Phase 20 — every route has an auth dependency, none missing. |
| Admin-facing listings don't leak sensitive fields beyond an explicit allowlist | READY | Phase 20: `/api/settings/admin` had no explicit output schema (relied entirely on the underlying query staying safe, which it did, but with no schema-level backstop); now `AdminInfoOut`. |
| Role changes can't lock an organization out of its own admin access | READY | Phase 20: demoting an organization's last admin is now rejected — previously unguarded, an unrecoverable-without-DB-access state. |

## 4. Connector security (SECURITY_MODEL.md §4, spec §6 — highest-stakes control)

| Item | Status | Notes |
|---|---|---|
| Enrollment (short-lived single-use token → asymmetric keypair) | READY | Phase 8, hardened Phase 20: enrollment now explicitly rejects a non-Ed25519 public key (previously accepted silently, then permanently failed to ever verify — not a bypass, but a confusing failure mode closed at the one point a clear error is possible). Genuine Ed25519 keypairs in tests, not mocked. |
| Job signing + allowlisted `job_type` (closed enum, DB CHECK + Pydantic) | READY | Phase 8. No job field ever reaches a shell/eval/dynamic import — architecturally impossible, not just avoided. |
| Job dispatch is at-most-once per job | READY | Phase 20: `get_next_pending_job` previously had a claim race (two near-simultaneous polls could both receive the same job); now a single atomic `UPDATE ... FOR UPDATE SKIP LOCKED`. Never verified against real Postgres under genuine concurrent load. |
| Result signing, verified against the connector's own registered key | READY | Phase 8, real crypto round-trip tested. |
| State machine (ONLINE/DEGRADED/OFFLINE/REVOKED), live-computed | READY | `connector_state()` is a pure function computed at read time — never stored/stale. Revocation checked on every request, no caching window. |
| Audit trail (enrollment, job sent, outcome, heartbeat transitions, revocation) | READY | Phase 8 + Phase 12 closed the remaining gap (job-result submission/rejection now audited with `user_id=None` since Phase 12 made that column nullable for exactly this case). |
| Full agent ↔ platform protocol over a **real network** | NEEDS REVIEW | The crypto and the HTTP contract are both real and tested; what's never run is the actual `connector/agent.py` process polling a live, network-reachable HydraX instance end-to-end. `tests/test_phase8_connector_agent.py` exercises the agent's own logic directly, not over a socket. |

## 5. Web scanning safety (SECURITY_MODEL.md §5)

| Item | Status | Notes |
|---|---|---|
| Non-destructive scanning | READY | Pre-existing design, `ddos_tester.py` reviewed explicitly (see THREAT_MODEL.md). |
| SSRF self-protection, re-checked per-request (not cached) | READY | Phase 7. Real DNS resolution + `ipaddress` classification, tested with literal IPs (hermetic — no real network needed) directly against the guard; bypassed only in unrelated route-level tests via the shared `fake` fixture, documented as such. |
| Authorization re-checked immediately before execution | READY | Phase 7 (scans), Phase 10 (remediation verification scans) both re-check `verification_status`/`authorization_status` immediately before running, not only at scheduling time. |
| Evidence-based findings only (confidence + evidence required) | READY | Pre-existing + Phase 4's classification layer built on top without weakening it. |
| Argument-injection hardening on system-scan targets | READY | Phase 13 closed a real gap: an unvalidated target starting with `-` could be parsed as a CLI flag by a Kali tool. Now rejected by an RFC-1123 hostname regex before ever reaching a tool invocation. |

## 6. Secrets management (SECURITY_MODEL.md §6)

| Item | Status | Notes |
|---|---|---|
| No secrets committed; fail-closed JWT default | READY | Verified via `.gitignore` review + manual grep for credential-shaped strings in tracked files (Phase 13/16). |
| `.env.example` documents every required variable | READY | Phase 17. |
| Connector job-signing key configurable, safe throwaway default for dev | READY | Phase 8; a `RuntimeWarning` fires if left unset, so it can't be silently forgotten. |
| No secrets in logs | READY | Phase 13: grepped every `logger.*`/`print(` call site across `webapp/` for password/secret/token/api_key/private_key — zero hits. |
| Secret scanning actually run against this repo's real history | NEEDS REVIEW | `.github/workflows/ci.yml`'s `secret-scan` job (gitleaks) and `.pre-commit-config.yaml` are wired up (Phase 16), but gitleaks itself couldn't be installed/run in this sandbox to preview the result — first real run is whenever this branch's CI executes. |

## 7. Input validation & output encoding (SECURITY_MODEL.md §7)

| Item | Status | Notes |
|---|---|---|
| Pydantic models with explicit types/constraints, not raw `dict` bodies | READY | Consistent across every router added in every phase. |
| Frontend output encoding (no raw HTML injection from scanned-target data) | READY | Phase 13 reviewed every `innerHTML` call site in `webapp/static/js/*.js` — every attacker-influenceable field passes through a local `esc()`/`escHtml()` helper first. |
| File handling (engagement letters, reports) | READY | Phase 13 confirmed server-generated filenames (`target_{id}_{token}{ext}`) and an extension allowlist for uploads; report paths are never derived from request input. Phase 19 added a 10MB hard size cap (previously unbounded, a DoS gap) and closed a `javascript:`-URI XSS vector in generated HTML reports' finding-URL links. |
| HTTP response security headers (CSP/X-Frame-Options/etc.) | READY | Phase 19: previously entirely absent from every response. Now applied platform-wide via middleware — tested (header presence, CSP content, `/api/*` no-store). |

## Client-side security (WSTG-CLNT, spec §12 frontend)

| Item | Status | Notes |
|---|---|---|
| No inline `<script>` blocks (CSP `script-src` without `unsafe-inline`) | READY | Phase 19: the one remaining inline script (`login.html`) extracted to a static file — tested (grep-based regression lock, since a browser-CSP violation can't be observed through the API test client). |
| `target="_blank"` reverse-tabnabbing protection | READY | Phase 19: `rel="noopener noreferrer"` added to both `target="_blank"` links — tested. |
| Unauthenticated API schema exposure (`/docs`, `/openapi.json`) | NEEDS REVIEW | Phase 19: left enabled by default (documented tradeoff for legitimate integrators); operators wanting reduced pre-auth recon surface should set `HYDRAX_DISABLE_API_DOCS=1` before a security-sensitive deployment. |

## 8. Dependency, code, and supply-chain security (SECURITY_MODEL.md §8, spec §21/§25)

| Item | Status | Notes |
|---|---|---|
| SAST (bandit) | READY | Phase 16. Run locally against this exact codebase: clean at the CI gate's threshold (medium+ severity AND confidence) after fixing 5 real findings (predictable temp paths in `kali_tools.py`) and annotating 8 reviewed false positives. |
| Dependency scanning (pip-audit) | READY | Phase 16. Run locally: no known vulnerabilities in current `requirements.txt`. |
| Secret scanning in CI + pre-commit | NEEDS REVIEW | Wired up, not executable in this sandbox (see §6 above). |
| Container scanning (trivy) | NEEDS REVIEW | Phase 17 wired the CI job; the image itself has never been built (no Docker in this sandbox), so trivy has never actually run against it. |

## 9. Observability (SECURITY_MODEL.md §9, spec §22)

| Item | Status | Notes |
|---|---|---|
| Structured JSON logs, request/org-correlated | READY | Phase 14, tested (formatter output, contextvar propagation through the auth choke point, per-request middleware). |
| Real health checks (`/health`, `/healthz`) | READY | Phase 14. DB round-trip, Redis reachability, scan-queue liveness — each independently tested (ok/down paths via monkeypatching, not dependent on this sandbox's actual infrastructure state). |
| System-health metrics for the admin dashboard | READY | Phase 14, tested against FakeDB with real scan/alert data. |
| Metrics actually observed against a live, running deployment | NEEDS REVIEW | The check *logic* is real and tested; nobody has yet pointed it at a live Postgres/Redis pair to see the "ok" path fire for real (only the "down" path is exercised for real in this sandbox, since there's genuinely no Redis/Postgres here). |

## Core platform capabilities (beyond the security-model checklist)

| Capability | Status | Notes |
|---|---|---|
| Asset/organization model | READY | Phase 2. |
| Finding lifecycle + fingerprint dedup | READY | Phase 4, hardened Phase 20: dedup was a check-then-act race (two concurrent scans detecting the same vulnerability could both insert a duplicate row); now a single atomic `INSERT ... ON CONFLICT DO UPDATE` backed by a real unique index. FIXED→REOPENED auto-transition on re-detection — tested. Never verified against real Postgres under genuine concurrent load, and the migration that de-duplicates any pre-existing violations before adding the index has never run against populated data — see `docs/SECURITY_VERIFICATION_REPORT.md` "Remaining risks" #1-2. |
| Continuous monitoring scheduler (Redis + Celery) | NEEDS REVIEW | Phase 5. Task logic verified via direct function calls bypassing the broker (`tests/test_phase5_scheduler.py`'s `_check_due_scans(enqueue=None)` pattern); the actual broker round-trip has never run against live Redis. |
| Risk engine (5-factor composite, not CVSS passthrough) | READY | Phase 6, tested. |
| Real-time alerting (webhook/Slack/Teams/email) | READY (webhook/Slack/Teams) / NEEDS REVIEW (email) | Phase 9, hardened Phase 20: webhook/Slack/Teams destination URLs previously had zero SSRF validation — an org admin (or a compromised admin account) could point a channel at cloud metadata or the platform's own internal services and have the alert engine request it automatically. Now validated at channel-creation time and re-validated immediately before every delivery (DNS-rebinding defense). Webhook/Slack/Teams delivery itself tested against a genuine local HTTP server — a real network round-trip, not a mock. Email delivery is tested by mocking `smtplib.SMTP` — no real SMTP server was available in this sandbox. |
| Remediation workflow, structurally-enforced verification | READY | Phase 10. `update_remediation_task` raises on any direct attempt to set a verification-owned status — there's no code path, not even a bug, that skips a real re-scan before marking something fixed. Verification for non-web (system/network) findings is explicitly not wired up yet (documented `ValueError`, not a silent gap). |
| Real-data SOC dashboard | READY (backend) / NEEDS REVIEW (frontend) | Phase 11. Every field is a real, tested, org-scoped computation. `dashboard.html`/`dashboard.js` were never updated to *display* this phase's new fields (total assets, connector states, recent alerts) — they're correct and API-tested, just not yet rendered in the existing UI beyond what predates this phase. Not a fabricated-data concern; a UI-completeness gap. |
| Executive/technical reporting (PDF/CSV/JSON) | READY | Phase 11, tested including real PDF magic-byte verification. |
| Audit log completeness | READY (backend) / NEEDS REVIEW (frontend) | Phase 12. Every spec §18 action is audited, including three previously-impossible machine-actor events after making `user_id` nullable. `GET /api/settings/audit-log` exists and is tested; no admin-console UI page renders it yet (same boat as user/API-key management, which are equally backend-complete and UI-absent). |
| Platform hardening (SQLi/XSS/CSRF/SSRF/IDOR/etc.) | READY | Phase 13's full category-by-category review; see the SECURITY_MODEL.md table above for the two concrete fixes it produced. |
| API abuse / rate limiting | READY | Phase 13. Auth endpoints (pre-existing) + scan creation + report generation now rate-limited; noted as in-memory/per-process (a multi-worker deployment gets one limit per worker, not one global limit) — acceptable today, a Redis-backed limiter would be needed for a strict cross-process guarantee. |
| Safe test environment (Juice Shop/WebGoat/DVWA) | READY | Phase 15. Docs + compose fixture; deliberately does not weaken the SSRF guard to make scanning them more convenient. |
| CI/CD pipeline | NEEDS REVIEW | Phase 16. Fully defined (`test`/`sast`/`dependency-scan`/`secret-scan`/`container-scan`), `sast` and `dependency-scan` verified locally with real, clean results; the workflow itself has never executed inside GitHub Actions. |
| Deployment (Dockerfile, compose profiles, env config) | NEEDS REVIEW | Phase 17. Fully defined and documented; `docker build` has never run (no Docker in this sandbox) — the Dockerfile's own header names the exact command to verify every `kali_tools.py` tool actually resolves in the built image before first production use. |

## Before first production deployment — a concrete checklist

Everything marked **NEEDS REVIEW** above reduces to these concrete, one-time
actions:

1. Run `docker build -t hydrax .` for real; run the Dockerfile header's
   `kali_tools.tool_status()` check; fix any missing apt/go package names.
2. Push this branch and let `.github/workflows/ci.yml` actually run —
   confirms the real-Postgres smoke test, gitleaks, and trivy all pass for
   real, not just "should."
3. Stand up a real Redis + Celery worker/beat pair; verify
   `check_due_scans` actually enqueues and a worker actually consumes a job
   (Phase 5's task logic is tested, the broker round-trip isn't).
4. Configure real SMTP credentials and manually verify one alert email
   actually arrives (Phase 9's webhook/Slack/Teams paths don't need this —
   only email does).
5. Enroll one real Company Connector agent against a real, network-reachable
   HydraX instance — confirms the full protocol, not just its crypto and
   HTTP contract in isolation.
6. Set `HYDRAX_JWT_SECRET` (and every other required `.env` value) — the
   platform fails closed without it, which is correct, but it's a manual
   step every fresh deployment must not skip.
7. As a UI-completeness pass (not a correctness blocker): wire
   `dashboard.html`/`dashboard.js` to display Phase 11's new fields, and
   build the admin-console pages Phase 12 noted as absent (audit log
   viewer, user management, API-key management) — all three already have
   working, tested backend endpoints.
8. **(Phase 20)** Specifically exercise the two atomic-upsert rewrites
   (`webapp/db.py::rotate_refresh_token`, `add_finding`) against real
   Postgres under genuine concurrent load — e.g. two processes calling
   `/api/auth/refresh` with the same token simultaneously, and two
   concurrent scans against the same target detecting the same
   vulnerability — to prove the race conditions are actually closed by the
   real database, not just by the SQL reading correctly.
9. **(Phase 20)** If deploying behind `deploy/nginx.conf.example` (or any
   reverse proxy), set `HYDRAX_TRUSTED_PROXY_IPS` to that proxy's address —
   otherwise rate limiting silently degrades to one shared bucket for every
   real client. Verify with a real request through the real proxy that
   `X-Forwarded-For` is honored end-to-end.

None of these are "something is broken." They are, honestly, "this was
built and reviewed as rigorously as a sandbox with no live infrastructure
allows, and the remaining gap between that and production confidence is
exactly the list above" — which is the accurate answer, not an optimistic
one.
