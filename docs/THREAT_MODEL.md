# THREAT_MODEL.md — HydraX CVM Platform

Scope: the platform itself (webapp, connector, queue, DB), not the customer assets it
scans. Methodology: STRIDE per component/trust boundary. This is a living document —
update it whenever a new component crosses a trust boundary.

## Trust boundaries

```
[Internet] ── (1) ── [webapp API/UI] ── (2) ── [Postgres]
     │                      │
     │                     (3)
     │                      ▼
     │              [Redis + Celery queue]
     │                      │
     │                     (4)
     ▼                      ▼
[Customer admin        [Scan workers]
 browser]                    │
                             (5)
                              ▼
[Customer network] ── (6) ── [Company Connector agent] ── (7) ── [webapp API]
```

1. Public internet ↔ platform API/UI — untrusted input boundary.
2. Platform ↔ its own database — should never be reachable from (1) directly.
3. API ↔ queue — job payloads must not be attacker-influenced beyond authorized scope.
4. Queue ↔ scan workers — workers execute scans against **customer** infrastructure,
   which is itself a sensitive trust boundary (SSRF-adjacent: a compromised worker or
   a maliciously crafted asset URL must not be able to pivot into platform-internal
   networks).
5. Scan workers ↔ target web assets — outbound only, rate-limited, non-destructive.
6. Customer network ↔ connector — connector-initiated only (spec §5/§6 requirement:
   "DO NOT create unrestricted remote command execution").
7. Connector ↔ platform API — mutually authenticated, encrypted, job results signed.

## STRIDE by component

### Platform API/UI (boundary 1)
- **Spoofing**: session/token theft → mitigate with short-lived JWTs, token rotation,
  MFA, rate-limited/lockout-protected login (`webapp/services/auth_limiter.py` exists;
  extend to lockout + risk signals per §17).
- **Tampering**: request body/param tampering → strict Pydantic validation on every
  endpoint (already partial via `webapp/schemas.py`; extend to all new endpoints).
- **Repudiation**: a user denies performing an action → audit log (§18) with
  timestamp/user/organization/action/resource/resource_id/source/result, never
  soft-deletable by the acting user's own role.
- **Information disclosure**: cross-tenant data leakage is the #1 platform-specific
  risk given §16's multi-tenancy requirement — every query touching a
  security-sensitive table MUST filter by `organization_id` derived from the
  authenticated session, never from a client-supplied parameter. Enforce this with a
  single query-building layer/helper, not ad-hoc per-router filtering, and cover it
  with explicit cross-tenant-isolation tests (§16, §25).
- **Denial of service**: rate limiting on all API routes, not just login; queue depth
  monitoring so a burst of scan requests can't starve the worker pool.
- **Elevation of privilege**: RBAC checks must be enforced server-side on every
  mutating endpoint (Admin/Security Manager/Security Analyst/Viewer per §17) — never
  inferred from UI state. IDOR is explicitly in scope (§21): every object fetch by ID
  must re-check organization + role, not just existence.

### Database (boundary 2)
- **Tampering**: SQL injection — `webapp/db.py` already uses parameterized psycopg2
  queries; enforce this convention for every new query (no f-string SQL, ever) and add
  a lint/CI check (§25 SAST) that flags string-formatted SQL.
- **Information disclosure**: secrets (connector credentials, notification webhook
  URLs/tokens, JWT signing secret) must be encrypted at rest or stored via a secrets
  manager, never plaintext columns. `connector_credentials` table in particular.

### Queue / scheduler (boundary 3, 4)
- **Tampering**: a job payload must be constructed server-side from validated asset/
  org state, never from raw client input passed through to the worker.
- **Denial of service**: per-organization queue quotas so one tenant's aggressive
  monitoring frequency can't starve others' scheduled scans.
- **Elevation of privilege**: a scan worker for org A must never be able to read/write
  data belonging to org B — workers receive an explicit organization_id + asset scope
  in the job payload and must not trust any other source.

### Scan workers → target assets (boundary 5)
- **SSRF**: the scanner is *itself* an SSRF-capable tool by design (it makes attacker-
  directed HTTP requests) — the platform-specific risk is a target URL that resolves
  to platform-internal infrastructure (`169.254.169.254`, RFC1918 ranges, `localhost`,
  the platform's own DB/Redis hosts). Mitigate: resolve and validate the target's IP
  against a denylist *before* every outbound request the scan engine makes (not just
  at asset-creation time — DNS can change between authorization and scan), consistent
  with §4's requirement for "SSRF indicators using controlled verification" — the
  verification itself must not become an SSRF vector.
- **Destructive testing**: spec explicitly forbids destructive exploitation. Audit
  `scanners/ddos_tester.py` specifically — confirm it only measures resilience with
  bounded, safe request volumes and never actually degrades the target; consider
  gating it behind an explicit extra authorization flag distinct from general scan
  authorization, or removing it if it can't be made safely non-destructive.
- **Authorization drift**: an asset's authorization can be revoked after a scan is
  scheduled but before it runs — the worker must re-check `authorization_status`
  immediately before executing, not only at job-creation time.

### Company Connector (boundary 6, 7) — highest platform-specific risk
- **Spoofing**: a rogue process impersonating a legitimate connector → mutual auth at
  enrollment (enrollment token, short-lived, single-use, delivered out-of-band to the
  org admin) plus per-connector long-lived credential rotated on a schedule.
- **Tampering**: a compromised platform (or MITM) pushing malicious jobs to a
  connector → every job is signed by the platform's job-signing key; connector
  verifies signature + expiry + scope before executing anything, and rejects
  unsigned/expired/out-of-scope jobs (spec §6, explicit requirement).
- **Tampering (reverse)**: a compromised connector sending falsified results →
  results are signed by the connector's key so the platform can at least detect
  tampering in transit; treat connector-reported findings as lower initial confidence
  than platform-run scans until correlated.
- **Repudiation**: every connector action (job received, job executed, job rejected
  and why, heartbeat) is audited server-side, keyed by connector_id + organization_id.
- **Information disclosure**: connector credentials must never be logged; heartbeat/
  telemetry payloads must be scoped to what §5 actually asks for (health, version, OS,
  current job) — not a general telemetry/exfil channel.
- **Denial of service**: a connector that floods the platform with heartbeats/results
  must be rate-limited per-connector; a revoked connector's credential must be
  rejected immediately (no cache window that lets a revoked agent keep working).
- **Elevation of privilege — the core design constraint**: this is explicitly *not* a
  general remote-execution agent. The allowlisted job model (§6) is the primary
  control: `job_type` is drawn from a fixed enum (inventory check, configuration
  check, vulnerability assessment, telemetry collection), each with a declared
  `scope`; the connector-side executor must map `job_type` to a fixed, non-
  parameterized (or narrowly parameterized) function — never `eval`/`exec`/shell-out
  with job-supplied strings. This is the single most important control in the whole
  platform: a connector that can be tricked into running arbitrary commands turns a
  defensive product into a customer-network RCE vector, which would be a
  platform-ending incident for a security vendor.

## Abuse cases specific to being a security-testing product

- A malicious actor registers an asset they don't control, to use HydraX as a
  scanning proxy against a third party → `asset_authorizations` + a verification step
  (e.g., DNS TXT record or file-based proof, similar to the existing
  `webapp/routers/verification.py`) must gate any scan from running, not just gate the
  UI from showing a "scan" button.
- A customer's compromised account is used to add unauthorized assets or pull another
  org's data → covered by multi-tenancy isolation (above) + audit log + anomaly-worthy
  event (e.g., a burst of asset creations) surfaced to admins.

## Residual risks / accepted for v1 (revisit in ROADMAP)

- Full anomaly-detection on connector telemetry is out of scope for v1; only basic
  rate limiting + heartbeat-timeout → DEGRADED/OFFLINE state transition.
- Automatic exploit verification is intentionally limited to non-destructive checks;
  some vulnerability classes (e.g., certain RCE indicators) will be reported at lower
  confidence rather than actively verified, by design (spec §4: "do not perform
  destructive exploitation").
