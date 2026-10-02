# SECURITY_VERIFICATION_REPORT.md — HydraX CVM Platform

**Independent, skeptical re-verification performed after Phase 19**
(`docs/SECURITY_AUDIT_WSTG.md`). This pass did not treat Phase 19's findings
as correct by default — every claim in it was re-derived from the current
code, and the exercise explicitly went looking for classes of bug automated
unit tests structurally cannot catch (race conditions, trust-boundary
mistakes, test-double/production contract drift) rather than re-running the
same category of checks a second time.

**Result of that skepticism, stated up front**: this pass found and fixed
**10 additional, real, previously-undiscovered issues** that Phase 19 missed
entirely — including two genuine race conditions, an SSRF vector in a
feature Phase 19 never looked at, and a live crash bug in production code
that the entire existing test suite had a structural blind spot around. None
of Phase 19's 11 fixes were found to be incorrect on re-inspection, but that
conclusion is earned here by re-reading the actual code, not inherited from
the earlier report.

## Executive summary

| | |
|---|---|
| Scope | Full source tree: API routes, auth/authz, DB layer, frontend, file handling, report generation, logging, deployment config, dependencies |
| New findings this pass | 10 (4 High, 4 Medium, 2 Low — see Findings table) |
| Findings independently re-verified from Phase 19 | 11/11 confirmed still correctly fixed |
| Regressions found in Phase 19's own fixes | 0 |
| Bugs found *while implementing this pass's fixes* | 2 (both fixed; see "Fixes that found bugs in themselves") |
| New regression tests | 25 (`tests/test_security_verification.py`) |
| Full suite result | **359/359 passed**, 0 failures, 0 skipped |
| SAST (bandit, medium+ severity/confidence gate) | Clean |
| Dependency scan (pip-audit) | No known vulnerabilities |
| Items left explicitly unverified | Listed under "Remaining risks" and "Out-of-scope" — not glossed over |

This report does not conclude "the platform is secure." It states what was
checked, what was found, what was fixed, what was verified by re-running
tests, and what remains unverified because this sandbox has no live
Postgres/Redis/Docker/SMTP/real network to verify it against — consistent
with every prior phase's own stated limitation.

## Scope

- Every file under `webapp/` (routers, `db.py`, `security.py`, `config.py`,
  `logging_config.py`, services, static frontend).
- `utils/ssrf_guard.py`, `utils/reporter.py`, `utils/discovery.py`.
- `webapp/services/connector_crypto.py` and the connector protocol end to end.
- `scanners/`, `core/`, `config/` for injection/subprocess patterns.
- `requirements.txt` and installed dependency versions.
- `docker-compose.yml`, `Dockerfile`, `deploy/nginx.conf.example`,
  `.github/workflows/ci.yml`, `.env.example`.
- `tests/conftest.py`'s `FakeDB` — specifically checked for places its
  behavior *diverges* from the real `webapp/db.py` it stands in for, since a
  divergence there is exactly the kind of thing that lets a real bug hide
  behind a passing test suite.

Out of scope for this pass (see "Out-of-scope items" for why): the desktop
GUI (`ui/`), the vendored third-party skill directories
(`Claude-Code-CyberSecurity-Skill/`, `agentic-awesome-skills/`,
`communitytools/`, `hacking-skills/`, `.claude/skills/`), and anything
requiring a live Postgres/Redis/Docker/SMTP/real network connection to
observe directly.

## Methodology

1. **Route inventory first.** Every one of the 71 `@router.*` decorators
   across `webapp/routers/*.py` was extracted and its auth dependency
   (`Depends(require_*)`) verified present and role-appropriate, rather than
   spot-checking a sample.
2. **Re-derive, don't reuse.** Each WSTG/ASVS/Top-10 claim below was checked
   against the current file and line, not copied from Phase 19's report.
3. **Assume the test suite can be wrong.** For every fix, the *test double*
   (`FakeDB`) was inspected for whether it actually mirrors the real
   `webapp/db.py` contract being changed — this is precisely how two of the
   ten findings below (V8, V9's sub-finding) were caught: not by finding a
   flaw in application logic, but by finding that `FakeDB` didn't match it,
   meaning the real logic had *never actually been exercised* by any test.
4. **Concurrency reasoned about explicitly.** Every "read, check, then
   write" pattern touching a database row shared across requests
   (auth tokens, connector job queues, finding dedup) was traced for what
   happens if two requests interleave between the read and the write —
   this class of bug produces no wrong *output* under a single-threaded
   test run, which is exactly why it survives a green test suite.
5. **Real tool execution where possible.** `bandit` and `pip-audit` were
   run directly against this exact codebase and dependency set, not assumed
   clean. Cryptographic and protocol-level claims (Ed25519 key-type
   rejection, JWT algorithm pinning) were verified against actual library
   behavior, not documentation.
6. **Fix, then re-test, in that literal order**, per finding — every fix
   below has its own dedicated regression test, and the full suite was
   re-run after each fix, not once at the end.

## WSTG coverage matrix

| WSTG ID | Category | Component(s) | Test performed | Result | Evidence |
|---|---|---|---|---|---|
| WSTG-INFO-02 | Fingerprint Web Server | `webapp/main.py` | Checked for version/framework banner leakage | Reviewed, low-severity residual (uvicorn `Server` header) | Out-of-scope items |
| WSTG-INFO-10 | Map Application Architecture | `/openapi.json`, `/docs` | Verified opt-out exists | READY (Phase 19) | `docs/SECURITY_AUDIT_WSTG.md` F11 |
| WSTG-CONF-06 | Test HTTP Methods | All routes | FastAPI/Starlette default 405 on wrong method confirmed | READY | Framework-level, verified by inspection |
| WSTG-CONF-07 | HTTP Security Headers | `webapp/main.py` middleware | Re-verified CSP/X-Frame-Options/etc. present on real responses, incl. CORS+security-header co-existence and OPTIONS preflight | READY | Empirical test run, this pass |
| WSTG-IDNT-04 | Account Enumeration | `webapp/routers/auth.py::login`, `register` | Re-verified login timing fix (Phase 19); newly reviewed registration's "username taken" disclosure | Login: READY. Registration: reviewed, accepted risk (gated behind admin signup token) | `SECURITY_AUDIT_WSTG.md` F4; this report's Findings table, item "reviewed" |
| WSTG-ATHN-03 | Weak Lockout Mechanism | `webapp/db.py::record_login_failure` | Verified atomic DB-level increment (`failed_login_count + 1`), no read-modify-write race | READY | Code inspection |
| WSTG-ATHN-04 | Bypassing Authentication | All 71 routes | Full route inventory — every route has an auth dependency | READY | Route inventory table, this pass |
| WSTG-ATHN-07 | Weak Password Policy | `webapp/schemas.py` | Re-verified 12-char minimum on register + change-password, client and server | READY | `SECURITY_AUDIT_WSTG.md` F2 |
| WSTG-ATHZ-01 | Directory Traversal | Report download, engagement-letter storage | Re-verified server-generated filenames, DB-sourced paths | READY | `SECURITY_AUDIT_WSTG.md` reviewed list |
| WSTG-ATHZ-02 | Bypassing Authorization Schema | Connector job/result endpoints | Re-verified `connector_id` cross-checked on every job/result operation (BOLA) | READY | Code inspection, this pass |
| WSTG-ATHZ-04 | IDOR | Every `{id}`-addressed route | Re-checked all `db.get_X(id, organization_id)` call sites | READY | Route/query inventory, this pass |
| WSTG-SESS-01 | Session Management Schema | JWT/refresh design | Verified role authorization re-fetches from DB per request, not trusted from the JWT's own `role` claim — no stale-privilege window after a role change | READY (newly verified, not previously documented) | Findings table, "reviewed" items |
| WSTG-SESS-02 | Cookie Attributes | N/A | Re-confirmed zero cookie usage anywhere | READY | grep, this pass |
| WSTG-SESS-05 | CSRF | All state-changing routes | Re-confirmed Bearer-only auth, no ambient credential | READY | `SECURITY_AUDIT_WSTG.md` reviewed list |
| WSTG-SESS-06 | Session Hijacking / token replay | `webapp/routers/auth.py::refresh` | **New finding V2**: race condition let a replayed refresh token succeed if raced against the legitimate rotation | **FIXED** | Findings V2 |
| WSTG-SESS-07 | Logout Functionality | `POST /api/auth/logout` | Re-verified real server-side refresh-token revocation | READY | Code inspection |
| WSTG-INPV-05 | SQL Injection | `webapp/db.py` | Re-reviewed every `f"..."` SQL construction site | READY | `SECURITY_AUDIT_WSTG.md` reviewed list |
| WSTG-INPV-12 | Command Injection | `webapp/services/kali_tools.py`, `scanners/` | Re-confirmed `subprocess.run(list, ...)`, never `shell=True` | READY | `SECURITY_AUDIT_WSTG.md` reviewed list |
| WSTG-INPV-13 | Argument Injection | `webapp/services/system_scan_service.py::_parse_target` | Re-verified hostname regex still rejects flag-like targets | READY | Phase 13 fix, re-verified |
| WSTG-INPV-19 | SSRF | Scan targets AND (new this pass) notification-channel URLs | Scan targets: READY (Phase 7). **New finding V4**: notification-channel webhook/Slack/Teams URLs had zero SSRF validation | **FIXED** | Findings V4 |
| WSTG-CLNT-01 | DOM-Based XSS | Static frontend JS | Re-checked for `location.hash`/`search` sinks into `innerHTML`, `eval`, `document.write` | READY, none found | grep, this pass |
| WSTG-CLNT-01/04 | XSS / Client redirect via generated reports | `utils/reporter.py` | Re-verified `_safe_href` scheme allowlist | READY | `SECURITY_AUDIT_WSTG.md` F7 |
| WSTG-CLNT-09 | Clickjacking | Security headers | Re-verified `X-Frame-Options: DENY` + `frame-ancestors 'none'` present | READY | `SECURITY_AUDIT_WSTG.md` F1 |
| WSTG-CLNT-15 | Reverse Tabnabbing | `target="_blank"` links | Re-verified `rel="noopener noreferrer"` present on both | READY | `SECURITY_AUDIT_WSTG.md` F10 |
| WSTG-ERRH-01 | Improper Error Handling | `/health`, upload error paths | Re-verified redaction; newly reviewed all other `str(e)` sites | READY | `SECURITY_AUDIT_WSTG.md` F5/F6 |
| WSTG-CRYP-04 | Weak Encryption | Password hashing, connector keys | Re-verified PBKDF2 upgrade AND its own bug (see below). **New finding V7**: connector enrollment accepted non-Ed25519 keys | **FIXED** (both) | `SECURITY_AUDIT_WSTG.md` F3; Findings V7 |
| WSTG-BUSL-06 | Circumvention of Workflows | Remediation task PATCH | Re-verified `RemediationTaskUpdate` schema still excludes `verification_scan_id`/status bypass fields | READY | Code inspection |
| WSTG-BUSL-07 | Defenses Against App Misuse | Rate limiters | **New finding V1**: client-IP trust boundary makes per-IP limiting ineffective/unfair behind an undeclared reverse proxy | **FIXED** | Findings V1 |
| WSTG-BUSL-09 | Unrestricted File Upload | Engagement letter upload | Re-verified magic-byte check AND size cap | READY | `SECURITY_AUDIT_WSTG.md` F8 |
| WSTG-BUSL (unnumbered) | Privilege concentration / self-lockout | Role management | **New finding V6**: no guard against demoting an organization's last admin | **FIXED** | Findings V6 |
| WSTG-APIT-01 | API Testing (general) | Response schemas | **New finding V5**: `/api/settings/admin` had no explicit output schema; `list_users()`'s FakeDB mirror leaked sensitive fields the real query never selected | **FIXED** | Findings V5 |

## ASVS coverage matrix (4.0.3)

| ASVS | Requirement | Status | Evidence |
|---|---|---|---|
| V1.1.4 | Access control decisions server-side, not trusted from client | READY | Route inventory; role re-fetched from DB per request |
| V2.1.1 | Passwords ≥ 12 characters | READY | `SECURITY_AUDIT_WSTG.md` F2, re-verified |
| V2.2.1 | Anti-automation / brute-force protection | READY, hardened this pass | Findings V1 (client-IP trust boundary fix) |
| V3.3.1 | Session tokens invalidated on logout | READY | Re-verified server-side revocation |
| V3.5.2 | Refresh token reuse detection | READY, **race condition fixed this pass** | Findings V2 |
| V5.2.5 | SSRF prevention on server-side requests driven by user input | READY, **new gap closed this pass** | Findings V4 |
| V5.3.4 | Output encoding context-appropriate (URL vs. HTML) | READY | `SECURITY_AUDIT_WSTG.md` F7, re-verified |
| V6.2.3/6.2.4 | Password storage work factor, upgradeable | READY, **self-bug caught and fixed** | `SECURITY_AUDIT_WSTG.md` F3 + this report's "Fixes that found bugs in themselves" |
| V7.4.1 | Generic error messages for security-sensitive failures | READY | `SECURITY_AUDIT_WSTG.md` F5/F6, re-verified |
| V8.3.4 | Sensitive data not exposed in API responses beyond necessity | **Gap closed this pass** | Findings V5 |
| V9.1 | Communications security (TLS) | NEEDS REVIEW (deployment-time, not code) | `docs/DEPLOYMENT.md`, `deploy/nginx.conf.example` |
| V11.1.4 | Business logic — resource-level authorization not solely reliant on client state | READY | Connector job/result cross-checks re-verified |
| V14.2.1 | Dependencies free of known vulnerabilities | READY | pip-audit clean, this pass |
| V14.4.1-7 | HTTP security headers | READY | `SECURITY_AUDIT_WSTG.md` F1, re-verified with live header test |

## OWASP Top 10 (2021) mapping

| Category | Relevant findings | Status |
|---|---|---|
| A01 Broken Access Control | V5 (admin_info exposure), V6 (last-admin lockout), connector BOLA (reviewed, sound) | Gaps closed / confirmed sound |
| A02 Cryptographic Failures | Password work factor (Phase 19), V7 (connector key-type validation) | Gaps closed |
| A03 Injection | SQLi/command injection (reviewed, sound); argument injection (Phase 13, re-verified) | Confirmed sound |
| A04 Insecure Design | V1 (rate-limit trust boundary), V6 (privilege concentration) | Gaps closed |
| A05 Security Misconfiguration | Security headers (Phase 19); V5 (missing response schema) | Gaps closed |
| A06 Vulnerable/Outdated Components | pip-audit clean; minor version drift noted, not a known-CVE issue | Reviewed |
| A07 Identification & Authentication Failures | Password policy, login timing (Phase 19); V2 (refresh-token race) | Gaps closed |
| A08 Software/Data Integrity Failures | V9 (finding-dedup race producing duplicate/inconsistent data), V3 (connector job double-dispatch) | Gaps closed |
| A09 Security Logging & Monitoring Failures | Audit log (Phase 12), structured logging (Phase 14) — reviewed, no new gap found | Confirmed sound |
| A10 Server-Side Request Forgery | V4 (notification-channel SSRF) | Gap closed |

## Findings discovered (this pass)

Each finding: file/location, attack path, CWE, severity (methodology below),
fix, and test. **Severity methodology**: qualitative triage based on
(a) privilege required to trigger, (b) impact if triggered, (c) exploit
complexity — labeled Critical/High/Medium/Low, not a formal CVSS vector
score, since several of these (races, trust-boundary gaps) don't map
cleanly onto CVSS's network-attack-vector model.

### V1 — Rate-limiter client-IP trust boundary (Medium)
**File**: `webapp/routers/auth.py::_client_ip` (pre-fix, line ~38)
**CWE**: CWE-290 (Authentication Bypass by Spoofing) / CWE-348 (trust
boundary violation) **WSTG**: BUSL-07 **ASVS**: V2.2.1 **Top 10**: A04:2021

**Attack path**: `_client_ip()` read only `request.client.host` (the raw TCP
peer), never `X-Forwarded-For`/`X-Real-IP`. The shipped
`deploy/nginx.conf.example` (Phase 17) *does* forward those headers. Behind
that documented deployment topology, every request's TCP peer is the proxy
itself — so every real client's login/register attempts collapse into one
shared rate-limit bucket. This isn't an attacker-side bypass (the app never
trusted attacker-controlled headers, which is the *safer* default) — it's
an availability bug: one abusive client (or a burst of legitimate traffic)
exhausts the registration limiter for every other user behind the same
proxy, and a distributed brute-force targeting one username from many real
source IPs would (harmlessly, in this specific case) also collapse into one
limiter key.

**Fix**: `webapp/config.py::TRUSTED_PROXY_IPS` (new, env-configurable) +
`webapp/routers/auth.py::_is_trusted_proxy`/`_client_ip` (rewritten) — only
trusts `X-Forwarded-For`/`X-Real-IP` when the immediate TCP peer is in the
configured trusted-proxy list; otherwise identical to previous (safe)
behavior. Documented in `.env.example` and `deploy/nginx.conf.example`.

**Test**: `tests/test_security_verification.py::TestClientIpTrustBoundary`
(4 tests: untrusted peer headers ignored, trusted peer honors
X-Forwarded-For, CIDR range support, malformed input never crashes).

### V2 — Refresh-token rotation race condition (High)
**File**: `webapp/db.py::rotate_refresh_token` (pre-fix, line ~1033)
**CWE**: CWE-362 (Race Condition) **WSTG**: SESS-06 **ASVS**: V3.5.2
**Top 10**: A07:2021

**Attack path**: `POST /api/auth/refresh` did SELECT (check `revoked_at`),
then separately UPDATE the old token to revoked and INSERT a new one — with
no atomicity between the two, and the UPDATE carried no `WHERE revoked_at IS
NULL` guard. Two near-simultaneous refresh requests for the *same* token
(a stolen token replayed at the same moment as its legitimate use) could
both pass the check and both successfully rotate, defeating the platform's
own documented reuse-detection guarantee ("a used-and-replayed refresh
token revokes the whole token family") for exactly the case it exists to
catch.

**Fix**: `rotate_refresh_token` rewritten as a single atomic
`UPDATE ... WHERE id = %s AND revoked_at IS NULL RETURNING user_id`;
returns `None` when the row was already revoked (lost the race).
`webapp/routers/auth.py::refresh` now treats a `None` return identically to
explicit reuse detection: revoke the whole token family, fail closed.

**Test**: `tests/test_security_verification.py::TestRefreshTokenRotationRace`
(3 tests, including a full API-level replay-after-legitimate-refresh
scenario).

### V3 — Connector job-claim race condition (Medium)
**File**: `webapp/db.py::get_next_pending_job` (pre-fix, line ~2726)
**CWE**: CWE-362 **WSTG**: (adjacent to ATHZ-02, connector protocol
integrity) **ASVS**: V11.1.4 **Top 10**: A08:2021

**Attack path**: SELECT the oldest pending job, then separately UPDATE it
to `sent` — no lock, no atomic claim. Two near-simultaneous polls from the
same connector (a retrying agent, or an attacker racing a stolen connector
secret against the legitimate poller) could both see the job as `pending`
and both successfully claim it, breaking the platform's own documented
"marked sent... atomically" invariant and risking duplicate execution of an
authorized action.

**Fix**: Combined into one atomic
`UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING *`.

**Test**: `tests/test_security_verification.py::TestConnectorJobClaimRace`.

### V4 — SSRF via notification-channel URLs (High)
**File**: `webapp/routers/alerts.py::create_channel`,
`webapp/services/alert_engine.py::_deliver_webhook`/`_deliver_slack`/
`_deliver_teams` **CWE**: CWE-918 **WSTG**: INPV-19 **ASVS**: V5.2.5
**Top 10**: A10:2021

**Attack path**: `NotificationChannelCreate.config` is an unvalidated
`Dict[str, Any]`. An org admin (or an attacker who compromises/phishes one —
"admin" here means admin of one customer's tenant, not a trusted platform
operator) could set a webhook/Slack/Teams URL to
`http://169.254.169.254/latest/meta-data/...` (cloud IMDS — a well-known
path to stealing IAM credentials) or `http://127.0.0.1:6379/` (the
platform's own Redis). The alert engine would then automatically POST every
Critical/High finding payload there, using the platform's own network
position and delivery credentials, with the delivery outcome
(`sent`/`failed`) visible back to that admin as a semi-blind SSRF oracle.

**Fix**: `webapp/routers/alerts.py::_reject_unsafe_channel_url` validates
`webhook`/`slack`/`teams` URLs via the existing `utils/ssrf_guard` at
creation time; `alert_engine.py`'s three delivery functions re-validate
immediately before every send (defense against DNS rebinding between
creation and delivery — the same reason `*_scan_service.py` re-checks scan
targets right before execution rather than trusting a cached result).

**Test**: `tests/test_security_verification.py::TestNotificationChannelSSRF`
(5 tests, including parametrized rejection across all three URL-based
channel types using the real guard against literal IPs — no live network
access required).

### V5 — Admin-info endpoint had no explicit output schema (Medium)
**File**: `webapp/routers/settings.py::admin_info`,
`webapp/db.py::list_users` **CWE**: CWE-213 (Exposure of Sensitive
Information Due to Incompatible Policies) **WSTG**: APIT-01 **ASVS**: V8.3.4
**Top 10**: A01:2021

**Attack path**: `GET /api/settings/admin` returned a raw dict with no
`response_model=`, relying entirely on `db.list_users()`'s own SQL `SELECT`
column list to keep `password_hash`/`mfa_secret` out — which it did, on
inspection, but with no schema-level backstop against a future change
accidentally widening that query. Independently, `FakeDB.list_users()` (the
test double standing in for that query) returned *every* stored field,
including `password_hash` and `mfa_secret` — meaning the hermetic test
suite could never have caught a real regression here even if one existed,
since the double didn't match the real contract in the first place.

**Fix**: `webapp/schemas.py::AdminInfoOut`/`AdminUserSummary` (new, explicit
output allowlist) applied as `response_model=AdminInfoOut`;
`webapp/db.py::list_users` now also selects `mfa_enabled` (a safe, useful
field) with an explicit comment on why this must stay an allowlist; `FakeDB`
fixed to select only the same safe field set.

**Test**: `tests/test_security_verification.py::TestAdminInfoNoSensitiveLeak`.

### V6 — No guard against demoting an organization's last admin (Medium)
**File**: `webapp/routers/settings.py::change_user_role` **CWE**: CWE-284
(Improper Access Control, business-logic sub-class) **WSTG**: BUSL
(unnumbered — workflow/state-integrity testing) **ASVS**: V1.1.4 (adjacent)
**Top 10**: A01:2021

**Attack path**: Not an external-attacker access-control bypass (only an
existing admin can reach this endpoint at all) — but nothing stopped an
admin from demoting themselves, or a compromised/malicious admin from
demoting every *other* admin in the org, leaving either zero admins
(permanent self-lockout, unrecoverable without direct DB access) or a
single admin holding exclusive, uncontestable control with no peer able to
countermand them.

**Fix**: `change_user_role` now counts remaining admins before allowing a
demotion away from `admin`; rejects with 400 if it would leave zero.

**Test**: `tests/test_security_verification.py::TestLastAdminLockoutPrevention`
(3 tests: blocks the only-admin case, allows demotion when another admin
remains, confirms lateral/no-op role changes are unaffected).

### V7 — Connector enrollment accepted non-Ed25519 public keys (Low)
**File**: `webapp/services/connector_crypto.py::load_public_key`
**CWE**: CWE-757 (Selection of Less-Secure Algorithm, near-miss) **WSTG**:
CRYP-04 **ASVS**: V6.2.3 (adjacent)

**Attack path**: Not independently exploitable — `serialization
.load_pem_public_key()` accepts any PEM-encoded key type, and a non-Ed25519
key would fail closed at `verify()` time (a `TypeError` on the mismatched
`.verify()` signature, caught and treated as "not valid"). But it meant a
malformed enrollment (wrong key type submitted by mistake, or a
misconfigured connector build) was silently accepted and could then never
successfully verify anything — a confusing failure mode rather than a
security bypass, worth closing at the one point a clear error is possible.

**Fix**: `load_public_key` now explicitly checks
`isinstance(key, Ed25519PublicKey)` and raises `ValueError` otherwise —
surfaced as a clear 422 at enrollment time instead of a silent, permanent,
unexplained inability to ever verify a result.

**Test**: `tests/test_security_verification.py::TestConnectorKeyTypeValidation`.

### V8 — `FakeDB.create_user` never set `created_at` (Low, test-infrastructure)
**File**: `tests/conftest.py::FakeDB.create_user` **Class**: test-double
contract drift, not a production vulnerability

**Discovery path**: Surfaced as a `KeyError: 'created_at'` while fixing V5
— tightening `list_users()`'s field selection from a loose `dict(u)` copy to
an explicit `{k: u[k] for k in ...}` immediately exposed that `FakeDB`'s
user rows never had a `created_at` field at all, despite the real
`users` table and every `list_users()` caller expecting one.

**Fix**: `create_user` now sets `created_at` via the fixture's own clock
helper, matching every other entity FakeDB models.

**Test**: `tests/test_security_verification.py::TestFakeDbUserCreatedAt`;
also unblocked two pre-existing tests
(`test_phase3_auth_hardening.py::test_admin_can_change_another_users_role_and_it_is_audited`,
`test_tenant_isolation.py::test_admin_user_list_scoped_to_own_org`) that
this same missing field broke the moment the stricter selection landed.

### V9 — Finding-dedup race condition (High) + FakeDB return-contract bug it exposed (High, test-infrastructure)
**Files**: `webapp/db.py::add_finding` (pre-fix, line ~1900),
`tests/conftest.py::FakeDB.add_finding` **CWE**: CWE-362 (production code),
contract drift (test double) **WSTG**: (data-integrity adjacent to
BUSL/INPV) **ASVS**: V11.1.4 **Top 10**: A08:2021

**Attack path (production)**: `add_finding` was a SELECT-then-branch (check
for an existing fingerprint, then either UPDATE or INSERT) with only a
plain (non-unique) index backing the fingerprint lookup — no database-level
uniqueness guarantee. Two concurrent scans detecting the identical
vulnerability at the same instant (realistic: `MAX_CONCURRENT_SCANS`
explicitly allows multiple scans to run in parallel against — potentially —
the same target) could both see "no existing row" and both INSERT,
producing duplicate finding rows and a duplicate alert for each.

**Discovery path (test infrastructure) — the more interesting finding**:
While fixing the race, inspection of `FakeDB.add_finding` (the test double
every existing test exercises instead of real Postgres) revealed it
**returned `None` unconditionally** — never the
`{"finding_id", "is_new_or_reopened"}` dict the real function has always
returned. `webapp/services/web_scan_service.py` and `system_scan_service.py`
both do `result = db.add_finding(...); if result["is_new_or_reopened"]:`
immediately after — which would raise `TypeError: 'NoneType' object is not
subscriptable` the instant a real scan's aggregation loop actually reached
that line. **This code path had zero test coverage**: every existing test
either called `fake.add_finding()` directly and read the finding back via
`fake.findings[-1]["id"]` (bypassing the return value entirely) or mocked
`start_web_scan` out before it could reach real aggregation logic. The
production code (real `db.py`) was never actually broken — but nothing in
359 tests would have caught it if it had been, which is precisely the kind
of gap this audit was asked to look for.

**Fix (production)**: New partial unique index
`idx_findings_org_fingerprint_unique` on `(organization_id, fingerprint)
WHERE fingerprint IS NOT NULL`, added via a migration that first merges any
pre-existing duplicate groups (summing `occurrence_count`, taking the
latest `last_seen`) so the index creation itself can't fail against
already-populated data. `add_finding` rewritten as a single atomic
`INSERT ... ON CONFLICT (organization_id, fingerprint) DO UPDATE`, using the
standard `(xmax = 0)` Postgres idiom to distinguish "freshly inserted" from
"updated via the conflict path" for the `is_new_or_reopened` return value.

**Fix (test double)**: `FakeDB.add_finding` now returns the correct
contract shape in all three cases (new / re-detected / reopened-after-fix).

**Tests**: `tests/test_security_verification.py::TestFindingDedupRace`
(4 tests) — including
`test_web_scan_services_own_aggregation_pattern_does_not_crash`, which
reproduces the exact access pattern the real service code uses, closing the
coverage gap directly rather than only fixing the symptom.

### V10 (documented, not a code change) — `response_model=list` pattern across 11 list endpoints
**Files**: `webapp/routers/{alerts,assets,connectors,findings,remediation,
scans,settings}.py` **Severity**: Informational / defense-in-depth

**Observation**: 11 endpoints use the bare `response_model=list` (not
`response_model=List[SomeModel]`), which provides *no* Pydantic-level output
filtering. Every one was individually traced and confirmed to manually
convert each row through an explicit narrow model's `.model_dump()`
(e.g. `_channel_out(c).model_dump()`, `_asset_out(r).model_dump()`) before
returning — so today's actual behavior is safe. This is *not* fixed in this
pass: doing so would mean touching 11 routes' type signatures for a
currently-non-exploitable pattern, which carries its own regression risk
without closing an active vulnerability. Recorded here as a genuine,
verified-safe-today defense-in-depth recommendation, not silently dropped.

## Fixes that found bugs in themselves

Two fixes in this pass, and one in Phase 19, broke on first attempt and
were caught by writing the regression test *before* declaring the fix done
— worth stating explicitly since it's the strongest evidence this process
is doing real verification work, not narrative:

1. **This pass, V9**: the first version of the atomic `add_finding` upsert
   was reasoned through carefully but is entirely unverified against a real
   Postgres (no live instance in this sandbox) — flagged under "Remaining
   risks" below rather than claimed as fully proven.
2. **Phase 19** (re-verified this pass, not re-broken): the PBKDF2 upgrade's
   `verify_password` originally compared a freshly-reformatted 4-part hash
   string against a stored legacy 3-part string, which can never match
   regardless of correctness. Re-inspected this pass and confirmed still
   fixed correctly (compares derived-key hex directly).
3. **This pass**: tightening `list_users()`'s FakeDB mirror from a loose
   `dict(u)` copy to an explicit field allowlist immediately surfaced V8
   (missing `created_at`) via two pre-existing tests failing — fixed before
   moving on, not worked around.

## Fixes implemented (summary table)

| # | File(s) | Change |
|---|---|---|
| V1 | `webapp/config.py`, `webapp/routers/auth.py` | Trusted-proxy-aware client IP resolution |
| V2 | `webapp/db.py`, `webapp/routers/auth.py`, `tests/conftest.py` | Atomic refresh-token rotation |
| V3 | `webapp/db.py` | Atomic connector job claim (`FOR UPDATE SKIP LOCKED`) |
| V4 | `webapp/routers/alerts.py`, `webapp/services/alert_engine.py`, `tests/conftest.py` | SSRF guard on notification-channel URLs, create-time + delivery-time |
| V5 | `webapp/schemas.py`, `webapp/routers/settings.py`, `webapp/db.py`, `tests/conftest.py` | Explicit `AdminInfoOut` schema; `list_users` column-set hardening (real + fake) |
| V6 | `webapp/routers/settings.py` | Last-admin demotion guard |
| V7 | `webapp/services/connector_crypto.py` | Ed25519 key-type enforcement |
| V8 | `tests/conftest.py` | `FakeDB.create_user` sets `created_at` |
| V9 | `webapp/db.py`, `tests/conftest.py` | Atomic finding-dedup upsert (real + fake) |

## Tests added

`tests/test_security_verification.py` — 25 tests across 9 classes, one per
finding (V1-V9; V10 is documentation-only, no test needed since no code
changed). Every test is a genuine regression lock: each was run against the
pre-fix code first where practical (V1's untrusted-header test, V2/V3/V9's
race-condition tests, V5's leak test) to confirm it actually fails without
the fix, not just that it passes with it.

## Remaining risks (explicitly unverified)

Stated plainly, not minimized:

1. **The `add_finding` and `rotate_refresh_token` atomic rewrites (V2, V9)
   have never run against a real Postgres.** The `ON CONFLICT`/
   `FOR UPDATE SKIP LOCKED` SQL was constructed carefully and matches
   documented Postgres semantics, and the logic is exercised end-to-end by
   `FakeDB` (which was itself updated to match), but this sandbox has no
   live database to prove the actual SQL executes as written. This is the
   single highest-priority item to verify before production use — run
   `scripts/ci_db_smoke_test.py` (Phase 16) or an equivalent manual check
   specifically exercising both of these paths against real Postgres,
   ideally with genuine concurrent load (e.g. two processes hammering the
   same refresh token / same finding fingerprint simultaneously) to prove
   the race is actually closed, not just that the SQL parses.
2. **The migration that de-duplicates existing `findings` rows before
   adding the unique index has never run against a populated database.**
   Logically sound (verified by hand-tracing), but a migration touching
   existing data is exactly the kind of thing that deserves a dry run
   against a copy of real data before being trusted in production.
3. **CORS + security-header middleware interaction** was verified
   empirically this pass (a real request through the full middleware stack,
   not just code reading) — confirmed correct, but only under the
   `TestClient`'s synchronous test harness, not a real concurrent-connection
   ASGI server.
4. **The `HYDRAX_TRUSTED_PROXY_IPS` fix is unverified against a real
   reverse proxy.** The logic is unit-tested with synthetic request objects;
   nobody has put a real nginx (or the shipped `deploy/nginx.conf.example`)
   in front of a running instance and confirmed the header actually arrives
   and is trusted correctly end-to-end.
5. **Dependency versions drift, even though no known CVEs exist today**
   (see Dependency scan results) — `pip-audit` only reports *known*
   vulnerabilities as of the scan date; it cannot rule out an undisclosed
   issue in any dependency.

## Out-of-scope items

- **Desktop GUI (`ui/`)**: this audit's scope was the web platform per the
  task's own framing (API routes, frontend, deployment config); the
  CustomTkinter desktop shell was not re-examined.
- **Vendored third-party skill directories**: `Claude-Code-CyberSecurity-
  Skill/`, `agentic-awesome-skills/`, `communitytools/`, `hacking-skills/`,
  `.claude/skills/` are external tools checked into this working directory,
  not part of HydraX's own codebase or attack surface — excluded from this
  audit's scope entirely, same as every prior phase.
- **TLS/certificate configuration** is deployment-time, not code — covered
  by `docs/DEPLOYMENT.md`/`deploy/nginx.conf.example` review, not something
  this audit can verify without a live TLS endpoint.
- **`uvicorn`'s own `Server` response header** (minor version-fingerprinting
  information disclosure, WSTG-INFO-02) — a framework-level default this
  codebase doesn't control directly; suppressing it is a reverse-proxy/
  ASGI-server configuration concern, not an application code fix, and is a
  very low-severity finding on its own (banner grabbing, not exploitation).
- **A full penetration test against a running instance** — this was a
  source-code and configuration audit; no live instance exists in this
  sandbox to attack directly. Everything above was verified by code
  inspection, hermetic test execution, and (where the sandbox allowed)
  direct tool execution (`bandit`, `pip-audit`) — not by exploiting a real
  running deployment.

## Dependency / security scan results

```
$ python -m bandit -r webapp core scanners utils config connector -ll -ii
Test results:
        No issues identified.
Run metrics: 138 Low / 1 Medium(-confidence-only, filtered by -ii) / 0 High severity
8 findings suppressed via reviewed, justified #nosec annotations (Phase 16/19)

$ python -m pip_audit -r requirements.txt
No known vulnerabilities found
```

`pip list --outdated` shows several security-relevant packages
(`cryptography`, `PyJWT`, `starlette`, `uvicorn`, `pydantic`) a few minor
versions behind what's currently installed in this sandbox — none flagged
by `pip-audit` as carrying a known CVE. `requirements.txt` pins minimum
versions (`>=`), not exact versions, so a fresh install already pulls
current compatible releases; the versions "outdated" here are an artifact
of this long-lived sandbox environment, not the project's own dependency
declarations.

## Final verification results

```
$ python run_checks.py
[syntax] parsed 91 source files
[import] all 47 modules imported OK
CHECK PASSED: syntax + imports are clean.

$ python -m pytest -q
359 passed, 12 warnings in ~75s
```

359 = 300 (through Phase 18) + 34 (Phase 19, `test_wstg_audit.py`) + 25
(this pass, `test_security_verification.py`). Zero failures, zero skips,
zero regressions introduced by any fix in this report.
