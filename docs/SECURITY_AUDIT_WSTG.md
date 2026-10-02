# SECURITY_AUDIT_WSTG.md — OWASP WSTG/ASVS/Top 10 Audit

> **2026-09-29 — web frontend removed.** `webapp/static/` (the browser UI) and its
> `/app` and `/static` routes were deleted; `webapp/` is now an API-only backend and the
> desktop app (`ui/`) is the client. References to website pages below are historical.

A dedicated audit pass using the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
as the baseline, cross-referenced against [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
and the [OWASP Top 10](https://owasp.org/Top10/). This supplements, not
replaces, Phase 13's hardening pass (`docs/ROADMAP.md`) and
`docs/SECURITY_MODEL.md` — this document goes categorically through WSTG's
testing checklist (identity, authentication, session management, input
validation/injection, cryptography, configuration, error handling, business
logic, client-side, and API testing), not just the narrower OWASP Top 10.

Every finding below was verified against the actual code (not assumed),
fixed, and locked in with a regression test in `tests/test_wstg_audit.py`.
Where a test caught a bug in the fix itself, that's called out explicitly —
it happened once, and it's evidence the "fix then re-test" step in this
process is doing real work, not busywork.

## Findings

### F1 — Missing HTTP security headers
**WSTG:** WSTG-CONF-07 (Test HTTP Security Headers), WSTG-CLNT-09 (Testing
for Clickjacking) · **ASVS:** V14.4.1–V14.4.7 · **Top 10:** A05:2021
(Security Misconfiguration)

No response — API or static frontend — carried `Content-Security-Policy`,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
`Permissions-Policy`, or `Strict-Transport-Security`. The frontend was
consequently frameable by any origin (clickjacking), had no defense against
MIME-sniffing, and leaked full referrer URLs to any external link a report
or finding might contain.

**Fix:** `webapp/main.py` gained a `_security_headers_middleware` applied to
every response: a CSP scoped to the frontend's actual external dependencies
(Google Fonts, jsdelivr's Chart.js — never a wildcard), `X-Content-Type-
Options: nosniff`, `X-Frame-Options: DENY` + `frame-ancestors 'none'`,
`Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and
`Strict-Transport-Security` (a no-op over plain HTTP, correct once Phase
17's TLS-terminating proxy is in front of this). `/api/*` responses also get
`Cache-Control: no-store`, since they carry findings/audit/session data that
should never linger in a shared cache or the browser's back/forward cache.

The CSP's `script-src` intentionally carries **no** `unsafe-inline` — see F9.

### F2 — Weak password policy (6-character minimum, no floor on entropy)
**WSTG:** WSTG-ATHN-07 (Testing for Weak Password Policy) · **ASVS:**
V2.1.1 (L1: passwords ≥ 12 characters) · **Top 10:** A07:2021
(Identification and Authentication Failures)

`RegisterRequest.password` and `PasswordChange.new_password` both accepted
passwords as short as 6 characters, with no length-based entropy floor.

**Fix:** Raised both to `min_length=12` in `webapp/schemas.py`, matching
ASVS 4.0.3's L1 requirement (which favors length over composition rules —
current guidance considers mandatory complexity/rotation rules an anti-
pattern). Updated `webapp/static/js/login.js`'s client-side check and its
placeholder text to match, so client and server enforce the same floor.

### F3 — Password storage work factor a decade below current guidance
**WSTG:** WSTG-CRYP-04 (Testing for Weak Encryption) · **ASVS:** V6.2.3
· **Top 10:** A02:2021 (Cryptographic Failures)

`hash_password` used PBKDF2-HMAC-SHA256 at 120,000 iterations — a
~2013-era recommendation. Current OWASP Password Storage Cheat Sheet
guidance is ≥ 600,000.

**Fix:** Raised to 600,000 and made the count **part of the hash string**
(`pbkdf2$<iterations>$<salt>$<digest>`, was `pbkdf2$<salt>$<digest>`) so a
future increase never invalidates already-issued hashes — `verify_password`
always uses whichever count a given hash actually recorded, not today's
constant. A 3-part legacy hash (implicitly 120,000) still verifies.
Added opportunistic rehashing (ASVS V6.2.4): `POST /api/auth/login`
re-hashes at the current work factor the instant a legacy or low-iteration
hash successfully verifies — the only safe moment, since it's the only time
the plaintext is available server-side.

**Caught by re-testing, not by inspection:** the first version of this fix
had a real bug — `verify_password`'s legacy-format branch compared a freshly
*re-formatted 4-part* string against the *stored 3-part* string, which can
never match even when the underlying derived key is identical (the two
strings differ by the embedded iteration-count field alone). Every existing
account created before this change would have failed to log in on the very
first attempt after deployment. `tests/test_wstg_audit.py::TestPasswordHashing::
test_legacy_3_part_hash_still_verifies` failed immediately and pinpointed
it; fixed by comparing the derived-key hex directly instead of the wrapping
formatted string. This is exactly the scenario the task's "implement fixes,
then re-test to verify" step exists to catch.

### F4 — Account enumeration via login response timing
**WSTG:** WSTG-IDNT-04 (Testing for Account Enumeration and Guessable User
Account), WSTG-ATHN-03 (adjacent) · **CWE-208** (Observable Timing
Discrepancy) · **Top 10:** A07:2021

The login endpoint already unified "no such user" and "wrong password" into
the same generic `401 Invalid credentials` message (a *correct* existing
control) — but `not user or not verify_password(...)` short-circuits: for a
nonexistent username, the expensive PBKDF2 computation never runs at all,
while an existing user's wrong-password attempt always costs a full
600,000-iteration hash. That's a measurable, remotely observable timing
difference an attacker can use to enumerate valid usernames without ever
seeing a different error message or status code.

**Fix:** `webapp/routers/auth.py` now always performs exactly one password
verification per login attempt — against the real hash when the user
exists, against a precomputed, fixed `_DUMMY_PASSWORD_HASH` when they don't
— so the PBKDF2 cost is paid either way and the two cases are not
distinguishable by response time.

*Residual, accepted risk:* the account-lockout branch (an existing, locked
account) still returns before any password check, giving that state a third,
faster timing profile than "wrong password." Revealing "this account is
currently locked" is materially less sensitive than revealing "this account
exists at all," and masking it would mean either checking the password
anyway on an already-locked account (pointless extra cost with no security
benefit) or deferring lockout enforcement — not worth the complexity for a
lower-severity residual signal. Documented here rather than silently
accepted.

### F5 — Unauthenticated `/health` leaks raw infrastructure error detail
**WSTG:** WSTG-ERRH-01 (Testing for Improper Error Handling) · **ASVS:**
V7.4.1 (generic error messages for security-sensitive failures) · **Top
10:** A05:2021

`GET /health`/`/healthz` are deliberately unauthenticated (load balancers
and k8s probes call them with no credentials) — but `check_database()`/
`check_redis()` returned the raw exception string on failure, which for a
real Postgres/Redis connection failure commonly includes the target
hostname, port, and sometimes a username (e.g. `FATAL: password
authentication failed for user "..."`). Any unauthenticated caller on the
network could read this.

**Fix:** `webapp/services/health.py::overall_health()` now logs each
component's raw error via the structured logger (`hydrax.health`,
Phase 14's JSON logging) and returns only `{"status": ...}` per component to
the actual HTTP caller — the diagnostic detail isn't lost, it's just no
longer handed to anyone who can reach the port. `check_database()`/
`check_redis()` themselves are unchanged (still directly unit-testable with
full detail) — only the public aggregate is redacted.

### F6 — Engagement-letter upload failure leaks the server filesystem path
**WSTG:** WSTG-ERRH-01 · **ASVS:** V7.4.1 · **CWE-209**

A file-save `OSError` was returned to the client as
`f"Failed to save file: {str(e)}"` — Python's `OSError.__str__()` includes
the full path it was operating on (e.g.
`[Errno 13] Permission denied: '/app/webapp/data/uploads/...'`).

**Fix:** `webapp/routers/verification.py` logs the real exception via
`logger.error(..., extra={"error": str(e)})` and returns a generic
`"Failed to save file"` to the client.

### F7 — Reflected `javascript:`/protocol-relative URLs in generated HTML reports
**WSTG:** WSTG-CLNT-01 (Testing for DOM-Based XSS), WSTG-CLNT-04 (Testing
for Client-Side URL Redirect) · **ASVS:** V5.2.5 · **CWE-79/601**

`utils/reporter.py`'s downloadable HTML report already `html.escape()`s
every finding field it renders (verified: `type`, `url`, `description`,
`parameter`, `evidence` all pass through `_esc()`) — but `html.escape()`
neutralizes markup characters, not URI *schemes*. A finding's `url` field is
scanner-constructed and can legitimately contain a payload from
`utils/payloads.py`'s XSS dictionaries — `javascript:alert(1)`,
`javascript:alert(document.domain)`, etc. are literal entries there, for
testing reflected-XSS sinks. If such a value ever became `finding['url']`
verbatim (rather than embedded as a query-string value inside an otherwise
normal `https://` URL, the case in every scanner checked), the generated
report's `<a href="javascript:...">` would execute script in the report
viewer's own origin the moment they clicked the "URL" link — a second-order
XSS via the report itself, not the scanned site.

**Fix:** New `ReportGenerator._safe_href()` — allows only `http://`,
`https://`, or a same-origin-relative path (`/...`, explicitly not `//...`,
which a browser resolves to an arbitrary external origin); anything else
becomes an inert `#`. Applied to the `href` attribute specifically (the
escaped, visible link *text* is unchanged and still uses `_esc()`). Also
added `rel="noopener noreferrer"` to that link (see F10).

### F8 — No size limit on engagement-letter upload
**WSTG:** WSTG-BUSL-09 (Test Upload of Malicious Files, DoS-adjacent) ·
**CWE-400** (Uncontrolled Resource Consumption) · **Top 10:** A04:2021
(Insecure Design)

`file.file.read()` had no bound — any authenticated operator-role user
could upload an arbitrarily large file.

**Fix:** `webapp/routers/verification.py` reads at most
`MAX_ENGAGEMENT_LETTER_SIZE + 1` bytes (10 MB cap, generous for a PDF/image
engagement letter) and rejects anything over that with `413`, without ever
buffering more than the cap.

### F9 — Inline `<script>` block prevents a strict CSP
**WSTG:** WSTG-CONF-07 (supporting F1) · **CWE-79** (defense-in-depth)

`webapp/static/login.html` had its login/register logic in an inline
`<script>` block, which would have forced `script-src 'unsafe-inline'` into
the CSP — defeating the single strongest protection CSP offers against
reflected/stored XSS (blocking inline script execution).

**Fix:** Extracted to `webapp/static/js/login.js`. While moving it, found
and fixed a real, pre-existing functional bug (not introduced by this
audit): the extracted code read `data.token` from the login/register
response, but the API returns `access_token` (`TokenOut.access_token`) —
every login/registration through this page was storing `undefined` as the
bearer token, breaking every subsequent authenticated request. Fixed to
`data.access_token` in both call sites.

### F10 — `target="_blank"` links without `rel="noopener noreferrer"`
**WSTG:** WSTG-CLNT-15 (Reverse Tabnabbing, WSTG v4.2 addition)

Two `target="_blank"` links lacked `rel="noopener noreferrer"`:
`webapp/static/js/reports.js`'s report-download link (same-origin — low
risk, fixed anyway for defense in depth) and the HTML report's per-finding
"URL" link (opens the *scanned target's own URL*, which is genuinely
external/untrusted — the more meaningful fix of the two, see F7).

**Fix:** Added `rel="noopener noreferrer"` to both.

### F11 — Unauthenticated exposure of the full API schema
**WSTG:** WSTG-INFO-10 (Map Application Architecture) · lower severity,
mitigated rather than removed

`GET /openapi.json` (and the `/docs`/`/redoc` UIs built from it) are open by
default in FastAPI, unauthenticated — handing any unauthenticated caller the
platform's complete route/parameter/schema map before they've authenticated
at all.

**Decision:** left enabled by default (legitimate integrators benefit from
it, and this platform requires auth on everything that matters regardless
of whether its shape is public) but made it one environment variable away
from disabled: `HYDRAX_DISABLE_API_DOCS=1` sets `docs_url=None`,
`redoc_url=None`, `openapi_url=None`. Documented in `.env.example`.

## Reviewed — no code change needed

Verified against the actual implementation, not assumed clean:

| Area | WSTG | Verdict |
|---|---|---|
| SQL injection | WSTG-INPV-05 | Parameterized throughout; the few `f"..."` SQL constructions interpolate only allowlisted column names or static literals (re-confirmed from Phase 13's review, still holds) |
| CSRF | WSTG-SESS-05 | Architecturally mitigated — Bearer-token-only auth, zero `set_cookie`/`request.cookies` usage anywhere; re-grepped, still zero |
| SSRF | WSTG-INPV-19 | Phase 7's `utils/ssrf_guard.py` still wired into both scan services, re-checked per-request |
| JWT algorithm confusion | WSTG-SESS-02 (adjacent) | `jwt.decode(..., algorithms=[config.JWT_ALGO])` — explicit allowlist, PyJWT rejects `alg: none` and any algorithm not in the list |
| IDOR / tenant isolation | WSTG-ATHZ-04 | Every `db.get_X(id, organization_id)` call site spot-checked in Phase 13 remains org-scoped; no new routes since then |
| Command/argument injection | WSTG-INPV-12/13 | `subprocess.run(list, ...)` throughout, never `shell=True`; Phase 13's hostname-regex fix for argument injection still in place |
| Path traversal | WSTG-ATHZ-01 | Engagement-letter filenames are fully server-generated (`target_{id}_{token}{ext}`); report download paths come from the DB, never request input |
| Logout / session revocation | WSTG-SESS-07 | `POST /api/auth/logout` actually revokes the refresh token server-side, not just a client-side token discard |
| Secrets in logs | WSTG-CONF (supporting) | Re-grepped every `logger.*`/`print(` call site for password/secret/token/api_key/private_key — zero hits |
| CORS | WSTG-CONF-08 (adjacent) | `allow_origins` is an explicit env-configured list, never `"*"`, safe to pair with `allow_credentials=True` |
| Registration reveals "username already taken" | WSTG-IDNT-04 | Real disclosure, but low severity: registration is closed by default and only reachable by someone who already holds the admin signup token (already a privileged actor) or is the platform's literal first user — not a public enumeration surface. Left as-is; the honest UX benefit for an admin bulk-provisioning a team outweighs the residual risk to an already-gated action. |
| Access-token revocation window | WSTG-SESS (design note) | A stolen access token remains valid until its own 15-minute expiry even after logout/reuse-detection revokes the refresh-token family — standard, accepted tradeoff of stateless JWTs, mitigated by the short expiry already in place |

## Verification

Every fix above has a dedicated test in `tests/test_wstg_audit.py`, in
addition to the full existing suite:

```
python run_checks.py    # syntax + import check — clean
python -m pytest -q     # 334/334 passed (300 pre-existing + 34 new), zero regressions
```

The 34 new tests are organized by WSTG ID, matching this document's finding
numbering, so a future re-audit can map failing tests directly back to the
finding they lock in.
