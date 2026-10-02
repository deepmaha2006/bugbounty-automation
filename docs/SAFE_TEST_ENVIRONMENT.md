# SAFE_TEST_ENVIRONMENT.md — HydraX CVM Platform

Spec §24: a documented, reproducible way to validate HydraX's detection
accuracy against *known* vulnerabilities, without ever running a scan
against a system nobody explicitly authorized — including, deliberately,
without carving out any exception in the platform's own authorization or
SSRF-protection code to make that convenient. If a target isn't safe to
authorize the normal way, it isn't safe to scan with HydraX.

## Why not just scan `localhost`?

The three fixtures below (OWASP Juice Shop, WebGoat, DVWA) are standard,
intentionally-vulnerable practice applications, normally run locally via
Docker. That's exactly the shape `utils/ssrf_guard.py` exists to block:
`resolve_and_check()`/`assert_safe_ip_or_cidr()` reject any target whose
resolved IP is loopback, link-local (including the cloud-metadata address
`169.254.169.254`), RFC1918 private space, multicast, reserved, or
unspecified — re-checked immediately before every scan execution, not just
at registration (docs/SECURITY_MODEL.md §5). A Docker container published to
`127.0.0.1` or a private bridge network IP is exactly what that guard is
designed to refuse, and this document does not ask you to weaken it. Two
supported paths follow instead.

## Path A (recommended): a real, authorized, non-private host

Stand up the fixtures on a small VM you actually control with a real public
IP (a $5-6/month cloud droplet/instance is enough for all three) — most host
providers let you firewall it down to only your own source IP if you don't
want it reachable by anyone else. Then treat it exactly like any other
HydraX asset:

1. `docker compose -f docker-compose.testenv.yml up -d` on that host.
2. Point a subdomain you control at it (e.g. `juiceshop-test.yourdomain.com`).
3. Register it in HydraX and complete DNS TXT (or engagement-letter)
   verification — the *same* authorization flow every production asset goes
   through, per spec §3/§8.
4. Run scans against it from the HydraX web platform normally.

This path exercises the platform end-to-end (authorization, scheduling,
SSRF guard passing a *legitimately* non-private target, finding lifecycle,
alerting, remediation, reporting) with zero code changes and zero special
cases — the fixture is just an authorized asset like any other.

## Path B: direct scan-engine invocation for quick local iteration

The desktop GUI and `core/scan_engine.py` predate the webapp platform
(see `CLAUDE.md`) and don't route through `webapp/services/web_scan_service.py`
or its SSRF guard at all — they're a separate, standalone entry point. For
fast local iteration while developing a scanner (not for validating the
*platform's* authorization/SSRF/lifecycle layers, only a scanner's raw
detection logic), run `python3 main.py` (the desktop GUI) or adapt
`run_test_scan.py` and point it at `http://localhost:3000` (Juice Shop) etc.
directly. This never touches the FastAPI platform, its database, or its
authorization model — it's scanner-logic testing only.

## Setting up the fixtures

```bash
docker compose -f docker-compose.testenv.yml up -d
# Juice Shop: http://127.0.0.1:3000
# WebGoat:    http://127.0.0.1:8080/WebGoat  (login/register on first visit)
# WebWolf:    http://127.0.0.1:9090/WebWolf  (WebGoat's companion attacker app)
# DVWA:       http://127.0.0.1:4280  (default login admin/password; set
#             security level in DVWA Security after first login)

docker compose -f docker-compose.testenv.yml down -v   # tear down + wipe state
```

Never point these at a public IP without a firewall unless you specifically
want them internet-reachable — they are deliberately vulnerable.

## Detection-accuracy checklist

Each application ships a well-documented, stable set of intentional
vulnerabilities. Use these as a checklist for what a HydraX scan *should*
surface — not an exhaustive list, but enough to sanity-check each scanner
category against real, known-answer targets rather than only synthetic
unit-test fixtures:

| Target | Categories to validate against |
|---|---|
| **OWASP Juice Shop** | Reflected/stored XSS, SQL injection (login bypass, UNION-based), broken access control (IDOR on order/basket IDs), sensitive data exposure, security misconfiguration, vulnerable/outdated components, CSRF, SSRF (via the "Server-Side Request Forgery" set of challenges) |
| **WebGoat** | SQL injection (multiple lesson variants: string/numeric/blind), XSS (reflected/stored/DOM), broken authentication, insecure deserialization, XXE, SSRF, path traversal, JWT vulnerabilities |
| **DVWA** | SQL injection (all 4 security levels: low/medium/high/impossible — useful for confirming a scanner's confidence scoring degrades correctly as mitigations get stronger), reflected/stored XSS, command injection, CSRF, file inclusion/upload, brute-force-able auth |

A scan that reports zero findings against any of these (with monitoring
scoped to cover the relevant categories) indicates a scanner regression, not
a clean target — these applications are vulnerable by design and never
"pass."

## What this phase does not do

Per the platform's own closing principle ("do NOT create fake vulnerability
records — all dashboard statistics must come from real backend data"), no
fixture data, sample findings, or synthetic scan results are seeded into the
production schema by this document or its compose file. Every finding a
validation run produces is a real finding from a real scan against a real
(if intentionally vulnerable) running application — exactly the same code
path production traffic uses.
