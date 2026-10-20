# HydraX — Live Lab Validation Runbook

This runbook describes how to stand up the HydraX lab environment and run the
S1–S12 live validation suite that proves HydraBrain's full
**sense → detect → respond → rollback** path against real containers.

---

## Lab safety rules

> **Self-owned, isolated targets only.** Every target is an app you run on
> your own VM/containers on an **isolated network** (host-only / dedicated
> Docker bridge, no port-forwarding to the public internet, no cloud ingress).
> Never point any of this at a system you don't own or at a public bug-bounty
> target.

> **"Attacks" are benign and self-inflicted** — simple scripted HTTP requests
> from a lab client container against YOUR vulnerable app to trigger the brain's
> detection signals. No real exploitation, no data exfil, no third parties.

> **No destructive tiers in v1.** Validate `observe` and `auto_contain` only.
> Do NOT exercise `auto_remediate` source/config edits against a live box in
> this pass — virtual-patch (WAF rule) apply/rollback is the ceiling, and only
> after containment is proven.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Desktop (or Docker Engine + Compose v2) | `docker compose version` must work |
| Python 3.10+ with lab dependencies | `pip install -r requirements.txt psycopg2-binary` |
| Port availability | 5433 (Postgres), 8000 (API), 8080 (connector/nginx) — must be free on the host |

---

## Quick start

```bash
# 1. Start containers and seed state (creates org, user, asset, enrollment token,
#    waits for connector to enroll, sets tier=observe).
make lab-up

# 2. Run the live test suite.
make lab-test

# 3. Inspect evidence.
ls evidence/

# 4. Tear down.
make lab-down
```

---

## Container topology

```
host (your machine)
│
├─ postgres:5433      ← Postgres 15 (hydrax DB)
├─ hydrax-api:8000    ← FastAPI + Celery worker
├─ connector:8080     ← nginx proxy (WAF) + connector agent
│                       (CAP_NET_ADMIN for iptables)
│                       → proxies to victim:3000
├─ victim:3000        ← OWASP Juice Shop (vulnerable target)
└─ attacker           ← attack_sim.py (started manually or via lab-attack)

All services are on the isolated Docker bridge network "hydraxlab".
No ports are forwarded to the public internet.
```

The connector acts as a **transparent proxy** between attacker and victim.
`block_source` translates to an iptables INPUT DROP rule on the connector
container, and `apply_waf_rule` writes an nginx `deny` snippet — both of
which physically cut off attacker → victim traffic.

---

## Test scenarios

| Scenario | What it proves |
|---|---|
| **S1** Smoke | API reachable, asset exists, connector enrolled, authorization present |
| **S2** Event persistence | brain_events can be written and read back via API |
| **S3** Signal detection | signals column correctly tagged for SQLi / path traversal / XSS patterns |
| **S4** Hunt incidents | `POST /api/brain/hunt` processes events and creates brain_incidents |
| **S5** Containment | `auto_contain` tier → hunt applies block_source action (connector job dispatched) |
| **S6** Allowlist | 127.0.0.1 (and other owner IPs) never appear in block_source actions |
| **S7** Kill switch | `POST /api/brain/kill-switch/engage` stops hunt at "kill_switch" stopped_reason |
| **S8** Rollback | `POST /api/brain/rollback-all` removes all applied actions for an asset |
| **S9** TTL expiry | `POST /api/brain/expire-actions` rolls back past-TTL applied actions |
| **S10** WAF rule | connector_job of type apply_waf_rule is created (xfail if dispatcher stub) |
| **S11** Knowledge update | hunt increments `total_learn_updates` and `brain_knowledge` is readable |
| **S12** FP brake | flooding one IP produces at most 5 block_source actions (rate brake) |

---

## Running a single scenario

```bash
pytest -m live tests_live/test_s1_s12.py::TestS7KillSwitch -v
```

---

## Manual attack simulation

```bash
# One-shot batch of attack signals (SQLi, XSS, path traversal, scanner UAs)
make lab-attack

# Or run continuously in the background (loops every 10 s)
docker compose -f lab/docker-compose.yml run --rm \
    -e TARGET_URL=http://connector attacker
```

---

## Cleaning up between runs

```bash
# Clears WAF rules, iptables, rolls back brain_actions — keeps containers up.
make lab-teardown

# Then re-seed (creates a fresh asset/token).
python lab/seed.py
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `lab_state.json not found` | seed.py not run | `make lab-up` |
| S1 connector test fails | connector still enrolling | wait 30 s, rerun |
| S5/S10 xfail | dispatcher stub not wired | ensure `brain/dispatcher.py` is present and `brain/response.py` calls it |
| `JOB_TYPES` ValueError in dispatcher | webapp/db.py JOB_TYPES missing new types | check `JOB_TYPES` includes `block_source`, etc. |
| `No active authorization` hunt stops | `asset_authorizations` row missing or expired | run `python lab/seed.py` |
| nginx 502 | victim container not yet ready | wait and retry |

---

## Evidence collection

Each `make lab-test` run saves a timestamped log to `evidence/`. Attach these
to any security review that certifies the live detection→containment path.
