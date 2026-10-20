#!/usr/bin/env python3
"""
HydraX Lab — seed script.

Creates the minimum DB/API state the live test suite needs:
  1. Register org + admin user via API.
  2. Login → get JWT.
  3. Create victim asset via API.
  4. Insert asset_authorizations row directly in Postgres.
  5. Create enrollment token via API; write it to CONNECTOR_TOKEN_FILE.
  6. Poll GET /api/connectors until the connector enrolls (or timeout).
  7. Set autonomy tier → observe via POST /api/brain/policy.
  8. Print a ready banner.

Environment variables:
  HYDRAX_API          Base URL of the hydrax API (default http://localhost:8000)
  POSTGRES_HOST       Postgres host (default localhost)
  POSTGRES_PORT       Postgres port (default 5433 — the host-side lab port)
  POSTGRES_DB         Database name (default hydrax)
  POSTGRES_USER       (default hydrax)
  POSTGRES_PASSWORD   (default hydraxpass)
  CONNECTOR_TOKEN_FILE  Where to write the enrollment token
                        (default /connector-home/enrollment.token)
  LAB_VICTIM_URL      URL the asset record should point to
                        (default http://connector — inside hydraxlab network)

Run from the host after `docker compose up -d` (postgres + hydrax-api + connector):
    python lab/seed.py
"""
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import psycopg2
import requests

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
API             = os.environ.get("HYDRAX_API",            "http://localhost:8000")
PG_HOST         = os.environ.get("POSTGRES_HOST",         "localhost")
PG_PORT         = int(os.environ.get("POSTGRES_PORT",     "5433"))
PG_DB           = os.environ.get("POSTGRES_DB",           "hydrax")
PG_USER         = os.environ.get("POSTGRES_USER",         "hydrax")
PG_PASS         = os.environ.get("POSTGRES_PASSWORD",     "hydraxpass")
TOKEN_FILE      = os.environ.get("CONNECTOR_TOKEN_FILE",  "/connector-home/enrollment.token")
VICTIM_URL      = os.environ.get("LAB_VICTIM_URL",        "http://connector")

LAB_ORG         = "HydraX Lab"
LAB_USER        = "labadmin"
LAB_EMAIL       = "labadmin@hydraxlab.internal"
LAB_PASSWORD    = "LabPassword123!"   # meets min 12 chars; only for isolated lab

ENROLL_TIMEOUT  = 180  # seconds to wait for connector to enroll
POLL_INTERVAL   = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ok(resp: requests.Response, ctx: str) -> dict:
    if not resp.ok:
        print(f"[seed] ERROR {ctx}: {resp.status_code} — {resp.text[:200]}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def _wait_api(timeout: int = 120):
    """Block until /api/health responds 200."""
    print(f"[seed] Waiting for API at {API} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{API}/api/health", timeout=3)
            if r.ok:
                print("[seed] API is ready.")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    print("[seed] ERROR: API did not become ready in time.", file=sys.stderr)
    sys.exit(1)


def _pg_conn():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
        connect_timeout=10,
    )


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step_register() -> None:
    print("[seed] Registering org + admin user ...")
    resp = requests.post(f"{API}/api/auth/register", json={
        "username":          LAB_USER,
        "email":             LAB_EMAIL,
        "password":          LAB_PASSWORD,
        "organization_name": LAB_ORG,
    })
    if resp.status_code == 400 and "already" in resp.text.lower():
        print("[seed] User already exists — continuing.")
    else:
        _ok(resp, "register")
        print("[seed] Registered.")


def step_login() -> tuple[str, int]:
    """Return (access_token, user_id)."""
    print("[seed] Logging in ...")
    data = _ok(
        requests.post(f"{API}/api/auth/login", json={
            "username": LAB_USER,
            "password": LAB_PASSWORD,
        }),
        "login",
    )
    token = data["access_token"]
    user_id = data["user"]["id"]
    print(f"[seed] Login OK (user_id={user_id}).")
    return token, user_id


def step_create_asset(token: str) -> tuple[int, int]:  # type: ignore[return]
    """Return (asset_id, org_id)."""
    print(f"[seed] Creating victim asset ({VICTIM_URL}) ...")
    headers = {"Authorization": f"Bearer {token}"}

    # Check if asset already exists.
    rows = _ok(requests.get(f"{API}/api/assets", headers=headers), "list assets")
    for r in rows:
        if r.get("url") == VICTIM_URL:
            print(f"[seed] Asset already exists: id={r['id']} org={r['organization_id']}")
            return r["id"], r["organization_id"]

    data = _ok(
        requests.post(f"{API}/api/assets", headers=headers, json={
            "name":                 "Lab Victim (Juice Shop)",
            "asset_type":           "WEB_APPLICATION",
            "url":                  VICTIM_URL,
            "environment":          "lab",
            "business_criticality": "low",
        }),
        "create asset",
    )
    print(f"[seed] Asset created: id={data['id']}")
    return data["id"], data["organization_id"]


def step_authorize_asset(asset_id: int, org_id: int, user_id: int) -> None:
    """Insert asset_authorizations row directly in Postgres (no public API for this)."""
    print("[seed] Inserting asset authorization ...")
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    conn = _pg_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO asset_authorizations(
                           organization_id, asset_id, authorized_by_user_id,
                           method, status, scope_hosts, max_req_per_sec, expires_at
                       ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT DO NOTHING""",
                    (
                        org_id, asset_id, user_id,
                        "self_attested", "authorized",
                        json.dumps(["connector", "victim"]),
                        10.0,
                        expires,
                    ),
                )
    finally:
        conn.close()
    print("[seed] Authorization inserted.")


def step_enrollment_token(token: str) -> str:
    print("[seed] Creating connector enrollment token ...")
    headers = {"Authorization": f"Bearer {token}"}
    data = _ok(
        requests.post(f"{API}/api/connectors/enrollment-tokens", headers=headers, json={}),
        "enrollment-token",
    )
    raw_token = data["enrollment_token"]
    print("[seed] Enrollment token created.")
    return raw_token


def step_write_token(raw_token: str) -> None:
    os.makedirs(os.path.dirname(TOKEN_FILE) or ".", exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        f.write(raw_token)
    print(f"[seed] Token written to {TOKEN_FILE}")


def step_wait_connector(token: str) -> int:
    """Poll GET /api/connectors until one appears active. Return connector_id."""
    print(f"[seed] Waiting for connector to enroll (up to {ENROLL_TIMEOUT}s) ...")
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.time() + ENROLL_TIMEOUT
    while time.time() < deadline:
        try:
            rows = _ok(requests.get(f"{API}/api/connectors", headers=headers), "list connectors")
            for r in rows:
                if r.get("state") in ("active", "enrolled"):
                    print(f"[seed] Connector enrolled: id={r['id']} state={r['state']}")
                    return r["id"]
        except SystemExit:
            pass
        time.sleep(POLL_INTERVAL)
    print("[seed] ERROR: Connector did not enroll in time.", file=sys.stderr)
    sys.exit(1)


def step_set_tier(token: str, asset_id: int, org_id: int, tier: str = "observe") -> None:
    print(f"[seed] Setting autonomy tier → {tier} ...")
    _ok(
        requests.post(
            f"{API}/api/brain/policy",
            headers={"Authorization": f"Bearer {token}"},
            json={"asset_id": asset_id, "org_id": org_id, "tier": tier},
        ),
        "set policy",
    )
    print(f"[seed] Autonomy tier set to {tier}.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _wait_api()

    step_register()
    token, user_id = step_login()
    asset_id, org_id = step_create_asset(token)
    step_authorize_asset(asset_id, org_id, user_id)
    raw_token = step_enrollment_token(token)
    step_write_token(raw_token)
    step_wait_connector(token)
    step_set_tier(token, asset_id, org_id, "observe")

    print()
    print("=" * 60)
    print("  HydraX Lab ready")
    print(f"  asset_id  = {asset_id}")
    print(f"  org_id    = {org_id}")
    print(f"  user_id   = {user_id}")
    print(f"  api       = {API}")
    print(f"  victim    = {VICTIM_URL}")
    print("=" * 60)
    print()

    # Write a state file so tests can read asset_id/org_id without re-seeding.
    state = {
        "asset_id": asset_id,
        "org_id":   org_id,
        "user_id":  user_id,
        "api":      API,
        "victim":   VICTIM_URL,
    }
    state_path = os.path.join(os.path.dirname(__file__), "lab_state.json")
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)
    print(f"[seed] State written to {state_path}")


if __name__ == "__main__":
    main()
