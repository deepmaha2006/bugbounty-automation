"""
Live test fixtures.

These tests run against a real Docker-based lab environment. They are tagged
`@pytest.mark.live` and excluded from the default `pytest` run via:

    [tool.pytest.ini_options]
    addopts = "-m 'not live'"

Start the lab first:
    make lab-up    # or: docker compose -f lab/docker-compose.yml up -d

Then run only live tests:
    make lab-test  # or: pytest -m live tests_live/

The fixtures here read `lab/lab_state.json` (written by `lab/seed.py`) so
the test suite always uses the asset_id/org_id that seed.py provisioned.
"""
import json
import os
import time
from pathlib import Path

import psycopg2
import pytest
import requests

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
STATE_FILE    = PROJECT_ROOT / "lab" / "lab_state.json"

# Overridable env vars (must match docker-compose lab env section).
API           = os.environ.get("HYDRAX_API",            "http://localhost:8000")
PG_HOST       = os.environ.get("POSTGRES_HOST",         "localhost")
PG_PORT       = int(os.environ.get("POSTGRES_PORT",     "5433"))
PG_DB         = os.environ.get("POSTGRES_DB",           "hydrax")
PG_USER       = os.environ.get("POSTGRES_USER",         "hydrax")
PG_PASS       = os.environ.get("POSTGRES_PASSWORD",     "hydraxpass")

LAB_USER      = "labadmin"
LAB_PASSWORD  = "LabPassword123!"


def pytest_configure(config):
    config.addinivalue_line("markers", "live: mark test as requiring the live Docker lab")


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def lab_state() -> dict:
    if not STATE_FILE.exists():
        pytest.skip(
            f"lab_state.json not found at {STATE_FILE}. Run `make lab-up` first."
        )
    with open(STATE_FILE) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def api_session(lab_state) -> requests.Session:
    """An authenticated requests.Session for the lab API."""
    s = requests.Session()
    resp = s.post(f"{API}/api/auth/login", json={
        "username": LAB_USER,
        "password": LAB_PASSWORD,
    })
    assert resp.ok, f"Lab login failed: {resp.status_code} {resp.text}"
    token = resp.json()["access_token"]
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s


@pytest.fixture(scope="session")
def pg_conn():
    """Direct Postgres connection for inspecting brain tables."""
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
        connect_timeout=10,
    )
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def asset_id(lab_state) -> int:
    return lab_state["asset_id"]


@pytest.fixture(scope="session")
def org_id(lab_state) -> int:
    return lab_state["org_id"]


# ---------------------------------------------------------------------------
# Helpers exposed as fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ingest_attack(lab_state, api_session, asset_id, org_id):
    """
    Returns a callable that posts a raw log line to
    POST /api/brain/telemetry/ingest (brain sensor ingestion endpoint).
    """
    def _ingest(log_line: str) -> dict:
        resp = api_session.post(f"{API}/api/brain/telemetry/ingest", json={
            "asset_id": asset_id,
            "org_id":   org_id,
            "lines":    [log_line],
        })
        assert resp.ok, f"Ingest failed: {resp.status_code} {resp.text}"
        return resp.json()
    return _ingest


@pytest.fixture
def poll_brain_events(api_session, asset_id, org_id):
    """
    Returns a callable that polls GET /api/brain/events until at least one
    event appears, or times out.
    """
    def _poll(timeout: int = 30, min_count: int = 1) -> list:
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = api_session.get(
                f"{API}/api/brain/events",
                params={"asset_id": asset_id, "org_id": org_id, "limit": 200},
            )
            if resp.ok:
                rows = resp.json()
                if len(rows) >= min_count:
                    return rows
            time.sleep(1)
        return []
    return _poll


@pytest.fixture
def poll_brain_incidents(api_session, asset_id, org_id):
    def _poll(timeout: int = 60, state: str = None) -> list:
        deadline = time.time() + timeout
        params = {"asset_id": asset_id, "org_id": org_id, "limit": 100}
        if state:
            params["state"] = state
        while time.time() < deadline:
            resp = api_session.get(f"{API}/api/brain/incidents", params=params)
            if resp.ok and resp.json():
                return resp.json()
            time.sleep(2)
        return []
    return _poll


@pytest.fixture
def poll_brain_actions(api_session, asset_id, org_id):
    def _poll(timeout: int = 60, status: str = "applied") -> list:
        deadline = time.time() + timeout
        params = {"asset_id": asset_id, "org_id": org_id, "status": status, "limit": 100}
        while time.time() < deadline:
            resp = api_session.get(f"{API}/api/brain/actions", params=params)
            if resp.ok and resp.json():
                return resp.json()
            time.sleep(2)
        return []
    return _poll
