#!/usr/bin/env python3
"""CI-only smoke test: run webapp.db.init_db() against a REAL, ephemeral
Postgres and do one real insert/read round trip.

This sandbox this project was built in has never had a live Postgres
available (see docs/ROADMAP.md's repeated "not yet verified against real
Postgres" caveats on almost every phase touching webapp/db.py) — every
schema/migration statement across 15+ phases has only ever been verified by
careful manual SQL review plus the hermetic FakeDB test suite. This script
is the first thing in the project's history that actually runs the real DDL.

Two things it specifically checks that a hermetic test suite structurally
cannot:
  1. init_db() is safe to run twice in a row (it must be — webapp/main.py's
     startup event calls it on every process start, including against an
     already-migrated database).
  2. A minimal end-to-end write/read actually round-trips through the real
     schema (catches a column type/name mismatch that "CREATE TABLE did not
     raise" alone would miss).

Exits non-zero on any failure. Not part of the pytest suite (which is
explicitly hermetic and must never touch a real database) — invoked
directly as its own CI step against a service-container Postgres.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from webapp import db, security  # noqa: E402


def main() -> int:
    print("[1/4] init_db() on a fresh database...")
    db.init_db()
    print("[2/4] init_db() again (idempotency check)...")
    db.init_db()

    print("[3/4] minimal write/read round trip...")
    org_id = db.create_organization("CI Smoke Test Org")
    uid = db.create_user("ci-smoke-user", "ci-smoke@example.invalid",
                         security.hash_password("irrelevant-password-1"), org_id)
    user = db.get_user_by_id(uid)
    assert user is not None, "created user was not readable back"
    assert user["organization_id"] == org_id, "organization_id did not round-trip"

    target_id = db.add_target("https://ci-smoke-test.example.invalid", org_id,
                              verification_method="dns_txt", added_by_user_id=uid)
    target = db.get_target(target_id, org_id)
    assert target is not None, "created target was not readable back"
    assert target["url"] == "https://ci-smoke-test.example.invalid"

    print("[4/4] connector_state() and compute_risk() pure functions...")
    assert db.connector_state({"revoked_at": "2026-01-01T00:00:00+00:00",
                               "last_heartbeat_at": None}) == "REVOKED"
    risk = db.compute_risk("Critical", "sqli", "confirmed", "high", "WEB_APPLICATION")
    assert "risk_score" in risk

    print("OK: schema created cleanly, is idempotent, and round-trips real data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
