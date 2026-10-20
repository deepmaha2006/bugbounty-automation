#!/usr/bin/env python3
"""
HydraX Lab — teardown script.

Removes transient lab state so the lab can be re-seeded cleanly:
  1. Clear WAF snippets from the connector's HYDRAX_WAF_DIR (docker exec).
  2. Roll back all outstanding brain_actions in Postgres.
  3. Reload nginx in the connector container so cleared rules take effect.
  4. Delete lab_state.json if it exists.

Designed to run from the host after `make lab-test` or before `make lab-up`
for a clean re-run. It does NOT stop or remove containers — use
`docker compose -f lab/docker-compose.yml down` for that.

Environment variables:
  COMPOSE_FILE      (default lab/docker-compose.yml)
  POSTGRES_HOST     (default localhost)
  POSTGRES_PORT     (default 5433)
  POSTGRES_DB       (default hydrax)
  POSTGRES_USER     (default hydrax)
  POSTGRES_PASSWORD (default hydraxpass)
  CONNECTOR_SERVICE Docker service name for the connector (default connector)
"""
import os
import subprocess
import sys

import psycopg2

PG_HOST     = os.environ.get("POSTGRES_HOST",    "localhost")
PG_PORT     = int(os.environ.get("POSTGRES_PORT",  "5433"))
PG_DB       = os.environ.get("POSTGRES_DB",      "hydrax")
PG_USER     = os.environ.get("POSTGRES_USER",    "hydrax")
PG_PASS     = os.environ.get("POSTGRES_PASSWORD","hydraxpass")

COMPOSE_FILE     = os.environ.get("COMPOSE_FILE",      "lab/docker-compose.yml")
CONNECTOR_SVC    = os.environ.get("CONNECTOR_SERVICE",  "connector")
WAF_DIR          = "/hydrax-waf-rules"
STATE_FILE       = os.path.join(os.path.dirname(__file__), "lab_state.json")


def _run(cmd: list, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    kwargs = {"check": check}
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    return subprocess.run(cmd, **kwargs)


def _pg_conn():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
        connect_timeout=10,
    )


def step_clear_waf_rules() -> None:
    """Remove all WAF snippet files from the connector container."""
    print("[teardown] Clearing WAF rules in connector ...")
    result = _run(
        ["docker", "compose", "-f", COMPOSE_FILE,
         "exec", "-T", CONNECTOR_SVC,
         "sh", "-c", f"rm -f {WAF_DIR}/*.conf && echo 'cleared'"],
        check=False, capture=True,
    )
    if result.returncode != 0:
        print(f"[teardown] WARNING: could not clear WAF rules: {result.stderr.strip()}")
    else:
        print("[teardown] WAF rules cleared.")


def step_reload_nginx() -> None:
    """nginx reload so cleared WAF rules are applied immediately."""
    print("[teardown] Reloading nginx in connector ...")
    result = _run(
        ["docker", "compose", "-f", COMPOSE_FILE,
         "exec", "-T", CONNECTOR_SVC,
         "nginx", "-s", "reload"],
        check=False, capture=True,
    )
    if result.returncode != 0:
        print(f"[teardown] WARNING: nginx reload failed: {result.stderr.strip()}")
    else:
        print("[teardown] nginx reloaded.")


def step_rollback_brain_actions() -> None:
    """Set all non-terminal brain_actions back to 'rolled_back' in Postgres."""
    print("[teardown] Rolling back brain_actions ...")
    try:
        conn = _pg_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE brain_actions
                       SET status = 'rolled_back', rolled_back_at = NOW()
                       WHERE status IN ('applied', 'proposed')""",
                )
                print(f"[teardown] {cur.rowcount} brain_actions rolled back.")
        conn.close()
    except Exception as exc:
        print(f"[teardown] WARNING: brain_actions rollback failed: {exc}")


def step_unblock_iptables() -> None:
    """Flush any HYDRAX-added iptables rules from the connector container.

    The connector agent inserts rules with a comment so we can target them.
    """
    print("[teardown] Flushing iptables INPUT rules in connector ...")
    result = _run(
        ["docker", "compose", "-f", COMPOSE_FILE,
         "exec", "-T", CONNECTOR_SVC,
         "sh", "-c",
         "iptables -S INPUT | grep HYDRAX || true"],
        check=False, capture=True,
    )
    rules = [l.strip() for l in result.stdout.splitlines() if "HYDRAX" in l]
    for rule in rules:
        # Convert -A … to -D … to delete
        delete_cmd = rule.replace("-A ", "-D ", 1).replace("-I ", "-D ", 1)
        _run(
            ["docker", "compose", "-f", COMPOSE_FILE,
             "exec", "-T", CONNECTOR_SVC,
             "iptables"] + delete_cmd.split(),
            check=False,
        )
    print(f"[teardown] Removed {len(rules)} iptables rule(s).")


def step_delete_state_file() -> None:
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        print(f"[teardown] Deleted {STATE_FILE}")
    else:
        print("[teardown] No lab_state.json to delete.")


def main():
    step_clear_waf_rules()
    step_reload_nginx()
    step_unblock_iptables()
    step_rollback_brain_actions()
    step_delete_state_file()
    print("[teardown] Done.")


if __name__ == "__main__":
    main()
