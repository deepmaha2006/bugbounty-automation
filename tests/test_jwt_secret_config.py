"""P2-2 regression tests — persistent (explicit) JWT secret.

The platform must never fall back to a silently generated random secret for
normal operation. An operator-provided HYDRAX_JWT_SECRET is required; explicit
HYDRAX_JWT_DEV_MODE=1 is the only branch allowed to use a throwaway in-process
secret. Missing secret outside dev mode fails closed (auth disabled).

Covered:
  * resolver: provided secret wins; missing -> disabled; dev -> ephemeral
  * in-process: the configured secret actually signs/verifies tokens
  * API: register/login/me still work with a configured secret
  * fresh interpreter: missing secret fails safely (create_token raises,
    decode_token returns None, no secret issued) — via subprocess so the real
    env-driven import-time resolution is exercised without contaminating the
    pytest process (conftest always provides a secret for the suite)
  * fresh interpreter: dev mode mints a working ephemeral secret, and the
    ephemeral secret value never leaks into output/logs

Hermetic: no network, no public targets, no production DB.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from webapp import config, security
from webapp.config import resolve_jwt_secret

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Pure resolver unit tests
# ---------------------------------------------------------------------------
class TestSecretResolution:
    def test_provided_secret_wins(self):
        r = resolve_jwt_secret("   operator-secret  ", dev_mode=False)
        assert r == {"secret": "operator-secret", "configured": True,
                     "ephemeral": False}

    def test_provided_secret_is_never_overridden_by_dev_mode(self):
        r = resolve_jwt_secret("op-secret", dev_mode=True)
        assert r == {"secret": "op-secret", "configured": True,
                     "ephemeral": False}

    def test_missing_secret_outside_dev_mode_disables_auth(self):
        r = resolve_jwt_secret("", dev_mode=False)
        assert r == {"secret": "", "configured": False, "ephemeral": False}

    def test_whitespace_secret_treated_as_unset(self):
        r = resolve_jwt_secret("   ", dev_mode=False)
        assert r["configured"] is False, "whitespace must not count as a secret"

    def test_dev_mode_mints_fresh_throwaway_secret(self):
        r1 = resolve_jwt_secret("", dev_mode=True)
        r2 = resolve_jwt_secret("", dev_mode=True)
        assert r1["configured"] is True and r1["ephemeral"] is True
        assert r1["secret"] and len(r1["secret"]) == 64  # token_hex(32)
        assert r1["secret"] != r2["secret"], "each boot mints a fresh key"


# ---------------------------------------------------------------------------
# Active (in-process) configuration — conftest injects an operator secret
# ---------------------------------------------------------------------------
class TestConfiguredSecretWorksInProcess:
    def test_active_config_reflects_operator_secret(self):
        # conftest sets HYDRAX_JWT_SECRET before webapp.config is imported.
        assert config.AUTH_CONFIGURED is True
        assert config.JWT_EPHEMERAL is False
        assert config.JWT_SECRET == os.environ.get("HYDRAX_JWT_SECRET", "")

    def test_token_round_trip_with_configured_secret(self):
        assert config.AUTH_CONFIGURED is True
        token = security.create_token(42, role="admin")
        payload = security.decode_token(token)
        assert payload is not None
        assert payload["sub"] == "42"
        assert payload["role"] == "admin"

    def test_garbage_token_rejected(self):
        assert security.decode_token("not-a-jwt") is None


# ---------------------------------------------------------------------------
# API integration — existing register/login/me behavior keeps working
# ---------------------------------------------------------------------------
class TestLoginAuthFlowWithConfiguredSecret:
    def test_register_login_me_flow(self, fake, client):
        assert config.AUTH_CONFIGURED is True
        reg = client.post("/api/auth/register", json={
            "username": "jwttest", "email": "jwttest@hydrax.local",
            "password": "passw0rd1234",
        })
        assert reg.status_code == 200, reg.text
        token = reg.json()["access_token"]
        assert security.decode_token(token) is not None

        me = client.get("/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200, me.text
        assert me.json()["username"] == "jwttest"

        login = client.post("/api/auth/login", json={
            "username": "jwttest", "password": "passw0rd1234",
        })
        assert login.status_code == 200, login.text
        me2 = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"})
        assert me2.status_code == 200, me2.text
        assert me2.json()["username"] == "jwttest"


# ---------------------------------------------------------------------------
# Fresh-interpreter tests — exercise real import-time env resolution
# ---------------------------------------------------------------------------
def _run_fresh(env_adjust: dict, body: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items()}
    env.pop("HYDRAX_JWT_SECRET", None)
    env.pop("HYDRAX_JWT_DEV_MODE", None)
    for k, v in env_adjust.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    env["PYTHONPATH"] = str(ROOT)
    code = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        + body
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=60,
    )


class TestMissingSecretFailsSafely:
    def test_auth_disabled_in_fresh_interpreter(self):
        body = """\
import webapp.config as c
import webapp.security as s
out = {}
out["secret_empty"] = c.JWT_SECRET == ""
out["auth_configured"] = bool(getattr(c, "AUTH_CONFIGURED", False))
out["ephemeral"] = bool(getattr(c, "JWT_EPHEMERAL", False))
try:
    s.create_token(1, "admin")
    out["create_token_raised"] = False
except RuntimeError:
    out["create_token_raised"] = True
out["decode_token_none"] = s.decode_token("bogus") is None
print(json.dumps(out))"""
        proc = _run_fresh(env_adjust={"HYDRAX_JWT_SECRET": None}, body=body)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        assert out == {
            "secret_empty": True, "auth_configured": False,
            "ephemeral": False, "create_token_raised": True,
            "decode_token_none": True,
        }, out

    def test_auth_disabled_warning_contains_no_secret(self):
        body = "import webapp.config"  # emits the disabled-auth RuntimeWarning
        proc = _run_fresh(env_adjust={"HYDRAX_JWT_SECRET": None}, body=body)
        assert proc.returncode == 0, proc.stderr
        assert "HYDRAX_JWT_SECRET" in proc.stderr  # actionable hint is fine
        # No 64-char hex secret anywhere in the process's stderr.
        assert "token_hex" not in proc.stderr


class TestDevModeIsExplicitAndDoesNotLeak:
    def test_dev_mode_mints_working_ephemeral_secret(self):
        body = """\
import webapp.config as c
import webapp.security as s
out = {}
out["secret_nonempty"] = bool(c.JWT_SECRET)
out["auth_configured"] = bool(getattr(c, "AUTH_CONFIGURED", False))
out["ephemeral"] = bool(getattr(c, "JWT_EPHEMERAL", False))
tok = s.create_token(7, "admin")
payload = s.decode_token(tok)
out["roundtrip"] = bool(payload and payload.get("sub") == "7"
                        and payload.get("role") == "admin")
print(json.dumps(out))
print("EPH:" + c.JWT_SECRET)"""
        proc = _run_fresh(env_adjust={"HYDRAX_JWT_DEV_MODE": "1"}, body=body)
        assert proc.returncode == 0, proc.stderr
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        out = json.loads(lines[0])
        assert out == {"secret_nonempty": True, "auth_configured": True,
                       "ephemeral": True, "roundtrip": True}, out
        ephemeral = lines[1].split(":", 1)[1]
        # The ephemeral secret value must never appear in stderr (logs/warnings).
        assert ephemeral not in proc.stderr
        assert ephemeral not in proc.stdout.replace(lines[1], "", 1)

    def test_dev_mode_is_never_the_default(self):
        # No HYDRAX_JWT_DEV_MODE and no secret -> disabled, not ephemeral.
        r = resolve_jwt_secret("", dev_mode=False)
        assert r["ephemeral"] is False and r["configured"] is False