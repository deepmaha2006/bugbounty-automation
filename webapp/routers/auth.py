"""Auth routes: register, login (+ MFA), refresh/logout, RBAC dependencies (HydraX)."""
import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from webapp import config, db, security
from webapp.logging_config import organization_id_var
from webapp.schemas import (RegisterRequest, LoginRequest, UserOut, TokenOut,
                            MfaRequiredOut, RefreshRequest, MfaVerifyRequest,
                            MfaSetupOut, MfaEnableRequest, MfaDisableRequest,
                            MessageOut)
from webapp.services.auth_limiter import AuthLimiter

router = APIRouter(prefix="/api/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)

# In-memory brute-force protection (P2-3). Bounded, local, deterministic.
login_limiter = AuthLimiter(
    max_attempts=config.RATE_LIMIT_LOGIN_MAX_ATTEMPTS,
    window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
    max_keys=config.RATE_LIMIT_MAX_KEYS,
)
register_limiter = AuthLimiter(
    max_attempts=config.RATE_LIMIT_REGISTER_MAX_ATTEMPTS,
    window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
    max_keys=config.RATE_LIMIT_MAX_KEYS,
)

# --- RBAC (Phase 3) ---------------------------------------------------------
ALL_ROLES = ("admin", "security_manager", "security_analyst", "viewer")
OPERATOR_ROLES = ("admin", "security_manager", "security_analyst")


def _is_trusted_proxy(host: str) -> bool:
    if not host or not config.TRUSTED_PROXY_IPS:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in config.TRUSTED_PROXY_IPS:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _client_ip(request: Request) -> str:
    """The real, rate-limiting-relevant client identity.

    Only reads X-Forwarded-For/X-Real-IP when the immediate TCP peer is a
    configured trusted proxy (HYDRAX_TRUSTED_PROXY_IPS) — otherwise those
    headers are attacker-controlled input an unauthenticated caller could
    set to any value at all, which would let them pick their own rate-limit
    key and never actually be throttled (CWE-290). With no trusted proxies
    configured (the default), this is identical to the raw TCP peer, exactly
    today's behavior.
    """
    peer = request.client.host if request.client else None
    if peer and _is_trusted_proxy(peer):
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            # Leftmost entry is the original client per the standard
            # convention; every hop after it is added by a proxy we trust.
            return xff.split(",")[0].strip() or peer
        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip:
            return x_real_ip.strip()
    return peer or "unknown"


def _rate_limited() -> HTTPException:
    """Uniform 429 for every throttled path — never reveals account state."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many attempts. Please try again later.",
        headers={"Retry-After": str(config.RATE_LIMIT_WINDOW_SECONDS)},
    )


# WSTG-IDNT-04 / CWE-208: db.get_user_by_username() returning None short-
# circuits verify_password() below for a nonexistent account, which is
# otherwise the only expensive step in this request (a real PBKDF2
# computation vs. none at all) — a measurable, exploitable timing
# difference an attacker can use to enumerate valid usernames without ever
# seeing a different error message. A precomputed dummy hash, always
# verified against on the "no such user" path, keeps the timing profile
# consistent regardless of whether the account exists.
_DUMMY_PASSWORD_HASH = security.hash_password(secrets.token_urlsafe(32))


def _as_aware_datetime(value) -> datetime:
    """Real Postgres rows come back as naive datetime (server=UTC by
    convention here); FakeDB stores ISO strings. Normalize either to an
    aware UTC datetime so lockout/expiry comparisons are always correct."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def require_roles(*allowed_roles: str):
    """Dependency factory: authenticated AND role is one of `allowed_roles`.

    Accepts either a JWT bearer token or an ``X-API-Key`` header (spec §17:
    API authentication distinct from user session tokens) — whichever is
    present; the API key path never touches the JWT machinery at all.
    """
    def _dep(cred: HTTPAuthorizationCredentials = Depends(bearer),
            x_api_key: Optional[str] = Header(None)) -> dict:
        user = _resolve_user(cred, x_api_key)
        if user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403,
                                detail="Your role does not permit this action")
        return user
    return _dep


def _resolve_user(cred: Optional[HTTPAuthorizationCredentials],
                  x_api_key: Optional[str]) -> Optional[dict]:
    user = _resolve_user_uncorrelated(cred, x_api_key)
    if user is not None and user.get("organization_id") is not None:
        # Every log line for the rest of this request now carries the
        # caller's org (spec §22's request/organization-correlated
        # structured logging) — set at the single choke point every
        # authenticated route passes through, not duplicated per-route.
        organization_id_var.set(user["organization_id"])
    return user


def _resolve_user_uncorrelated(cred: Optional[HTTPAuthorizationCredentials],
                               x_api_key: Optional[str]) -> Optional[dict]:
    if x_api_key:
        row = db.get_api_key_by_hash(security.hash_opaque_token(x_api_key))
        if not row:
            return None
        db.touch_api_key(row["id"])
        return db.get_user_by_id(row["user_id"])
    if cred:
        return security.current_user_from_token(cred.credentials)
    return None


def require_user(cred: HTTPAuthorizationCredentials = Depends(bearer),
                 x_api_key: Optional[str] = Header(None)) -> dict:
    """Any authenticated user, regardless of role — for self-service routes
    (profile, MFA setup, organization info) that every role may use."""
    user = _resolve_user(cred, x_api_key)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


require_admin = require_roles("admin")
# Can create/modify assets, run scans, manage verification — not user/org admin.
require_operator = require_roles(*OPERATOR_ROLES)
# Read-only access to assets/scans/findings/reports/dashboards — every role.
require_viewer = require_roles(*ALL_ROLES)


def optional_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred:
        return None
    return security.current_user_from_token(cred.credentials)


def require_viewer_sse(request: Request,
                       cred: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """Same role check as require_viewer, but also accepts the token as a
    ``?token=`` query parameter.

    The browser's native EventSource API cannot set an Authorization header,
    so the SSE scan-events route (the only consumer of this dependency) must
    accept the token some other way. Every other route keeps using a
    header-only dependency — this widening is scoped to that one route.
    """
    token = cred.credentials if cred else request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = security.current_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if user.get("role") not in ALL_ROLES:
        raise HTTPException(status_code=403,
                            detail="Your role does not permit this action")
    return user


# --- token issuance ----------------------------------------------------------
def _issue_token_pair(user: dict) -> TokenOut:
    access = security.create_token(user["id"], role=user["role"])
    raw_refresh = security.generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    db.create_refresh_token(user["id"], security.hash_opaque_token(raw_refresh), expires_at)
    return TokenOut(access_token=access, refresh_token=raw_refresh, user=UserOut(**user))


@router.post("/register", response_model=TokenOut)
def register(body: RegisterRequest, request: Request):
    """Admin-only platform: registration is closed unless an admin already
    exists (first account bootstraps as admin) or HYDRAX_ADMIN_SIGNUP_TOKEN
    is configured and supplied as the username prefix.

    When `organization_name` is supplied (and the above gate is satisfied),
    registration creates a brand-new, isolated organization with this user as
    its Admin — this is the multi-tenant "a new company signs up" path.
    Without it, the user joins the platform's pre-existing Default
    Organization, exactly matching pre-multi-tenancy behavior.
    """
    ip = _client_ip(request)
    with register_limiter.guard(ip) as gate:
        if not gate.allowed():
            raise _rate_limited()
        is_first_user_ever = db.count_users() == 0
        if not is_first_user_ever:
            token = os.environ.get("HYDRAX_ADMIN_SIGNUP_TOKEN", "")
            if not token:
                gate.fail()
                raise HTTPException(
                    status_code=403,
                    detail="Registration is closed. Contact the platform administrator.",
                )
            # Require the bootstrap token via the email field: token@hydrax.local
            if body.email.strip().lower() != f"{token.lower()}@hydrax.local":
                gate.fail()
                raise HTTPException(
                    status_code=403,
                    detail="Registration is closed. A valid admin signup token is required.",
                )
        if db.get_user_by_username(body.username):
            gate.fail()
            raise HTTPException(status_code=400, detail="Username already taken")

        new_org_name = (body.organization_name or "").strip()
        creating_new_org = bool(new_org_name)
        organization_id = (db.create_organization(new_org_name) if creating_new_org
                          else db.get_default_organization_id())

        uid = db.create_user(body.username, body.email,
                             security.hash_password(body.password), organization_id)
        # Always-admin cases: the very first user on the whole platform, or
        # the founding user of a newly created organization.
        if is_first_user_ever or creating_new_org:
            db.promote_to_admin(uid)
        user = db.get_user_by_id(uid)
        gate.success()
        db.add_audit_log(uid, "user_created", details={"self_registered": True})
        return _issue_token_pair(user)


@router.post("/login", response_model=Union[TokenOut, MfaRequiredOut])
def login(body: LoginRequest, request: Request):
    # Keyed by normalized username + IP so a brute-force burst on one account
    # from one source is throttled without affecting other users/sources.
    with login_limiter.guard(body.username.strip().lower(), _client_ip(request)) as gate:
        if not gate.allowed():
            raise _rate_limited()
        user = db.get_user_by_username(body.username)

        # Persistent, user-keyed account lockout — distinct from (and on top
        # of) the sliding-window limiter above; see config.py.
        if user and user.get("locked_until"):
            if datetime.now(timezone.utc) < _as_aware_datetime(user["locked_until"]):
                gate.fail()
                raise HTTPException(
                    status_code=403,
                    detail="Account locked due to repeated failed logins. "
                           "Try again later or contact your administrator.",
                )

        if user:
            password_ok = security.verify_password(body.password, user["password_hash"])
        else:
            # Burn the same PBKDF2 computation a real user would cost, so
            # "no such user" and "wrong password" are not distinguishable by
            # response time (see _DUMMY_PASSWORD_HASH above).
            security.verify_password(body.password, _DUMMY_PASSWORD_HASH)
            password_ok = False

        if not user or not password_ok:
            gate.fail()
            if user:
                db.record_login_failure(user["id"], config.ACCOUNT_LOCKOUT_THRESHOLD,
                                        config.ACCOUNT_LOCKOUT_DURATION_MINUTES)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        gate.success()
        db.clear_login_failures(user["id"])

        # Opportunistic upgrade (ASVS V6.2.4): a successful login is exactly
        # when we know the plaintext, so it's the only safe moment to
        # transparently re-hash a hash created under a lower, now-outdated
        # work factor — never done any other time, and never blocks login.
        if security.needs_rehash(user["password_hash"]):
            db.update_password_hash(user["id"], security.hash_password(body.password))

        if user.get("mfa_enabled"):
            return MfaRequiredOut(mfa_token=security.create_mfa_pending_token(user["id"]))

        db.add_audit_log(user["id"], "login")
        return _issue_token_pair(user)


@router.post("/mfa/verify", response_model=TokenOut)
def mfa_verify(body: MfaVerifyRequest, request: Request):
    with login_limiter.guard("mfa", _client_ip(request)) as gate:
        if not gate.allowed():
            raise _rate_limited()
        uid = security.user_id_from_mfa_pending_token(body.mfa_token)
        user = db.get_user_by_id(uid) if uid else None
        if not user or not user.get("mfa_enabled"):
            gate.fail()
            raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")
        if not security.verify_totp(user.get("mfa_secret"), body.code):
            gate.fail()
            raise HTTPException(status_code=401, detail="Invalid authentication code")
        gate.success()
        db.add_audit_log(user["id"], "login", details={"mfa": True})
        return _issue_token_pair(user)


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshRequest):
    row = db.get_refresh_token(security.hash_opaque_token(body.refresh_token))
    if not row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if row.get("revoked_at"):
        # Reuse of an already-rotated token — the whole family may be
        # compromised (spec §17 token rotation with reuse detection).
        db.revoke_all_refresh_tokens_for_user(row["user_id"])
        raise HTTPException(status_code=401,
                            detail="Refresh token already used — all sessions revoked, please log in again")
    if datetime.now(timezone.utc) >= _as_aware_datetime(row["expires_at"]):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db.get_user_by_id(row["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_raw = security.generate_refresh_token()
    new_expires = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    new_id = db.rotate_refresh_token(row["id"], security.hash_opaque_token(new_raw), new_expires)
    if new_id is None:
        # Lost an atomic race against a concurrent refresh of the same
        # token (CWE-362) — indistinguishable from replay of an
        # already-rotated token, and handled identically: fail closed.
        db.revoke_all_refresh_tokens_for_user(row["user_id"])
        raise HTTPException(status_code=401,
                            detail="Refresh token already used — all sessions revoked, please log in again")
    access = security.create_token(user["id"], role=user["role"])
    return TokenOut(access_token=access, refresh_token=new_raw, user=UserOut(**user))


@router.post("/logout", response_model=MessageOut)
def logout(body: RefreshRequest, user: dict = Depends(require_user)):
    db.revoke_refresh_token(security.hash_opaque_token(body.refresh_token))
    db.add_audit_log(user["id"], "logout")
    return MessageOut(message="Logged out")


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(require_user)):
    return UserOut(**user)


# --- MFA self-service --------------------------------------------------------
@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(user: dict = Depends(require_user)):
    if user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    secret = security.generate_totp_secret()
    db.set_mfa_secret_pending(user["id"], secret)
    return MfaSetupOut(secret=secret,
                       otpauth_url=security.totp_provisioning_uri(secret, user["email"]))


@router.post("/mfa/enable", response_model=MessageOut)
def mfa_enable(body: MfaEnableRequest, user: dict = Depends(require_user)):
    fresh = db.get_user_by_id(user["id"])
    if not fresh or not fresh.get("mfa_secret"):
        raise HTTPException(status_code=400, detail="Call /mfa/setup first")
    if not security.verify_totp(fresh["mfa_secret"], body.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    db.enable_mfa(user["id"])
    db.add_audit_log(user["id"], "mfa_enabled")
    return MessageOut(message="MFA enabled")


@router.post("/mfa/disable", response_model=MessageOut)
def mfa_disable(body: MfaDisableRequest, user: dict = Depends(require_user)):
    fresh = db.get_user_by_id(user["id"])
    if not fresh or not security.verify_password(body.password, fresh["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not fresh.get("mfa_enabled") or not security.verify_totp(fresh.get("mfa_secret"), body.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    db.disable_mfa(user["id"])
    db.add_audit_log(user["id"], "mfa_disabled")
    return MessageOut(message="MFA disabled")
