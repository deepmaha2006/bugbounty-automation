"""Auth helpers: password hashing + JWT tokens (HydraX)."""
import datetime
import hashlib
import hmac
import secrets
from typing import Optional

import jwt
import pyotp

from webapp import config, db


# OWASP password storage cheat sheet / ASVS V6.2.3 current guidance for
# PBKDF2-HMAC-SHA256 is >= 600,000 iterations — was 120,000 (roughly a
# decade-old recommendation). The iteration count is embedded in the hash
# string itself (4-part format) so it can be raised again in the future
# without invalidating already-issued hashes: verify_password always uses
# whatever count a given hash was actually created with, never today's
# constant, so this upgrade doesn't lock out any existing account.
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, salt: Optional[str] = None,
                  iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or hashlib.sha256(password.encode()).hexdigest()[:16]
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    parts = stored.split("$")
    if len(parts) == 4:
        _, iterations, salt, expected_hex = parts
        try:
            iterations = int(iterations)
        except ValueError:
            return False
    elif len(parts) == 3:
        # Legacy format from before the iteration count was embedded
        # (always 120,000) — still verifiable, never silently rejected.
        _, salt, expected_hex = parts
        iterations = 120_000
    else:
        return False
    # Compare the derived key itself, not a re-formatted hash string: a
    # legacy 3-part `stored` can never equal hash_password()'s always-4-part
    # output even when the underlying bytes match, since the two would only
    # differ by the embedded iteration-count field.
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return hmac.compare_digest(dk.hex(), expected_hex)


def needs_rehash(stored: str) -> bool:
    """True if `stored` was created with a lower work factor than today's
    PBKDF2_ITERATIONS (or predates the versioned format entirely) — the
    login route uses this to opportunistically upgrade a hash the instant
    it has the plaintext available, never any other time."""
    parts = stored.split("$")
    if len(parts) == 4:
        try:
            return int(parts[1]) < PBKDF2_ITERATIONS
        except ValueError:
            return True
    return True


def create_token(user_id: int, role: str = "user") -> str:
    if not getattr(config, "AUTH_CONFIGURED", False):
        raise RuntimeError(
            "JWT signing is disabled: HYDRAX_JWT_SECRET is not configured and "
            "HYDRAX_JWT_DEV_MODE is not enabled. Set the secret before "
            "starting the service."
        )
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=config.JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGO)


def decode_token(token: str) -> Optional[dict]:
    if not getattr(config, "AUTH_CONFIGURED", False):
        return None
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGO])
        return payload
    except jwt.PyJWTError:
        return None


def current_user_from_token(token: str) -> Optional[dict]:
    payload = decode_token(token)
    if not payload or payload.get("mfa_pending"):
        # An MFA-pending token is only ever valid for /auth/mfa/verify — never
        # as a general bearer credential, even though it's a normal signed JWT.
        return None
    return db.get_user_by_id(int(payload["sub"]))


# --- MFA-pending token (Phase 3) -------------------------------------------
def create_mfa_pending_token(user_id: int) -> str:
    if not getattr(config, "AUTH_CONFIGURED", False):
        raise RuntimeError("JWT signing is disabled: HYDRAX_JWT_SECRET is not configured.")
    payload = {
        "sub": str(user_id),
        "mfa_pending": True,
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=config.MFA_PENDING_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGO)


def user_id_from_mfa_pending_token(token: str) -> Optional[int]:
    payload = decode_token(token)
    if not payload or not payload.get("mfa_pending"):
        return None
    return int(payload["sub"])


# --- TOTP (Phase 3) ---------------------------------------------------------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account_email, issuer_name="HydraX")


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.totp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:  # noqa: BLE001 — malformed code/secret is just "invalid"
        return False


# --- High-entropy token hashing (Phase 3) -----------------------------------
# Refresh tokens and API keys are random, high-entropy strings, not
# human-chosen passwords — a fast cryptographic hash is the correct (and
# standard) choice here, unlike hash_password's deliberately slow PBKDF2.
def hash_opaque_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def generate_api_key() -> tuple:
    """Returns (raw_key, display_prefix). The raw key is shown to the caller
    exactly once and never stored — only its hash is persisted."""
    raw = f"hdx_{secrets.token_urlsafe(32)}"
    return raw, raw[:12]
