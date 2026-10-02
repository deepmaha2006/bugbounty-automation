"""Ed25519 signing for the Company Connector job/result protocol (spec §6).

The platform signs every job it sends; the connector must verify that
signature — plus expiry and that the job is within its assigned scope —
before ever executing anything (docs/SECURITY_MODEL.md §4). The connector
signs its own results with its own per-connector keypair (generated on the
connector itself, private key never transmitted) so the platform can detect
tampering in transit and hold the connector accountable for what it reports.

A connector's *identity* auth (which connector is making this HTTP request)
is a separate, simpler bearer secret (see webapp/db.py's connector_secret
functions) — deliberately not folded into the signing scheme: the signature
is about payload integrity/non-repudiation of jobs and results specifically,
not session authentication, and conflating the two would need replay-attack
handling (nonces, timestamp windows) for no real security gain over
TLS-protected bearer auth for the routine heartbeat/poll traffic.
"""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from webapp import config


def canonical_bytes(payload: dict) -> bytes:
    """Deterministic serialization so both sides sign/verify identical
    bytes regardless of dict insertion order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def generate_keypair_pem() -> tuple:
    """Returns (private_key_pem, public_key_pem) for a brand-new identity —
    used both by the platform's own signing key (if not preconfigured) and
    by the connector agent at enrollment time."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem.encode(), password=None)


def load_public_key(pem: str) -> Ed25519PublicKey:
    # load_pem_public_key() is a generic loader that happily accepts any key
    # type (RSA, EC, DSA, ...) — nothing about the PEM format itself
    # enforces Ed25519. Enrolling a non-Ed25519 key wouldn't be a security
    # bypass (verify() below fails closed on the resulting TypeError/
    # ValueError, since e.g. RSAPublicKey.verify() has a different, non-
    # compatible signature), but it would silently accept an enrollment
    # that can then never successfully verify anything — reject it here
    # instead, at the point where a clear error is actually possible.
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key must be Ed25519, got " + type(key).__name__)
    return key


def sign(private_key_pem: str, payload: dict) -> str:
    key = load_private_key(private_key_pem)
    sig = key.sign(canonical_bytes(payload))
    return base64.b64encode(sig).decode()


def verify(public_key_pem: str, payload: dict, signature_b64: str) -> bool:
    """Never raises — a malformed key/signature/payload is simply 'not
    valid', matching how every other auth check in this platform fails
    closed without leaking why."""
    try:
        key = load_public_key(public_key_pem)
        key.verify(base64.b64decode(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def job_signing_payload(job: dict) -> dict:
    """The exact canonical payload every job signature covers — shared by
    both the signer (job creation) and every verifier (the connector agent,
    and this platform's own tests), so a datetime vs. already-ISO-string
    field never produces mismatched bytes."""
    def _iso(v):
        return v if isinstance(v, str) else v.isoformat()
    return {
        "job_id": job["id"],
        "organization_id": job["organization_id"],
        "connector_id": job["connector_id"],
        "job_type": job["job_type"],
        "scope": job["scope"],
        "authorization": (f"user:{job['authorized_by_user_id']}"
                         if job.get("authorized_by_user_id") else "system"),
        "created_at": _iso(job["created_at"]),
        "expires_at": _iso(job["expires_at"]),
    }


_ephemeral_platform_keys = None


def get_platform_signing_keys() -> tuple:
    """Returns (private_pem, public_pem) for the platform's own job-signing
    identity. Falls back to a process-lifetime ephemeral keypair if
    HYDRAX_JOB_SIGNING_PRIVATE_KEY isn't configured — exactly the same
    fail-safe-for-dev-only pattern as webapp.config's JWT secret handling:
    connectors enrolled against an ephemeral key stop trusting the platform
    after a restart, which is loud and obvious rather than a silent security
    gap in a real deployment."""
    global _ephemeral_platform_keys
    if config.JOB_SIGNING_PRIVATE_KEY_PEM:
        priv = config.JOB_SIGNING_PRIVATE_KEY_PEM
        pub = load_private_key(priv).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return priv, pub
    if _ephemeral_platform_keys is None:
        import warnings
        warnings.warn(
            "HYDRAX_JOB_SIGNING_PRIVATE_KEY is not configured: using a throwaway "
            "in-process job-signing key. Connectors enrolled now will stop trusting "
            "the platform after a restart — set this for any real deployment.",
            RuntimeWarning,
        )
        _ephemeral_platform_keys = generate_keypair_pem()
    return _ephemeral_platform_keys
