"""
Production-Grade Cryptographic Authentication & Principal Resolution.

Provides strict HMAC-SHA256 signed bearer token authentication with:
  - Cryptographic signature validation with constant-time comparison (timing-attack resistant).
  - Configurable token expiration (default: 3600 seconds / 1 hour).
  - Clock-skew window validation for future timestamps.
  - Zero support for forged or unsigned plaintext tokens (e.g. token_*, usr_*).
  - Secure-by-default production enforcement (REQUIRE_AUTH=true default).
  - Cryptographic entropy validation on AUTH_SECRET_KEY (minimum 32 characters / 256 bits).
"""

import os
import hmac
import hashlib
import time
import secrets
from dataclasses import dataclass
from typing import Optional
from fastapi import Request, Header, HTTPException, status


# Ephemeral in-memory fallback ONLY used in explicit dev/test environments if AUTH_SECRET_KEY is omitted
_EPHEMERAL_DEV_KEY = secrets.token_hex(32)


def is_auth_required() -> bool:
    """
    Returns True if authentication is strictly required (default in production).
    Can only be disabled by explicitly setting REQUIRE_AUTH=false in environment.
    """
    val = os.getenv("REQUIRE_AUTH")
    if val is None:
        return True  # Secure default
    return val.strip().lower() in ("true", "1", "yes")


def is_dev_headers_allowed() -> bool:
    """
    Returns True only when unauthenticated client-provided 'user-id' headers are
    explicitly permitted via ALLOW_UNAUTHENTICATED_DEV_HEADERS=true AND REQUIRE_AUTH=false.
    Never silently enabled in production.
    """
    if is_auth_required():
        return False
    val = os.getenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
    return val.strip().lower() in ("true", "1", "yes")


def get_auth_secret_key() -> str:
    """
    Retrieves and validates the HMAC signing secret key.
    
    Security Validation:
      1. Must be defined in environment (AUTH_SECRET_KEY).
      2. Must contain at least 32 characters (256 bits of entropy).
      3. Fails server startup immediately if missing or weak in production.
      4. Secrets are NEVER logged.
    """
    key = os.getenv("AUTH_SECRET_KEY", "").strip()

    is_dev_env = os.getenv("ENVIRONMENT", "").strip().lower() in ("development", "test", "testing")
    allow_dev = is_dev_headers_allowed() or is_dev_env

    if not key:
        if allow_dev:
            return _EPHEMERAL_DEV_KEY
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY environment variable is not configured. "
            "A cryptographically strong secret key (at least 32 characters / 256 bits) is mandatory in production."
        )

    if len(key) < 32:
        if allow_dev:
            return key
        raise ValueError(
            f"CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY has insufficient length "
            f"({len(key)} characters). Minimum required length is 32 characters (256 bits)."
        )

    return key


@dataclass
class AuthenticatedPrincipal:
    """
    Represents the verified identity of the requesting entity.
    
    Attributes:
        user_id (str): Canonical user identifier used for rate limiting and quota accounting.
        auth_type (str): Mechanism used to resolve the identity ('bearer_token', 'api_key', 'client_header').
        is_authenticated (bool): True if verified via cryptographic token or API key; False if client-asserted.
    """
    user_id: str
    auth_type: str
    is_authenticated: bool


def create_signed_token(
    user_id: str,
    secret_key: Optional[str] = None,
    timestamp: Optional[int] = None
) -> str:
    """
    Creates a tamper-proof HMAC-SHA256 signed bearer token.
    Format: <user_id>:<timestamp>:<hmac_sha256_hex_digest>
    """
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string")
    clean_uid = user_id.strip()
    if ":" in clean_uid:
        raise ValueError("user_id cannot contain colon ':' delimiter")

    ts = int(time.time()) if timestamp is None else int(timestamp)
    key = secret_key if secret_key is not None else get_auth_secret_key()

    payload = f"{clean_uid}:{ts}"
    signature = hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def verify_signed_token(
    token: str,
    secret_key: Optional[str] = None,
    max_age_seconds: int = 3600,
    allowed_clock_skew: int = 60
) -> Optional[str]:
    """
    Strictly verifies an HMAC-SHA256 signed token.
    
    Enforces:
      1. Exact 3-part format: <user_id>:<timestamp>:<signature>
      2. Valid cryptographic signature verified with constant-time comparison.
      3. Token expiration: Rejects tokens where now - timestamp > max_age_seconds.
      4. Future-timestamp rejection: Rejects timestamps beyond allowed_clock_skew into future.
      5. Complete rejection of all unsigned formats (e.g. token_*, usr_*).
    
    Returns:
        user_id (str) if valid and unexpired; None otherwise.
    """
    if not token or not isinstance(token, str):
        return None
    token = token.strip()

    # Reject unsigned shorthand patterns immediately
    if token.startswith("token_") or token.startswith("usr_"):
        return None

    parts = token.split(":")
    if len(parts) != 3:
        return None

    user_id, ts_str, provided_sig = parts
    if not user_id or not ts_str or not provided_sig:
        return None

    try:
        token_time = int(ts_str)
    except ValueError:
        return None

    key = secret_key if secret_key is not None else get_auth_secret_key()
    payload = f"{user_id}:{token_time}"
    expected_sig = hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    # Constant-time signature verification (prevents timing attacks)
    if not hmac.compare_digest(provided_sig, expected_sig):
        return None

    now = int(time.time())

    # Rejection of future timestamps outside clock-skew window
    if token_time > now + allowed_clock_skew:
        return None

    # Rejection of expired tokens
    if now - token_time > max_age_seconds:
        return None

    return user_id


def get_authenticated_principal(
    request: Request,
    authorization: Optional[str] = Header(None, alias="authorization"),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    user_id_dash: Optional[str] = Header(None, alias="user-id"),
    user_id_underscore: Optional[str] = Header(None, alias="user_id"),
) -> AuthenticatedPrincipal:
    """
    FastAPI dependency resolving the authenticated principal.

    Security Rules:
      1. If 'Authorization: Bearer <token>' or 'x-api-key' is present:
         - Token must be valid, unexpired, and cryptographically signed.
         - The rate limit identity is SOLELY derived from the validated token.
         - ANY client-provided 'user-id' or 'user_id' header is STRICTLY IGNORED.
         - Invalid or expired tokens return 401 Unauthorized.
      2. If no credentials are provided:
         - Under default production settings (REQUIRE_AUTH=true): Rejects with 401 Unauthorized.
         - Under explicit dev override (ALLOW_UNAUTHENTICATED_DEV_HEADERS=true and REQUIRE_AUTH=false):
           Accepts 'user-id' header with is_authenticated=False.
    """
    # 1. Evaluate Authorization: Bearer <token>
    if authorization:
        parts = authorization.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
            verified_uid = verify_signed_token(token)
            if verified_uid:
                return AuthenticatedPrincipal(
                    user_id=verified_uid,
                    auth_type="bearer_token",
                    is_authenticated=True
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or malformed bearer token."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must follow 'Bearer <token>' format."
            )

    # 2. Evaluate X-API-Key
    if x_api_key:
        verified_uid = verify_signed_token(x_api_key.strip())
        if verified_uid:
            return AuthenticatedPrincipal(
                user_id=verified_uid,
                auth_type="api_key",
                is_authenticated=True
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or malformed API key."
        )

    # 3. Handle unauthenticated requests
    if is_auth_required():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide 'Authorization: Bearer <token>' or 'X-API-Key'."
        )

    # 4. Explicit development-only fallback using client-controlled header
    if is_dev_headers_allowed():
        raw_header_uid = (user_id_dash or user_id_underscore or "").strip()
        if raw_header_uid:
            return AuthenticatedPrincipal(
                user_id=raw_header_uid,
                auth_type="client_header",
                is_authenticated=False
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authentication credentials or 'user-id' header."
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required."
    )
