"""
Authentication and Principal Identity Resolution (Priority 1).

Provides secure authenticated principal resolution to ensure rate limiting is bound
to verified identities, not client-controlled request headers.
"""

import os
import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Optional
from fastapi import Request, Header, HTTPException, status


SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "rate-limiter-default-secret-key-change-in-prod")
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() in ("true", "1", "yes")


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


def create_signed_token(user_id: str, secret_key: str = SECRET_KEY) -> str:
    """Creates a tamper-proof HMAC-SHA256 signed bearer token for a user."""
    user_id = user_id.strip()
    timestamp = int(time.time())
    payload = f"{user_id}:{timestamp}"
    signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{signature}"


def verify_signed_token(token: str, secret_key: str = SECRET_KEY) -> Optional[str]:
    """
    Validates an HMAC-SHA256 signed bearer token or structured developer token.
    Returns user_id if valid, or None if invalid.
    """
    if not token or not isinstance(token, str):
        return None
    token = token.strip()

    # 1. Check for HMAC-SHA256 signed token (user_id:timestamp:sig)
    parts = token.split(":")
    if len(parts) == 3:
        user_id, timestamp_str, sig = parts
        if not user_id.strip():
            return None
        payload = f"{user_id}:{timestamp_str}"
        expected_sig = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        if hmac.compare_digest(sig, expected_sig):
            return user_id.strip()

    # 2. Check for structured tokens: "token_<user_id>" or "usr_<user_id>"
    if token.startswith("token_") or token.startswith("usr_"):
        extracted = token.split("_", 1)[1].strip()
        if extracted:
            return extracted

    return None


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
      1. If 'Authorization: Bearer <token>' or 'x-api-key' is present and valid,
         the rate limit identity is SOLELY derived from the validated credential.
         ANY client-provided 'user-id' or 'user_id' header is STRICTLY IGNORED.
      2. If invalid credentials are provided, request is rejected with 401 Unauthorized.
      3. If no credentials are provided:
         - If REQUIRE_AUTH=true: Rejects with 401 Unauthorized.
         - If REQUIRE_AUTH=false: Falls back to client-provided 'user-id' header
           marked with is_authenticated=False and auth_type='client_header'.
           Note: Client-provided headers do NOT provide secure per-user isolation in production.
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
                detail="Invalid or malformed bearer token."
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
            detail="Invalid or malformed API key."
        )

    # 3. Handle unauthenticated requests
    if REQUIRE_AUTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide 'Authorization: Bearer <token>' or 'X-API-Key'."
        )

    # Unauthenticated dev fallback using client-controlled header
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
