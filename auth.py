"""
Production-Grade Cryptographic Authentication & Principal Resolution.

Provides strict HMAC-SHA256 signed bearer token authentication with:
  - Cryptographic signature validation with constant-time comparison (timing-attack resistant).
  - Configurable token expiration (default: 3600 seconds / 1 hour).
  - Clock-skew window validation for future timestamps.
  - Zero support for forged or unsigned plaintext tokens (e.g. token_*, usr_*).
  - Secure-by-default production enforcement (REQUIRE_AUTH=true default, ENVIRONMENT=production default).
  - Strict prohibition of unauthenticated client-provided identity headers in production.
  - Strict boolean environment variable parsing (typos like 'treu' raise errors, never silently bypass).
  - Cryptographic entropy validation on AUTH_SECRET_KEY and ADMIN_API_KEY (minimum 32 bytes / 256 bits,
    Shannon entropy >= 3.0 bits/symbol, minimum 10 unique symbols, blocklist for known placeholders).
  - Startup-time configuration validation via validate_auth_configuration() and FastAPI lifespan.
  - Fail-closed administrative protection: unauthenticated public access to diagnostics is strictly prohibited.
"""

import os
import math
import hmac
import hashlib
import time
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from fastapi import Request, Header, HTTPException, status


# Ephemeral in-memory fallback ONLY used in explicit dev/test environments if AUTH_SECRET_KEY is omitted
_EPHEMERAL_DEV_KEY = secrets.token_hex(32)

# Blocklist of known public placeholders and example secrets that must never be used in production
KNOWN_INSECURE_SECRETS = {
    "replace-with-a-secure-random-secret-key-at-least-32-chars-long",
    "rate-limiter-default-secret-key-change-in-prod",
    "change-me-in-production-secret-key-min-32-chars",
    "test-secret-key-with-sufficient-length-32-characters",
}


def get_environment() -> str:
    """
    Returns the normalized environment name.
    Defaults to 'production' if not explicitly configured.
    """
    return os.getenv("ENVIRONMENT", "production").strip().lower()


def is_production_env() -> bool:
    """
    Returns True if the application is running in production.
    Secure-by-default: Any environment other than explicit 'development', 'dev', 'test', 'testing', 'local'
    is treated strictly as production.
    """
    env = get_environment()
    return env in ("production", "prod") or env not in ("development", "dev", "test", "testing", "local")


def calculate_shannon_entropy(data: str) -> float:
    """
    Computes the Shannon entropy (in bits per symbol) of a string.
    H(X) = -sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def parse_bool_env(var_name: str, default: bool) -> bool:
    """
    Parses a boolean environment variable strictly.
    
    Accepts:
      - Truthy: 'true', '1', 'yes', 'on'
      - Falsy: 'false', '0', 'no', 'off'
      - Unset / empty: returns `default`
    
    Raises:
      - ValueError if the value is non-empty and not recognized (prevents typos from bypassing security).
    """
    val = os.getenv(var_name)
    if val is None or val.strip() == "":
        return default
    clean = val.strip().lower()
    if clean in ("true", "1", "yes", "on"):
        return True
    if clean in ("false", "0", "no", "off"):
        return False
    raise ValueError(
        f"CRITICAL SECURITY CONFIGURATION ERROR: Invalid boolean value for environment variable '{var_name}': {val!r}. "
        "Allowed values are 'true', 'false', '1', '0', 'yes', 'no'. Typos must not silently disable security."
    )


def is_auth_required() -> bool:
    """
    Returns True if authentication is strictly required (default in production).
    Can only be disabled by explicitly setting REQUIRE_AUTH=false in environment.
    Strictly validates boolean format and raises ValueError on typos.
    """
    return parse_bool_env("REQUIRE_AUTH", default=True)


def is_dev_headers_allowed() -> bool:
    """
    Returns True only when unauthenticated client-provided 'user-id' headers are
    explicitly permitted in a non-production development/test environment.

    Security Rules:
      1. If running in production (ENVIRONMENT=production or default), ALWAYS returns False,
         regardless of other environment variable settings.
      2. In development/test, requires BOTH REQUIRE_AUTH=false AND ALLOW_UNAUTHENTICATED_DEV_HEADERS=true.
      3. Otherwise returns False.
    """
    # Production environments strictly prohibit unauthenticated client identity headers
    if is_production_env():
        return False

    if is_auth_required():
        return False

    dev_allowed = parse_bool_env("ALLOW_UNAUTHENTICATED_DEV_HEADERS", default=False)
    return dev_allowed


def get_auth_secret_key() -> str:
    """
    Retrieves and validates the HMAC signing secret key.
    
    Security Validation:
      1. Must be defined in environment (AUTH_SECRET_KEY).
      2. Must contain at least 32 characters (256 bits of raw material).
      3. Must NOT be a known example or placeholder string.
      4. Must exhibit sufficient cryptographic entropy:
         - Unique characters: at least 10 unique symbols (rejects trivial repeats like 'x' * 32).
         - Shannon entropy: at least 3.0 bits per symbol.
      5. Fails server startup immediately if missing or weak in production.
      6. Secrets are NEVER logged.
    """
    key = os.getenv("AUTH_SECRET_KEY", "").strip()

    is_prod = is_production_env()
    allow_dev = not is_prod

    if not key:
        if allow_dev:
            return _EPHEMERAL_DEV_KEY
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY environment variable is not configured. "
            "A cryptographically strong secret key (at least 32 bytes / 256 bits of securely generated random material) is mandatory in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    if key in KNOWN_INSECURE_SECRETS:
        if allow_dev:
            return key
        raise ValueError(
            "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY is configured with a known insecure placeholder or example value. "
            "Generate a unique secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    if len(key) < 32:
        if allow_dev:
            return key
        raise ValueError(
            f"CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY has insufficient length "
            f"({len(key)} characters). Minimum required length is 32 characters (256 bits)."
        )

    # Entropy and character diversity validation
    unique_chars = len(set(key))
    entropy = calculate_shannon_entropy(key)

    if not allow_dev:
        if unique_chars < 10 or entropy < 3.0:
            raise ValueError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY has insufficient cryptographic entropy "
                f"(entropy: {entropy:.2f} bits/symbol, unique chars: {unique_chars}). "
                "Length alone is not entropy. Secret must be securely generated random material (e.g. python -c \"import secrets; print(secrets.token_hex(32))\")."
            )

    return key


def validate_admin_configuration() -> None:
    """
    Validates admin API key security configuration during application startup.

    Security Rules:
      - In production (ENVIRONMENT=production or default):
        * ADMIN_API_KEY must be configured (RuntimeError if missing or empty).
        * ADMIN_API_KEY must not be in KNOWN_INSECURE_SECRETS (ValueError).
        * ADMIN_API_KEY must have at least 32 characters / 256 bits (ValueError).
        * ADMIN_API_KEY must meet entropy requirements: Shannon entropy >= 3.0 bits/symbol
          and at least 10 unique symbols (ValueError).
      - In development/test:
        * If ADMIN_API_KEY is configured, it is validated against known placeholders.
        * If omitted or empty in dev/test, access to admin endpoints remains strictly denied
          (fail-closed: never silently allows public access).
      - Never logs admin keys.
    """
    key = os.getenv("ADMIN_API_KEY", "").strip()

    if is_production_env():
        if not key:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: ADMIN_API_KEY environment variable is not configured. "
                "A cryptographically strong admin key (at least 32 bytes / 256 bits of securely generated random material) is mandatory in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        if key in KNOWN_INSECURE_SECRETS:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: ADMIN_API_KEY is configured with a known insecure placeholder or example value. "
                "Generate a unique secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        if len(key) < 32:
            raise ValueError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: ADMIN_API_KEY has insufficient length "
                f"({len(key)} characters). Minimum required length is 32 characters (256 bits)."
            )

        unique_chars = len(set(key))
        entropy = calculate_shannon_entropy(key)
        if unique_chars < 10 or entropy < 3.0:
            raise ValueError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: ADMIN_API_KEY has insufficient cryptographic entropy "
                f"(entropy: {entropy:.2f} bits/symbol, unique chars: {unique_chars}). "
                "Length alone is not entropy. Secret must be securely generated random material (e.g. python -c \"import secrets; print(secrets.token_hex(32))\")."
            )
    else:
        if key and key in KNOWN_INSECURE_SECRETS:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: ADMIN_API_KEY is configured with a known insecure placeholder."
            )


def validate_auth_configuration() -> None:
    """
    Validates all authentication and admin security configurations at application startup.
    Executed during FastAPI lifespan / startup initialization.
    
    Aborts startup immediately if:
      - Boolean flags have invalid syntax (e.g., REQUIRE_AUTH=treu).
      - Contradictory security settings are detected (e.g. REQUIRE_AUTH=true AND ALLOW_UNAUTHENTICATED_DEV_HEADERS=true).
      - In production:
        * REQUIRE_AUTH is set to false.
        * ALLOW_UNAUTHENTICATED_DEV_HEADERS is set to true.
        * AUTH_SECRET_KEY is missing, weak (< 32 chars), low-entropy (< 3.0 bits or < 10 unique symbols), or a known placeholder.
        * ADMIN_API_KEY is missing, weak, low-entropy, or a known placeholder.
    """
    # 1. Validate boolean configurations (throws ValueError on invalid formats like 'treu')
    req_auth = is_auth_required()
    dev_headers_flag = parse_bool_env("ALLOW_UNAUTHENTICATED_DEV_HEADERS", default=False)

    # 2. Reject contradictory configuration settings
    if req_auth and dev_headers_flag:
        raise ValueError(
            "CRITICAL SECURITY CONFIGURATION ERROR: Contradictory security settings: "
            "ALLOW_UNAUTHENTICATED_DEV_HEADERS cannot be set to true when REQUIRE_AUTH is true. "
            "Unauthenticated identity headers are prohibited when authentication is required."
        )

    # 3. Enforce strict production requirements
    if is_production_env():
        if not req_auth:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Insecure production configuration: "
                "REQUIRE_AUTH cannot be set to false in a production environment. "
                "Cryptographic authentication is mandatory in production."
            )
        if dev_headers_flag:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Insecure production configuration: "
                "ALLOW_UNAUTHENTICATED_DEV_HEADERS cannot be set to true in a production environment. "
                "Unauthenticated client-provided identity headers are strictly prohibited in production."
            )

    # 4. Validate bearer token secret key (throws RuntimeError if missing, ValueError if weak/low-entropy/placeholder)
    get_auth_secret_key()

    # 5. Validate admin diagnostic endpoint security configuration
    validate_admin_configuration()


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
         - Under default production settings (REQUIRE_AUTH=true, ENVIRONMENT=production):
           Rejects with 401 Unauthorized.
         - Under explicit dev override in development/test (ALLOW_UNAUTHENTICATED_DEV_HEADERS=true and REQUIRE_AUTH=false):
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
