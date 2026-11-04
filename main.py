from fastapi.responses import PlainTextResponse
from fastapi import FastAPI, Header, HTTPException, status, Request, Response, Depends, Query
from contextlib import asynccontextmanager
import math
import hmac
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import redis

from rate_limiter import (
    RateLimiter,
    FailureMode,
    RedisUnavailableError,
    validate_tokens_requested,
    parse_env_positive_float,
    validate_rate_limiter_configuration
)
from spam_detector import AdaptiveSpamDetector
from ip_utils import resolve_client_ip, parse_trusted_proxies, is_ip_trusted
from auth import (
    get_authenticated_principal,
    AuthenticatedPrincipal,
    validate_auth_configuration,
    is_production_env,
    parse_bool_env
)
from metrics import metrics_collector


# -----------------------------------------------------------------------------
# Service Initializations
# -----------------------------------------------------------------------------
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
raw_pwd = os.getenv("REDIS_PASSWORD")
redis_password = raw_pwd if (raw_pwd is not None and raw_pwd != "") else None
ssl_certfile = os.getenv("REDIS_SSL_CERTFILE", "").strip() or None
ssl_keyfile = os.getenv("REDIS_SSL_KEYFILE", "").strip() or None
ssl_ca_certs = os.getenv("REDIS_SSL_CA_CERTS", "").strip() or None
trusted_proxies_cfg = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
TRUSTED_PROXIES = parse_trusted_proxies(trusted_proxies_cfg)
failure_mode_str = os.getenv("RATE_LIMITER_FAILURE_MODE", FailureMode.FAIL_CLOSED.value)
try:
    configured_failure_mode = FailureMode(failure_mode_str.lower())
except ValueError:
    configured_failure_mode = FailureMode.FAIL_CLOSED

# Read Token Bucket parameters from environment variables (Priority 2)
user_capacity = parse_env_positive_float("RATE_LIMITER_CAPACITY", default=10.0)
user_refill_rate = parse_env_positive_float("RATE_LIMITER_REFILL_RATE", default=10.0 / 60.0)
ip_capacity = parse_env_positive_float("IP_RATE_LIMITER_CAPACITY", default=30.0)
ip_refill_rate = parse_env_positive_float("IP_RATE_LIMITER_REFILL_RATE", default=30.0 / 60.0)

# Initialize Token Bucket Rate Limiter
limiter = RateLimiter(
    redis_url=redis_url,
    redis_password=redis_password,
    ssl_certfile=ssl_certfile,
    ssl_keyfile=ssl_keyfile,
    ssl_ca_certs=ssl_ca_certs,
    capacity=user_capacity,
    refill_rate=user_refill_rate,
    failure_mode=configured_failure_mode
)

# Initialize Outer IP Guardrail Rate Limiter
ip_limiter = RateLimiter(
    redis_url=redis_url,
    redis_password=redis_password,
    ssl_certfile=ssl_certfile,
    ssl_keyfile=ssl_keyfile,
    ssl_ca_certs=ssl_ca_certs,
    capacity=ip_capacity,
    refill_rate=ip_refill_rate,
    failure_mode=configured_failure_mode
)

# Initialize Self-Learning Spam & Abuse Detector
detector = AdaptiveSpamDetector(redis_client=limiter.redis)

# Connect Prometheus metrics collector to Redis for atomic cluster-wide aggregation
metrics_collector.set_redis(limiter.redis)


def sync_rate_limiter_configuration() -> None:
    """
    Synchronizes instantiated RateLimiter objects with the latest validated
    environment variable configuration.
    Called during application lifespan startup to guarantee runtime consistency.
    """
    user_cap, user_refill, ip_cap, ip_refill, f_mode = validate_rate_limiter_configuration()
    cur_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    raw_cur_pwd = os.getenv("REDIS_PASSWORD")
    cur_pwd = raw_cur_pwd if (raw_cur_pwd is not None and raw_cur_pwd != "") else None
    cur_certfile = os.getenv("REDIS_SSL_CERTFILE", "").strip() or None
    cur_keyfile = os.getenv("REDIS_SSL_KEYFILE", "").strip() or None
    cur_ca_certs = os.getenv("REDIS_SSL_CA_CERTS", "").strip() or None
    cur_cert_reqs = os.getenv("REDIS_SSL_CERT_REQS", "").strip() or None
    cur_check_hostname_raw = os.getenv("REDIS_SSL_CHECK_HOSTNAME")
    cur_check_hostname = parse_bool_env("REDIS_SSL_CHECK_HOSTNAME", True) if (cur_check_hostname_raw is not None and cur_check_hostname_raw.strip() != "") else None

    limiter.configure(
        capacity=user_cap,
        refill_rate=user_refill,
        failure_mode=f_mode,
        redis_url=cur_url,
        redis_password=cur_pwd,
        ssl_certfile=cur_certfile,
        ssl_keyfile=cur_keyfile,
        ssl_ca_certs=cur_ca_certs,
        ssl_cert_reqs=cur_cert_reqs,
        ssl_check_hostname=cur_check_hostname
    )
    ip_limiter.configure(
        capacity=ip_cap,
        refill_rate=ip_refill,
        failure_mode=f_mode,
        redis_url=cur_url,
        redis_password=cur_pwd,
        ssl_certfile=cur_certfile,
        ssl_keyfile=cur_keyfile,
        ssl_ca_certs=cur_ca_certs,
        ssl_cert_reqs=cur_cert_reqs,
        ssl_check_hostname=cur_check_hostname
    )
    detector.redis = limiter.redis
    metrics_collector.set_redis(limiter.redis)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler executing startup configuration validation and synchronization.
    Ensures authentication, encryption keys, admin secrets, and rate limiter
    environment variables are verified and synchronized before accepting incoming HTTP requests.
    Validates Redis connectivity and authentication with a bounded-time PING.
    """
    validate_auth_configuration()
    sync_rate_limiter_configuration()
    limiter.verify_connection(timeout=1.0)
    ip_limiter.verify_connection(timeout=1.0)
    yield


app = FastAPI(
    title="Distributed Rate Limiter with Self-Learning Spam Detection",
    description="Adaptive rate limiting using Token Bucket algorithm, Behavioral Feature Extraction, and Online Self-Learning Anomaly Detection.",
    version="2.0.0",
    lifespan=lifespan
)


def format_token_limit(val: float) -> str:
    """Formats rate limit capacity preserving fractional precision when non-integer."""
    if val.is_integer():
        return str(int(val))
    return str(val)


def format_token_remaining(val: float) -> str:
    """Formats remaining tokens as integer string, clamped to >= 0."""
    return str(max(0, int(val)))


def verify_admin_key(x_admin_key: Optional[str] = Header(None, alias="x-admin-key")) -> bool:
    """
    Protects internal model diagnostics and metrics from unauthorized inspection.

    Security Rules:
      1. Missing or empty ADMIN_API_KEY configuration NEVER grants access (fail-closed).
      2. Missing or incorrect 'x-admin-key' header returns HTTP 401 Unauthorized.
      3. Compares UTF-8 encoded bytes using hmac.compare_digest to safely handle
         non-ASCII characters without raising unexpected 500 errors.
      4. Single authoritative configuration source: os.getenv("ADMIN_API_KEY") (no stale global fallback).
      5. Does not leak whether the key is missing from server configuration or mismatched.
      6. The actual key is never logged.
    """
    configured_key = os.getenv("ADMIN_API_KEY", "").strip()
    if not configured_key or not x_admin_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing admin credentials."
        )

    # Convert to UTF-8 bytes to safely handle non-ASCII headers in constant time
    header_bytes = x_admin_key.strip().encode("utf-8")
    configured_bytes = configured_key.encode("utf-8")

    if not hmac.compare_digest(header_bytes, configured_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing admin credentials."
        )

    return True


def verify_metrics_access(
    request: Request,
    x_admin_key: Optional[str] = Header(None, alias="x-admin-key"),
    x_metrics_key: Optional[str] = Header(None, alias="x-metrics-key"),
    authorization: Optional[str] = Header(None, alias="authorization")
) -> bool:
    """
    Controls access to the /metrics endpoint (Priority 3, Item 9).

    Security Policy:
      1. Production Environment (ENVIRONMENT=production or default):
         - Access is strictly protected (fail-closed).
         - Clients must authenticate via x-admin-key, x-metrics-key, Bearer token,
           or originate from an allowed network CIDR (METRICS_ALLOWED_CIDRS).
      2. Development/Test Environment:
         - If PROTECT_METRICS=true is explicitly set, enforces authentication.
         - If PROTECT_METRICS=false (or unset in dev/test), permits unauthenticated access for local scraping.
      3. Credential Evaluation:
         - Compares supplied keys against METRICS_API_KEY (if configured) or ADMIN_API_KEY.
         - Constant-time comparison using UTF-8 byte encoding prevents timing attacks and handles non-ASCII gracefully.
         - Does not leak key configuration details in error messages.
      4. Network Policy:
         - If METRICS_ALLOWED_CIDRS is configured, requests from IPs within these subnets are authorized.
    """
    is_prod = is_production_env()
    protect_metrics = parse_bool_env("PROTECT_METRICS", default=True if is_prod else False)

    if is_prod and not protect_metrics:
        # Insecure production configuration: fail closed immediately
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: metrics protection cannot be disabled in production."
        )

    if not protect_metrics:
        return True

    # 1. Network allowlist check (METRICS_ALLOWED_CIDRS)
    allowed_cidrs_str = os.getenv("METRICS_ALLOWED_CIDRS", "").strip()
    if allowed_cidrs_str:
        allowed_networks = parse_trusted_proxies(allowed_cidrs_str)
        client_ip = resolve_client_ip(request, trusted_networks=TRUSTED_PROXIES)
        if is_ip_trusted(client_ip, allowed_networks):
            return True

    # 2. Extract supplied key from headers
    supplied_key = None
    if x_metrics_key and x_metrics_key.strip():
        supplied_key = x_metrics_key.strip()
    elif x_admin_key and x_admin_key.strip():
        supplied_key = x_admin_key.strip()
    elif authorization and authorization.strip():
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "apikey"):
            supplied_key = parts[1].strip()

    if not supplied_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing metrics credentials."
        )

    # 3. Candidate keys: METRICS_API_KEY (if set) and ADMIN_API_KEY (if set)
    metrics_key = os.getenv("METRICS_API_KEY", "").strip()
    admin_key = os.getenv("ADMIN_API_KEY", "").strip()

    supplied_bytes = supplied_key.encode("utf-8")

    authorized = False
    if metrics_key:
        if hmac.compare_digest(supplied_bytes, metrics_key.encode("utf-8")):
            authorized = True
    if not authorized and admin_key:
        if hmac.compare_digest(supplied_bytes, admin_key.encode("utf-8")):
            authorized = True

    if not authorized:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing metrics credentials."
        )

    return True

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class ChallengeVerificationRequest(BaseModel):
    challenge_id: str
    answer: str
    user_id: Optional[str] = None


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "Distributed Rate Limiter & Self-Learning Spam Detector API",
        "redis_connected": limiter.is_redis_active(),
        "storage_mode": "Distributed (Redis)" if limiter.is_redis_active() else "In-Memory (Local Fallback)",
        "endpoints": {
            "GET /limited-resource": "Protected resource with adaptive spam & rate limit evaluation",
            "POST /verify-challenge": "Verify challenge for suspicious users (triggers model self-learning)",
            "GET /model-stats": "Inspect learned model centroids and spam vs human metrics (Admin)",
            "GET /docs": "Interactive Swagger UI",
            "GET /metrics": "Prometheus metrics exposition"
        }
    }


@app.get("/metrics", response_class=PlainTextResponse)
def get_metrics(authorized: bool = Depends(verify_metrics_access)):
    """
    Exposes system telemetry, request counters, and cluster health in Prometheus exposition format.
    Protected according to the metrics security policy (Priority 3, Item 9).
    """
    return metrics_collector.generate_prometheus_output(limiter=limiter, detector=detector)


@app.get("/limited-resource")
def limited_resource(
    request: Request,
    response: Response,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
    user_agent: Optional[str] = Header("", alias="user-agent")
):
    """
    Adaptive Rate Limited & Abuse Protected Endpoint.
    
    Server-Controlled Cost Semantics (Priority 2):
      - Ordinary requests consume strictly 1.0 token (server-controlled cost).
      - Clients cannot specify arbitrary token weights or reduce consumption via query parameters.
      - Burst capacity is explicitly distinguished from sustained refill rate in telemetry and errors.
    
    Tiers of evaluation:
      1. Penalty Box Check: If user was flagged as spammer and jailed, immediately block (429).
      2. Behavioral Feature Extraction: Analyzes request jitter (std dev of time gaps), burst frequency, etc.
      3. Self-Learning ML Risk Scoring: Classifies as 'human', 'suspicious', or 'spammer'.
         - 'spammer': Immediately jailed in Penalty Box.
         - 'suspicious': Serves challenge (403). Solving challenge trains model that user is human.
         - 'human': Evaluated by Token Bucket.
    """
    # Server-controlled request cost: exactly 1 token per request
    REQUEST_COST = 1.0

    # Rate limit identity is derived strictly from the authenticated principal
    user_id = principal.user_id

    # Extract client IP address securely (supports trusted reverse proxies)
    client_ip = resolve_client_ip(request, trusted_networks=TRUSTED_PROXIES)

    # Extract heuristic Device Fingerprint from untrusted client telemetry (headers)
    device_id = detector.compute_device_fingerprint(request.headers, user_agent=user_agent or "")

    # -------------------------------------------------------------------------
    # Tier 0: Check Penalty Box (Jailed Users, Jailed IPs, or Jailed Devices)
    # -------------------------------------------------------------------------
    is_jailed, remaining = detector.is_in_penalty_box(user_id, client_ip=client_ip, device_id=device_id)
    if is_jailed:
        metrics_collector.inc_request("jailed")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Access blocked: this user, IP, or device is currently jailed in the Penalty Box.",
                "user_id": user_id,
                "client_ip": client_ip,
                "device_id": device_id,
                "remaining_seconds": remaining
            },
            headers={"Retry-After": str(max(1, remaining))}
        )

    # -------------------------------------------------------------------------
    # Tier 1: VPN Hopping / IP Churning Defense
    # If a single device fingerprint rotates across > 2 distinct IPs in 60s, jail the device!
    # -------------------------------------------------------------------------
    is_vpn_hop, ip_count = detector.track_vpn_hopping(device_id, client_ip, max_allowed_ips=2)
    if is_vpn_hop:
        metrics_collector.inc_vpn_hopping()
        metrics_collector.inc_jailed()
        metrics_collector.inc_request("jailed")
        detector.jail_user(f"dev:{device_id}", duration_seconds=120)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": f"VPN Hopping / IP Churning detected: single device ({device_id}) rotated across {ip_count} distinct IP addresses in under 60 seconds. Device jailed for 120s.",
                "device_id": device_id,
                "client_ip": client_ip,
                "distinct_ips_detected": ip_count
            },
            headers={"Retry-After": "120"}
        )

    # -------------------------------------------------------------------------
    # Tier 1: Sybil Attack Defense (Identity Rotation Detection)
    # If a single IP generates > 3 distinct user IDs in 60s, jail the entire IP!
    # -------------------------------------------------------------------------
    is_sybil, distinct_count = detector.track_identity_velocity(client_ip, user_id, max_allowed_ids=3)
    if is_sybil:
        metrics_collector.inc_sybil()
        metrics_collector.inc_jailed()
        metrics_collector.inc_request("jailed")
        detector.jail_user(f"ip:{client_ip}", duration_seconds=120)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": f"Sybil Attack / ID Cycling detected: {distinct_count} distinct user IDs generated from this IP in under 60 seconds. IP jailed for 120s.",
                "client_ip": client_ip,
                "distinct_ids_detected": distinct_count
            },
            headers={"Retry-After": "120"}
        )

    # -------------------------------------------------------------------------
    # Tier 2: Outer Physical IP Rate Limit (30 requests / minute per IP)
    # Caps total traffic from the physical network, regardless of user accounts.
    # -------------------------------------------------------------------------
    try:
        ip_result = ip_limiter.check_limit(f"ip:{client_ip}", tokens=1.0)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rate limit request: {e}"
        )
    except (redis.RedisError, RedisUnavailableError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if not ip_result.allowed:
        metrics_collector.inc_request("rate_limited")
        refill_per_min = ip_limiter.refill_rate * 60.0
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": (
                    f"Physical IP rate limit exceeded (burst capacity: {format_token_limit(ip_limiter.capacity)} tokens, "
                    f"sustained refill rate: {refill_per_min:.1f} requests/minute across all accounts). Try again later."
                ),
                "client_ip": client_ip
            },
            headers={
                "X-RateLimit-Limit": format_token_limit(ip_result.limit),
                "X-RateLimit-Remaining": format_token_remaining(ip_result.remaining),
                "X-RateLimit-Reset": str(math.ceil(ip_result.reset_after)),
                "RateLimit-Limit": format_token_limit(ip_result.limit),
                "RateLimit-Remaining": format_token_remaining(ip_result.remaining),
                "RateLimit-Reset": str(math.ceil(ip_result.reset_after)),
                "Retry-After": str(ip_result.retry_after or 1)
            }
        )

    # -------------------------------------------------------------------------
    # Tier 3: User Token Bucket Quota
    # -------------------------------------------------------------------------
    try:
        rate_result = limiter.check_limit(user_id, tokens=REQUEST_COST)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rate limit request: {e}"
        )
    except (redis.RedisError, RedisUnavailableError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if not rate_result.allowed:
        metrics_collector.inc_request("rate_limited")
        refill_per_min = limiter.refill_rate * 60.0
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": (
                    f"Rate limit exceeded (burst capacity: {format_token_limit(limiter.capacity)} tokens, "
                    f"sustained refill rate: {refill_per_min:.1f} requests/minute). Quota exhausted. Try again later."
                ),
                "user_id": user_id
            },
            headers={
                "X-RateLimit-Limit": format_token_limit(rate_result.limit),
                "X-RateLimit-Remaining": format_token_remaining(rate_result.remaining),
                "X-RateLimit-Reset": str(math.ceil(rate_result.reset_after)),
                "RateLimit-Limit": format_token_limit(rate_result.limit),
                "RateLimit-Remaining": format_token_remaining(rate_result.remaining),
                "RateLimit-Reset": str(math.ceil(rate_result.reset_after)),
                "Retry-After": str(rate_result.retry_after or 1)
            }
        )

    # Attach standard RFC and IETF rate limit headers to successful evaluation
    response.headers["X-RateLimit-Limit"] = format_token_limit(rate_result.limit)
    response.headers["X-RateLimit-Remaining"] = format_token_remaining(rate_result.remaining)
    response.headers["X-RateLimit-Reset"] = str(math.ceil(rate_result.reset_after))
    response.headers["RateLimit-Limit"] = format_token_limit(rate_result.limit)
    response.headers["RateLimit-Remaining"] = format_token_remaining(rate_result.remaining)
    response.headers["RateLimit-Reset"] = str(math.ceil(rate_result.reset_after))

    # If the user already has an unsolved challenge and continues hammering -> Auto-jail!
    if detector.has_pending_challenge(user_id):
        detector.jail_user(user_id, duration_seconds=60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "User ignored verification challenge and continued spamming. Jailed for 60s.",
                "user_id": user_id
            }
        )

    # -------------------------------------------------------------------------
    # Tier 3: Verified Human Session Pass
    # If the user already solved a challenge in the last 5 minutes, allow smoothly
    # without repeated challenges, while still counting toward their 10-req quota.
    # -------------------------------------------------------------------------
    if detector.is_verified_human(user_id):
        metrics_collector.inc_request("allowed")
        return {
            "message": "Request allowed (Verified Human Session)",
            "user_id": user_id,
            "risk_score": 0.0,
            "classification": "verified_human"
        }

    # -------------------------------------------------------------------------
    # Tier 4: Behavioral Feature Extraction & ML Abuse Detection (Under the quota)
    # -------------------------------------------------------------------------
    features = detector.record_and_extract_features(user_id, user_agent=user_agent or "")
    risk_score, classification = detector.compute_risk_score(features, user_id=user_id)

    if classification == "spammer":
        metrics_collector.inc_jailed()
        metrics_collector.inc_request("jailed")
        detector.jail_user(user_id, duration_seconds=60)
        detector.update_model(features, label="spammer")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "High-risk automated spam pattern detected. User jailed for 60s.",
                "user_id": user_id,
                "risk_score": risk_score,
                "classification": classification,
                "features": features
            },
            headers={"Retry-After": "60"}
        )

    if classification == "suspicious":
        metrics_collector.inc_challenge_issued()
        metrics_collector.inc_request("challenge_required")
        challenge = detector.generate_challenge(user_id, features)
        if challenge.get("jailed"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Challenge generation limit exceeded. User placed in penalty box.",
                    "user_id": user_id,
                    "retry_after": challenge.get("retry_after", 300)
                },
                headers={"Retry-After": str(challenge.get("retry_after", 300))}
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Abnormal burst pattern detected. Verification challenge required.",
                "user_id": user_id,
                "risk_score": risk_score,
                "classification": classification,
                "challenge": challenge
            }
        )

    metrics_collector.inc_request("allowed")
    return {
        "message": "Request allowed",
        "user_id": user_id,
        "risk_score": risk_score,
        "classification": classification,
        "features": features
    }


@app.post("/verify-challenge")
def verify_challenge(
    payload: ChallengeVerificationRequest,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal)
):
    """
    Submits an answer to a verification challenge.
    
    Authentication & Ownership:
      - Uses the exact same get_authenticated_principal dependency as /limited-resource.
      - Binds challenge verification strictly to the authenticated principal.
      - payload.user_id or client headers can NEVER override the authenticated principal.
    """
    effective_user_id = principal.user_id
    success, message = detector.verify_challenge(payload.challenge_id, payload.answer, expected_user_id=effective_user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": message}
        )

    metrics_collector.inc_challenge_verified()
    return {
        "success": True,
        "message": message,
        "self_learning": "Model parameters successfully updated with verified human feedback."
    }


@app.get("/model-stats")
def model_stats(authorized: bool = Depends(verify_admin_key)):
    """
    Inspect the live state of the self-learning spam detection engine,
    including learned centroids and evaluation metrics.
    Protected strictly by verify_admin_key with constant-time HMAC comparison.
    """
    diagnostics = detector.get_diagnostics()
    diagnostics["redis_connected"] = limiter.is_redis_active()
    diagnostics["storage_mode"] = "Distributed (Redis)" if limiter.is_redis_active() else "In-Memory (Local Fallback)"
    return diagnostics
