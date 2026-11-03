from fastapi.responses import PlainTextResponse
from fastapi import FastAPI, Header, HTTPException, status, Request, Response, Depends
from contextlib import asynccontextmanager
import math
import hmac
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from spam_detector import AdaptiveSpamDetector
from ip_utils import resolve_client_ip, parse_trusted_proxies
from auth import get_authenticated_principal, AuthenticatedPrincipal, validate_auth_configuration
from metrics import metrics_collector


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler executing startup configuration validation.
    Ensures authentication, encryption keys, and environment variables are
    verified before accepting incoming HTTP requests.
    """
    validate_auth_configuration()
    yield


app = FastAPI(
    title="Distributed Rate Limiter with Self-Learning Spam Detection",
    description="Adaptive rate limiting using Token Bucket algorithm, Behavioral Feature Extraction, and Online Self-Learning Anomaly Detection.",
    version="2.0.0",
    lifespan=lifespan
)

# -----------------------------------------------------------------------------
# Service Initializations
# -----------------------------------------------------------------------------
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
trusted_proxies_cfg = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
TRUSTED_PROXIES = parse_trusted_proxies(trusted_proxies_cfg)
failure_mode_str = os.getenv("RATE_LIMITER_FAILURE_MODE", FailureMode.FAIL_CLOSED.value)
try:
    configured_failure_mode = FailureMode(failure_mode_str.lower())
except ValueError:
    configured_failure_mode = FailureMode.FAIL_CLOSED

# Initialize Token Bucket Rate Limiter (10 requests per minute with in-memory fallback)
limiter = RateLimiter(
    redis_url=redis_url,
    capacity=10,
    refill_rate=10.0 / 60.0,
    failure_mode=configured_failure_mode
)

# Initialize Outer IP Guardrail Rate Limiter (30 requests per minute per physical IP)
ip_limiter = RateLimiter(
    redis_url=redis_url,
    capacity=30,
    refill_rate=30.0 / 60.0,
    failure_mode=configured_failure_mode
)

# Initialize Self-Learning Spam & Abuse Detector
detector = AdaptiveSpamDetector(redis_client=limiter.redis)


ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()


def verify_admin_key(x_admin_key: Optional[str] = Header(None, alias="x-admin-key")) -> bool:
    """
    Protects internal model diagnostics and metrics from unauthorized inspection.

    Security Rules:
      1. Missing or empty ADMIN_API_KEY configuration NEVER grants access (fail-closed).
      2. Missing or incorrect 'x-admin-key' header returns HTTP 401 Unauthorized.
      3. Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
      4. Does not leak whether the key is missing from server configuration or mismatched.
      5. The actual key is never logged.
    """
    configured_key = os.getenv("ADMIN_API_KEY", "").strip() or globals().get("ADMIN_API_KEY", "").strip()
    if not configured_key or not x_admin_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing admin credentials."
        )

    if not hmac.compare_digest(x_admin_key.strip(), configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing admin credentials."
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
def get_metrics():
    """Exposes system telemetry, request counters, and cluster health in Prometheus exposition format."""
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
    
    Tiers of evaluation:
      1. Penalty Box Check: If user was flagged as spammer and jailed, immediately block (429).
      2. Behavioral Feature Extraction: Analyzes request jitter (std dev of time gaps), burst frequency, etc.
      3. Self-Learning ML Risk Scoring: Classifies as 'human', 'suspicious', or 'spammer'.
         - 'spammer': Immediately jailed in Penalty Box.
         - 'suspicious': Serves challenge (403). Solving challenge trains model that user is human.
         - 'human': Evaluated by Token Bucket (10 requests/min).
    """
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
        ip_allowed = ip_limiter.is_allowed(f"ip:{client_ip}")
    except (redis.RedisError, RedisUnavailableError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if not ip_allowed:
        metrics_collector.inc_request("rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Physical IP rate limit exceeded (30 requests per minute across all accounts). Try again later.",
                "client_ip": client_ip
            },
            headers={"Retry-After": "60"}
        )

    # -------------------------------------------------------------------------
    # Tier 3: User Token Bucket Quota (10 requests / minute per user_id)
    # -------------------------------------------------------------------------
    try:
        rate_result = limiter.check_limit(user_id)
    except (redis.RedisError, RedisUnavailableError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if not rate_result.allowed:
        metrics_collector.inc_request("rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Rate limit exceeded (10 requests per minute). Quota exhausted. Try again later.",
                "user_id": user_id
            },
            headers={
                "X-RateLimit-Limit": str(rate_result.limit),
                "X-RateLimit-Remaining": str(max(0, int(rate_result.remaining))),
                "X-RateLimit-Reset": str(math.ceil(rate_result.reset_after)),
                "Retry-After": str(rate_result.retry_after or 1)
            }
        )

    # Attach standard RFC rate limit headers to successful evaluation
    response.headers["X-RateLimit-Limit"] = str(rate_result.limit)
    response.headers["X-RateLimit-Remaining"] = str(max(0, int(rate_result.remaining)))
    response.headers["X-RateLimit-Reset"] = str(math.ceil(rate_result.reset_after))

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
