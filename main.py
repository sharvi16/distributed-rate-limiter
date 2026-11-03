from fastapi import FastAPI, Header, HTTPException, status, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import redis

from rate_limiter import RateLimiter
from spam_detector import AdaptiveSpamDetector

app = FastAPI(
    title="Distributed Rate Limiter with Self-Learning Spam Detection",
    description="Adaptive rate limiting using Token Bucket algorithm, Behavioral Feature Extraction, and Online Self-Learning Anomaly Detection.",
    version="2.0.0"
)

# -----------------------------------------------------------------------------
# Service Initializations
# -----------------------------------------------------------------------------
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

# Initialize Token Bucket Rate Limiter (10 requests per minute with in-memory fallback)
limiter = RateLimiter(
    redis_url=redis_url,
    capacity=10,
    refill_rate=10.0 / 60.0,
    enable_fallback=True
)

# Initialize Outer IP Guardrail Rate Limiter (30 requests per minute per physical IP)
ip_limiter = RateLimiter(
    redis_url=redis_url,
    capacity=30,
    refill_rate=30.0 / 60.0,
    enable_fallback=True
)

# Initialize Self-Learning Spam & Abuse Detector
detector = AdaptiveSpamDetector(redis_client=limiter.redis)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class ChallengeVerificationRequest(BaseModel):
    challenge_id: str
    answer: str


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "message": "Distributed Rate Limiter & Self-Learning Spam Detector API",
        "redis_connected": limiter.is_redis_active(),
        "storage_mode": "Distributed (Redis)" if limiter.is_redis_active() else "In-Memory (Local Fallback)",
        "endpoints": {
            "GET /limited-resource": "Protected resource with adaptive spam & rate limit evaluation",
            "POST /verify-challenge": "Verify challenge for suspicious users (triggers model self-learning)",
            "GET /model-stats": "Inspect learned model centroids and spam vs human metrics",
            "GET /docs": "Interactive Swagger UI"
        }
    }


@app.get("/limited-resource")
async def limited_resource(
    request: Request,
    user_id_dash: Optional[str] = Header(None, alias="user-id"),
    user_id_underscore: Optional[str] = Header(None, alias="user_id"),
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
    raw_user_id = user_id_dash or user_id_underscore
    user_id = raw_user_id.strip() if raw_user_id else ""
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header 'user-id' (or 'user_id') is required."
        )

    # Extract client IP address (supports X-Forwarded-For for proxy/VPN simulation)
    forwarded_for = request.headers.get("x-forwarded-for")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "127.0.0.1")

    # Extract deterministic Device Fingerprint (Hardware Signature)
    device_id = detector.compute_device_fingerprint(request.headers, user_agent=user_agent or "")

    # -------------------------------------------------------------------------
    # Tier 0: Check Penalty Box (Jailed Users, Jailed IPs, or Jailed Devices)
    # -------------------------------------------------------------------------
    is_jailed, remaining = detector.is_in_penalty_box(user_id, client_ip=client_ip, device_id=device_id)
    if is_jailed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Access blocked: this user, IP, or device is currently jailed in the Penalty Box.",
                "user_id": user_id,
                "client_ip": client_ip,
                "device_id": device_id,
                "remaining_seconds": remaining
            }
        )

    # -------------------------------------------------------------------------
    # Tier 1: VPN Hopping / IP Churning Defense
    # If a single device fingerprint rotates across > 2 distinct IPs in 60s, jail the device!
    # -------------------------------------------------------------------------
    is_vpn_hop, ip_count = detector.track_vpn_hopping(device_id, client_ip, max_allowed_ips=2)
    if is_vpn_hop:
        detector.jail_user(f"dev:{device_id}", duration_seconds=120)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": f"VPN Hopping / IP Churning detected: single device ({device_id}) rotated across {ip_count} distinct IP addresses in under 60 seconds. Device jailed for 120s.",
                "device_id": device_id,
                "client_ip": client_ip,
                "distinct_ips_detected": ip_count
            }
        )

    # -------------------------------------------------------------------------
    # Tier 1: Sybil Attack Defense (Identity Rotation Detection)
    # If a single IP generates > 3 distinct user IDs in 60s, jail the entire IP!
    # -------------------------------------------------------------------------
    is_sybil, distinct_count = detector.track_identity_velocity(client_ip, user_id, max_allowed_ids=3)
    if is_sybil:
        detector.jail_user(f"ip:{client_ip}", duration_seconds=120)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": f"Sybil Attack / ID Cycling detected: {distinct_count} distinct user IDs generated from this IP in under 60 seconds. IP jailed for 120s.",
                "client_ip": client_ip,
                "distinct_ids_detected": distinct_count
            }
        )

    # -------------------------------------------------------------------------
    # Tier 2: Outer Physical IP Rate Limit (30 requests / minute per IP)
    # Caps total traffic from the physical network, regardless of user accounts.
    # -------------------------------------------------------------------------
    try:
        ip_allowed = ip_limiter.is_allowed(f"ip:{client_ip}")
    except redis.RedisError:
        ip_allowed = True

    if not ip_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Physical IP rate limit exceeded (30 requests per minute across all accounts). Try again later.",
                "client_ip": client_ip
            }
        )

    # -------------------------------------------------------------------------
    # Tier 3: User Token Bucket Quota (10 requests / minute per user_id)
    # -------------------------------------------------------------------------
    try:
        is_allowed = limiter.is_allowed(user_id)
    except redis.RedisError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Rate limit exceeded (10 requests per minute). Quota exhausted. Try again later.",
                "user_id": user_id
            }
        )

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
            }
        )

    if classification == "suspicious":
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

    return {
        "message": "Request allowed",
        "user_id": user_id,
        "risk_score": risk_score,
        "classification": classification,
        "features": features
    }


@app.post("/verify-challenge")
async def verify_challenge(payload: ChallengeVerificationRequest):
    """
    Submits an answer to a verification challenge.
    
    Self-Learning Impact:
      - If answer is correct: The model learns that this bursty traffic pattern belonged to a HUMAN,
        updating its internal Gaussian centroids online!
      - If answer is incorrect: The model learns the pattern belonged to a SPAMMER and jails the user.
    """
    success, message = detector.verify_challenge(payload.challenge_id, payload.answer)
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
async def model_stats():
    """
    Inspect the live state of the self-learning spam detection engine,
    including learned centroids and evaluation metrics.
    """
    diagnostics = detector.get_diagnostics()
    diagnostics["redis_connected"] = limiter.is_redis_active()
    diagnostics["storage_mode"] = "Distributed (Redis)" if limiter.is_redis_active() else "In-Memory (Local Fallback)"
    return diagnostics
