"""
Priority 1 Security Regression Tests.

Covers:
  1. Redis failure modes at the API level (FAIL_CLOSED, FAIL_OPEN, LOCAL_FALLBACK).
  2. Challenge session binding (omitted identities, mismatched users, replay attacks) in Redis and local fallback.
  3. Cryptographic token verification (rejection of usr_*, token_*, arbitrary strings, tampered signatures, expired, future).
  4. Signing secret entropy and strict production validation (missing/weak key rejection).
  5. Production authentication defaults (REQUIRE_AUTH=true, 401 rejection, dev header lockdown).
  6. Identity trust & anti-spoofing across both /limited-resource and /verify-challenge endpoints.
  7. Device fingerprinting limitations: verifying header-derived heuristic nature.
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, ip_limiter, detector
from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from spam_detector import AdaptiveSpamDetector
from auth import (
    create_signed_token,
    verify_signed_token,
    get_auth_secret_key,
    is_auth_required,
    is_dev_headers_allowed,
    AuthenticatedPrincipal
)


class UnreachableRedisMock:
    """Simulates Redis connection failure."""
    def ping(self):
        import redis
        raise redis.ConnectionError("Simulated Redis outage")

    def __getattr__(self, name):
        import redis
        def _fail(*args, **kwargs):
            raise redis.ConnectionError("Simulated Redis outage")
        return _fail


@pytest.fixture(autouse=True)
def clean_test_state():
    if detector.redis:
        try:
            detector.redis.delete("ip_identities:testclient")
            detector.redis.delete("penalty_box:ip:testclient")
            detector.redis.delete("rate_limit:ip:testclient")
            detector.redis.delete("penalty_box:dev_372fe9e20e1e99b6")
        except Exception:
            pass
    with detector._lock:
        if hasattr(detector, "_local_ip_identities"):
            detector._local_ip_identities.pop("testclient", None)
        if hasattr(detector, "_local_penalties"):
            detector._local_penalties.pop("ip:testclient", None)


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. Redis Failure Mode Enforcement at the API Level
# =============================================================================
class TestAPIRedisFailureModes:
    def test_api_fail_closed_mode_returns_503(self, client, monkeypatch):
        """When Redis is down under FAIL_CLOSED, requests must return 503 Service Unavailable."""
        mock_redis = UnreachableRedisMock()
        mock_user_limiter = RateLimiter(redis_client=mock_redis, capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)
        mock_ip_limiter = RateLimiter(redis_client=mock_redis, capacity=30, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)

        monkeypatch.setattr(main, "limiter", mock_user_limiter)
        monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

        response = client.get("/limited-resource", headers={"user-id": "test_fc_user"})
        assert response.status_code == 503
        data = response.json()
        assert "Service Unavailable" in data["detail"] or "Redis down" in data["detail"]

    def test_api_fail_closed_mode_ip_limiter_returns_503(self, client, monkeypatch):
        """When user limiter succeeds but ip_limiter hits Redis down under FAIL_CLOSED, must return 503, never silently allow."""
        mock_redis = UnreachableRedisMock()
        mock_ip_limiter = RateLimiter(redis_client=mock_redis, capacity=30, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)

        monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

        response = client.get("/limited-resource", headers={"user-id": "test_fc_ip_user"})
        assert response.status_code == 503
        assert "Redis down" in response.json()["detail"]

    def test_api_fail_open_mode_allows_requests(self, client, monkeypatch):
        """When Redis is down under FAIL_OPEN, requests are allowed through without error."""
        mock_redis = UnreachableRedisMock()
        mock_user_limiter = RateLimiter(redis_client=mock_redis, capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)
        mock_ip_limiter = RateLimiter(redis_client=mock_redis, capacity=30, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)

        monkeypatch.setattr(main, "limiter", mock_user_limiter)
        monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

        response = client.get("/limited-resource", headers={"user-id": "test_fo_user"})
        assert response.status_code in [200, 403]  # Allowed past rate limiters

    def test_api_local_fallback_mode_throttles_locally(self, client, monkeypatch):
        """When Redis is down under LOCAL_FALLBACK, requests use local memory and throttle when exhausted."""
        mock_redis = UnreachableRedisMock()
        mock_user_limiter = RateLimiter(redis_client=mock_redis, capacity=2, refill_rate=0.01, failure_mode=FailureMode.LOCAL_FALLBACK)
        mock_ip_limiter = RateLimiter(redis_client=mock_redis, capacity=30, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)

        monkeypatch.setattr(main, "limiter", mock_user_limiter)
        monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

        user = f"test_lf_{uuid.uuid4().hex[:6]}"
        # Grant human pass so ML anomaly detector doesn't intervene before token bucket
        detector.set_verified_human(user, duration_seconds=60)

        # 2 tokens allowed locally
        r1 = client.get("/limited-resource", headers={"user-id": user})
        assert r1.status_code == 200
        r2 = client.get("/limited-resource", headers={"user-id": user})
        assert r2.status_code == 200

        # 3rd request throttled with 429
        r3 = client.get("/limited-resource", headers={"user-id": user})
        assert r3.status_code == 429
        assert "Quota exhausted" in r3.json()["detail"]["message"]


# =============================================================================
# 2. Challenge Session Binding & Verification Security
# =============================================================================
class TestChallengeSessionBinding:
    def test_empty_expected_user_id_rejected_in_redis(self):
        """Empty expected_user_id must never bypass challenge verification in Redis."""
        det = AdaptiveSpamDetector(redis_client=limiter.redis)
        user_a = f"user_a_{uuid.uuid4().hex[:6]}"
        ch = det.generate_challenge(user_a, {"interval_std": 0.1, "burst_count": 3, "mean_interval": 0.5})
        cid = ch["challenge_id"]

        # Fetch answer from Redis for test
        true_answer = limiter.redis.hget(f"challenge:{cid}", "expected_answer")
        assert true_answer is not None

        # Attempt verification with empty user ID
        success, msg = det.verify_challenge(cid, true_answer, expected_user_id="")
        assert success is False
        assert "valid user identity" in msg

        # Attempt verification with None
        success, msg = det.verify_challenge(cid, true_answer, expected_user_id=None)
        assert success is False
        assert "valid user identity" in msg

    def test_empty_expected_user_id_rejected_in_local_fallback(self):
        """Empty expected_user_id must never bypass challenge verification in local fallback."""
        det = AdaptiveSpamDetector(redis_client=None)  # pure local
        user_a = f"user_local_a_{uuid.uuid4().hex[:6]}"
        ch = det.generate_challenge(user_a, {"interval_std": 0.1, "burst_count": 3, "mean_interval": 0.5})
        cid = ch["challenge_id"]

        true_answer = det._local_challenges[cid]["expected_answer"]

        # Empty user ID
        success, msg = det.verify_challenge(cid, true_answer, expected_user_id="")
        assert success is False
        assert "valid user identity" in msg

        # Wrong user ID
        success, msg = det.verify_challenge(cid, true_answer, expected_user_id="imposter_user")
        assert success is False
        assert "different user session" in msg

    def test_api_verify_challenge_requires_identity(self, client):
        """POST /verify-challenge without identity must return 400 or 401."""
        response = client.post(
            "/verify-challenge",
            json={"challenge_id": "ch_dummy_12345", "answer": "42"}
        )
        assert response.status_code in (400, 401)
        detail = str(response.json().get("detail", ""))
        assert any(k in detail for k in ("Missing authentication", "Authentication required", "valid authenticated identity"))

    def test_api_verify_challenge_mismatched_identity_rejected(self, client):
        """Solving User A's challenge with User B's identity must be rejected."""
        det = AdaptiveSpamDetector(redis_client=limiter.redis)
        user_alice = f"alice_{uuid.uuid4().hex[:6]}"
        user_bob = f"bob_{uuid.uuid4().hex[:6]}"

        ch = det.generate_challenge(user_alice, {"interval_std": 0.1, "burst_count": 3, "mean_interval": 0.5})
        cid = ch["challenge_id"]
        true_answer = limiter.redis.hget(f"challenge:{cid}", "expected_answer")

        # Bob attempts to submit Alice's challenge
        token_bob = create_signed_token(user_bob)
        response = client.post(
            "/verify-challenge",
            headers={"Authorization": f"Bearer {token_bob}"},
            json={"challenge_id": cid, "answer": true_answer, "user_id": user_alice}
        )
        assert response.status_code == 400
        assert "different user session" in response.json()["detail"]["message"]

        # Alice submits Alice's challenge -> must succeed
        token_alice = create_signed_token(user_alice)
        res_alice = client.post(
            "/verify-challenge",
            headers={"Authorization": f"Bearer {token_alice}"},
            json={"challenge_id": cid, "answer": true_answer}
        )
        assert res_alice.status_code == 200
        assert res_alice.json()["success"] is True


# =============================================================================
# 3. Cryptographic Token Verification & Unsigned Token Rejection
# =============================================================================
class TestCryptographicTokenVerification:
    def test_forged_unsigned_token_usr_admin_rejected(self):
        """Shallow shorthand 'usr_admin' must be unconditionally rejected."""
        assert verify_signed_token("usr_admin") is None
        assert verify_signed_token("usr_alice") is None

    def test_forged_unsigned_token_token_admin_rejected(self):
        """Shallow shorthand 'token_admin' must be unconditionally rejected."""
        assert verify_signed_token("token_admin") is None
        assert verify_signed_token("token_12345") is None

    def test_arbitrary_strings_rejected(self):
        """Arbitrary strings or malformed inputs must be rejected."""
        assert verify_signed_token("arbitrary_string_123") is None
        assert verify_signed_token("") is None
        assert verify_signed_token(None) is None
        assert verify_signed_token("user:notatimestamp:sig") is None
        assert verify_signed_token("user:12345") is None

    def test_valid_signed_token_accepted(self):
        """Valid HMAC-SHA256 signed token within validity window must be accepted."""
        user = f"user_{uuid.uuid4().hex[:6]}"
        token = create_signed_token(user)
        assert verify_signed_token(token) == user

    def test_tampered_token_signature_rejected(self):
        """Any modification to user_id, timestamp, or signature must invalidate the token."""
        user = "verified_alice"
        token = create_signed_token(user)
        parts = token.split(":")
        
        # Tamper user
        tampered_user = f"verified_bob:{parts[1]}:{parts[2]}"
        assert verify_signed_token(tampered_user) is None

        # Tamper timestamp
        tampered_ts = f"{parts[0]}:{int(parts[1]) + 10}:{parts[2]}"
        assert verify_signed_token(tampered_ts) is None

        # Tamper signature hex
        tampered_sig = f"{parts[0]}:{parts[1]}:{'a' * 64}"
        assert verify_signed_token(tampered_sig) is None

    def test_expired_token_rejected(self):
        """Tokens older than max_age_seconds must be rejected."""
        user = "alice_expired"
        now = int(time.time())
        # Token generated 3601 seconds ago (max_age is 3600)
        expired_token = create_signed_token(user, timestamp=now - 3601)
        assert verify_signed_token(expired_token, max_age_seconds=3600) is None

        # Token within window (3500 seconds ago) must still be accepted
        valid_token = create_signed_token(user, timestamp=now - 3500)
        assert verify_signed_token(valid_token, max_age_seconds=3600) == user

    def test_future_dated_token_rejected(self):
        """Tokens with future timestamps exceeding clock skew window must be rejected."""
        user = "alice_future"
        now = int(time.time())
        # Token timestamped 120 seconds into the future (clock skew allowed is 60s)
        future_token = create_signed_token(user, timestamp=now + 120)
        assert verify_signed_token(future_token, allowed_clock_skew=60) is None

        # Token timestamped 20 seconds into the future (within 60s skew) is accepted
        slight_skew_token = create_signed_token(user, timestamp=now + 20)
        assert verify_signed_token(slight_skew_token, allowed_clock_skew=60) == user


# =============================================================================
# 4. Signing Secret Security, Entropy & Startup Validation
# =============================================================================
class TestSigningSecretSecurityAndEntropy:
    def test_missing_signing_secret_in_production_raises_runtime_error(self, monkeypatch):
        """In production environment without dev overrides, missing AUTH_SECRET_KEY must raise RuntimeError."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)
        monkeypatch.setenv("AUTH_SECRET_KEY", "")

        with pytest.raises(RuntimeError) as exc_info:
            get_auth_secret_key()
        assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
        assert "AUTH_SECRET_KEY" in str(exc_info.value)

    def test_weak_signing_secret_in_production_raises_value_error(self, monkeypatch):
        """In production environment, an AUTH_SECRET_KEY shorter than 32 characters must raise ValueError."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)
        monkeypatch.setenv("AUTH_SECRET_KEY", "too-short-secret")

        with pytest.raises(ValueError) as exc_info:
            get_auth_secret_key()
        assert "insufficient length" in str(exc_info.value)
        assert "Minimum required length is 32 characters" in str(exc_info.value)

    def test_strong_signing_secret_accepted(self, monkeypatch):
        """A 32+ character key is valid and accepted."""
        strong_key = "x" * 32
        monkeypatch.setenv("AUTH_SECRET_KEY", strong_key)
        assert get_auth_secret_key() == strong_key


# =============================================================================
# 5. Production Authentication Defaults & Endpoint Enforcement
# =============================================================================
class TestProductionAuthDefaultsAndEndpointEnforcement:
    def test_default_production_auth_requirement(self, monkeypatch):
        """When REQUIRE_AUTH is unset, is_auth_required() must evaluate to True (secure default)."""
        monkeypatch.delenv("REQUIRE_AUTH", raising=False)
        assert is_auth_required() is True

    def test_unauthenticated_request_rejected_with_401_when_auth_required(self, client, monkeypatch):
        """When REQUIRE_AUTH is true, calling /limited-resource without credentials must return 401."""
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        response = client.get("/limited-resource")
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_unauthenticated_verify_challenge_rejected_with_401_when_auth_required(self, client, monkeypatch):
        """When REQUIRE_AUTH is true, calling /verify-challenge without credentials must return 401."""
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        response = client.post(
            "/verify-challenge",
            json={"challenge_id": "ch_dummy_12345", "answer": "42"}
        )
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_dev_headers_ignored_when_auth_required(self, client, monkeypatch):
        """
        When REQUIRE_AUTH is true, client-supplied user-id header is ignored and returns 401,
        even if ALLOW_UNAUTHENTICATED_DEV_HEADERS is true.
        """
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
        assert is_dev_headers_allowed() is False

        response = client.get("/limited-resource", headers={"user-id": "attacker_user"})
        assert response.status_code == 401

    def test_client_cannot_change_identity_via_headers_when_authenticated(self, client):
        """
        When authenticated as 'alice', supplying a header 'user-id: victim_bob'
        must NOT change the rate limit identity to bob.
        """
        alice = f"alice_{uuid.uuid4().hex[:6]}"
        victim_bob = f"victim_bob_{uuid.uuid4().hex[:6]}"
        limiter.reset(alice)
        limiter.reset(victim_bob)

        token_alice = create_signed_token(alice)

        # Make requests with Alice's token and Bob's header
        res = client.get(
            "/limited-resource",
            headers={
                "Authorization": f"Bearer {token_alice}",
                "user-id": victim_bob,
                "user-agent": f"TestUA_{uuid.uuid4().hex[:6]}"
            }
        )
        assert res.status_code == 200
        data = res.json()
        assert data["user_id"] == alice

        # Alice's rate limit key must exist in Redis
        if limiter.redis:
            assert limiter.redis.exists(f"rate_limit:{alice}") == 1
            # Bob's key must NOT exist at all in Redis (completely untouched)
            assert limiter.redis.exists(f"rate_limit:{victim_bob}") == 0

    def test_verify_challenge_ignores_payload_user_id_when_authenticated(self, client):
        """
        When authenticated via token, /verify-challenge resolves identity strictly
        from the token and ignores any payload user_id mismatch.
        """
        det = AdaptiveSpamDetector(redis_client=limiter.redis)
        user_alice = f"alice_{uuid.uuid4().hex[:6]}"
        ch = det.generate_challenge(user_alice, {"interval_std": 0.1, "burst_count": 3, "mean_interval": 0.5})
        cid = ch["challenge_id"]
        true_answer = limiter.redis.hget(f"challenge:{cid}", "expected_answer")

        token_alice = create_signed_token(user_alice)

        # Alice submits with payload mentioning "some_other_id"
        res = client.post(
            "/verify-challenge",
            headers={"Authorization": f"Bearer {token_alice}"},
            json={"challenge_id": cid, "answer": true_answer, "user_id": "some_other_id"}
        )
        assert res.status_code == 200
        assert res.json()["success"] is True


# =============================================================================
# 6. Device Fingerprint Heuristic Verification
# =============================================================================
class TestDeviceFingerprintHeuristicLimitations:
    def test_fingerprint_changes_with_untrusted_client_headers(self):
        """Confirms that rotating untrusted headers shifts the heuristic fingerprint."""
        det = AdaptiveSpamDetector(redis_client=None)
        h1 = {"user-agent": "BrowserA", "sec-ch-ua-platform": "Windows"}
        h2 = {"user-agent": "BrowserB", "sec-ch-ua-platform": "macOS"}

        fp1 = det.compute_device_fingerprint(h1, user_agent="BrowserA")
        fp2 = det.compute_device_fingerprint(h2, user_agent="BrowserB")
        assert fp1 != fp2
        assert fp1.startswith("dev_")
        assert fp2.startswith("dev_")
