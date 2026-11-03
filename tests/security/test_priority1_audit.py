"""
Priority 1 Security Regression Tests.

Covers:
  1. Redis failure modes at the API level (FAIL_CLOSED, FAIL_OPEN, LOCAL_FALLBACK).
  2. Challenge session binding (omitted identities, mismatched users, replay attacks) in Redis and local fallback.
  3. Identity trust & authenticated principals: verifying credentials take precedence over client-supplied headers.
  4. Device fingerprinting limitations: verifying header-derived heuristic nature.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, ip_limiter, detector
from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from spam_detector import AdaptiveSpamDetector
from auth import create_signed_token, verify_signed_token, AuthenticatedPrincipal


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
        """POST /verify-challenge without identity must return 400 Bad Request."""
        response = client.post(
            "/verify-challenge",
            json={"challenge_id": "ch_dummy_12345", "answer": "42"}
        )
        assert response.status_code == 400
        assert "valid authenticated identity" in response.json()["detail"]

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
# 3. Identity Trust & Authenticated Principal Enforcement
# =============================================================================
class TestIdentityTrustAndAuthentication:
    def test_authenticated_principal_derivation_from_bearer_token(self):
        token = create_signed_token("verified_alice")
        assert verify_signed_token(token) == "verified_alice"

    def test_tampered_token_rejected(self):
        token = create_signed_token("verified_alice")
        # Tamper with the user_id portion
        tampered = "verified_bob" + token[len("verified_alice"):]
        assert verify_signed_token(tampered) is None

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
        # Check response details: user_id must be Alice, never Bob
        data = res.json()
        assert data["user_id"] == alice

        # Alice's rate limit key must exist in Redis
        if limiter.redis:
            assert limiter.redis.exists(f"rate_limit:{alice}") == 1
            # Bob's key must NOT exist at all in Redis (completely untouched)
            assert limiter.redis.exists(f"rate_limit:{victim_bob}") == 0


# =============================================================================
# 4. Device Fingerprint Heuristic Verification
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
