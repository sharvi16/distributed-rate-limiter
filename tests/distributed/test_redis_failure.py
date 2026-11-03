"""
Failure & Resilience Tests for Redis Outages (Phase 7).

Verifies the system's resilience when Redis becomes unreachable:
  1. FAIL_CLOSED mode: strictly blocks traffic with RedisUnavailableError.
  2. FAIL_OPEN mode: gracefully allows requests.
  3. LOCAL_FALLBACK mode: falls back to thread-safe bounded local memory bucket.
  4. Challenge and detector fallback when Redis connection drops mid-operation.
"""

import pytest
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from spam_detector import AdaptiveSpamDetector


class DeadRedisMock:
    """Mock Redis client that consistently simulates network disconnection or timeouts."""
    def ping(self):
        raise redis.ConnectionError("Simulated Redis network partition")

    def __getattr__(self, name):
        def _fail(*args, **kwargs):
            raise redis.ConnectionError("Simulated Redis connection failure")
        return _fail


def test_fail_closed_mode_on_redis_partition():
    dead_client = DeadRedisMock()
    limiter = RateLimiter(
        redis_client=dead_client,
        capacity=5,
        refill_rate=1.0,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    with pytest.raises(RedisUnavailableError):
        limiter.is_allowed("user_fail_closed")

    with pytest.raises(RedisUnavailableError):
        limiter.check_limit("user_fail_closed")


def test_fail_open_mode_on_redis_partition():
    dead_client = DeadRedisMock()
    limiter = RateLimiter(
        redis_client=dead_client,
        capacity=5,
        refill_rate=1.0,
        failure_mode=FailureMode.FAIL_OPEN
    )
    assert limiter.is_allowed("user_fail_open") is True
    res = limiter.check_limit("user_fail_open")
    assert res.allowed is True
    assert res.limit == 5


def test_local_fallback_mode_on_redis_partition():
    dead_client = DeadRedisMock()
    limiter = RateLimiter(
        redis_client=dead_client,
        capacity=3,
        refill_rate=0.01,
        failure_mode=FailureMode.LOCAL_FALLBACK
    )
    # Allows initial 3 tokens locally
    assert limiter.is_allowed("user_local") is True
    assert limiter.is_allowed("user_local") is True
    assert limiter.is_allowed("user_local") is True

    # 4th token is rejected locally
    assert limiter.is_allowed("user_local") is False

    res = limiter.check_limit("user_local")
    assert res.allowed is False
    assert res.retry_after >= 1


def test_detector_fallback_during_redis_partition():
    dead_client = DeadRedisMock()
    detector = AdaptiveSpamDetector(redis_client=dead_client)

    # Penalty box fallback
    is_jailed, _ = detector.is_in_penalty_box("user_any")
    assert is_jailed is False

    # Jailing fallback
    detector.jail_user("user_fallback_jail", duration_seconds=30)
    is_jailed, rem = detector.is_in_penalty_box("user_fallback_jail")
    assert is_jailed is True
    assert 20 <= rem <= 30

    # Challenge fallback
    features = {"request_interval": 0.5, "interval_std": 0.1, "burst_count": 2}
    challenge = detector.generate_challenge("user_fb_ch", features)
    assert "challenge_id" in challenge

    # Verification fallback
    # Solve directly using local challenge store
    local_ch = detector._local_challenges.get(challenge["challenge_id"])
    assert local_ch is not None
    success, _ = detector.verify_challenge(challenge["challenge_id"], local_ch["expected_answer"], expected_user_id="user_fb_ch")
    assert success is True
    assert detector.is_verified_human("user_fb_ch") is True
