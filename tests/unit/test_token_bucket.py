"""
Unit & Integration Tests for Token Bucket Rate Limiter (Phase 1).

Tests:
  - Initial bucket capacity and consumption
  - Continuous token refill over time
  - Bucket exhaustion (empty bucket)
  - Oversized requests (> capacity)
  - Input validation (zero/negative tokens, invalid user_id)
  - Configuration invariants (negative capacity/refill_rate)
  - FailureMode behaviors (FAIL_CLOSED, FAIL_OPEN, LOCAL_FALLBACK)
  - Concurrent requests under high contention
  - Multiple application instances sharing the same Redis state
  - Redis disconnection and reconnection resilience
"""

import time
import threading
import uuid
import pytest
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError


@pytest.fixture
def redis_client():
    """Provides a clean Redis client for test isolation."""
    try:
        client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=1.0)
        client.ping()
        yield client
    except Exception:
        pytest.skip("Redis is not available on localhost:6379")


@pytest.fixture
def unique_user():
    """Returns a unique user ID for test isolation."""
    return f"test_user_{uuid.uuid4().hex[:12]}"


# =============================================================================
# 1. Configuration & Invariant Validation Tests
# =============================================================================

def test_invalid_configuration_raises():
    """Initialization with non-positive capacity or refill_rate must raise ValueError."""
    with pytest.raises(ValueError, match="capacity must be a positive number"):
        RateLimiter(capacity=0)

    with pytest.raises(ValueError, match="capacity must be a positive number"):
        RateLimiter(capacity=-5)

    with pytest.raises(ValueError, match="refill_rate must be a positive number"):
        RateLimiter(capacity=10, refill_rate=0)

    with pytest.raises(ValueError, match="refill_rate must be a positive number"):
        RateLimiter(capacity=10, refill_rate=-1.5)

    with pytest.raises(ValueError, match="max_local_keys must be positive"):
        RateLimiter(capacity=10, refill_rate=1.0, max_local_keys=0)


def test_invalid_input_validation():
    """is_allowed must validate user_id and tokens parameters."""
    limiter = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)

    # Invalid user_id
    with pytest.raises(ValueError, match="user_id must be a non-empty string"):
        limiter.is_allowed("")

    with pytest.raises(ValueError, match="user_id must be a non-empty string"):
        limiter.is_allowed("   ")

    with pytest.raises(ValueError, match="user_id must be a non-empty string"):
        limiter.is_allowed(None)  # type: ignore

    # Invalid tokens
    with pytest.raises(ValueError, match="tokens requested must be greater than zero"):
        limiter.is_allowed("valid_user", tokens=0)

    with pytest.raises(ValueError, match="tokens requested must be greater than zero"):
        limiter.is_allowed("valid_user", tokens=-3)


# =============================================================================
# 2. Token Bucket Mechanics (Redis & Local Fallback)
# =============================================================================

def test_initial_bucket_capacity_and_exhaustion(redis_client, unique_user):
    """A fresh bucket starts with full capacity and allows exactly capacity requests."""
    capacity = 5
    limiter = RateLimiter(capacity=capacity, refill_rate=0.01, redis_client=redis_client)
    limiter.reset(unique_user)

    # Exactly 5 requests should be allowed
    for i in range(capacity):
        assert limiter.is_allowed(unique_user, tokens=1) is True, f"Request {i+1} should be allowed"

    # 6th request must be rejected
    assert limiter.is_allowed(unique_user, tokens=1) is False, "Request beyond capacity must be rejected"


def test_request_larger_than_capacity(redis_client, unique_user):
    """Requests demanding more tokens than the total bucket capacity must be rejected without mutating state."""
    limiter = RateLimiter(capacity=5, refill_rate=1.0, redis_client=redis_client)
    limiter.reset(unique_user)

    # Requesting 6 tokens when capacity is 5
    assert limiter.is_allowed(unique_user, tokens=6) is False

    # State should remain intact; a valid 5-token request should still succeed
    assert limiter.is_allowed(unique_user, tokens=5) is True


def test_token_refill_after_elapsed_time(redis_client, unique_user):
    """Tokens refill continuously at refill_rate over elapsed time."""
    capacity = 2
    refill_rate = 2.0  # 2 tokens per second (1 token every 0.5s)
    limiter = RateLimiter(capacity=capacity, refill_rate=refill_rate, redis_client=redis_client)
    limiter.reset(unique_user)

    # Empty the bucket
    assert limiter.is_allowed(unique_user, tokens=2) is True
    assert limiter.is_allowed(unique_user, tokens=1) is False

    # Sleep 0.6s -> should refill at least 1 token
    time.sleep(0.6)
    assert limiter.is_allowed(unique_user, tokens=1) is True

    # Sleep another 1.1s -> should refill 2 tokens (capped at capacity)
    time.sleep(1.1)
    assert limiter.is_allowed(unique_user, tokens=2) is True


# =============================================================================
# 3. Failure Mode Behaviors
# =============================================================================

def test_failure_mode_fail_closed():
    """FAIL_CLOSED raises RedisUnavailableError when Redis is down."""
    limiter = RateLimiter(
        redis_url="redis://nonexistent_host:9999",
        capacity=5,
        refill_rate=1.0,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    with pytest.raises(RedisUnavailableError, match="Rate limiter service unavailable"):
        limiter.is_allowed("some_user")


def test_failure_mode_fail_open():
    """FAIL_OPEN returns True when Redis is down to preserve availability."""
    limiter = RateLimiter(
        redis_url="redis://nonexistent_host:9999",
        capacity=5,
        refill_rate=1.0,
        failure_mode=FailureMode.FAIL_OPEN
    )
    # When Redis is down, normal requests are allowed under fail_open
    assert limiter.is_allowed("some_user", tokens=1) is True
    assert limiter.is_allowed("some_user", tokens=5) is True


def test_failure_mode_local_fallback(unique_user):
    """LOCAL_FALLBACK enforces rate limits in-memory when Redis is unreachable."""
    limiter = RateLimiter(
        redis_url="redis://nonexistent_host:9999",
        capacity=3,
        refill_rate=0.1,
        failure_mode=FailureMode.LOCAL_FALLBACK
    )
    assert limiter.is_allowed(unique_user) is True
    assert limiter.is_allowed(unique_user) is True
    assert limiter.is_allowed(unique_user) is True
    # 4th request exceeds local capacity
    assert limiter.is_allowed(unique_user) is False


# =============================================================================
# 4. Multi-Instance Distributed Consensus Test
# =============================================================================

def test_multiple_instances_share_same_redis_bucket(redis_client, unique_user):
    """
    Two independent RateLimiter instances sharing the same Redis server
    must enforce the single shared quota without double-spending.
    """
    capacity = 6
    instance_1 = RateLimiter(capacity=capacity, refill_rate=0.01, redis_client=redis_client)
    instance_2 = RateLimiter(capacity=capacity, refill_rate=0.01, redis_client=redis_client)
    instance_1.reset(unique_user)

    # Instance 1 consumes 3 tokens
    assert instance_1.is_allowed(unique_user, tokens=3) is True

    # Instance 2 consumes 3 tokens
    assert instance_2.is_allowed(unique_user, tokens=3) is True

    # Total 6 tokens consumed. Neither instance should be able to consume more tokens
    assert instance_1.is_allowed(unique_user, tokens=1) is False
    assert instance_2.is_allowed(unique_user, tokens=1) is False


# =============================================================================
# 5. Concurrency Race Condition Test
# =============================================================================

def test_concurrent_requests_strict_atomicity(redis_client, unique_user):
    """
    20 concurrent threads trying to consume 1 token each from a bucket of capacity 10.
    Exactly 10 must succeed and exactly 10 must be rejected. Zero race conditions.
    """
    capacity = 10
    limiter = RateLimiter(capacity=capacity, refill_rate=0.01, redis_client=redis_client)
    limiter.reset(unique_user)

    results = []
    lock = threading.Lock()

    def worker():
        allowed = limiter.is_allowed(unique_user, tokens=1)
        with lock:
            results.append(allowed)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r is True)
    rejections = sum(1 for r in results if r is False)

    assert successes == capacity, f"Expected exactly {capacity} successes under concurrency, got {successes}"
    assert rejections == (20 - capacity), f"Expected {20 - capacity} rejections under concurrency, got {rejections}"


def test_check_limit_telemetry_and_headers(redis_client):
    limiter = RateLimiter(redis_client=redis_client, capacity=5, refill_rate=1.0)
    user = f"user_chk_{int(time.time()*1000)}"
    limiter.reset(user)

    res1 = limiter.check_limit(user, tokens=1)
    assert res1.allowed is True
    assert res1.limit == 5
    assert 3.9 <= res1.remaining <= 4.1
    assert res1.retry_after is None
    assert 0.0 <= res1.reset_after <= 1.2

    # Consume all remaining
    res2 = limiter.check_limit(user, tokens=4)
    assert res2.allowed is True
    assert 0.0 <= res2.remaining <= 0.1

    # Now should be rejected with positive retry_after
    res3 = limiter.check_limit(user, tokens=1)
    assert res3.allowed is False
    assert res3.retry_after >= 1
