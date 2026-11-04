"""
Unit and regression tests verifying all fixes for the code review follow-up.
"""

import math
import threading
import time
from typing import Optional
import uuid
import pytest
from unittest.mock import MagicMock, patch

import rate_limiter
from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
import spam_detector
from spam_detector import AdaptiveSpamDetector
import main
from metrics import metrics_collector


# =============================================================================
# Issue 1: rate_limiter.py — _init_redis() raises RedisUnavailableError on FAIL_CLOSED
# =============================================================================

def test_init_redis_raises_on_fail_closed_outage():
    """_init_redis() must raise RedisUnavailableError when failure_mode == FAIL_CLOSED."""
    with patch("redis.from_url", side_effect=Exception("Failed to connect")):
        with pytest.raises(RedisUnavailableError) as exc_info:
            RateLimiter(
                redis_url="redis://localhost:6379",
                failure_mode=FailureMode.FAIL_CLOSED
            )
        assert "Redis initialization failed" in str(exc_info.value)


def test_init_redis_suppresses_under_fail_open_and_local_fallback():
    """_init_redis() sets redis=None and does not raise when in FAIL_OPEN or LOCAL_FALLBACK."""
    with patch("redis.from_url", side_effect=Exception("Failed to connect")):
        lim_open = RateLimiter(
            redis_url="redis://localhost:6379",
            failure_mode=FailureMode.FAIL_OPEN
        )
        assert lim_open.redis is None

        lim_fallback = RateLimiter(
            redis_url="redis://localhost:6379",
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        assert lim_fallback.redis is None


# =============================================================================
# Issue 2: spam_detector.py — Misplaced docstring in compute_risk_score
# =============================================================================

def test_compute_risk_score_has_proper_docstring():
    """compute_risk_score function docstring must not be None and must describe the classifier."""
    doc = AdaptiveSpamDetector.compute_risk_score.__doc__
    assert doc is not None
    assert "Computes a continuous risk score" in doc


# =============================================================================
# Issue 3: spam_detector.py — Race condition: _local_device_ips and _local_ip_identities in __init__
# =============================================================================

def test_local_tracking_dicts_initialized_in_init():
    """_local_device_ips and _local_ip_identities must be initialized as empty dicts upon instantiation."""
    det = AdaptiveSpamDetector(redis_client=None)
    assert hasattr(det, "_local_device_ips")
    assert isinstance(det._local_device_ips, dict)
    assert len(det._local_device_ips) == 0

    assert hasattr(det, "_local_ip_identities")
    assert isinstance(det._local_ip_identities, dict)
    assert len(det._local_ip_identities) == 0

    assert hasattr(det, "_local_challenge_throttles")
    assert isinstance(det._local_challenge_throttles, dict)
    assert len(det._local_challenge_throttles) == 0


# =============================================================================
# Issue 4: main.py — sync_rate_limiter_configuration defined before lifespan
# =============================================================================

def test_sync_rate_limiter_configuration_callable_and_consistent():
    """sync_rate_limiter_configuration must be defined and execute cleanly."""
    main.sync_rate_limiter_configuration()
    assert main.limiter is not None
    assert main.ip_limiter is not None


# =============================================================================
# Issue 5: spam_detector.py — Per-user throttle on challenge generation
# =============================================================================

def test_challenge_generation_per_user_throttle_local():
    """A user requesting more than 3 challenges in 5 minutes must be jailed, not issued new challenges."""
    det = AdaptiveSpamDetector(redis_client=None)
    user_id = f"throttle_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    # First 3 challenges should succeed
    ch1 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch1

    ch2 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch2

    ch3 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch3

    # 4th challenge exceeds limit -> user jailed
    ch4 = det.generate_challenge(user_id, features)
    assert "challenge_id" not in ch4
    assert ch4.get("jailed") is True
    assert ch4.get("retry_after") == 300

    # Verify user is in penalty box
    is_jailed, rem = det.is_in_penalty_box(user_id)
    assert is_jailed is True
    assert rem > 0


def test_challenge_generation_per_user_throttle_redis():
    """Redis-backed throttle properly jails user after 3 challenge requests."""
    mock_redis = MagicMock()
    # Simulate INCR returning 1, 2, 3, 4
    mock_redis.incr.side_effect = [1, 2, 3, 4]
    mock_redis.ttl.return_value = 300

    det = AdaptiveSpamDetector(redis_client=mock_redis)
    user_id = f"throttle_user_redis_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch1 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch1
    ch2 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch2
    ch3 = det.generate_challenge(user_id, features)
    assert "challenge_id" in ch3

    # 4th challenge
    ch4 = det.generate_challenge(user_id, features)
    assert "challenge_id" not in ch4
    assert ch4.get("jailed") is True


# =============================================================================
# Issue 6 & Priority 2: Strengthened Lua result validation in check_limit
# =============================================================================

@pytest.mark.parametrize("bad_result", [
    None,
    [],
    [1],
    [1, "invalid"],
    [1, None],
    [1, True],
    [1, float("nan")],
    [1, float("inf")],
    [1, -5.0],
    ["invalid", 5.0],
    123,
    {"allowed": 1, "remaining": 5},
    [True, 5.0],
    [False, 5.0],
    [1, 15.0],             # Remaining exceeds bucket capacity (10)
    [1, 5.0, "extra"],     # Unexpected extra element (len > 2)
    [1, 5.0, 0]            # Unexpected extra element (len > 2)
])
def test_check_limit_handles_all_malformed_lua_responses(bad_result):
    """check_limit routes any malformed Lua response to failure handler across all 3 failure modes."""
    # 1. LOCAL_FALLBACK: falls back to local in-memory token bucket gracefully
    lim_fallback = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    lim_fallback.redis = MagicMock()
    lim_fallback.check_limit_script = MagicMock(return_value=bad_result)
    res_fallback = lim_fallback.check_limit("user_fb_bad")
    assert res_fallback.allowed is True

    # 2. FAIL_OPEN: allows gracefully
    lim_open = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)
    lim_open.redis = MagicMock()
    lim_open.check_limit_script = MagicMock(return_value=bad_result)
    res_open = lim_open.check_limit("user_fo_bad")
    assert res_open.allowed is True
    assert res_open.remaining == 10.0

    # 3. FAIL_CLOSED: raises RedisUnavailableError
    lim_closed = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)
    lim_closed.redis = MagicMock()
    lim_closed.check_limit_script = MagicMock(return_value=bad_result)
    with pytest.raises(RedisUnavailableError) as exc_info:
        lim_closed.check_limit("user_fc_bad")
    assert "Rate limiter service unavailable" in str(exc_info.value)


def test_check_limit_rejects_boolean_allowed_indicator_across_modes():
    """check_limit strictly rejects booleans for allowed indicator (True/False) across all failure modes."""
    for bool_allowed in [True, False]:
        bad_response = [bool_allowed, 5.0]

        # FAIL_CLOSED
        lim_closed = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)
        lim_closed.redis = MagicMock()
        lim_closed.check_limit_script = MagicMock(return_value=bad_response)
        with pytest.raises(RedisUnavailableError) as exc_info:
            lim_closed.check_limit("user_bool_allowed")
        assert "invalid allowed indicator" in str(exc_info.value)

        # FAIL_OPEN
        lim_open = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)
        lim_open.redis = MagicMock()
        lim_open.check_limit_script = MagicMock(return_value=bad_response)
        res_open = lim_open.check_limit("user_bool_allowed")
        assert res_open.allowed is True

        # LOCAL_FALLBACK
        lim_fallback = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        lim_fallback.redis = MagicMock()
        lim_fallback.check_limit_script = MagicMock(return_value=bad_response)
        res_fallback = lim_fallback.check_limit("user_bool_allowed")
        assert res_fallback.allowed is True


def test_check_limit_rejects_remaining_exceeding_capacity_across_modes():
    """check_limit rejects remaining tokens exceeding configured bucket capacity across all failure modes."""
    capacity = 10
    excessive_remaining = capacity + 5.0  # 15.0 > 10.0
    bad_response = [1, excessive_remaining]

    # FAIL_CLOSED
    lim_closed = RateLimiter(capacity=capacity, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)
    lim_closed.redis = MagicMock()
    lim_closed.check_limit_script = MagicMock(return_value=bad_response)
    with pytest.raises(RedisUnavailableError) as exc_info:
        lim_closed.check_limit("user_excessive_tokens")
    assert "cannot exceed bucket capacity" in str(exc_info.value)

    # FAIL_OPEN
    lim_open = RateLimiter(capacity=capacity, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)
    lim_open.redis = MagicMock()
    lim_open.check_limit_script = MagicMock(return_value=bad_response)
    res_open = lim_open.check_limit("user_excessive_tokens")
    assert res_open.allowed is True

    # LOCAL_FALLBACK
    lim_fallback = RateLimiter(capacity=capacity, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    lim_fallback.redis = MagicMock()
    lim_fallback.check_limit_script = MagicMock(return_value=bad_response)
    res_fallback = lim_fallback.check_limit("user_excessive_tokens")
    assert res_fallback.allowed is True


def test_check_limit_rejects_unexpected_extra_elements_across_modes():
    """check_limit strictly enforces exact sequence length of 2 across all failure modes."""
    for bad_response in [[1, 5.0, "extra"], [1, 5.0, 0], [1, 5.0, None, "unexpected"]]:
        # FAIL_CLOSED
        lim_closed = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_CLOSED)
        lim_closed.redis = MagicMock()
        lim_closed.check_limit_script = MagicMock(return_value=bad_response)
        with pytest.raises(RedisUnavailableError) as exc_info:
            lim_closed.check_limit("user_extra_elements")
        assert "expected sequence of exactly 2 elements" in str(exc_info.value)

        # FAIL_OPEN
        lim_open = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.FAIL_OPEN)
        lim_open.redis = MagicMock()
        lim_open.check_limit_script = MagicMock(return_value=bad_response)
        res_open = lim_open.check_limit("user_extra_elements")
        assert res_open.allowed is True

        # LOCAL_FALLBACK
        lim_fallback = RateLimiter(capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        lim_fallback.redis = MagicMock()
        lim_fallback.check_limit_script = MagicMock(return_value=bad_response)
        res_fallback = lim_fallback.check_limit("user_extra_elements")
        assert res_fallback.allowed is True


# =============================================================================
# Issue 7 & Priority 1: Accurate diagnostics without double-counting
# =============================================================================

def test_get_diagnostics_active_jailed_users_local():
    """get_diagnostics() accurately reports local jailed users and clarifies scope note."""
    det = AdaptiveSpamDetector(redis_client=None)
    det.jail_user("jailed_user_1", duration_seconds=60)
    det.jail_user("jailed_user_2", duration_seconds=60)

    diag = det.get_diagnostics()
    assert diag["active_jailed_users"] == 2
    assert "active_jailed_users_note" in diag
    assert "local in-memory" in diag["active_jailed_users_note"]


def test_get_diagnostics_no_double_counting_between_redis_and_local():
    """When the same user exists in both Redis and local penalty box, they must NOT be double-counted."""
    mock_redis = MagicMock()
    # Redis holds user 'alice' and user 'bob'
    mock_redis.scan_iter.return_value = ["penalty_box:alice", "penalty_box:bob"]

    det = AdaptiveSpamDetector(redis_client=mock_redis)
    now = time.time()
    with det._lock:
        # Local state mirrors 'alice' (from jail_user) and has a distinct local-only user 'charlie'
        det._local_penalty_box["alice"] = now + 60
        det._local_penalty_box["charlie"] = now + 60

    diag = det.get_diagnostics()
    # Total distinct jailed users: alice, bob, charlie = exactly 3 (NOT 2+2=4)
    assert diag["active_jailed_users"] == 3
    assert "active_jailed_users_note" in diag
    assert "Deduplicated" in diag["active_jailed_users_note"]


def test_get_diagnostics_falls_back_to_local_when_redis_scan_fails():
    """When Redis scan raises an exception, get_diagnostics safely reports local-only count."""
    mock_redis = MagicMock()
    mock_redis.scan_iter.side_effect = Exception("Redis scan network error")

    det = AdaptiveSpamDetector(redis_client=mock_redis)
    now = time.time()
    with det._lock:
        det._local_penalty_box["local_user_only"] = now + 60

    diag = det.get_diagnostics()
    assert diag["active_jailed_users"] == 1
    assert "local in-memory" in diag["active_jailed_users_note"]


# =============================================================================
# Issue 8 & Priority 3: Metric counters for challenge issued and verified
# =============================================================================

def test_verify_challenge_increments_metrics():
    """Successful challenge verification increments ratelimit_challenges_verified_total."""
    from fastapi.testclient import TestClient
    client = TestClient(main.app)

    det = main.detector
    user_id = f"test_metric_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    # Bypass Redis for unit test to use local challenges
    old_redis = det.redis
    det.redis = None
    try:
        challenge = det.generate_challenge(user_id, features)
        cid = challenge["challenge_id"]
        correct_answer = det._local_challenges[cid]["expected_answer"]

        initial_count = metrics_collector.challenges_verified_total

        # Call endpoint
        response = client.post(
            "/verify-challenge",
            headers={"user-id": user_id},
            json={"challenge_id": cid, "user_id": user_id, "answer": correct_answer}
        )
        assert response.status_code == 200
        assert metrics_collector.challenges_verified_total == initial_count + 1
    finally:
        det.redis = old_redis


def test_throttled_challenge_does_not_increment_issued_counter(monkeypatch):
    """A throttled challenge request must jail user and NOT increment challenges_issued_total."""
    from fastapi.testclient import TestClient

    # Ensure rate limiters use local fallback so request reaches Tier 4 (spam detector)
    mock_user_limiter = RateLimiter(redis_client=None, capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    mock_ip_limiter = RateLimiter(redis_client=None, capacity=30, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    monkeypatch.setattr(main, "limiter", mock_user_limiter)
    monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

    client = TestClient(main.app)

    user_id = f"test_throttle_metrics_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.5}

    det = main.detector
    # Fill up 3 allowed challenge requests
    det.generate_challenge(user_id, features)
    det.generate_challenge(user_id, features)
    det.generate_challenge(user_id, features)

    # Clear pending challenge so request passes Tier 2 and reaches Tier 4 (ML classifier)
    with det._lock:
        det._local_challenges.clear()
    if det.redis:
        try:
            det.redis.delete(f"user_pending_challenge:{user_id}")
        except Exception:
            pass

    initial_issued = metrics_collector.challenges_issued_total

    # Mock classifier to return "suspicious" to trigger the challenge route
    with patch.object(det, "compute_risk_score", return_value=(0.6, "suspicious")):
        response = client.get("/limited-resource", headers={"user-id": user_id})
        assert response.status_code == 429
        assert "Challenge generation limit exceeded" in response.json()["detail"]["message"]

    # Must NOT have incremented challenges_issued_total
    assert metrics_collector.challenges_issued_total == initial_issued


def test_successful_challenge_increments_issued_counter(monkeypatch):
    """A successfully issued challenge must increment challenges_issued_total."""
    from fastapi.testclient import TestClient

    mock_user_limiter = RateLimiter(redis_client=None, capacity=10, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    mock_ip_limiter = RateLimiter(redis_client=None, capacity=30, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    monkeypatch.setattr(main, "limiter", mock_user_limiter)
    monkeypatch.setattr(main, "ip_limiter", mock_ip_limiter)

    client = TestClient(main.app)
    user_id = f"test_success_issued_{uuid.uuid4().hex[:8]}"

    det = main.detector
    initial_issued = metrics_collector.challenges_issued_total

    with patch.object(det, "compute_risk_score", return_value=(0.6, "suspicious")):
        response = client.get("/limited-resource", headers={"user-id": user_id})
        assert response.status_code == 403
        assert "Verification challenge required" in response.json()["detail"]["message"]

    assert metrics_collector.challenges_issued_total == initial_issued + 1


# =============================================================================
# Issue 9: rate_limiter.py — from dataclasses import dataclass appears after docstring
# =============================================================================

def test_rate_limiter_module_docstring_per_pep257():
    """rate_limiter module docstring must precede all imports per PEP 257."""
    assert rate_limiter.__doc__ is not None
    assert rate_limiter.__doc__.strip().startswith("Distributed Token Bucket Rate Limiter")


# =============================================================================
# Issue 10: spam_detector.py — Direct hset instead of pipeline in _init_or_load_redis_model
# =============================================================================

def test_init_or_load_redis_model_uses_direct_hset():
    """_init_or_load_redis_model uses direct self.redis.hset instead of pipeline."""
    mock_redis = MagicMock()
    mock_redis.exists.return_value = False

    det = AdaptiveSpamDetector(redis_client=mock_redis)
    mock_redis.pipeline.assert_not_called()
    mock_redis.hset.assert_called_once()
    assert mock_redis.hset.call_args[0][0] == "model_state:centroids"


# =============================================================================
# Priority 4: Bounded verify_connection for client without connection pool
# =============================================================================

class MockTimeoutCapableRedisClient:
    """Simulates a custom Redis client without connection_pool that provides a timeout-capable ping."""
    def __init__(self, delay: float = 0.0, should_fail: bool = False):
        self.connection_pool = None
        self.delay = delay
        self.should_fail = should_fail

    def ping(self, timeout: Optional[float] = None):
        if timeout is not None and self.delay > timeout:
            raise TimeoutError(f"Redis connectivity check timed out after {timeout}s")
        if self.delay > 0:
            time.sleep(self.delay)
        if self.should_fail:
            raise ConnectionError("Custom connection failure")
        return True


class MockNonTimeoutCapableRedisClient:
    """Simulates a custom Redis client without connection_pool whose ping() does not accept timeout."""
    def __init__(self):
        self.connection_pool = None

    def ping(self):
        return True


class MockVerifyConnectionCapableRedisClient:
    """Simulates a custom Redis client implementing its own bounded verify_connection method."""
    def __init__(self, succeeds: bool = True):
        self.connection_pool = None
        self.succeeds = succeeds

    def verify_connection(self, timeout: float = 1.0) -> bool:
        if not self.succeeds:
            raise TimeoutError(f"Custom verify_connection timed out after {timeout}s")
        return True


def test_verify_connection_without_connection_pool_fast_success():
    """verify_connection succeeds quickly for a client without a connection pool."""
    client = MockTimeoutCapableRedisClient(delay=0.0)
    limiter = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    assert limiter.verify_connection(timeout=0.5) is True


def test_verify_connection_without_connection_pool_times_out():
    """verify_connection respects timeout bound even when client has no connection pool."""
    # Client blocks for 1.0s, but timeout is 0.05s
    client = MockTimeoutCapableRedisClient(delay=1.0)

    # 1. FAIL_CLOSED: raises RedisUnavailableError mentioning timeout
    limiter_closed = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    with pytest.raises(RedisUnavailableError) as exc_info:
        limiter_closed.verify_connection(timeout=0.05)
    assert "timed out after 0.05s" in str(exc_info.value)

    # 2. FAIL_OPEN: returns False
    limiter_open = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_OPEN
    )
    assert limiter_open.verify_connection(timeout=0.05) is False

    # 3. LOCAL_FALLBACK: returns False
    limiter_fallback = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.LOCAL_FALLBACK
    )
    assert limiter_fallback.verify_connection(timeout=0.05) is False


def test_verify_connection_without_connection_pool_error_propagation():
    """verify_connection sanitizes and propagates errors from client without connection pool."""
    client = MockTimeoutCapableRedisClient(delay=0.0, should_fail=True)
    limiter = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    with pytest.raises(RedisUnavailableError) as exc_info:
        limiter.verify_connection(timeout=0.5)
    assert "Custom connection failure" in str(exc_info.value)


def test_verify_connection_without_connection_pool_repeated_timeouts_no_thread_accumulation():
    """Repeated timed-out verify_connection calls without connection pool do not accumulate threads."""
    client = MockTimeoutCapableRedisClient(delay=1.0)
    limiter = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_CLOSED
    )

    initial_threads = threading.active_count()

    for _ in range(25):
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.verify_connection(timeout=0.01)
        assert "timed out after 0.01s" in str(exc_info.value)

    # Strictly assert that zero threads leaked or accumulated
    assert threading.active_count() <= initial_threads


def test_verify_connection_without_connection_pool_fails_clearly_when_not_timeout_capable():
    """verify_connection fails clearly when custom client lacks connection_pool and timeout-capable ping."""
    client = MockNonTimeoutCapableRedisClient()

    # 1. FAIL_CLOSED: raises RedisUnavailableError detailing the capability requirement
    limiter_closed = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    with pytest.raises(RedisUnavailableError) as exc_info:
        limiter_closed.verify_connection(timeout=0.5)
    assert "Bounded Redis connectivity check cannot be guaranteed" in str(exc_info.value)

    # 2. FAIL_OPEN: returns False without raising
    limiter_open = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.FAIL_OPEN
    )
    assert limiter_open.verify_connection(timeout=0.5) is False

    # 3. LOCAL_FALLBACK: returns False without raising
    limiter_fallback = RateLimiter(
        redis_client=client,
        failure_mode=FailureMode.LOCAL_FALLBACK
    )
    assert limiter_fallback.verify_connection(timeout=0.5) is False

    # Verify no threads accumulated across repeated calls
    initial_threads = threading.active_count()
    for _ in range(15):
        assert limiter_fallback.verify_connection(timeout=0.5) is False
    assert threading.active_count() <= initial_threads


def test_verify_connection_custom_client_verify_connection_interface():
    """verify_connection supports custom clients providing their own verify_connection method."""
    client_ok = MockVerifyConnectionCapableRedisClient(succeeds=True)
    limiter_ok = RateLimiter(redis_client=client_ok, failure_mode=FailureMode.FAIL_CLOSED)
    assert limiter_ok.verify_connection(timeout=0.5) is True

    client_fail = MockVerifyConnectionCapableRedisClient(succeeds=False)
    limiter_fail = RateLimiter(redis_client=client_fail, failure_mode=FailureMode.FAIL_CLOSED)
    with pytest.raises(RedisUnavailableError) as exc_info:
        limiter_fail.verify_connection(timeout=0.05)
    assert "timed out after 0.05s" in str(exc_info.value)
