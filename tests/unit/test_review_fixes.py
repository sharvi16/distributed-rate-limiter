"""
Unit and regression tests verifying all 10 fixes for the code review follow-up.
"""

import time
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
# Issue 6: rate_limiter.py — Type guard on Redis Lua script result in check_limit
# =============================================================================

def test_check_limit_handles_unexpected_lua_result():
    """check_limit routes unexpected result types from Lua (None, empty list, etc.) to failure handler."""
    limiter = RateLimiter(
        capacity=10,
        refill_rate=1.0,
        failure_mode=FailureMode.LOCAL_FALLBACK
    )
    mock_redis = MagicMock()
    limiter.redis = mock_redis

    # Case A: Lua script returns None
    limiter.check_limit_script = MagicMock(return_value=None)
    result = limiter.check_limit("user_test_none")
    assert result.allowed is True  # handled via local fallback

    # Case B: Lua script returns empty list []
    limiter.check_limit_script = MagicMock(return_value=[])
    result = limiter.check_limit("user_test_empty")
    assert result.allowed is True

    # Case C: Under FAIL_CLOSED, unexpected return routes to RedisUnavailableError
    limiter_closed = RateLimiter(
        capacity=10,
        refill_rate=1.0,
        failure_mode=FailureMode.FAIL_CLOSED
    )
    limiter_closed.redis = mock_redis
    limiter_closed.check_limit_script = MagicMock(return_value=None)
    with pytest.raises(RedisUnavailableError):
        limiter_closed.check_limit("user_test_closed")


# =============================================================================
# Issue 7: spam_detector.py — active_jailed_users in get_diagnostics()
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


def test_get_diagnostics_active_jailed_users_redis_aggregation():
    """get_diagnostics() aggregates Redis SCAN keys with local state."""
    mock_redis = MagicMock()
    mock_redis.scan_iter.return_value = ["penalty_box:u1", "penalty_box:u2", "penalty_box:u3"]

    det = AdaptiveSpamDetector(redis_client=mock_redis)
    with det._lock:
        det._local_penalty_box["local_u1"] = time.time() + 60

    diag = det.get_diagnostics()
    assert diag["active_jailed_users"] == 4  # 3 from Redis + 1 local
    assert "active_jailed_users_note" in diag
    assert "Redis cluster" in diag["active_jailed_users_note"]


# =============================================================================
# Issue 8: main.py — Metrics increment on successful challenge verification
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
    # pipeline() should not have been called for centroid seeding
    mock_redis.pipeline.assert_not_called()
    # direct hset() must have been called
    mock_redis.hset.assert_called_once()
    assert mock_redis.hset.call_args[0][0] == "model_state:centroids"

