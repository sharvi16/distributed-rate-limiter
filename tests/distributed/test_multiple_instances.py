"""
Distributed Cluster Simulation Tests (Phase 7).

Simulates multiple independent FastAPI application workers / instances sharing
a common Redis cluster, verifying:
  1. Distributed quota sharing: Requests hitting instances A, B, and C decrement a unified bucket.
  2. Instant cluster-wide penalties: Jailing a user or device on Instance 1 immediately blocks Instance 2.
  3. Distributed verification pass: Solving a challenge on Instance 1 unlocks requests on Instance 2.
  4. Distributed model updates: Feedback trained on Instance 1 propagates across the entire cluster.
"""

import time
import uuid
import pytest
import redis

from rate_limiter import RateLimiter, FailureMode
from spam_detector import AdaptiveSpamDetector


@pytest.fixture
def redis_client():
    try:
        client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=1.0)
        client.ping()
        yield client
    except Exception:
        pytest.skip("Redis is not available on localhost:6379")


def test_distributed_quota_sharing_across_workers(redis_client):
    """Three workers share a capacity of 10 tokens. Total allowed requests across all workers must be exactly 10."""
    worker_a = RateLimiter(redis_client=redis_client, capacity=10, refill_rate=0.01)
    worker_b = RateLimiter(redis_client=redis_client, capacity=10, refill_rate=0.01)
    worker_c = RateLimiter(redis_client=redis_client, capacity=10, refill_rate=0.01)

    user_id = f"dist_user_{uuid.uuid4().hex[:8]}"
    worker_a.reset(user_id)

    # 4 requests to Worker A
    for _ in range(4):
        assert worker_a.is_allowed(user_id) is True

    # 3 requests to Worker B
    for _ in range(3):
        assert worker_b.is_allowed(user_id) is True

    # 3 requests to Worker C (total 10 reached)
    for _ in range(3):
        assert worker_c.is_allowed(user_id) is True

    # 11th request to any worker must be rejected
    assert worker_a.is_allowed(user_id) is False
    assert worker_b.is_allowed(user_id) is False
    assert worker_c.is_allowed(user_id) is False


def test_cluster_wide_penalty_box_propagation(redis_client):
    """Jailing a user or device on Worker 1 must immediately be enforced by Worker 2."""
    detector_1 = AdaptiveSpamDetector(redis_client=redis_client)
    detector_2 = AdaptiveSpamDetector(redis_client=redis_client)

    user_id = f"jailed_dist_{uuid.uuid4().hex[:8]}"
    redis_client.delete(f"strikes:{user_id}")

    # Worker 1 jails the user
    detector_1.jail_user(user_id, duration_seconds=60)

    # Worker 2 must immediately see user in penalty box
    is_jailed, remaining = detector_2.is_in_penalty_box(user_id)
    assert is_jailed is True
    assert 50 <= remaining <= 60


def test_cluster_wide_verified_human_pass(redis_client):
    """Solving a challenge on Worker 1 grants cluster-wide verified human status."""
    detector_1 = AdaptiveSpamDetector(redis_client=redis_client)
    detector_2 = AdaptiveSpamDetector(redis_client=redis_client)

    user_id = f"human_dist_{uuid.uuid4().hex[:8]}"
    features = {"request_interval": 0.2, "interval_std": 0.05, "burst_count": 4}

    # Worker 1 creates a challenge
    challenge = detector_1.generate_challenge(user_id, features)
    ch_id = challenge["challenge_id"]

    # Solve challenge using true answer stored in Redis
    raw_answer = redis_client.hget(f"challenge:{ch_id}", "expected_answer")
    assert raw_answer is not None

    # Worker 2 receives the verification answer
    success, _ = detector_2.verify_challenge(ch_id, raw_answer, expected_user_id=user_id)
    assert success is True

    # Worker 1 must immediately recognize verified pass
    assert detector_1.is_verified_human(user_id) is True
    # Worker 2 must also recognize verified pass
    assert detector_2.is_verified_human(user_id) is True


def test_cluster_wide_model_update_propagation(redis_client):
    """Worker 1 updates Gaussian centroids in Redis; Worker 2 syncs the new centroids."""
    detector_1 = AdaptiveSpamDetector(redis_client=redis_client)
    detector_2 = AdaptiveSpamDetector(redis_client=redis_client)

    features = {"request_interval": 0.05, "interval_std": 0.01, "burst_count": 8}
    initial_version = detector_2.model_version

    # Worker 1 updates the model with spam telemetry
    detector_1.update_model(features, label="spammer")

    # Force Worker 2 sync cache invalidation
    detector_2._last_model_sync = 0.0
    detector_2.sync_model_from_redis()

    assert detector_2.model_version > initial_version
    assert detector_2.model_state["spammer"]["mean"] == detector_1.model_state["spammer"]["mean"]
