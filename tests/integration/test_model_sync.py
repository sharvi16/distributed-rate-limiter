"""
Integration Tests for Distributed State Management & Model Synchronization (Phase 3).

Tests:
  - Model centroid persistence across server/detector restarts
  - Real-time cross-instance centroid synchronization
  - Concurrency safety during simultaneous online model training
  - Graceful fallback when Redis is unreachable
"""

import time
import threading
import pytest
import redis

from spam_detector import AdaptiveSpamDetector


@pytest.fixture
def redis_client():
    """Provides a clean Redis client for test isolation."""
    try:
        client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=1.0)
        client.ping()
        # Clean test key
        client.delete("model_state:centroids")
        yield client
        client.delete("model_state:centroids")
    except Exception:
        pytest.skip("Redis is not available on localhost:6379")


# =============================================================================
# 1. Persistence Across Restarts
# =============================================================================

def test_model_state_persists_across_instance_restart(redis_client):
    """
    When an instance updates Gaussian centroids and restarts/terminates,
    the newly booted instance loads the latest learned state from Redis.
    """
    # 1. Instance 1 boots and learns from a verified human challenge
    instance_1 = AdaptiveSpamDetector(redis_client=redis_client)
    initial_updates = instance_1.model_state["total_updates"]

    features = {"interval_std": 1.95, "burst_count": 1.0, "mean_interval": 2.8}
    instance_1.update_model(features, label="human")

    updated_updates = instance_1.model_state["total_updates"]
    assert updated_updates == initial_updates + 1
    learned_mean = instance_1.model_state["human"]["mean"]

    # 2. Simulate server restart: terminate instance 1, spin up instance 2
    del instance_1
    instance_2 = AdaptiveSpamDetector(redis_client=redis_client)

    # 3. Instance 2 must load the learned state from Redis
    assert instance_2.model_state["total_updates"] == updated_updates
    assert instance_2.model_state["human"]["mean"] == learned_mean
    assert instance_2.model_version > 1


# =============================================================================
# 2. Cross-Instance Synchronization
# =============================================================================

def test_cross_instance_model_synchronization(redis_client):
    """
    When Worker A updates the learned model, Worker B synchronizes
    the updated centroids and version without restarting.
    """
    worker_a = AdaptiveSpamDetector(redis_client=redis_client)
    worker_b = AdaptiveSpamDetector(redis_client=redis_client)

    # Worker A processes spam pattern
    spam_features = {"interval_std": 0.01, "burst_count": 8.0, "mean_interval": 0.05}
    worker_a.update_model(spam_features, label="spammer")

    assert worker_a.model_state["total_updates"] == 1

    # Worker B syncs from Redis
    worker_b.sync_model_from_redis(force=True)

    assert worker_b.model_state["total_updates"] == 1
    assert worker_b.model_state["spammer"]["mean"] == worker_a.model_state["spammer"]["mean"]
    assert worker_b.model_version == worker_a.model_version


# =============================================================================
# 3. Concurrent Model Training Atomicity
# =============================================================================

def test_concurrent_model_updates_no_lost_updates(redis_client):
    """
    10 concurrent threads on multiple workers updating centroids simultaneously.
    Redis Lua script guarantees atomic EMA calculation and exact total_updates count.
    """
    worker = AdaptiveSpamDetector(redis_client=redis_client)
    num_updates = 10

    def update_worker(i):
        features = {
            "interval_std": 1.5 + (i * 0.05),
            "burst_count": 2.0,
            "mean_interval": 1.8 + (i * 0.02)
        }
        label = "human" if i % 2 == 0 else "spammer"
        worker.update_model(features, label=label)

    threads = [threading.Thread(target=update_worker, args=(i,)) for i in range(num_updates)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Re-sync from Redis to verify total updates
    worker.sync_model_from_redis(force=True)
    assert worker.model_state["total_updates"] == num_updates
    assert worker.model_version == num_updates + 1


# =============================================================================
# 4. Fallback Behavior When Redis Unavailable
# =============================================================================

def test_model_fallback_when_redis_unavailable():
    """When Redis is not available, model updates run cleanly in local memory."""
    local_detector = AdaptiveSpamDetector(redis_client=None)
    assert local_detector.model_state["total_updates"] == 0

    features = {"interval_std": 1.8, "burst_count": 1.0, "mean_interval": 2.2}
    local_detector.update_model(features, label="human")

    assert local_detector.model_state["total_updates"] == 1
    assert local_detector.model_version == 2
