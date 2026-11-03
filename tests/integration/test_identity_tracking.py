"""
Integration Tests for Atomic Behavioral Tracking (Phase 4).

Tests:
  - Atomic VPN hopping detection under rapid and concurrent IP rotations
  - Atomic Sybil attack detection (identity velocity) under concurrent account cycling
  - Atomic multi-target penalty box checking (user, IP, device)
  - Atomic jail escalation with strike multiplier
  - Atomic sliding window traffic history pruning
"""

import time
import threading
import uuid
import pytest
import redis

from spam_detector import AdaptiveSpamDetector


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
def detector(redis_client):
    """Provides a clean AdaptiveSpamDetector."""
    return AdaptiveSpamDetector(redis_client=redis_client)


# =============================================================================
# 1. VPN Hopping Detection & Concurrency
# =============================================================================

def test_vpn_hopping_detection_atomic(detector, redis_client):
    """
    Rotating through more than max_allowed_ips (2) within 60s flags as VPN hopping.
    """
    device_id = f"test_dev_{uuid.uuid4().hex[:10]}"
    redis_client.delete(f"dev_ips:{device_id}")

    # IP 1: allowed
    is_hop, count = detector.track_vpn_hopping(device_id, "185.220.101.1", max_allowed_ips=2)
    assert is_hop is False and count == 1

    # IP 2: allowed
    is_hop, count = detector.track_vpn_hopping(device_id, "104.244.72.2", max_allowed_ips=2)
    assert is_hop is False and count == 2

    # IP 3: exceeds max_allowed_ips (2) -> Flagged as VPN hopping!
    is_hop, count = detector.track_vpn_hopping(device_id, "45.33.32.3", max_allowed_ips=2)
    assert is_hop is True and count == 3

    redis_client.delete(f"dev_ips:{device_id}")


def test_vpn_hopping_concurrent_rotations(detector, redis_client):
    """
    10 concurrent threads reporting different IPs for the same device.
    Redis Lua script guarantees atomic updates without lost entries.
    """
    device_id = f"test_dev_concurrent_{uuid.uuid4().hex[:10]}"
    redis_client.delete(f"dev_ips:{device_id}")

    def worker(idx):
        ip = f"198.51.100.{idx}"
        detector.track_vpn_hopping(device_id, ip, max_allowed_ips=2)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 11)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Final count must be exactly 10 distinct IPs
    is_hop, count = detector.track_vpn_hopping(device_id, "198.51.100.1", max_allowed_ips=2)
    assert count == 10
    assert is_hop is True

    redis_client.delete(f"dev_ips:{device_id}")


# =============================================================================
# 2. Sybil Attack (Identity Velocity) Detection
# =============================================================================

def test_sybil_attack_detection_atomic(detector, redis_client):
    """
    Generating more than max_allowed_ids (3) distinct accounts from single IP flags Sybil attack.
    """
    client_ip = f"203.0.113.{uuid.uuid4().int % 250}"
    redis_client.delete(f"ip_identities:{client_ip}")

    # 3 distinct IDs allowed
    for i in range(1, 4):
        is_sybil, count = detector.track_identity_velocity(client_ip, f"user_{i}", max_allowed_ids=3)
        assert is_sybil is False
        assert count == i

    # 4th distinct ID from same IP -> Flagged!
    is_sybil, count = detector.track_identity_velocity(client_ip, "user_4", max_allowed_ids=3)
    assert is_sybil is True
    assert count == 4

    redis_client.delete(f"ip_identities:{client_ip}")


# =============================================================================
# 3. Multi-Target Penalty Box & Escalation
# =============================================================================

def test_multi_target_penalty_box_atomic(detector, redis_client):
    """
    is_in_penalty_box atomically checks user_id, client_ip, and device_id.
    If ANY of them is jailed, access is blocked.
    """
    u = f"test_u_{uuid.uuid4().hex[:6]}"
    ip = f"198.51.100.{uuid.uuid4().int % 250}"
    dev = f"dev_{uuid.uuid4().hex[:6]}"

    # Initially clean
    is_jailed, _ = detector.is_in_penalty_box(u, client_ip=ip, device_id=dev)
    assert is_jailed is False

    # Jail only the IP
    detector.jail_user(f"ip:{ip}", duration_seconds=30)
    is_jailed, ttl = detector.is_in_penalty_box(u, client_ip=ip, device_id=dev)
    assert is_jailed is True
    assert ttl > 0

    # Clean up
    redis_client.delete(f"penalty_box:ip:{ip}")


def test_jail_escalation_with_strikes(detector, redis_client):
    """
    Repeat offenders receive escalating penalty durations (1x -> 2x -> 3x).
    """
    u = f"repeat_offender_{uuid.uuid4().hex[:6]}"
    redis_client.delete(f"strikes:{u}")
    redis_client.delete(f"penalty_box:{u}")

    # Strike 1: 10s * 1 = 10s
    detector.jail_user(u, duration_seconds=10)
    assert detector.get_strikes(u) == 1
    ttl_1 = redis_client.ttl(f"penalty_box:{u}")
    assert 7 <= ttl_1 <= 10

    # Strike 2: 10s * 2 = 20s
    detector.jail_user(u, duration_seconds=10)
    assert detector.get_strikes(u) == 2
    ttl_2 = redis_client.ttl(f"penalty_box:{u}")
    assert 16 <= ttl_2 <= 20

    # Strike 3: 10s * 3 = 30s
    detector.jail_user(u, duration_seconds=10)
    assert detector.get_strikes(u) == 3
    ttl_3 = redis_client.ttl(f"penalty_box:{u}")
    assert 25 <= ttl_3 <= 30

    redis_client.delete(f"strikes:{u}")
    redis_client.delete(f"penalty_box:{u}")
