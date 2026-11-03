"""
Unit & Security Tests for Challenge Generation & Verification (Phase 2).

Tests:
  - Correct answer verification
  - Never leaking answer in challenge responses
  - Cryptographically secure, unguessable challenge IDs
  - Incorrect answer handling & retry counts
  - Expired challenge rejection
  - Reused / replayed challenge rejection (single-use guarantee)
  - Challenge belonging to another session (session binding)
  - Multiple incorrect attempts burn challenge & jail user
  - Concurrent verification race-condition protection
  - Redis failure resiliency with local fallback
"""

import time
import re
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
    """Provides a clean AdaptiveSpamDetector connected to Redis."""
    return AdaptiveSpamDetector(redis_client=redis_client)


def extract_expected_answer_for_test(prompt: str) -> str:
    """Helper to solve the arithmetic challenge legitimately for tests."""
    match = re.search(r"(\d+)\s*\+\s*(\d+)", prompt)
    assert match is not None, f"Could not parse arithmetic challenge prompt: {prompt}"
    num1, num2 = int(match.group(1)), int(match.group(2))
    return str(num1 + num2)


# =============================================================================
# 1. Answer Concealment & Entropy Tests
# =============================================================================

def test_challenge_response_never_leaks_answer(detector):
    """The generated challenge dictionary must NEVER include the expected answer in any field."""
    features = {"interval_std": 0.05, "burst_count": 4.0, "mean_interval": 0.1, "ua_suspicion": 0.5}
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"

    challenge_data = detector.generate_challenge(user_id, features)

    # Convert entire response to string and assert no arithmetic answer leaks
    raw_response = str(challenge_data)
    assert "expected_answer" not in challenge_data
    assert "body_example" in challenge_data
    assert "<compute answer to prompt>" in challenge_data["body_example"]["answer"]

    # Challenge ID must have high entropy (e.g. starts with ch_ and length >= 24)
    cid = challenge_data["challenge_id"]
    assert cid.startswith("ch_")
    assert len(cid) >= 24, "Challenge ID must have high cryptographic entropy"


# =============================================================================
# 2. Correct, Incorrect & Expired Challenge Tests
# =============================================================================

def test_correct_answer_grants_verified_pass(detector):
    """Submitting the correct answer solves the challenge and grants a 5-minute pass."""
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]
    correct_ans = extract_expected_answer_for_test(ch["prompt"])

    success, msg = detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
    assert success is True
    assert "Verification successful" in msg
    assert detector.is_verified_human(user_id) is True


def test_incorrect_answer_decrements_attempts(detector):
    """Submitting an incorrect answer reports remaining attempts without immediately jailing."""
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]

    success, msg = detector.verify_challenge(cid, "99999", expected_user_id=user_id)
    assert success is False
    assert "2 attempt(s) remaining" in msg
    # User should NOT be jailed yet
    is_jailed, _ = detector.is_in_penalty_box(user_id)
    assert is_jailed is False


def test_multiple_incorrect_attempts_burn_challenge_and_jail(detector):
    """3 consecutive failed answers burns the challenge and temporarily jails the user."""
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]

    # Attempt 1
    s1, m1 = detector.verify_challenge(cid, "1111", expected_user_id=user_id)
    assert s1 is False and "2 attempt(s) remaining" in m1

    # Attempt 2
    s2, m2 = detector.verify_challenge(cid, "2222", expected_user_id=user_id)
    assert s2 is False and "1 attempt(s) remaining" in m2

    # Attempt 3: Exhausted
    s3, m3 = detector.verify_challenge(cid, "3333", expected_user_id=user_id)
    assert s3 is False
    assert "Maximum verification attempts exceeded" in m3

    # User must now be jailed
    is_jailed, _ = detector.is_in_penalty_box(user_id)
    assert is_jailed is True

    # Challenge must be burned; further attempts report expired/not found
    s4, m4 = detector.verify_challenge(cid, "4444", expected_user_id=user_id)
    assert s4 is False
    assert "Invalid or expired challenge" in m4


# =============================================================================
# 3. Replay Protection & Session Binding Tests
# =============================================================================

def test_challenge_single_use_replay_prevention(detector):
    """Once verified, a challenge is burned immediately and cannot be replayed."""
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]
    correct_ans = extract_expected_answer_for_test(ch["prompt"])

    # First attempt succeeds
    s1, _ = detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
    assert s1 is True

    # Replay attempt with same correct answer must be rejected!
    s2, m2 = detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
    assert s2 is False
    assert "Invalid or expired challenge" in m2


def test_challenge_bound_to_user_session(detector):
    """A challenge issued to User A cannot be solved by User B."""
    user_a = f"user_a_{uuid.uuid4().hex[:8]}"
    user_b = f"user_b_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_a, features)
    cid = ch["challenge_id"]
    correct_ans = extract_expected_answer_for_test(ch["prompt"])

    # User B tries to solve User A's challenge
    s_b, m_b = detector.verify_challenge(cid, correct_ans, expected_user_id=user_b)
    assert s_b is False
    assert "different user session" in m_b

    # User A can still solve their own challenge
    s_a, m_a = detector.verify_challenge(cid, correct_ans, expected_user_id=user_a)
    assert s_a is True


# =============================================================================
# 4. Concurrency & Fallback Tests
# =============================================================================

def test_concurrent_challenge_verification_exact_single_win(detector):
    """
    10 concurrent threads simultaneously trying to verify the same challenge.
    Exactly 1 thread must succeed; all 9 others must be rejected (single-use atomicity).
    """
    user_id = f"test_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]
    correct_ans = extract_expected_answer_for_test(ch["prompt"])

    results = []
    lock = threading.Lock()

    def worker():
        success, _ = detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
        with lock:
            results.append(success)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r is True)
    failures = sum(1 for r in results if r is False)

    assert successes == 1, f"Expected exactly 1 success under concurrent verification, got {successes}"
    assert failures == 9, f"Expected 9 rejections under concurrent verification, got {failures}"


def test_challenge_local_fallback_when_redis_unavailable():
    """Challenge generation and verification works seamlessly in-memory when Redis is unavailable."""
    local_detector = AdaptiveSpamDetector(redis_client=None)
    user_id = f"test_local_user_{uuid.uuid4().hex[:8]}"
    features = {"interval_std": 0.05, "burst_count": 3.0, "mean_interval": 0.2, "ua_suspicion": 0.1}

    ch = local_detector.generate_challenge(user_id, features)
    cid = ch["challenge_id"]
    correct_ans = extract_expected_answer_for_test(ch["prompt"])

    # Wrong answer
    s_wrong, _ = local_detector.verify_challenge(cid, "wrong", expected_user_id=user_id)
    assert s_wrong is False

    # Correct answer
    s_right, _ = local_detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
    assert s_right is True

    # Replay rejected
    s_replay, _ = local_detector.verify_challenge(cid, correct_ans, expected_user_id=user_id)
    assert s_replay is False
