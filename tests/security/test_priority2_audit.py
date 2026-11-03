"""
Priority 2 Audit Regression Tests: Correctness, Configuration & Telemetry Semantics.

Covers:
  1. Numeric Invariants & Type Safety (Rejection of NaN, Infinity, Booleans, None, strings, and non-positive numbers).
  2. Server-Controlled Cost & Oversized Request Protection (Removal of client token parameter, strictly 1 token per request, 400 Bad Request on oversized requests).
  3. Environment Configuration & Lifecycle Sync (Syncing startup configuration into instantiated limiters, rejecting malformed env values).
  4. Monotonic Clock Recovery Semantics (Redis Lua script and Local Fallback monotonic effective timestamps, preventing artificial refill after backward jumps).
  5. RateLimitResult Telemetry & RFC/IETF HTTP Rate-Limit Headers (Float capacity preservation, burst capacity vs sustained refill rate distinction, 200 and 429 header parity).
"""

import math
import os
import time
import uuid
from typing import Optional, Dict, Tuple
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, ip_limiter, detector, sync_rate_limiter_configuration
from rate_limiter import (
    RateLimiter,
    FailureMode,
    RateLimitResult,
    validate_positive_number,
    validate_positive_int,
    validate_tokens_requested,
    parse_env_positive_float,
    validate_rate_limiter_configuration
)


@pytest.fixture(autouse=True)
def clean_testclient_ip():
    if detector.redis:
        detector.redis.delete("ip_identities:testclient")
        detector.redis.delete("penalty_box:ip:testclient")
        detector.redis.delete("rate_limit:ip:testclient")
        detector.redis.delete("rate_limit:ip:127.0.0.1")
        detector.redis.delete("penalty_box:ip:127.0.0.1")
        try:
            for k in detector.redis.scan_iter("penalty_box:dev:*"):
                detector.redis.delete(k)
        except Exception:
            pass
    with detector._lock:
        if hasattr(detector, "_local_ip_identities"):
            detector._local_ip_identities.pop("testclient", None)
            detector._local_ip_identities.pop("127.0.0.1", None)
        if hasattr(detector, "_local_penalty_box"):
            detector._local_penalty_box.clear()
    main.ip_limiter.reset("ip:testclient")
    main.ip_limiter.reset("ip:127.0.0.1")


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. Numeric Invariants & Type Safety Tests (Priority 2, Item 5)
# =============================================================================

class TestNumericInvariantsAndTypeSafety:
    """Tests rejecting NaN, infinity, booleans, and invalid numeric values."""

    def test_rate_limiter_rejects_nan_capacity_and_refill_rate(self):
        """RateLimiter initialization must reject NaN for capacity and refill_rate."""
        with pytest.raises(ValueError, match="capacity cannot be NaN"):
            RateLimiter(capacity=float("nan"), refill_rate=1.0)

        with pytest.raises(ValueError, match="refill_rate cannot be NaN"):
            RateLimiter(capacity=10.0, refill_rate=float("nan"))

    def test_rate_limiter_rejects_infinity_capacity_and_refill_rate(self):
        """RateLimiter initialization must reject +/- infinity for capacity and refill_rate."""
        with pytest.raises(ValueError, match="capacity cannot be infinity"):
            RateLimiter(capacity=float("inf"), refill_rate=1.0)

        with pytest.raises(ValueError, match="capacity cannot be infinity"):
            RateLimiter(capacity=-float("inf"), refill_rate=1.0)

        with pytest.raises(ValueError, match="refill_rate cannot be infinity"):
            RateLimiter(capacity=10.0, refill_rate=float("inf"))

        with pytest.raises(ValueError, match="refill_rate cannot be infinity"):
            RateLimiter(capacity=10.0, refill_rate=-float("inf"))

    def test_rate_limiter_rejects_booleans_for_numeric_arguments(self):
        """RateLimiter must reject bools for capacity, refill_rate, and max_local_keys."""
        with pytest.raises(ValueError, match="capacity cannot be a boolean"):
            RateLimiter(capacity=True, refill_rate=1.0)

        with pytest.raises(ValueError, match="capacity cannot be a boolean"):
            RateLimiter(capacity=False, refill_rate=1.0)

        with pytest.raises(ValueError, match="refill_rate cannot be a boolean"):
            RateLimiter(capacity=10.0, refill_rate=True)

        with pytest.raises(ValueError, match="max_local_keys cannot be a boolean"):
            RateLimiter(capacity=10.0, refill_rate=1.0, max_local_keys=True)

    def test_rate_limiter_rejects_non_numeric_and_none_arguments(self):
        """RateLimiter must reject strings, None, and complex types for numeric parameters."""
        with pytest.raises(ValueError, match="capacity must be a number"):
            RateLimiter(capacity="10", refill_rate=1.0)  # type: ignore

        with pytest.raises(ValueError, match="capacity must be a number"):
            RateLimiter(capacity=None, refill_rate=1.0)  # type: ignore

        with pytest.raises(ValueError, match="refill_rate must be a number"):
            RateLimiter(capacity=10.0, refill_rate="0.5")  # type: ignore

        with pytest.raises(ValueError, match="max_local_keys must be an integer"):
            RateLimiter(capacity=10.0, refill_rate=1.0, max_local_keys="1000")  # type: ignore

        with pytest.raises(ValueError, match="max_local_keys must be an integer"):
            RateLimiter(capacity=10.0, refill_rate=1.0, max_local_keys=100.5)  # type: ignore

    def test_rate_limiter_rejects_non_positive_numbers(self):
        """RateLimiter must reject zero or negative values for capacity and refill_rate."""
        with pytest.raises(ValueError, match="capacity must be a positive number"):
            RateLimiter(capacity=0, refill_rate=1.0)

        with pytest.raises(ValueError, match="capacity must be a positive number"):
            RateLimiter(capacity=-10.0, refill_rate=1.0)

        with pytest.raises(ValueError, match="refill_rate must be a positive number"):
            RateLimiter(capacity=10.0, refill_rate=0.0)

        with pytest.raises(ValueError, match="refill_rate must be a positive number"):
            RateLimiter(capacity=10.0, refill_rate=-0.5)

        with pytest.raises(ValueError, match="max_local_keys must be positive"):
            RateLimiter(capacity=10.0, refill_rate=1.0, max_local_keys=0)

        with pytest.raises(ValueError, match="max_local_keys must be positive"):
            RateLimiter(capacity=10.0, refill_rate=1.0, max_local_keys=-5)

    def test_check_limit_rejects_nan_inf_booleans_tokens(self):
        """check_limit and is_allowed must reject NaN, infinity, booleans, and non-positive tokens."""
        rl = RateLimiter(capacity=10.0, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)

        # Booleans
        with pytest.raises(ValueError, match="tokens requested cannot be a boolean"):
            rl.check_limit("user1", tokens=True)  # type: ignore

        with pytest.raises(ValueError, match="tokens requested cannot be a boolean"):
            rl.is_allowed("user1", tokens=False)  # type: ignore

        # NaN
        with pytest.raises(ValueError, match="tokens requested cannot be NaN"):
            rl.check_limit("user1", tokens=float("nan"))

        # Infinity
        with pytest.raises(ValueError, match="tokens requested cannot be infinity"):
            rl.check_limit("user1", tokens=float("inf"))

        with pytest.raises(ValueError, match="tokens requested cannot be infinity"):
            rl.check_limit("user1", tokens=-float("inf"))

        # Non-numeric
        with pytest.raises(ValueError, match="tokens requested must be a number"):
            rl.check_limit("user1", tokens="5")  # type: ignore

        with pytest.raises(ValueError, match="tokens requested must be a number"):
            rl.check_limit("user1", tokens=None)  # type: ignore

        # Zero or negative
        with pytest.raises(ValueError, match="tokens requested must be greater than zero"):
            rl.check_limit("user1", tokens=0)

        with pytest.raises(ValueError, match="tokens requested must be greater than zero"):
            rl.check_limit("user1", tokens=-2)

    def test_spam_detector_numeric_validation(self):
        """Spam detector methods must validate duration, strikes, and window parameters."""
        with pytest.raises(ValueError, match="duration_seconds cannot be a boolean"):
            detector.jail_user("user1", duration_seconds=True)  # type: ignore

        with pytest.raises(ValueError, match="duration_seconds cannot be NaN"):
            detector.jail_user("user1", duration_seconds=float("nan"))

        with pytest.raises(ValueError, match="duration_seconds cannot be infinity"):
            detector.jail_user("user1", duration_seconds=float("inf"))

        with pytest.raises(ValueError, match="duration_seconds must be a positive number"):
            detector.jail_user("user1", duration_seconds=-10)

        with pytest.raises(ValueError, match="duration_seconds cannot be a boolean"):
            detector.set_verified_human("user1", duration_seconds=True)  # type: ignore

        with pytest.raises(ValueError, match="duration_seconds cannot be NaN"):
            detector.set_verified_human("user1", duration_seconds=float("nan"))

        with pytest.raises(ValueError, match="count must be a non-negative integer"):
            detector.set_strikes("user1", count=True)  # type: ignore

        with pytest.raises(ValueError, match="count must be a non-negative integer"):
            detector.set_strikes("user1", count=-1)

        with pytest.raises(ValueError, match="max_allowed_ips cannot be a boolean"):
            detector.track_vpn_hopping("dev1", "1.2.3.4", max_allowed_ips=True)  # type: ignore

        with pytest.raises(ValueError, match="window_seconds cannot be NaN"):
            detector.track_vpn_hopping("dev1", "1.2.3.4", window_seconds=float("nan"))


# =============================================================================
# 2. Server-Controlled Cost & Oversized Request Protection (Priority 2, Items 1 & 3)
# =============================================================================

class TestServerControlledCostAndOversizedRequests:
    """Tests that token costs are strictly server-controlled and oversized requests are rejected."""

    def test_query_parameters_cannot_reduce_token_cost(self, client):
        """Clients passing ?tokens=0.01 cannot reduce cost; request consumes exactly 1 full token."""
        uid = f"cost_test_{uuid.uuid4().hex[:8]}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(uid)
        detector.set_verified_human(uid, duration_seconds=300)

        # Initial request supplying query param tokens=0.01
        res = client.get("/limited-resource?tokens=0.01", headers={"user-id": uid, "user-agent": ua})
        assert res.status_code == 200
        # Started with 10 tokens; strictly 1 token was consumed -> 9 remaining (NOT 9.99)
        assert res.headers["x-ratelimit-remaining"] == "9"
        assert res.headers["ratelimit-remaining"] == "9"

    def test_arbitrary_query_parameters_do_not_bypass_token_consumption(self, client):
        """Query parameters like ?tokens=0 or ?cost=0 do not bypass consumption; exactly 1 token is consumed."""
        uid = f"cost_bypass_{uuid.uuid4().hex[:8]}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(uid)
        detector.set_verified_human(uid, duration_seconds=300)

        res1 = client.get("/limited-resource?tokens=0", headers={"user-id": uid, "user-agent": ua})
        assert res1.status_code == 200
        assert res1.headers["x-ratelimit-remaining"] == "9"

        res2 = client.get("/limited-resource?cost=0", headers={"user-id": uid, "user-agent": ua})
        assert res2.status_code == 200
        assert res2.headers["x-ratelimit-remaining"] == "8"

    def test_ten_requests_with_fractional_tokens_exhausts_ten_token_bucket(self, client):
        """Ten requests with ?tokens=0.001 exhaust the entire 10-token bucket; 11th request receives 429."""
        uid = f"exhaust_cost_{uuid.uuid4().hex[:8]}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(uid)
        detector.set_verified_human(uid, duration_seconds=300)

        for i in range(10):
            res = client.get("/limited-resource?tokens=0.001", headers={"user-id": uid, "user-agent": ua})
            assert res.status_code == 200, f"Request {i+1} failed"

        # 11th request must be rate limited (429)
        res_blocked = client.get("/limited-resource?tokens=0.001", headers={"user-id": uid, "user-agent": ua})
        assert res_blocked.status_code == 429
        assert res_blocked.headers["x-ratelimit-remaining"] == "0"

    def test_check_limit_raises_value_error_when_tokens_exceed_capacity(self):
        """RateLimiter.check_limit must raise ValueError when tokens requested exceeds capacity."""
        rl = RateLimiter(capacity=10.0, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        with pytest.raises(ValueError, match="exceeds maximum bucket capacity"):
            rl.check_limit("user1", tokens=15.0)

    def test_is_allowed_returns_false_without_state_mutation_when_tokens_exceed_capacity(self):
        """RateLimiter.is_allowed must return False when tokens exceed capacity without mutating quota."""
        rl = RateLimiter(capacity=10.0, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        # Requesting 20 tokens on a 10-token capacity bucket returns False
        assert rl.is_allowed("user1", tokens=20) is False

        # Quota remains intact; 10 tokens request still succeeds
        assert rl.is_allowed("user1", tokens=10) is True

    def test_api_returns_400_not_429_when_request_exceeds_bucket_capacity(self, client):
        """
        When a request cost exceeds bucket capacity, API returns 400 Bad Request,
        NEVER 429 with a misleading Retry-After header.
        """
        uid = f"oversized_api_{uuid.uuid4().hex[:8]}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(uid)
        detector.set_verified_human(uid, duration_seconds=300)

        # Temporarily reconfigure limiter capacity to 0.5 (smaller than server request cost 1.0)
        original_cap = limiter.capacity
        try:
            limiter.configure(capacity=0.5)
            res = client.get("/limited-resource", headers={"user-id": uid, "user-agent": ua})
            assert res.status_code == 400
            assert "exceeds maximum bucket capacity" in res.json()["detail"]
            assert "Retry-After" not in res.headers
        finally:
            limiter.configure(capacity=original_cap)


# =============================================================================
# 3. Environment Variable Configuration & Lifecycle Sync (Priority 2, Items 5 & 6)
# =============================================================================

class TestEnvironmentConfiguration:
    """Tests reading rate limiter parameters from environment variables and startup synchronization."""

    def test_parse_env_positive_float_valid_values(self, monkeypatch):
        """parse_env_positive_float correctly parses positive numeric values."""
        monkeypatch.setenv("TEST_VAR", "42.5")
        assert parse_env_positive_float("TEST_VAR", default=10.0) == 42.5

        monkeypatch.setenv("TEST_VAR", "100")
        assert parse_env_positive_float("TEST_VAR", default=10.0) == 100.0

    def test_parse_env_positive_float_fallback_to_default(self, monkeypatch):
        """parse_env_positive_float falls back to default when variable is missing or empty."""
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert parse_env_positive_float("TEST_VAR", default=15.0) == 15.0

        monkeypatch.setenv("TEST_VAR", "   ")
        assert parse_env_positive_float("TEST_VAR", default=15.0) == 15.0

    def test_parse_env_positive_float_rejects_invalid_values(self, monkeypatch):
        """parse_env_positive_float raises ValueError on NaN, inf, <= 0, booleans, and non-numeric strings."""
        # NaN
        monkeypatch.setenv("TEST_VAR", "nan")
        with pytest.raises(ValueError, match="cannot be NaN"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        # Infinity
        monkeypatch.setenv("TEST_VAR", "inf")
        with pytest.raises(ValueError, match="cannot be infinity"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        # Zero or negative
        monkeypatch.setenv("TEST_VAR", "0")
        with pytest.raises(ValueError, match="must be a positive number"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        monkeypatch.setenv("TEST_VAR", "-10")
        with pytest.raises(ValueError, match="must be a positive number"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        # Booleans
        monkeypatch.setenv("TEST_VAR", "true")
        with pytest.raises(ValueError, match="cannot be a boolean"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        monkeypatch.setenv("TEST_VAR", "false")
        with pytest.raises(ValueError, match="cannot be a boolean"):
            parse_env_positive_float("TEST_VAR", default=10.0)

        # Arbitrary strings
        monkeypatch.setenv("TEST_VAR", "not_a_number")
        with pytest.raises(ValueError, match="must be a valid number"):
            parse_env_positive_float("TEST_VAR", default=10.0)

    def test_validate_rate_limiter_configuration_at_startup(self, monkeypatch):
        """validate_rate_limiter_configuration validates all 4 rate limiter environment variables."""
        monkeypatch.setenv("RATE_LIMITER_CAPACITY", "20")
        monkeypatch.setenv("RATE_LIMITER_REFILL_RATE", "0.5")
        monkeypatch.setenv("IP_RATE_LIMITER_CAPACITY", "60")
        monkeypatch.setenv("IP_RATE_LIMITER_REFILL_RATE", "1.0")

        validate_rate_limiter_configuration()

        monkeypatch.setenv("RATE_LIMITER_CAPACITY", "invalid_capacity")
        with pytest.raises(ValueError, match="RATE_LIMITER_CAPACITY must be a valid number"):
            validate_rate_limiter_configuration()

    def test_startup_configuration_synchronization(self, monkeypatch):
        """sync_rate_limiter_configuration dynamically synchronizes active limiters with validated env values."""
        orig_user_cap = limiter.capacity
        orig_ip_cap = ip_limiter.capacity

        try:
            monkeypatch.setenv("RATE_LIMITER_CAPACITY", "25.0")
            monkeypatch.setenv("RATE_LIMITER_REFILL_RATE", "0.5")
            monkeypatch.setenv("IP_RATE_LIMITER_CAPACITY", "50.0")
            monkeypatch.setenv("IP_RATE_LIMITER_REFILL_RATE", "2.0")

            sync_rate_limiter_configuration()

            assert limiter.capacity == 25.0
            assert limiter.refill_rate == 0.5
            assert ip_limiter.capacity == 50.0
            assert ip_limiter.refill_rate == 2.0
        finally:
            limiter.configure(capacity=orig_user_cap, refill_rate=10.0/60.0)
            ip_limiter.configure(capacity=orig_ip_cap, refill_rate=30.0/60.0)


class TestRateLimiterConfigurationTransactional:
    """Tests transactional integrity and thread safety of RateLimiter.configure()."""

    def test_configure_rejects_partial_mutation_on_invalid_arguments(self):
        """
        When configure() receives multiple parameters where one is valid and another invalid,
        it must raise ValueError without mutating ANY attributes (all-or-nothing transactional update).
        """
        rl = RateLimiter(
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED,
            max_local_keys=5000
        )

        # 1. Valid capacity (25.0) paired with invalid refill_rate (-2.0)
        with pytest.raises(ValueError, match="refill_rate must be a positive number"):
            rl.configure(capacity=25.0, refill_rate=-2.0)
        assert rl.capacity == 10.0
        assert rl.refill_rate == 1.0

        # 2. Valid capacity (30.0) paired with invalid failure_mode string
        with pytest.raises(ValueError, match="Invalid failure_mode"):
            rl.configure(capacity=30.0, failure_mode="not_a_mode")
        assert rl.capacity == 10.0
        assert rl.failure_mode == FailureMode.FAIL_CLOSED

        # 3. Invalid capacity (0) paired with valid max_local_keys (10000)
        with pytest.raises(ValueError, match="capacity must be a positive number"):
            rl.configure(capacity=0, max_local_keys=10000)
        assert rl.capacity == 10.0
        assert rl.max_local_keys == 5000

        # 4. Invalid failure_mode type paired with valid refill_rate
        with pytest.raises(ValueError, match="failure_mode must be FailureMode or str"):
            rl.configure(refill_rate=2.0, failure_mode=12345)  # type: ignore
        assert rl.refill_rate == 1.0

        # 5. Clean valid update succeeds completely
        rl.configure(capacity=20.0, refill_rate=2.0, failure_mode=FailureMode.LOCAL_FALLBACK, max_local_keys=2000)
        assert rl.capacity == 20.0
        assert rl.refill_rate == 2.0
        assert rl.failure_mode == FailureMode.LOCAL_FALLBACK
        assert rl.max_local_keys == 2000

    def test_configure_concurrent_updates_thread_safety(self):
        """
        Concurrent threads updating configuration and checking limits must not cause race conditions,
        corrupted/torn attributes, or deadlocks.

        Verifies:
        1. Thread termination is guaranteed and asserted with `assert not t.is_alive()`.
        2. Synchronization uses bounded iteration counters rather than arbitrary sleep alone.
        3. No torn state occurs between capacity, refill_rate, and failure_mode under concurrent mutation.
        """
        import threading

        rl = RateLimiter(
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.LOCAL_FALLBACK,
            max_local_keys=1000
        )
        rl.redis = None
        rl.check_limit_script = None

        config_a = (10.0, 1.0, FailureMode.FAIL_CLOSED, 1000)
        config_b = (50.0, 5.0, FailureMode.LOCAL_FALLBACK, 5000)

        errors = []
        stop_event = threading.Event()

        def updater(cfg):
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    rl.configure(capacity=cfg[0], refill_rate=cfg[1], failure_mode=cfg[2], max_local_keys=cfg[3])
                except Exception as e:
                    errors.append(e)

        def reader():
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    with rl._lock:
                        cap = rl.capacity
                        refill = rl.refill_rate
                        if cap == 10.0 and refill != 1.0:
                            errors.append(ValueError(f"Torn state detected: cap={cap}, refill={refill}"))
                        elif cap == 50.0 and refill != 5.0:
                            errors.append(ValueError(f"Torn state detected: cap={cap}, refill={refill}"))
                    try:
                        rl.check_limit("concurrent_user", tokens=1.0)
                    except Exception as e:
                        if "Redis is not connected" not in str(e):
                            errors.append(e)
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=updater, args=(config_a,), name="updater_a"),
            threading.Thread(target=updater, args=(config_b,), name="updater_b"),
            threading.Thread(target=reader, name="reader_1"),
            threading.Thread(target=reader, name="reader_2"),
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), f"Thread {t.name} did not terminate within timeout"

        stop_event.set()

        assert not errors, f"Concurrent configuration update errors: {errors}"

    def test_check_limit_uses_consistent_snapshot_during_concurrent_configure(self):
        """
        Under concurrent configure() calls, each check_limit() request must use
        one complete configuration version without torn capacity/refill_rate snapshots.

        Verifies:
        1. Workers execute deterministic iteration counts without depending exclusively on arbitrary sleep.
        2. Every worker and updater thread cleanly terminates (`assert not t.is_alive()`).
        3. Observed limits and reset_after values strictly adhere to unified configuration snapshots.
        """
        import threading

        rl = RateLimiter(
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.LOCAL_FALLBACK,
            max_local_keys=1000
        )
        rl.redis = None
        rl.check_limit_script = None

        config_1 = (10.0, 1.0)
        config_2 = (60.0, 2.0)

        errors = []
        stop_event = threading.Event()
        observed_limits = set()
        observed_lock = threading.Lock()

        def updater():
            toggle = False
            while not stop_event.is_set():
                cfg = config_2 if toggle else config_1
                toggle = not toggle
                try:
                    rl.configure(capacity=cfg[0], refill_rate=cfg[1])
                except Exception as e:
                    errors.append(e)

        def worker(worker_id):
            user = f"worker_{worker_id}"
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    res = rl.check_limit(user, tokens=1.0)
                    with observed_lock:
                        observed_limits.add(res.limit)
                    if res.limit not in (10.0, 60.0):
                        errors.append(ValueError(f"Invalid limit: {res.limit}"))
                    expected_refill = 1.0 if res.limit == 10.0 else 2.0
                    if res.remaining < res.limit and res.reset_after > 0:
                        calculated_refill = (res.limit - res.remaining) / res.reset_after
                        if not math.isclose(calculated_refill, expected_refill, rel_tol=1e-2):
                            errors.append(ValueError(
                                f"Torn snapshot detected: limit={res.limit}, remaining={res.remaining}, "
                                f"reset_after={res.reset_after}, expected_refill={expected_refill}, "
                                f"calculated_refill={calculated_refill}"
                            ))
                except Exception as e:
                    errors.append(e)

        worker_threads = [
            threading.Thread(target=worker, args=(i,), name=f"snapshot_worker_{i}")
            for i in range(4)
        ]
        updater_thread = threading.Thread(target=updater, name="snapshot_updater")

        threads = [updater_thread] + worker_threads

        for t in threads:
            t.start()

        # Wait for all workers to finish their deterministic 50 requests
        for t in worker_threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), f"Worker thread {t.name} did not terminate within timeout"

        # Signal updater to finish
        stop_event.set()
        updater_thread.join(timeout=5.0)
        assert not updater_thread.is_alive(), "Updater thread did not terminate within timeout"

        assert not errors, f"Snapshot consistency errors under concurrency: {errors}"
        assert len(observed_limits) >= 1, "Expected at least one configuration limit to be observed"

    def test_redis_arguments_and_telemetry_match_exact_snapshot_under_concurrency(self):
        """
        When check_limit() passes arguments to Redis Lua during concurrent configure(),
        the arguments passed to Redis and the returned RateLimitResult must belong to the exact same snapshot.

        Verifies:
        1. Thread-local association connects each Redis script invocation directly to its returned RateLimitResult.
        2. Redis capacity argument exactly equals result.limit.
        3. Refill rate passed to Redis and used in reset/retry calculations belongs to the same configuration version.
        4. Detects cross-configuration mismatches even when each individual parameter is valid in isolation
           (e.g., capacity=10.0 from config_1 combined with refill_rate=2.0 from config_2).
        5. Every worker thread terminates cleanly without deadlocks or unjoined threads.
        """
        if not limiter.redis or not limiter.check_limit_script:
            pytest.skip("Redis not available")

        import threading

        config_1 = (10.0, 1.0)
        config_2 = (60.0, 2.0)

        # Helper function to validate snapshot parity between Redis invocation and RateLimitResult
        def validate_snapshot_parity(
            redis_cap: float,
            redis_refill: float,
            result: RateLimitResult
        ) -> Optional[str]:
            # 1. Capacity parity: Redis capacity must exactly match RateLimitResult.limit
            if redis_cap != result.limit:
                return f"Redis capacity ({redis_cap}) != result.limit ({result.limit})"

            # 2. Unified version check: the pair (redis_cap, redis_refill) must belong
            # to a single coherent configuration version, rejecting cross-version contamination
            # even when each component is individually valid
            if (redis_cap, redis_refill) not in (config_1, config_2):
                return (
                    f"Torn Redis configuration tuple: ({redis_cap}, {redis_refill}) "
                    f"is a cross-version mixture of {config_1} and {config_2}"
                )

            # 3. Refill rate version coherence with result.limit
            expected_refill = 1.0 if result.limit == 10.0 else 2.0
            if not math.isclose(redis_refill, expected_refill, rel_tol=1e-3):
                return (
                    f"Refill rate mismatch: redis_refill={redis_refill} does not match "
                    f"expected_refill={expected_refill} for limit={result.limit}"
                )

            # 4. Telemetry formula coherence: reset_after = (limit - remaining) / refill_rate
            if result.remaining < result.limit and result.reset_after > 0:
                calculated_refill = (result.limit - result.remaining) / result.reset_after
                if not math.isclose(calculated_refill, redis_refill, rel_tol=1e-2):
                    return (
                        f"Refill rate mismatch in reset_after: calculated={calculated_refill}, "
                        f"redis_refill={redis_refill}, limit={result.limit}"
                    )

            # 5. Retry-after formula coherence when rejected
            if not result.allowed and result.retry_after is not None:
                expected_retry = max(1, math.ceil((1.0 - result.remaining) / redis_refill))
                if result.retry_after != expected_retry:
                    return (
                        f"Retry-after mismatch: expected={expected_retry}, got={result.retry_after}"
                    )

            return None

        # Unit verification: prove that validate_snapshot_parity detects cross-configuration
        # mismatches even when each individual value belongs to a valid configuration
        # Case A: Torn Redis arguments (cap=10.0 from config_1, refill=2.0 from config_2)
        dummy_res_a = RateLimitResult(allowed=True, limit=10.0, remaining=9.0, reset_after=1.0, retry_after=None)
        err_a = validate_snapshot_parity(10.0, 2.0, dummy_res_a)
        assert err_a is not None and "Torn Redis configuration tuple" in err_a

        # Case B: Redis cap=10.0 (from config_1) but result.limit=60.0 (from config_2)
        dummy_res_b = RateLimitResult(allowed=True, limit=60.0, remaining=59.0, reset_after=0.5, retry_after=None)
        err_b = validate_snapshot_parity(10.0, 1.0, dummy_res_b)
        assert err_b is not None and "Redis capacity (10.0) != result.limit (60.0)" in err_b

        # Case C: Valid cap & refill, but reset_after calculated using foreign refill_rate (2.0 instead of 1.0)
        # For limit=10, remaining=8: correct reset_after with refill 1.0 is 2.0s. If computed with 2.0, it's 1.0s.
        dummy_res_c = RateLimitResult(allowed=True, limit=10.0, remaining=8.0, reset_after=1.0, retry_after=None)
        err_c = validate_snapshot_parity(10.0, 1.0, dummy_res_c)
        assert err_c is not None and "Refill rate mismatch in reset_after" in err_c

        # Case D: Coherent snapshots are cleanly accepted
        dummy_res_valid_1 = RateLimitResult(allowed=True, limit=10.0, remaining=9.0, reset_after=1.0, retry_after=None)
        assert validate_snapshot_parity(10.0, 1.0, dummy_res_valid_1) is None
        dummy_res_valid_2 = RateLimitResult(allowed=True, limit=60.0, remaining=58.0, reset_after=1.0, retry_after=None)
        assert validate_snapshot_parity(60.0, 2.0, dummy_res_valid_2) is None

        # Live multi-threaded test against Redis
        rl = RateLimiter(
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED,
            redis_client=limiter.redis
        )

        original_script = rl.check_limit_script
        thread_local = threading.local()
        recorded_calls = []
        recorded_lock = threading.Lock()

        def script_wrapper(keys, args):
            cap = float(args[0])
            refill = float(args[1])
            tokens_req = float(args[2])
            call_info = {
                "keys": keys,
                "capacity": cap,
                "refill_rate": refill,
                "tokens": tokens_req
            }
            thread_local.last_redis_call = call_info
            with recorded_lock:
                recorded_calls.append(call_info)
            return original_script(keys=keys, args=args)

        rl.check_limit_script = script_wrapper

        errors = []
        stop_event = threading.Event()
        verified_count = 0
        verified_lock = threading.Lock()

        def updater():
            toggle = False
            while not stop_event.is_set():
                cfg = config_2 if toggle else config_1
                toggle = not toggle
                try:
                    rl.configure(capacity=cfg[0], refill_rate=cfg[1])
                except Exception as e:
                    errors.append(e)

        def worker(worker_id):
            nonlocal verified_count
            user = f"redis_snap_user_{worker_id}"
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    thread_local.last_redis_call = None
                    res = rl.check_limit(user, tokens=1.0)
                    last_call = getattr(thread_local, "last_redis_call", None)
                    if last_call is None:
                        errors.append(RuntimeError(f"Worker {worker_id}: check_limit did not invoke Redis script"))
                        continue

                    parity_err = validate_snapshot_parity(
                        last_call["capacity"],
                        last_call["refill_rate"],
                        res
                    )
                    if parity_err:
                        errors.append(ValueError(f"Worker {worker_id} snapshot parity error: {parity_err}"))
                    else:
                        with verified_lock:
                            verified_count += 1
                except Exception as e:
                    errors.append(e)

        worker_threads = [
            threading.Thread(target=worker, args=(i,), name=f"redis_worker_{i}")
            for i in range(4)
        ]
        updater_thread = threading.Thread(target=updater, name="redis_updater")

        threads = [updater_thread] + worker_threads

        for t in threads:
            t.start()

        # Wait for all workers to finish their 50 requests
        for t in worker_threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), f"Worker thread {t.name} did not terminate within timeout"

        # Signal updater to stop
        stop_event.set()
        updater_thread.join(timeout=5.0)
        assert not updater_thread.is_alive(), "Updater thread did not terminate within timeout"

        rl.check_limit_script = original_script

        assert not errors, f"Redis snapshot parity errors under concurrency: {errors}"
        assert verified_count >= 100, f"Expected at least 100 verified invocations, got {verified_count}"
        assert len(recorded_calls) >= 100, "Insufficient Redis script calls recorded"

    def test_max_local_keys_cleanup_during_concurrent_configuration_change(self):
        """
        Tests local cache behavior when max_local_keys is dynamically reduced via configure()
        under concurrent request load.

        Architecture & Semantics:
        `max_local_keys` operates as an eviction cleanup threshold, NOT a strict pre-allocation
        hard ceiling. When cache entries exceed `effective_max_keys`, stale entries (>1h) are
        evicted first, followed by LRU batch eviction of the oldest 20% entries
        (max(1, int(effective_max_keys * 0.2))) to amortize sorting overhead.

        This test:
        1. Pre-seeds 100 distinct entries in the local cache with staggered timestamps.
        2. Dynamically reduces max_local_keys from 100 to 20 via configure().
        3. Runs concurrent request workers and configuration inspection threads, verifying
           that no deadlocks, KeyError, or dictionary mutation errors occur.
        4. Verifies every worker thread terminates cleanly (assert not t.is_alive()).
        5. Issues repeated requests to trigger successive 20% batch evictions, proving that
           cache size progressively drains and strictly reaches the documented bound (len <= 20).
        """
        import threading

        rl = RateLimiter(
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.LOCAL_FALLBACK,
            max_local_keys=100
        )
        rl.redis = None
        rl.check_limit_script = None

        # 1. Pre-seed 100 local buckets with strictly staggered timestamps (LRU ordering)
        base_time = time.time()
        with rl._lock:
            for i in range(100):
                rl._local_buckets[f"preseed_user_{i}"] = (10.0, base_time - (100 - i))
            assert len(rl._local_buckets) == 100, "Initial cache should contain exactly 100 entries"

        # 2. Dynamically reduce threshold from 100 to 20
        rl.configure(max_local_keys=20)
        assert rl.max_local_keys == 20

        errors = []
        stop_event = threading.Event()

        # 3. Concurrent workers: request workers hitting keys while config updater reads/checks
        def config_inspector():
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    snap = rl._get_config_snapshot()
                    if snap.max_local_keys != 20:
                        errors.append(ValueError(f"Unexpected max_local_keys: {snap.max_local_keys}"))
                except Exception as e:
                    errors.append(e)

        def request_worker(worker_id):
            for i in range(25):
                if stop_event.is_set():
                    break
                # Mix of existing preseeded keys and worker-specific keys
                uid = f"preseed_user_{i % 20}" if i % 2 == 0 else f"worker_{worker_id}_user_{i}"
                try:
                    rl.check_limit(uid, tokens=1.0)
                except Exception as e:
                    errors.append(e)

        worker_threads = [
            threading.Thread(target=request_worker, args=(i,), name=f"cleanup_worker_{i}")
            for i in range(4)
        ]
        inspector_thread = threading.Thread(target=config_inspector, name="config_inspector")

        threads = [inspector_thread] + worker_threads

        for t in threads:
            t.start()

        # 4. Ensure every worker thread terminates cleanly and assert not alive
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), f"Thread {t.name} did not terminate within timeout"

        stop_event.set()

        # Verify no deadlocks, KeyError, or RuntimeError (e.g. dictionary changed size during iteration)
        assert not errors, f"Errors during concurrent max_local_keys cleanup: {errors}"

        # 5. Progressive eviction verification:
        # With effective_max_keys=20, evict_count = max(1, int(20 * 0.2)) = 4 keys evicted per request.
        # Repeated requests progressively drain the cache. Within at most 25 requests,
        # all excess entries beyond the 20 threshold are evicted.
        for _ in range(25):
            rl.check_limit("drain_user", tokens=1.0)

        with rl._lock:
            final_cache_size = len(rl._local_buckets)
            assert final_cache_size <= 20, (
                f"Expected cache count <= 20 after repeated requests, got {final_cache_size}"
            )

        # Subsequent requests for existing keys do not cause further evictions once within bound
        with rl._lock:
            stable_size = len(rl._local_buckets)
        rl.check_limit("drain_user", tokens=1.0)
        with rl._lock:
            assert len(rl._local_buckets) == stable_size
            assert len(rl._local_buckets) <= 20


# =============================================================================
# 4. Redis Clock Semantics & Monotonic Backward Shift Recovery (Priority 2, Item 2)
# =============================================================================

class TestRedisClockSemanticsAndSafeguards:
    """Tests Redis server wall-clock time semantics and backward clock step safeguards."""

    def test_lua_script_uses_monotonic_effective_timestamp(self):
        """Verifies that the Lua script strictly guards elapsed time with monotonic effective_now."""
        lua_source = RateLimiter.LUA_TOKEN_BUCKET
        assert "math.max(now, last_updated)" in lua_source
        assert "effective_now - last_updated" in lua_source
        assert "redis.call('HMSET', key, 'tokens', filled_tokens, 'last_updated', effective_now)" in lua_source
        assert "redis.call('TIME')" in lua_source

    def test_local_fallback_complete_six_step_backward_clock_recovery(self):
        """
        Full 6-step verification of monotonic backward clock jump recovery in local fallback:
          1. Consume tokens at T=1000.
          2. Host clock steps backward to T=950.
          3. Request tokens: effective_now clamps delta to 0, persists 1000.
          4. Clock restores to T=1000.
          5. Request tokens: delta is 0; zero artificial refill occurred.
          6. Clock advances normally to T=1003: refills normal elapsed tokens.
        """
        rl = RateLimiter(capacity=10.0, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        rl.redis = None
        rl.check_limit_script = None
        user = "clock_recovery_user"
        rl.reset(user)

        # 1. Consume tokens at initial time T=1000
        simulated_time = 1000.0
        with rl._lock:
            rl._local_buckets[user] = (10.0, simulated_time)

        # Mock time.time to simulate clock movements
        current_mock_time = 1000.0

        def mock_time():
            return current_mock_time

        import time as time_mod
        orig_time = time_mod.time
        time_mod.time = mock_time

        try:
            # Step 1: Request 2 tokens at T=1000 -> remaining 8, last_updated=1000
            res1 = rl.check_limit(user, tokens=2)
            assert res1.allowed is True
            assert res1.remaining == 8.0

            # Step 2: Clock jumps backward by 50 seconds to T=950
            current_mock_time = 950.0

            # Step 3: Request 1 token at T=950
            # effective_now = max(950, 1000) = 1000, delta = 0
            # Remaining becomes 8 - 1 = 7, last_updated remains 1000!
            res2 = rl.check_limit(user, tokens=1)
            assert res2.allowed is True
            assert res2.remaining == 7.0
            with rl._lock:
                assert rl._local_buckets[user][1] == 1000.0

            # Step 4 & 5: Clock restores to T=1000 (when step occurred)
            current_mock_time = 1000.0

            # Request 1 token: delta = max(1000, 1000) - 1000 = 0 -> 0 artificial refill!
            # Remaining should be exactly 7 - 1 = 6 (if it had refilled from 950, it would be 10!)
            res3 = rl.check_limit(user, tokens=1)
            assert res3.allowed is True
            assert res3.remaining == 6.0

            # Step 6: Clock advances normally to T=1003 (3 seconds later, refill_rate=1 token/sec)
            current_mock_time = 1003.0
            # Refills min(10, 6 + 3*1) = 9 tokens, request 1 -> 8 remaining
            res4 = rl.check_limit(user, tokens=1)
            assert res4.allowed is True
            assert res4.remaining == 8.0
        finally:
            time_mod.time = orig_time

    def test_redis_lua_complete_backward_clock_and_recovery_sequence(self):
        """
        Executes the exact Redis Lua script on Redis across the full backward-clock and recovery sequence:
          Stage 1 (T=1000.0): Consume 2 tokens -> remaining=8.0, last_updated=1000.0 stored in Redis.
          Stage 2 (T=950.0, -50s clock step): Request 1 token -> delta clamped to 0, remaining=7.0,
                  last_updated persists 1000.0 in Redis (never regresses to 950.0).
          Stage 3 (T=1000.0, clock catches up): Request 1 token -> delta is 0, zero artificial refill,
                  remaining=6.0, last_updated=1000.0 stored in Redis.
          Stage 4 (T=1003.0, clock advances normally 3s): Request 1 token -> 3 tokens refilled,
                  remaining=8.0, last_updated updates to 1003.0 in Redis.
        """
        if not limiter.redis:
            pytest.skip("Redis not available")

        user = f"redis_clock_seq_{uuid.uuid4().hex[:6]}"
        key = f"rate_limit:{user}"
        limiter.reset(user)

        script = limiter.redis.register_script(RateLimiter.LUA_TOKEN_BUCKET)
        capacity = 10.0
        refill_rate = 1.0

        try:
            # Stage 1: T=1000.0, consume 2 tokens
            res1 = script(keys=[key], args=[capacity, refill_rate, 2.0, 1000.0])
            assert res1[0] == 1
            assert float(res1[1]) == 8.0
            state1 = limiter.redis.hmget(key, "tokens", "last_updated")
            assert float(state1[0]) == 8.0
            assert float(state1[1]) == 1000.0

            # Stage 2: Clock steps backward to T=950.0 (-50s)
            res2 = script(keys=[key], args=[capacity, refill_rate, 1.0, 950.0])
            assert res2[0] == 1
            assert float(res2[1]) == 7.0
            state2 = limiter.redis.hmget(key, "tokens", "last_updated")
            assert float(state2[0]) == 7.0
            # Crucial: effective_now was persisted, NOT 950.0
            assert float(state2[1]) == 1000.0

            # Stage 3: Clock catches up to T=1000.0
            res3 = script(keys=[key], args=[capacity, refill_rate, 1.0, 1000.0])
            assert res3[0] == 1
            assert float(res3[1]) == 6.0
            state3 = limiter.redis.hmget(key, "tokens", "last_updated")
            assert float(state3[0]) == 6.0
            assert float(state3[1]) == 1000.0

            # Stage 4: Clock advances normally to T=1003.0 (3s elapsed)
            res4 = script(keys=[key], args=[capacity, refill_rate, 1.0, 1003.0])
            assert res4[0] == 1
            # Refilled: min(10.0, 6.0 + 3.0*1.0) = 9.0; minus 1.0 requested = 8.0
            assert float(res4[1]) == 8.0
            state4 = limiter.redis.hmget(key, "tokens", "last_updated")
            assert float(state4[0]) == 8.0
            assert float(state4[1]) == 1003.0
        finally:
            limiter.redis.delete(key)

    def test_redis_live_clock_backward_jump_and_catchup(self):
        """
        Tests live Redis server time execution via check_limit() across backward shift and recovery:
        verifies that setting last_updated ahead clamps refills and persists monotonic timestamp until clock catches up.
        """
        if not limiter.redis or not limiter.check_limit_script:
            pytest.skip("Redis not available")

        user = f"redis_live_clock_{uuid.uuid4().hex[:6]}"
        key = f"rate_limit:{user}"
        limiter.reset(user)

        try:
            # Initial consumption: consumes 2 tokens
            res1 = limiter.check_limit(user, tokens=2.0)
            assert res1.allowed is True
            state1 = limiter.redis.hmget(key, "tokens", "last_updated")
            last_t = float(state1[1])

            # Simulate clock step backward: advance last_updated in Redis by 1.0 second
            future_t = last_t + 1.0
            limiter.redis.hset(key, mapping={"tokens": "8.0", "last_updated": str(future_t)})

            # Immediate request: live Redis TIME is behind future_t
            res2 = limiter.check_limit(user, tokens=1.0)
            assert res2.allowed is True
            assert res2.remaining == 7.0
            state2 = limiter.redis.hmget(key, "tokens", "last_updated")
            # Persisted effective_now is still future_t
            assert float(state2[1]) == future_t

            # Wait 1.1s for live Redis server clock to naturally catch up and pass future_t
            time.sleep(1.1)

            # Request after live clock caught up: should refill normally
            res3 = limiter.check_limit(user, tokens=1.0)
            assert res3.allowed is True
            state3 = limiter.redis.hmget(key, "tokens", "last_updated")
            # Now last_updated has advanced past future_t
            assert float(state3[1]) > future_t
        finally:
            limiter.redis.delete(key)


# =============================================================================
# 5. RateLimitResult & HTTP Rate-Limit Headers Semantics (Priority 2, Items 4 & 5)
# =============================================================================

class TestRateLimitResultAndHeaderSemantics:
    """Tests RateLimitResult telemetry fields and standard RFC/IETF HTTP headers."""

    def test_rate_limit_result_dataclass_fields(self):
        """RateLimitResult dataclass must expose allowed, limit, remaining, reset_after, retry_after."""
        res = RateLimitResult(
            allowed=True,
            limit=10.0,
            remaining=8.5,
            reset_after=9.0,
            retry_after=None
        )
        assert res.allowed is True
        assert res.limit == 10.0
        assert isinstance(res.limit, float)
        assert res.remaining == 8.5
        assert res.reset_after == 9.0
        assert res.retry_after is None

    def test_rate_limit_result_preserves_fractional_capacity(self):
        """RateLimitResult.limit must accurately reflect fractional capacity without truncation."""
        rl = RateLimiter(capacity=2.5, refill_rate=0.5, failure_mode=FailureMode.LOCAL_FALLBACK)
        res = rl.check_limit("frac_user", tokens=1.0)
        assert res.limit == 2.5
        assert isinstance(res.limit, float)

    def test_fractional_capacity_formatted_in_headers(self, client):
        """Fractional capacities must be formatted without truncation in HTTP response headers."""
        orig_cap = limiter.capacity
        try:
            limiter.configure(capacity=2.5)
            uid = f"frac_hdr_{uuid.uuid4().hex[:6]}"
            ua = f"TestAgent/1.0 ({uid})"
            detector.set_verified_human(uid, duration_seconds=300)

            res = client.get("/limited-resource", headers={"user-id": uid, "user-agent": ua})
            assert res.status_code == 200
            assert res.headers["x-ratelimit-limit"] == "2.5"
            assert res.headers["ratelimit-limit"] == "2.5"
        finally:
            limiter.configure(capacity=orig_cap)

    def test_reset_after_formula_accuracy(self):
        """
        reset_after must equal (capacity - remaining) / refill_rate, representing the
        seconds until the bucket is 100% replenished back to full capacity.
        """
        capacity = 10.0
        refill_rate = 2.0  # 2 tokens/sec
        rl = RateLimiter(capacity=capacity, refill_rate=refill_rate, failure_mode=FailureMode.LOCAL_FALLBACK)
        user = "test_reset_formula"
        rl.reset(user)

        res = rl.check_limit(user, tokens=4)
        assert res.allowed is True
        assert 5.9 <= res.remaining <= 6.1
        expected_reset = (capacity - res.remaining) / refill_rate
        assert math.isclose(res.reset_after, expected_reset, rel_tol=1e-2)

    def test_retry_after_semantics_on_rejection(self):
        """
        When a request is rejected, retry_after must indicate integer seconds client must wait
        before at least requested tokens become available: ceil((tokens - remaining) / refill_rate).
        When allowed is True, retry_after must be None.
        """
        capacity = 5.0
        refill_rate = 1.0  # 1 token/sec
        rl = RateLimiter(capacity=capacity, refill_rate=refill_rate, failure_mode=FailureMode.LOCAL_FALLBACK)
        user = "test_retry_semantics"
        rl.reset(user)

        res_ok = rl.check_limit(user, tokens=5)
        assert res_ok.allowed is True
        assert res_ok.retry_after is None
        assert 0.0 <= res_ok.remaining <= 0.1

        res_fail = rl.check_limit(user, tokens=3)
        assert res_fail.allowed is False
        assert res_fail.retry_after == 3

    def test_http_rate_limit_headers_on_success(self, client):
        """
        Successful request (200 OK) must return both standard RFC (X-RateLimit-*)
        and IETF (RateLimit-*) response headers with consistent values.
        """
        uid = uuid.uuid4().hex[:8]
        user_id = f"test_hdr_success_{uid}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(user_id)
        detector.set_verified_human(user_id, duration_seconds=300)

        response = client.get("/limited-resource", headers={"user-id": user_id, "user-agent": ua})
        assert response.status_code == 200

        headers = response.headers
        # Standard X-RateLimit-*
        assert "x-ratelimit-limit" in headers
        assert "x-ratelimit-remaining" in headers
        assert "x-ratelimit-reset" in headers

        # IETF RateLimit-*
        assert "ratelimit-limit" in headers
        assert "ratelimit-remaining" in headers
        assert "ratelimit-reset" in headers

        # Parity between headers
        assert headers["x-ratelimit-limit"] == headers["ratelimit-limit"]
        assert headers["x-ratelimit-remaining"] == headers["ratelimit-remaining"]
        assert headers["x-ratelimit-reset"] == headers["ratelimit-reset"]

    def test_http_rate_limit_headers_on_user_exhaustion(self, client):
        """
        When user quota is exhausted (429 Too Many Requests), response must attach
        Retry-After, X-RateLimit-*, and RateLimit-* headers, and detail must distinguish
        burst capacity from sustained refill rate.
        """
        uid = uuid.uuid4().hex[:8]
        user_id = f"test_hdr_exhaust_{uid}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(user_id)
        detector.set_verified_human(user_id, duration_seconds=300)

        # Exhaust bucket
        for _ in range(int(limiter.capacity)):
            res = client.get("/limited-resource", headers={"user-id": user_id, "user-agent": ua})
            assert res.status_code == 200

        # 429 Request
        response = client.get("/limited-resource", headers={"user-id": user_id, "user-agent": ua})
        assert response.status_code == 429
        headers = response.headers

        assert "retry-after" in headers
        assert int(headers["retry-after"]) >= 1

        assert headers["x-ratelimit-remaining"] == "0"
        assert headers["ratelimit-remaining"] == "0"
        assert headers["x-ratelimit-limit"] == str(int(limiter.capacity))
        assert headers["ratelimit-limit"] == str(int(limiter.capacity))
        assert int(headers["x-ratelimit-reset"]) >= 1

        # Check detail explicitly distinguishes burst capacity from sustained refill rate
        detail_msg = response.json()["detail"]["message"]
        assert "burst capacity:" in detail_msg
        assert "sustained refill rate:" in detail_msg

    def test_http_rate_limit_headers_on_ip_exhaustion(self):
        """
        When physical IP rate limit is exhausted, response must return 429
        with Retry-After, X-RateLimit-*, and RateLimit-* headers derived from the IP limiter.
        """
        proxy_client = TestClient(app, client=("127.0.0.1", 50000))
        client_ip = f"198.51.100.{int(time.time()*1000) % 250 + 1}"
        ip_limiter.reset(f"ip:{client_ip}")

        uid = f"ip_exhaust_user_{uuid.uuid4().hex[:6]}"
        detector.set_verified_human(uid, duration_seconds=300)
        req_headers = {
            "user-id": uid,
            "x-forwarded-for": client_ip,
            "device-id": f"device_{uid}",
            "user-agent": f"TestAgent/{uid}"
        }

        # Exhaust IP bucket using single user through trusted proxy client
        for _ in range(int(ip_limiter.capacity)):
            limiter.reset(uid)
            res = proxy_client.get("/limited-resource", headers=req_headers)
            assert res.status_code == 200, f"Got {res.status_code}: {res.json()}"

        # Next request from this IP must be blocked by IP rate limiter (429)
        limiter.reset(uid)
        res_blocked = proxy_client.get("/limited-resource", headers=req_headers)
        assert res_blocked.status_code == 429
        headers = res_blocked.headers

        assert "retry-after" in headers
        assert int(headers["retry-after"]) >= 1
        assert "Physical IP rate limit exceeded" in res_blocked.json()["detail"]["message"]

        # IP limiter headers attached
        assert headers["x-ratelimit-remaining"] == "0"
        assert headers["ratelimit-remaining"] == "0"
        assert headers["x-ratelimit-limit"] == str(int(ip_limiter.capacity))
        assert headers["ratelimit-limit"] == str(int(ip_limiter.capacity))
