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

    def test_redis_lua_monotonic_clock_recovery_persists_effective_timestamp(self):
        """Verifies Redis Lua persists effective_now when clock is behind last_updated."""
        if not limiter.redis or not limiter.check_limit_script:
            pytest.skip("Redis not available")

        user = f"redis_clock_test_{uuid.uuid4().hex[:6]}"
        key = f"rate_limit:{user}"
        limiter.reset(user)

        # Simulate that Redis clock was at a future timestamp (e.g. 9999999999.0)
        future_timestamp = 9999999999.0
        limiter.redis.hset(key, mapping={"tokens": "8.0", "last_updated": str(future_timestamp)})

        # Check limit against live Redis: current wall clock (< future_timestamp)
        # Lua computes effective_now = math.max(now, 9999999999.0) = 9999999999.0, delta = 0
        res = limiter.check_limit(user, tokens=1.0)
        assert res.allowed is True
        assert res.remaining == 7.0

        # Verify Redis state persisted effective_now, never regressing to current wall clock
        persisted = limiter.redis.hgetall(key)
        assert float(persisted["last_updated"]) == future_timestamp

        # Cleanup
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
