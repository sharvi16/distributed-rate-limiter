"""
Priority 2 Audit Regression Tests: Correctness, Configuration & Telemetry Semantics.

Covers:
  1. Numeric Invariants & Type Safety (Rejection of NaN, Infinity, Booleans, None, strings, and non-positive numbers in RateLimiter, check_limit, and spam detector).
  2. Request parameter validation on API endpoint (/limited-resource?tokens=...).
  3. Environment Configuration (Reading RATE_LIMITER_CAPACITY, RATE_LIMITER_REFILL_RATE, IP_RATE_LIMITER_CAPACITY from env with startup validation).
  4. Redis server wall-clock time documentation & backward clock shift resilience.
  5. RateLimitResult telemetry and RFC/IETF HTTP rate-limit headers (X-RateLimit-*, RateLimit-*, Retry-After).
"""

import math
import os
import time
import uuid
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, ip_limiter, detector
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
        # In Python, bool is a subclass of int (isinstance(True, int) is True).
        # RateLimiter must explicitly reject booleans.
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
        # jail_user
        with pytest.raises(ValueError, match="duration_seconds cannot be a boolean"):
            detector.jail_user("user1", duration_seconds=True)  # type: ignore

        with pytest.raises(ValueError, match="duration_seconds cannot be NaN"):
            detector.jail_user("user1", duration_seconds=float("nan"))

        with pytest.raises(ValueError, match="duration_seconds cannot be infinity"):
            detector.jail_user("user1", duration_seconds=float("inf"))

        with pytest.raises(ValueError, match="duration_seconds must be a positive number"):
            detector.jail_user("user1", duration_seconds=-10)

        # set_verified_human
        with pytest.raises(ValueError, match="duration_seconds cannot be a boolean"):
            detector.set_verified_human("user1", duration_seconds=True)  # type: ignore

        with pytest.raises(ValueError, match="duration_seconds cannot be NaN"):
            detector.set_verified_human("user1", duration_seconds=float("nan"))

        # set_strikes
        with pytest.raises(ValueError, match="count must be a non-negative integer"):
            detector.set_strikes("user1", count=True)  # type: ignore

        with pytest.raises(ValueError, match="count must be a non-negative integer"):
            detector.set_strikes("user1", count=-1)

        # track_vpn_hopping & track_identity_velocity
        with pytest.raises(ValueError, match="max_allowed_ips cannot be a boolean"):
            detector.track_vpn_hopping("dev1", "1.2.3.4", max_allowed_ips=True)  # type: ignore

        with pytest.raises(ValueError, match="window_seconds cannot be NaN"):
            detector.track_vpn_hopping("dev1", "1.2.3.4", window_seconds=float("nan"))


# =============================================================================
# 2. API Request Parameter Validation Tests (Priority 2, Item 5)
# =============================================================================

class TestAPIRequestParameterValidation:
    """Tests numeric parameter validation on the HTTP API level (/limited-resource?tokens=...)."""

    def test_endpoint_rejects_nan_tokens(self, client):
        """GET /limited-resource?tokens=nan must return 400 Bad Request."""
        res = client.get("/limited-resource?tokens=nan", headers={"user-id": "param_test_user"})
        assert res.status_code == 400
        assert "Invalid tokens parameter" in res.json()["detail"]
        assert "cannot be NaN" in res.json()["detail"]

    def test_endpoint_rejects_inf_tokens(self, client):
        """GET /limited-resource?tokens=inf must return 400 Bad Request."""
        res = client.get("/limited-resource?tokens=inf", headers={"user-id": "param_test_user"})
        assert res.status_code == 400
        assert "Invalid tokens parameter" in res.json()["detail"]
        assert "cannot be infinity" in res.json()["detail"]

    def test_endpoint_rejects_negative_and_zero_tokens(self, client):
        """GET /limited-resource?tokens=0 or negative must return 400 Bad Request."""
        res_zero = client.get("/limited-resource?tokens=0", headers={"user-id": "param_test_user"})
        assert res_zero.status_code == 400
        assert "greater than zero" in res_zero.json()["detail"]

        res_neg = client.get("/limited-resource?tokens=-5", headers={"user-id": "param_test_user"})
        assert res_neg.status_code == 400
        assert "greater than zero" in res_neg.json()["detail"]

    def test_endpoint_rejects_non_numeric_tokens_string(self, client):
        """GET /limited-resource?tokens=invalid must return 422 Unprocessable Entity."""
        res = client.get("/limited-resource?tokens=invalid_str", headers={"user-id": "param_test_user"})
        assert res.status_code == 422

    def test_endpoint_accepts_valid_tokens_parameter(self, client):
        """GET /limited-resource?tokens=3 consumes exactly 3 tokens from the user quota."""
        uid = uuid.uuid4().hex[:8]
        user_id = f"test_tokens_query_{uid}"
        ua = f"TestAgent/1.0 ({uid})"
        limiter.reset(user_id)
        detector.set_verified_human(user_id, duration_seconds=300)

        res = client.get(f"/limited-resource?tokens=3", headers={"user-id": user_id, "user-agent": ua})
        assert res.status_code == 200
        # Started with 10 tokens, consumed 3 -> 7 remaining
        assert res.headers["x-ratelimit-remaining"] == "7"
        assert res.headers["ratelimit-remaining"] == "7"


# =============================================================================
# 3. Environment Variable Configuration Tests (Priority 2, Item 6)
# =============================================================================

class TestEnvironmentConfiguration:
    """Tests reading rate limiter parameters from environment variables."""

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

        # Must succeed without error
        validate_rate_limiter_configuration()

        # Malformed capacity must fail startup validation
        monkeypatch.setenv("RATE_LIMITER_CAPACITY", "invalid_capacity")
        with pytest.raises(ValueError, match="RATE_LIMITER_CAPACITY must be a valid number"):
            validate_rate_limiter_configuration()


# =============================================================================
# 4. Redis Clock Semantics & Backward Shift Safeguard (Priority 2, Item 7)
# =============================================================================

class TestRedisClockSemanticsAndSafeguards:
    """Tests Redis server wall-clock time semantics and backward clock step safeguards."""

    def test_backward_clock_jump_safeguard_in_local_fallback(self):
        """
        When host time steps backward (e.g. NTP step adjustment or clock correction),
        the rate limiter must clamp delta to zero and NEVER allow negative tokens or corruption.
        """
        rl = RateLimiter(capacity=10.0, refill_rate=1.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        user = "clock_shift_user"
        rl.reset(user)

        # Consume 2 tokens at current time
        res1 = rl.check_limit(user, tokens=2)
        assert res1.allowed is True
        assert 7.9 <= res1.remaining <= 8.1

        # Simulate host clock jumping backward by 100 seconds
        # Set last_updated to future (now + 100s)
        future_time = time.time() + 100.0
        with rl._lock:
            rl._local_buckets[user] = (8.0, future_time)

        # Request at present time: now - last_updated is negative (-100s)
        # Clamped to 0 via max(0.0, now - last_updated)
        res2 = rl.check_limit(user, tokens=1)
        assert res2.allowed is True
        # Remaining should be 8 - 1 = 7 (not corrupted or negative)
        assert 6.9 <= res2.remaining <= 7.1

    def test_lua_script_uses_math_max_zero_for_clock_skew(self):
        """Verifies that the Lua script strictly guards elapsed time with math.max(0, now - last_updated)."""
        lua_source = RateLimiter.LUA_TOKEN_BUCKET
        assert "math.max(0, now - last_updated)" in lua_source
        assert "redis.call('TIME')" in lua_source


# =============================================================================
# 5. RateLimitResult & HTTP Rate-Limit Headers Semantics (Priority 2, Item 8)
# =============================================================================

class TestRateLimitResultAndHeaderSemantics:
    """Tests RateLimitResult telemetry fields and standard RFC/IETF HTTP headers."""

    def test_rate_limit_result_dataclass_fields(self):
        """RateLimitResult dataclass must expose allowed, limit, remaining, reset_after, retry_after."""
        res = RateLimitResult(
            allowed=True,
            limit=10,
            remaining=8.5,
            reset_after=9.0,
            retry_after=None
        )
        assert res.allowed is True
        assert res.limit == 10
        assert res.remaining == 8.5
        assert res.reset_after == 9.0
        assert res.retry_after is None

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

        # Fresh bucket: remaining = 10 -> consumed 4 -> remaining = 6
        res = rl.check_limit(user, tokens=4)
        assert res.allowed is True
        assert 5.9 <= res.remaining <= 6.1
        # reset_after = (10 - 6) / 2 = 2.0 seconds
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

        # Success -> retry_after is None
        res_ok = rl.check_limit(user, tokens=5)
        assert res_ok.allowed is True
        assert res_ok.retry_after is None
        assert 0.0 <= res_ok.remaining <= 0.1

        # Rejection -> requesting 3 tokens with 0 available -> (3 - 0) / 1 = 3 seconds
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
        Retry-After, X-RateLimit-*, and RateLimit-* headers.
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

        # Exhaust IP bucket using single user through trusted proxy client (resetting user bucket
        # so user quota doesn't exhaust first, and keeping identity count at 1 so Sybil defense is not triggered).
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
