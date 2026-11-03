from dataclasses import dataclass
"""
Distributed Token Bucket Rate Limiter with Redis Lua Atomicity and Configurable Failure Modes.

Architectural Guarantees & Redis Time Semantics:
  1. Redis Server Wall-Clock Time:
     Uses Redis server time via `redis.call('TIME')` inside the Lua script.
     - Non-Monotonic Wall-Clock Time: The Redis `TIME` command calls `gettimeofday()` on the
       host operating system (CLOCK_REALTIME), which is NOT a guaranteed hardware monotonic
       clock (CLOCK_MONOTONIC). It reflects wall-clock time and is subject to system clock
       adjustments, NTP stepping or slewing, and leap seconds.
     - Backward Jump Defense: To protect against negative elapsed time intervals caused by NTP steps
       or backward clock shifts, the Lua script strictly clamps delta calculation:
       `local delta = math.max(0, now - last_updated)`
       ensuring accrued tokens cannot underflow or be erased by backward clock shifts.
     - Clock Adjustment Assumptions: Production Redis instances should run NTP in slew mode (e.g.
       using chrony with slewing or ntpd `-x`) to adjust time continuously rather than in abrupt steps.
     - Failover & Replica Assumptions: In distributed Redis setups (Sentinel / Cluster), failover
       promotion assumes replica host wall-clocks are synchronized with low skew (< a few milliseconds).
       A promoted replica whose wall-clock lags behind will briefly pause refills until elapsed time
       catches up; a promoted replica whose wall-clock is ahead will refill proportionally to the delta,
       capped at total bucket capacity.
  2. Strict Atomicity: Token evaluation, refill calculation, consumption, and TTL expiration
     execute in a single atomic Lua transaction.
  3. Configurable Failure Modes:
     - `FAIL_CLOSED` (Default / Recommended): Rejects requests or raises when Redis is unavailable,
       preventing quota circumvention and DDoS during infrastructure outages.
     - `FAIL_OPEN`: Allows requests when Redis is unavailable to prioritize service availability.
     - `LOCAL_FALLBACK`: Uses a thread-safe, memory-bounded local in-memory token bucket.
  4. Explicit State Semantics: Requests exceeding remaining tokens update accumulated refill tokens
     and refresh key TTL without deducting, preserving correct accrued token state.
"""

from enum import Enum
import math
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple, Union
import redis


class FailureMode(str, Enum):
    """Failure mode strategies when Redis is unreachable."""
    FAIL_CLOSED = "fail_closed"        # Secure default: raise/reject to prevent abuse
    FAIL_OPEN = "fail_open"            # Availability priority: allow traffic if Redis drops
    LOCAL_FALLBACK = "local_fallback"  # Fallback to local in-memory Token Bucket


class RateLimiterError(Exception):
    """Base exception for rate limiter errors."""
    pass


class RedisUnavailableError(RateLimiterError):
    """Raised when Redis is down and failure_mode is FAIL_CLOSED."""
    pass


@dataclass
class RateLimitResult:
    """
    Detailed telemetry resulting from a rate limit evaluation.

    Attributes:
        allowed (bool): True if the requested tokens were permitted and consumed;
            False if remaining quota was insufficient.
        limit (float): Maximum burst capacity of the token bucket (never truncated).
        remaining (float): Available tokens remaining in the bucket immediately
            following evaluation.
        reset_after (float): Relative duration in seconds until the bucket is completely
            replenished back to its full maximum capacity: (capacity - remaining) / refill_rate.
        retry_after (Optional[int]): Recommended wait duration in integer seconds for HTTP
            Retry-After headers before retrying the rejected request:
            max(1, ceil((tokens - remaining) / refill_rate)). Populated only when allowed=False;
            None when allowed=True.
    """
    allowed: bool
    limit: float
    remaining: float
    reset_after: float
    retry_after: Optional[int] = None


# -----------------------------------------------------------------------------
# Numeric Validation & Configuration Helpers (Priority 2)
# -----------------------------------------------------------------------------

def validate_positive_number(name: str, val: Any) -> float:
    """
    Validates that a numeric argument is a finite, strictly positive real number.
    Explicitly rejects booleans, None, strings, NaN, and positive/negative infinity.
    """
    if isinstance(val, bool):
        raise ValueError(f"{name} cannot be a boolean")
    if not isinstance(val, (int, float)):
        raise ValueError(f"{name} must be a number, got {type(val).__name__}")
    if math.isnan(val):
        raise ValueError(f"{name} cannot be NaN")
    if math.isinf(val):
        raise ValueError(f"{name} cannot be infinity")
    if val <= 0:
        raise ValueError(f"{name} must be a positive number, got {val}")
    return float(val)


def validate_positive_int(name: str, val: Any) -> int:
    """
    Validates that a numeric argument is a strictly positive integer.
    Explicitly rejects booleans, non-integers, floats, None, strings, NaN, and infinity.
    """
    if isinstance(val, bool):
        raise ValueError(f"{name} cannot be a boolean")
    if not isinstance(val, int) or isinstance(val, float):
        raise ValueError(f"{name} must be an integer, got {type(val).__name__}")
    if val <= 0:
        raise ValueError(f"{name} must be positive, got {val}")
    return val


def validate_tokens_requested(tokens: Any) -> float:
    """
    Validates requested tokens for rate limit checks.
    Explicitly rejects booleans, None, strings, NaN, infinity, and values <= 0.
    """
    if isinstance(tokens, bool):
        raise ValueError("tokens requested cannot be a boolean")
    if not isinstance(tokens, (int, float)):
        raise ValueError(f"tokens requested must be a number, got {type(tokens).__name__}")
    if math.isnan(tokens):
        raise ValueError("tokens requested cannot be NaN")
    if math.isinf(tokens):
        raise ValueError("tokens requested cannot be infinity")
    if tokens <= 0:
        raise ValueError(f"tokens requested must be greater than zero, got {tokens}")
    return float(tokens)


def parse_env_positive_float(var_name: str, default: float) -> float:
    """
    Safely parses an environment variable as a strictly positive finite float.
    Rejects boolean strings, non-numeric strings, NaN, infinity, and values <= 0.
    Falls back to default if unset or empty.
    """
    raw = os.getenv(var_name)
    if raw is None or raw.strip() == "":
        return default
    raw_str = raw.strip()
    if raw_str.lower() in ("true", "false", "yes", "no"):
        raise ValueError(f"Environment variable {var_name} cannot be a boolean, got {raw!r}")
    try:
        val = float(raw_str)
    except ValueError:
        raise ValueError(f"Environment variable {var_name} must be a valid number, got {raw!r}")
    if math.isnan(val):
        raise ValueError(f"Environment variable {var_name} cannot be NaN")
    if math.isinf(val):
        raise ValueError(f"Environment variable {var_name} cannot be infinity")
    if val <= 0:
        raise ValueError(f"Environment variable {var_name} must be a positive number, got {val}")
    return val


def load_rate_limiter_config() -> Tuple[float, float, float, float, FailureMode]:
    """
    Reads and strictly validates rate limiter configuration from environment variables.
    Fails fast if any value is invalid, NaN, infinity, boolean, or non-positive.
    Returns: (user_capacity, user_refill_rate, ip_capacity, ip_refill_rate, failure_mode)
    """
    user_cap = parse_env_positive_float("RATE_LIMITER_CAPACITY", default=10.0)
    user_refill = parse_env_positive_float("RATE_LIMITER_REFILL_RATE", default=10.0 / 60.0)
    ip_cap = parse_env_positive_float("IP_RATE_LIMITER_CAPACITY", default=30.0)
    ip_refill = parse_env_positive_float("IP_RATE_LIMITER_REFILL_RATE", default=30.0 / 60.0)

    failure_mode_str = os.getenv("RATE_LIMITER_FAILURE_MODE", FailureMode.FAIL_CLOSED.value).lower().strip()
    try:
        failure_mode = FailureMode(failure_mode_str)
    except ValueError:
        raise ValueError(
            f"Invalid RATE_LIMITER_FAILURE_MODE: {failure_mode_str!r}. "
            "Must be one of: fail_closed, fail_open, local_fallback"
        )

    return user_cap, user_refill, ip_cap, ip_refill, failure_mode


def validate_rate_limiter_configuration() -> Tuple[float, float, float, float, FailureMode]:
    """
    Validates rate limiter environment variables at application startup.
    Fails fast if RATE_LIMITER_CAPACITY or RATE_LIMITER_REFILL_RATE are invalid.
    """
    return load_rate_limiter_config()


class RateLimiter:
    """
    Production-grade Token Bucket Rate Limiter with distributed Redis support.
    
    Attributes:
        capacity (float): Maximum tokens bucket can hold.
        refill_rate (float): Tokens added per second.
        failure_mode (FailureMode): Policy when Redis is unreachable.
    """

    LUA_TOKEN_BUCKET = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local requested = tonumber(ARGV[3])

    -- 1. Obtain server wall-clock time from Redis (gettimeofday, CLOCK_REALTIME).
    -- Note: Server wall-clock time eliminates client drift across distributed application nodes.
    -- Non-monotonic steps are safeguarded below via monotonic effective_now = math.max(now, last_updated).
    local time_val = redis.call('TIME')
    local now = tonumber(time_val[1]) + (tonumber(time_val[2]) / 1000000)

    -- 2. Fetch current bucket state
    local state = redis.call('HMGET', key, 'tokens', 'last_updated')
    local tokens = tonumber(state[1])
    local last_updated = tonumber(state[2])

    -- 3. Initialize bucket on first observation
    if not tokens then
        tokens = capacity
        last_updated = now
    end

    -- 4. Monotonic effective timestamp: effective_now never decreases
    local effective_now = math.max(now, last_updated)
    local delta = effective_now - last_updated
    local filled_tokens = math.min(capacity, tokens + (delta * refill_rate))

    local allowed = 0
    if filled_tokens >= requested then
        filled_tokens = filled_tokens - requested
        allowed = 1
    end

    -- 5. Atomic state update & dynamic TTL (persist effective_now, never a regressed timestamp)
    local ttl = math.max(300, math.ceil((capacity / refill_rate) * 2))
    redis.call('HMSET', key, 'tokens', filled_tokens, 'last_updated', effective_now)
    redis.call('EXPIRE', key, ttl)

    return {allowed, tostring(filled_tokens)}
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        capacity: float = 10,
        refill_rate: float = 10.0 / 60.0,
        failure_mode: FailureMode = FailureMode.FAIL_CLOSED,
        enable_fallback: Optional[bool] = None,
        max_local_keys: int = 10000,
        redis_client: Optional[redis.Redis] = None
    ):
        """
        Initialize the Token Bucket Rate Limiter.

        :param redis_url: URL for the Redis connection.
        :param capacity: Maximum number of tokens in the bucket (must be > 0).
        :param refill_rate: Tokens added per second (must be > 0).
        :param failure_mode: FailureMode strategy when Redis drops.
        :param enable_fallback: Deprecated legacy argument. If True, maps to LOCAL_FALLBACK.
        :param max_local_keys: Maximum entries in local memory fallback to avoid memory leaks.
        :param redis_client: Optional pre-configured Redis client instance (e.g. for testing).
        """
        # Validate initialization invariants (reject booleans, None, strings, NaN, infinity, <= 0)
        self.capacity = validate_positive_number("capacity", capacity)
        self.refill_rate = validate_positive_number("refill_rate", refill_rate)
        self.max_local_keys = validate_positive_int("max_local_keys", max_local_keys)
        self.redis_url = redis_url

        # Backwards compatibility for legacy `enable_fallback` parameter
        if enable_fallback is not None:
            self.failure_mode = FailureMode.LOCAL_FALLBACK if enable_fallback else FailureMode.FAIL_CLOSED
        else:
            if isinstance(failure_mode, str):
                failure_mode = FailureMode(failure_mode.lower())
            self.failure_mode = failure_mode

        # In-memory storage fallback: user_id -> (tokens, last_updated)
        # NOTE: Local in-memory fallback does NOT provide globally consistent distributed enforcement.
        # Multiple application instances maintain isolated local state. When Redis recovers,
        # local quota usage is NOT reconciled with Redis state.
        self._local_buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

        # Redis setup
        self.redis: Optional[redis.Redis] = redis_client
        self.check_limit_script = None
        if self.redis is None:
            self._init_redis()
        else:
            self._register_script()

    def configure(
        self,
        capacity: Optional[float] = None,
        refill_rate: Optional[float] = None,
        failure_mode: Optional[Union[FailureMode, str]] = None,
        max_local_keys: Optional[int] = None
    ) -> None:
        """
        Dynamically updates rate limiter configuration in place.
        Validates arguments prior to mutating instance state.
        """
        if capacity is not None:
            self.capacity = validate_positive_number("capacity", capacity)
        if refill_rate is not None:
            self.refill_rate = validate_positive_number("refill_rate", refill_rate)
        if max_local_keys is not None:
            self.max_local_keys = validate_positive_int("max_local_keys", max_local_keys)
        if failure_mode is not None:
            if isinstance(failure_mode, str):
                failure_mode = FailureMode(failure_mode.lower())
            self.failure_mode = failure_mode

    def _init_redis(self):
        """Initialize Redis connection and register Lua script."""
        try:
            self.redis = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5
            )
            self._register_script()
        except Exception as e:
            self.check_limit_script = None
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                # Do not suppress if strictly failing closed on startup
                pass

    def _register_script(self):
        """Register the Lua script with Redis."""
        if self.redis:
            try:
                self.check_limit_script = self.redis.register_script(self.LUA_TOKEN_BUCKET)
            except Exception:
                self.check_limit_script = None

    def check_limit(self, user_id: str, tokens: Union[int, float] = 1) -> RateLimitResult:
        """
        Evaluates rate limit and returns detailed telemetry including remaining tokens,
        reset duration, and retry-after guidance for RFC-compliant HTTP headers.
        """
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        user_id = user_id.strip()

        tokens = validate_tokens_requested(tokens)

        if tokens > self.capacity:
            raise ValueError(
                f"tokens requested ({tokens}) exceeds maximum bucket capacity ({self.capacity})"
            )

        if self.redis and self.check_limit_script:
            key = f"rate_limit:{user_id}"
            try:
                result = self.check_limit_script(
                    keys=[key],
                    args=[self.capacity, self.refill_rate, tokens]
                )
                allowed = bool(result[0] == 1)
                remaining = max(0.0, float(result[1]))
                reset_after = max(0.0, (self.capacity - remaining) / self.refill_rate)
                retry_after = max(1, math.ceil((tokens - remaining) / self.refill_rate)) if not allowed else None
                return RateLimitResult(
                    allowed=allowed,
                    limit=self.capacity,
                    remaining=remaining,
                    reset_after=reset_after,
                    retry_after=retry_after
                )
            except (redis.RedisError, redis.ConnectionError, TimeoutError, OSError) as e:
                return self._handle_check_limit_failure(user_id, tokens, e)

        return self._handle_check_limit_failure(user_id, tokens, ConnectionError("Redis is not connected"))
    
    def _handle_check_limit_failure(self, user_id: str, tokens: Union[int, float], error: Exception) -> RateLimitResult:
        if self.failure_mode == FailureMode.FAIL_CLOSED:
            raise RedisUnavailableError(f"Rate limiter service unavailable (Redis down: {error})") from error

        if self.failure_mode == FailureMode.FAIL_OPEN:
            return RateLimitResult(
                allowed=True,
                limit=self.capacity,
                remaining=self.capacity,
                reset_after=0.0,
                retry_after=None
            )

        # LOCAL_FALLBACK Mode
        now = time.time()
        with self._lock:
            if len(self._local_buckets) > self.max_local_keys:
                cutoff = now - 3600.0
                stale_keys = [k for k, (_, last_t) in self._local_buckets.items() if last_t < cutoff]
                for k in stale_keys:
                    del self._local_buckets[k]
                if len(self._local_buckets) > self.max_local_keys:
                    sorted_items = sorted(self._local_buckets.items(), key=lambda item: item[1][1])
                    for k, _ in sorted_items[: int(self.max_local_keys * 0.2)]:
                        del self._local_buckets[k]

            current_tokens, last_updated = self._local_buckets.get(user_id, (self.capacity, now))
            effective_now = max(now, last_updated)
            delta = effective_now - last_updated
            refilled = min(self.capacity, current_tokens + (delta * self.refill_rate))

            if refilled >= tokens:
                remaining = refilled - tokens
                self._local_buckets[user_id] = (remaining, effective_now)
                reset_after = max(0.0, (self.capacity - remaining) / self.refill_rate)
                return RateLimitResult(
                    allowed=True,
                    limit=self.capacity,
                    remaining=remaining,
                    reset_after=reset_after,
                    retry_after=None
                )
            else:
                self._local_buckets[user_id] = (refilled, effective_now)
                reset_after = max(0.0, (self.capacity - refilled) / self.refill_rate)
                retry_after = max(1, math.ceil((tokens - refilled) / self.refill_rate))
                return RateLimitResult(
                    allowed=False,
                    limit=self.capacity,
                    remaining=refilled,
                    reset_after=reset_after,
                    retry_after=retry_after
                )

    def is_allowed(self, user_id: str, tokens: Union[int, float] = 1) -> bool:
        try:
            return self.check_limit(user_id, tokens).allowed
        except ValueError as e:
            if "exceeds maximum bucket capacity" in str(e):
                return False
            raise

    def is_redis_active(self) -> bool:
        """Helper to inspect Redis reachability."""
        if not self.redis:
            return False
        try:
            return bool(self.redis.ping())
        except Exception:
            return False

    def reset(self, user_id: str):
        """Reset token bucket for a specific user (for test isolation & admin)."""
        if not user_id:
            return
        user_id = user_id.strip()
        if self.redis:
            try:
                self.redis.delete(f"rate_limit:{user_id}")
            except Exception:
                pass
        with self._lock:
            self._local_buckets.pop(user_id, None)
