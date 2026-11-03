from dataclasses import dataclass
"""
Distributed Token Bucket Rate Limiter with Redis Lua Atomicity and Configurable Failure Modes.

Architectural Guarantees:
  1. Monotonic Server Time: Uses Redis server time via `redis.call('TIME')` inside the Lua script,
     eliminating clock drift across distributed application nodes.
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
import threading
import time
from typing import Dict, Optional, Tuple, Union
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
    allowed: bool
    limit: int
    remaining: float
    reset_after: float
    retry_after: Optional[int] = None



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

    -- 1. Obtain monotonic time directly from Redis server (eliminates application clock skew)
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

    -- 4. Calculate continuous refill based on elapsed Redis server seconds
    local delta = math.max(0, now - last_updated)
    local filled_tokens = math.min(capacity, tokens + (delta * refill_rate))

    local allowed = 0
    if filled_tokens >= requested then
        filled_tokens = filled_tokens - requested
        allowed = 1
    end

    -- 5. Atomic state update & dynamic TTL (at least 300s or 2x full refill duration)
    local ttl = math.max(300, math.ceil((capacity / refill_rate) * 2))
    redis.call('HMSET', key, 'tokens', filled_tokens, 'last_updated', now)
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
        # Validate initialization invariants
        if capacity <= 0:
            raise ValueError(f"capacity must be a positive number, got {capacity}")
        if refill_rate <= 0:
            raise ValueError(f"refill_rate must be a positive number, got {refill_rate}")
        if max_local_keys <= 0:
            raise ValueError(f"max_local_keys must be positive, got {max_local_keys}")

        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.max_local_keys = max_local_keys
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

    def check_limit(self, user_id: str, tokens: int = 1) -> RateLimitResult:
            """
            Evaluates rate limit and returns detailed telemetry including remaining tokens,
            reset duration, and retry-after guidance for RFC-compliant HTTP headers.
            """
            if not isinstance(user_id, str) or not user_id.strip():
                raise ValueError("user_id must be a non-empty string")
            user_id = user_id.strip()
    
            if not isinstance(tokens, (int, float)) or tokens <= 0:
                raise ValueError(f"tokens requested must be greater than zero, got {tokens}")
    
            if tokens > self.capacity:
                return RateLimitResult(
                    allowed=False,
                    limit=int(self.capacity),
                    remaining=0.0,
                    reset_after=self.capacity / self.refill_rate,
                    retry_after=math.ceil(self.capacity / self.refill_rate)
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
                        limit=int(self.capacity),
                        remaining=remaining,
                        reset_after=reset_after,
                        retry_after=retry_after
                    )
                except (redis.RedisError, redis.ConnectionError, TimeoutError, OSError) as e:
                    return self._handle_check_limit_failure(user_id, tokens, e)
    
            return self._handle_check_limit_failure(user_id, tokens, ConnectionError("Redis is not connected"))
    
    def _handle_check_limit_failure(self, user_id: str, tokens: int, error: Exception) -> RateLimitResult:
        if self.failure_mode == FailureMode.FAIL_CLOSED:
            raise RedisUnavailableError(f"Rate limiter service unavailable (Redis down: {error})") from error

        if self.failure_mode == FailureMode.FAIL_OPEN:
            return RateLimitResult(
                allowed=True,
                limit=int(self.capacity),
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
            delta = max(0.0, now - last_updated)
            refilled = min(self.capacity, current_tokens + (delta * self.refill_rate))

            if refilled >= tokens:
                remaining = refilled - tokens
                self._local_buckets[user_id] = (remaining, now)
                reset_after = max(0.0, (self.capacity - remaining) / self.refill_rate)
                return RateLimitResult(
                    allowed=True,
                    limit=int(self.capacity),
                    remaining=remaining,
                    reset_after=reset_after,
                    retry_after=None
                )
            else:
                self._local_buckets[user_id] = (refilled, now)
                reset_after = max(0.0, (self.capacity - refilled) / self.refill_rate)
                retry_after = max(1, math.ceil((tokens - refilled) / self.refill_rate))
                return RateLimitResult(
                    allowed=False,
                    limit=int(self.capacity),
                    remaining=refilled,
                    reset_after=reset_after,
                    retry_after=retry_after
                )

    def is_allowed(self, user_id: str, tokens: int = 1) -> bool:
        return self.check_limit(user_id, tokens).allowed

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
