"""
Distributed Token Bucket Rate Limiter with Redis Lua Atomicity and Configurable Failure Modes.

Architectural Guarantees & Redis Time Semantics:
  1. Redis Server Wall-Clock Time:
     Uses Redis server time via `redis.call('TIME')` inside the Lua script.
     - Non-Monotonic Wall-Clock Time: The Redis `TIME` command calls `gettimeofday()` on the
       host operating system (CLOCK_REALTIME), which is NOT a guaranteed hardware monotonic
       clock (CLOCK_MONOTONIC). It reflects wall-clock time and is subject to system clock
       adjustments, NTP stepping or slewing, and leap seconds.
     - Monotonic Backward Jump Recovery: To protect against negative elapsed time intervals and prevent
       excess artificial refills when the host clock later recovers, the Lua script strictly calculates:
       `local effective_now = math.max(now, last_updated)`
       `local delta = effective_now - last_updated`
       persisting `effective_now` back to Redis. This guarantees that `last_updated` never decreases,
       preventing artificial token refills when host time catches up.
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

from dataclasses import dataclass
from enum import Enum
import math
import os
import re
import socket
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple, Union
import redis

# Sentinel value to distinguish omitted arguments from explicitly supplied None in configure()
_UNSET = object()


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


@dataclass(frozen=True)
class _ConfigSnapshot:
    """
    Immutable snapshot of RateLimiter configuration for a single request evaluation.
    Guarantees that a request uses one consistent version of capacity, refill_rate,
    failure_mode, and max_local_keys even if configure() is called concurrently.
    """
    capacity: float
    refill_rate: float
    failure_mode: FailureMode
    max_local_keys: int


# -----------------------------------------------------------------------------
# Credential Masking & Safe Diagnostics (Priority 3)
# -----------------------------------------------------------------------------

def mask_redis_url(url: str) -> str:
    """
    Masks embedded credentials in a Redis URL for safe logging, diagnostics, and exceptions.
    Replaces embedded password with '***', e.g.:
      'redis://:secret@localhost:6379' -> 'redis://:***@localhost:6379'
      'redis://admin:secret@host:6379' -> 'redis://admin:***@host:6379'
    """
    if not url or not isinstance(url, str):
        return ""

    def _repl(match):
        prefix = match.group(1)
        auth = match.group(2)
        if ":" in auth:
            user, _ = auth.split(":", 1)
            return f"{prefix}{user}:***@"
        return f"{prefix}***@"

    return re.sub(r"(rediss?://)([^@\s]+)@", _repl, url)


def sanitize_redis_error_message(err: Union[str, Exception]) -> str:
    """
    Sanitizes an exception or error message string to ensure raw passwords or
    embedded Redis credentials are never exposed in error responses or logs.
    """
    msg = str(err)
    return mask_redis_url(msg)


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


def parse_bool_env(var_name: str, default: bool) -> bool:
    """
    Parses a boolean environment variable strictly.
    Accepts: true, 1, yes, on / false, 0, no, off.
    Raises ValueError on unrecognized non-empty value.
    """
    val = os.getenv(var_name)
    if val is None or val.strip() == "":
        return default
    clean = val.strip().lower()
    if clean in ("true", "1", "yes", "on"):
        return True
    if clean in ("false", "0", "no", "off"):
        return False
    raise ValueError(f"Invalid boolean value for environment variable {var_name}: {val!r}")


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
    -- Monotonic backward recovery is safeguarded below via monotonic effective_now = math.max(now, last_updated).
    local now
    if ARGV[4] then
        now = tonumber(ARGV[4])
    else
        local time_val = redis.call('TIME')
        now = tonumber(time_val[1]) + (tonumber(time_val[2]) / 1000000)
    end

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
        redis_client: Optional[redis.Redis] = None,
        redis_password: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        ssl_ca_certs: Optional[str] = None,
        ssl_cert_reqs: Optional[str] = None,
        ssl_check_hostname: Optional[bool] = None
    ):
        """
        Initialize the Token Bucket Rate Limiter.

        :param redis_url: URL for the Redis connection.
        :param capacity: Maximum number of tokens in the bucket (must be > 0).
        :param refill_rate: Tokens added per second (must be > 0).
        :param failure_mode: FailureMode strategy when Redis drops.
        :param enable_fallback: Deprecated legacy argument. If True, maps to LOCAL_FALLBACK.
        :param max_local_keys: Memory bound cleanup threshold for local fallback cache.
            When cache entries exceed max_local_keys, stale entries (>1h) are purged, followed by
            LRU batch eviction of the oldest 20% entries (at least 1 entry) to amortize sorting overhead.
        :param redis_client: Optional pre-configured Redis client instance (e.g. for testing).
        :param redis_password: Optional Redis authentication password. If omitted, checks REDIS_PASSWORD env var.
        :param ssl_certfile: Path to client SSL certificate for mTLS.
        :param ssl_keyfile: Path to client SSL private key for mTLS.
        :param ssl_ca_certs: Path to trusted CA bundle for Redis TLS verification.
        :param ssl_cert_reqs: Certificate requirement mode (e.g. 'required').
        :param ssl_check_hostname: Whether to verify hostname against certificate.
        """
        # Validate initialization invariants (reject booleans, None, strings, NaN, infinity, <= 0)
        self.capacity = validate_positive_number("capacity", capacity)
        self.refill_rate = validate_positive_number("refill_rate", refill_rate)
        self.max_local_keys = validate_positive_int("max_local_keys", max_local_keys)
        self.redis_url = redis_url

        # SSL / mTLS Configuration
        self.ssl_certfile = ssl_certfile if ssl_certfile is not None else (os.getenv("REDIS_SSL_CERTFILE", "").strip() or None)
        self.ssl_keyfile = ssl_keyfile if ssl_keyfile is not None else (os.getenv("REDIS_SSL_KEYFILE", "").strip() or None)
        self.ssl_ca_certs = ssl_ca_certs if ssl_ca_certs is not None else (os.getenv("REDIS_SSL_CA_CERTS", "").strip() or None)
        self.ssl_cert_reqs = ssl_cert_reqs if ssl_cert_reqs is not None else (os.getenv("REDIS_SSL_CERT_REQS", "").strip() or None)
        self.ssl_check_hostname = ssl_check_hostname

        # Enforce TLS scheme integrity: plain redis:// can NEVER claim TLS or use SSL settings
        is_rediss = self.redis_url.startswith("rediss://")
        is_redis_plain = self.redis_url.startswith("redis://")
        redis_ssl_val = os.getenv("REDIS_SSL")
        redis_ssl_bool = parse_bool_env("REDIS_SSL", False) if (redis_ssl_val is not None and redis_ssl_val.strip() != "") else None

        if is_redis_plain and (redis_ssl_bool is True or self.ssl_certfile or self.ssl_keyfile or self.ssl_ca_certs):
            raise ValueError(
                "Insecure TLS configuration: plain 'redis://' connection scheme cannot claim TLS or use SSL/mTLS parameters. "
                "REDIS_URL must use the 'rediss://' scheme for TLS connections."
            )

        if is_rediss and redis_ssl_bool is False:
            raise ValueError(
                "Contradictory TLS configuration: REDIS_URL uses 'rediss://' scheme, but REDIS_SSL is explicitly set to false."
            )

        if is_rediss and (self.ssl_certfile or self.ssl_keyfile):
            if not self.ssl_certfile or not self.ssl_keyfile:
                raise ValueError("mTLS configuration requires both ssl_certfile and ssl_keyfile.")
            if not os.path.isfile(self.ssl_certfile):
                raise ValueError(f"mTLS client certificate file does not exist: {self.ssl_certfile!r}")
            if not os.path.isfile(self.ssl_keyfile):
                raise ValueError(f"mTLS client private key file does not exist: {self.ssl_keyfile!r}")
            if self.ssl_ca_certs and not os.path.isfile(self.ssl_ca_certs):
                raise ValueError(f"mTLS CA certificate file does not exist: {self.ssl_ca_certs!r}")

        # Redis password configuration: explicitly passed or from environment
        parsed = urllib.parse.urlsplit(self.redis_url)
        url_pwd_raw = parsed.password
        url_pwd = urllib.parse.unquote(url_pwd_raw) if url_pwd_raw is not None else None

        if redis_password is not None:
            self.redis_password = redis_password if redis_password != "" else None
        else:
            env_pwd = os.getenv("REDIS_PASSWORD")
            self.redis_password = env_pwd if (env_pwd is not None and env_pwd != "") else (url_pwd if url_pwd is not None else None)

        # Contradiction check with percent-encoded normalization
        if url_pwd is not None and self.redis_password is not None:
            norm_env = urllib.parse.unquote(self.redis_password)
            if url_pwd != self.redis_password and url_pwd != norm_env:
                raise ValueError(
                    "Contradictory Redis credentials: REDIS_PASSWORD does not match the password supplied in REDIS_URL."
                )

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

    @property
    def masked_redis_url(self) -> str:
        """Returns the Redis URL with embedded credentials safely masked."""
        return mask_redis_url(self.redis_url)

    def __repr__(self) -> str:
        return (
            f"<RateLimiter url={self.masked_redis_url} "
            f"capacity={self.capacity} refill_rate={self.refill_rate} "
            f"failure_mode={self.failure_mode.value}>"
        )

    def configure(
        self,
        capacity: Union[float, object] = _UNSET,
        refill_rate: Union[float, object] = _UNSET,
        failure_mode: Union[FailureMode, str, object] = _UNSET,
        max_local_keys: Union[int, object] = _UNSET,
        redis_url: Union[str, object] = _UNSET,
        redis_password: Union[Optional[str], object] = _UNSET,
        ssl_certfile: Union[Optional[str], object] = _UNSET,
        ssl_keyfile: Union[Optional[str], object] = _UNSET,
        ssl_ca_certs: Union[Optional[str], object] = _UNSET,
        ssl_cert_reqs: Union[Optional[str], object] = _UNSET,
        ssl_check_hostname: Union[Optional[bool], object] = _UNSET
    ) -> None:
        """
        Dynamically updates rate limiter configuration in place.
        Validates all supplied arguments into temporary variables first.
        Applies changes under instance lock only if all validations succeed (all-or-nothing transactional update).

        Callers can explicitly clear SSL certificate, key, CA, certificate requirement, and hostname-check
        settings by passing None. Omitted parameters retain their current values.
        """
        new_capacity = None
        if capacity is not _UNSET:
            new_capacity = validate_positive_number("capacity", capacity)

        new_refill_rate = None
        if refill_rate is not _UNSET:
            new_refill_rate = validate_positive_number("refill_rate", refill_rate)

        new_max_local_keys = None
        if max_local_keys is not _UNSET:
            new_max_local_keys = validate_positive_int("max_local_keys", max_local_keys)

        new_failure_mode = None
        if failure_mode is not _UNSET:
            if isinstance(failure_mode, str):
                try:
                    new_failure_mode = FailureMode(failure_mode.lower())
                except ValueError:
                    raise ValueError(f"Invalid failure_mode: {failure_mode!r}")
            elif isinstance(failure_mode, FailureMode):
                new_failure_mode = failure_mode
            else:
                raise ValueError(f"failure_mode must be FailureMode or str, got {type(failure_mode).__name__}")

        new_redis_url = None
        if redis_url is not _UNSET:
            if redis_url is None:
                raise ValueError("redis_url cannot be None")
            clean_url = redis_url.strip()
            if not clean_url:
                raise ValueError("redis_url cannot be empty")
            new_redis_url = clean_url

        changed_redis_password = (redis_password is not _UNSET)
        new_redis_password = None
        if changed_redis_password:
            new_redis_password = redis_password if (redis_password is not None and redis_password != "") else None

        # Verify credential consistency between URL and password parameter (with percent-encoding normalization)
        target_url = new_redis_url if new_redis_url is not None else self.redis_url
        target_pwd = new_redis_password if changed_redis_password else self.redis_password
        parsed = urllib.parse.urlsplit(target_url)
        url_pwd = urllib.parse.unquote(parsed.password) if parsed.password is not None else None
        if url_pwd is not None and target_pwd is not None:
            norm_target = urllib.parse.unquote(target_pwd)
            if url_pwd != target_pwd and url_pwd != norm_target:
                raise ValueError(
                    "Contradictory Redis credentials: REDIS_PASSWORD does not match the password supplied in REDIS_URL."
                )

        # SSL / mTLS parameter resolution: distinguish omitted (_UNSET) from explicitly passed (including None)
        changed_ssl_certfile = (ssl_certfile is not _UNSET)
        new_ssl_certfile = (ssl_certfile.strip() if (isinstance(ssl_certfile, str) and ssl_certfile.strip()) else None) if changed_ssl_certfile else self.ssl_certfile

        changed_ssl_keyfile = (ssl_keyfile is not _UNSET)
        new_ssl_keyfile = (ssl_keyfile.strip() if (isinstance(ssl_keyfile, str) and ssl_keyfile.strip()) else None) if changed_ssl_keyfile else self.ssl_keyfile

        changed_ssl_ca_certs = (ssl_ca_certs is not _UNSET)
        new_ssl_ca_certs = (ssl_ca_certs.strip() if (isinstance(ssl_ca_certs, str) and ssl_ca_certs.strip()) else None) if changed_ssl_ca_certs else self.ssl_ca_certs

        changed_ssl_cert_reqs = (ssl_cert_reqs is not _UNSET)
        new_ssl_cert_reqs = (ssl_cert_reqs.strip() if (isinstance(ssl_cert_reqs, str) and ssl_cert_reqs.strip()) else None) if changed_ssl_cert_reqs else self.ssl_cert_reqs

        changed_ssl_check_hostname = (ssl_check_hostname is not _UNSET)
        if changed_ssl_check_hostname:
            if ssl_check_hostname is not None and not isinstance(ssl_check_hostname, bool):
                raise ValueError(f"ssl_check_hostname must be a boolean or None, got {type(ssl_check_hostname).__name__}")
            new_ssl_check_hostname = ssl_check_hostname
        else:
            new_ssl_check_hostname = self.ssl_check_hostname

        target_is_rediss = target_url.startswith("rediss://")
        target_is_plain = target_url.startswith("redis://")

        if target_is_plain and (new_ssl_certfile or new_ssl_keyfile or new_ssl_ca_certs):
            raise ValueError(
                "Insecure TLS configuration: plain 'redis://' connection scheme cannot claim TLS or use SSL/mTLS parameters. "
                "REDIS_URL must use the 'rediss://' scheme for TLS connections."
            )

        if target_is_rediss and (new_ssl_certfile or new_ssl_keyfile):
            if not new_ssl_certfile or not new_ssl_keyfile:
                raise ValueError("mTLS configuration requires both ssl_certfile and ssl_keyfile.")
            if not os.path.isfile(new_ssl_certfile):
                raise ValueError(f"mTLS client certificate file does not exist: {new_ssl_certfile!r}")
            if not os.path.isfile(new_ssl_keyfile):
                raise ValueError(f"mTLS client private key file does not exist: {new_ssl_keyfile!r}")

        if target_is_rediss and new_ssl_ca_certs and not os.path.isfile(new_ssl_ca_certs):
            raise ValueError(f"mTLS CA certificate file does not exist: {new_ssl_ca_certs!r}")

        reconnect_redis = (
            (new_redis_url is not None and new_redis_url != self.redis_url) or
            (changed_redis_password and new_redis_password != self.redis_password) or
            (changed_ssl_certfile and new_ssl_certfile != self.ssl_certfile) or
            (changed_ssl_keyfile and new_ssl_keyfile != self.ssl_keyfile) or
            (changed_ssl_ca_certs and new_ssl_ca_certs != self.ssl_ca_certs) or
            (changed_ssl_cert_reqs and new_ssl_cert_reqs != self.ssl_cert_reqs) or
            (changed_ssl_check_hostname and new_ssl_check_hostname != self.ssl_check_hostname)
        )

        # All validations passed; atomically mutate instance state under lock
        with self._lock:
            if new_capacity is not None:
                self.capacity = new_capacity
            if new_refill_rate is not None:
                self.refill_rate = new_refill_rate
            if new_max_local_keys is not None:
                self.max_local_keys = new_max_local_keys
            if new_failure_mode is not None:
                self.failure_mode = new_failure_mode
            if reconnect_redis:
                if new_redis_url is not None:
                    self.redis_url = new_redis_url
                if changed_redis_password:
                    self.redis_password = new_redis_password
                if changed_ssl_certfile:
                    self.ssl_certfile = new_ssl_certfile
                if changed_ssl_keyfile:
                    self.ssl_keyfile = new_ssl_keyfile
                if changed_ssl_ca_certs:
                    self.ssl_ca_certs = new_ssl_ca_certs
                if changed_ssl_cert_reqs:
                    self.ssl_cert_reqs = new_ssl_cert_reqs
                if changed_ssl_check_hostname:
                    self.ssl_check_hostname = new_ssl_check_hostname
                self._init_redis()

    def _init_redis(self):
        """Initialize Redis connection and register Lua script."""
        try:
            kwargs = {
                "decode_responses": True,
                "socket_connect_timeout": 1.0,
                "socket_timeout": 1.0,
            }
            if self.redis_url.startswith("rediss://"):
                if self.ssl_certfile:
                    kwargs["ssl_certfile"] = self.ssl_certfile
                if self.ssl_keyfile:
                    kwargs["ssl_keyfile"] = self.ssl_keyfile
                if self.ssl_ca_certs:
                    kwargs["ssl_ca_certs"] = self.ssl_ca_certs
                kwargs["ssl_cert_reqs"] = self.ssl_cert_reqs or "required"
                kwargs["ssl_check_hostname"] = self.ssl_check_hostname if self.ssl_check_hostname is not None else True

            parsed = urllib.parse.urlsplit(self.redis_url)
            url_pwd = urllib.parse.unquote(parsed.password) if parsed.password is not None else None
            if parsed.password:
                if self.redis_password:
                    norm_env = urllib.parse.unquote(self.redis_password)
                    if url_pwd != self.redis_password and url_pwd != norm_env:
                        raise ValueError(
                            "Contradictory Redis credentials: REDIS_PASSWORD does not match the password supplied in REDIS_URL."
                        )
            elif self.redis_password:
                kwargs["password"] = self.redis_password

            self.redis = redis.from_url(self.redis_url, **kwargs)
            self._register_script()
        except ValueError:
            raise
        except Exception as e:
            self.redis = None
            self.check_limit_script = None
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                clean_err = sanitize_redis_error_message(e)
                raise RedisUnavailableError(f"Redis initialization failed: {clean_err}") from e

    def verify_connection(self, timeout: float = 1.0) -> bool:
        """
        Validates Redis reachability and authentication during application startup
        using a bounded-time socket PING command without background worker threads.

        Under FAIL_CLOSED:
          - Raises RedisUnavailableError (with sanitized error messages) if Redis is
            unreachable, down, authentication fails, or execution exceeds timeout.
        Under FAIL_OPEN / LOCAL_FALLBACK:
          - Returns False if unreachable, auth fails, or times out, permitting graceful degradation.
        """
        timeout_val = validate_positive_number("timeout", timeout)
        if not self.redis:
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                raise RedisUnavailableError("Rate limiter service unavailable (Redis client not configured)")
            return False

        conn = None
        try:
            # Enforce bounded Redis socket operation without background worker threads
            pool = getattr(self.redis, "connection_pool", None)
            if pool is not None and hasattr(pool, "connection_class") and hasattr(pool, "connection_kwargs"):
                conn_class = pool.connection_class
                conn_kwargs = dict(pool.connection_kwargs)
                conn_kwargs["socket_connect_timeout"] = timeout_val
                conn_kwargs["socket_timeout"] = timeout_val
                conn = conn_class(**conn_kwargs)
                conn.send_command("PING")
                res = conn.read_response()
                return bool(str(res).upper() in ("PONG", "TRUE", "OK", "1") or res is True)
            else:
                # Client does not expose a standard connection pool (e.g. mock or custom wrapper).
                # Execute bounded ping using a daemon worker with join(timeout) to never hang indefinitely.
                result_box = []
                err_box = []

                def _do_ping():
                    try:
                        result_box.append(self.redis.ping())
                    except Exception as err:
                        err_box.append(err)

                worker = threading.Thread(target=_do_ping, daemon=True)
                worker.start()
                worker.join(timeout=timeout_val)

                if worker.is_alive():
                    raise TimeoutError(f"Redis connectivity check timed out after {timeout_val}s")
                if err_box:
                    raise err_box[0]
                if result_box:
                    res = result_box[0]
                    return bool(str(res).upper() in ("PONG", "TRUE", "OK", "1") or res is True)
                return False
        except (redis.TimeoutError, TimeoutError, socket.timeout) as e:
            clean_err = f"Redis connectivity check timed out after {timeout_val}s"
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                raise RedisUnavailableError(
                    f"Rate limiter startup connectivity check failed: {clean_err}"
                ) from e
            return False
        except (redis.RedisError, OSError) as e:
            clean_err = sanitize_redis_error_message(e)
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                raise RedisUnavailableError(
                    f"Rate limiter startup connectivity check failed (Redis unreachable or authentication failed: {clean_err})"
                ) from e
            return False
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass

    def _register_script(self):
        """Register the Lua script with Redis."""
        if self.redis:
            try:
                self.check_limit_script = self.redis.register_script(self.LUA_TOKEN_BUCKET)
            except Exception:
                self.check_limit_script = None

    def _get_config_snapshot(self) -> _ConfigSnapshot:
        """
        Reads capacity, refill_rate, failure_mode, and max_local_keys together under self._lock.
        Returns an immutable _ConfigSnapshot guaranteeing that the caller operates on a consistent,
        non-torn configuration version even during concurrent configure() mutations.
        """
        with self._lock:
            return _ConfigSnapshot(
                capacity=self.capacity,
                refill_rate=self.refill_rate,
                failure_mode=self.failure_mode,
                max_local_keys=self.max_local_keys
            )

    def check_limit(self, user_id: str, tokens: Union[int, float] = 1) -> RateLimitResult:
        """
        Evaluates rate limit and returns detailed telemetry including remaining tokens,
        reset duration, and retry-after guidance for RFC-compliant HTTP headers.
        """
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        user_id = user_id.strip()

        tokens = validate_tokens_requested(tokens)

        # 1. Obtain consistent configuration snapshot under lock
        snapshot = self._get_config_snapshot()

        # 2. Validate requested tokens against snapshot capacity
        if tokens > snapshot.capacity:
            raise ValueError(
                f"tokens requested ({tokens}) exceeds maximum bucket capacity ({snapshot.capacity})"
            )

        # 3. Evaluate limit via Redis Lua script if reachable
        if self.redis and self.check_limit_script:
            key = f"rate_limit:{user_id}"
            try:
                result = self.check_limit_script(
                    keys=[key],
                    args=[snapshot.capacity, snapshot.refill_rate, tokens]
                )
                try:
                    if not isinstance(result, (list, tuple)) or len(result) < 2:
                        raise ValueError(f"Malformed Lua response: expected sequence of at least 2 elements, got {result!r}")

                    raw_allowed = result[0]
                    if raw_allowed not in (0, 1):
                        raise ValueError(f"Malformed Lua response: invalid allowed indicator {raw_allowed!r}")
                    allowed = bool(raw_allowed == 1)

                    raw_remaining = result[1]
                    if isinstance(raw_remaining, bool):
                        raise TypeError(f"Malformed Lua response: boolean remaining tokens {raw_remaining!r}")

                    remaining_float = float(raw_remaining)
                    if math.isnan(remaining_float) or math.isinf(remaining_float) or remaining_float < 0:
                        raise ValueError(f"Malformed Lua response: invalid remaining tokens value {remaining_float!r}")
                    remaining = remaining_float
                except (TypeError, IndexError, ValueError) as parse_err:
                    return self._handle_check_limit_failure(user_id, tokens, parse_err, snapshot=snapshot)

                reset_after = max(0.0, (snapshot.capacity - remaining) / snapshot.refill_rate)
                retry_after = max(1, math.ceil((tokens - remaining) / snapshot.refill_rate)) if not allowed else None
                return RateLimitResult(
                    allowed=allowed,
                    limit=snapshot.capacity,
                    remaining=remaining,
                    reset_after=reset_after,
                    retry_after=retry_after
                )
            except (redis.RedisError, redis.ConnectionError, TimeoutError, OSError) as e:
                return self._handle_check_limit_failure(user_id, tokens, e, snapshot=snapshot)

        return self._handle_check_limit_failure(
            user_id, tokens, ConnectionError("Redis is not connected"), snapshot=snapshot
        )
    
    def _handle_check_limit_failure(
        self,
        user_id: str,
        tokens: Union[int, float],
        error: Exception,
        snapshot: Optional[_ConfigSnapshot] = None
    ) -> RateLimitResult:
        if snapshot is None:
            snapshot = self._get_config_snapshot()

        if snapshot.failure_mode == FailureMode.FAIL_CLOSED:
            clean_error = sanitize_redis_error_message(error)
            raise RedisUnavailableError(f"Rate limiter service unavailable (Redis down: {clean_error})") from error

        if snapshot.failure_mode == FailureMode.FAIL_OPEN:
            return RateLimitResult(
                allowed=True,
                limit=snapshot.capacity,
                remaining=snapshot.capacity,
                reset_after=0.0,
                retry_after=None
            )

        # LOCAL_FALLBACK Mode
        now = time.time()
        with self._lock:
            # Enforce memory bounds using live configured max_local_keys under lock
            effective_max_keys = self.max_local_keys
            if len(self._local_buckets) > effective_max_keys:
                cutoff = now - 3600.0
                stale_keys = [k for k, (_, last_t) in self._local_buckets.items() if last_t < cutoff]
                for k in stale_keys:
                    del self._local_buckets[k]
                if len(self._local_buckets) > effective_max_keys:
                    sorted_items = sorted(self._local_buckets.items(), key=lambda item: item[1][1])
                    evict_count = max(1, int(effective_max_keys * 0.2))
                    for k, _ in sorted_items[:evict_count]:
                        del self._local_buckets[k]

            current_tokens, last_updated = self._local_buckets.get(user_id, (snapshot.capacity, now))
            effective_now = max(now, last_updated)
            delta = effective_now - last_updated
            refilled = min(snapshot.capacity, current_tokens + (delta * snapshot.refill_rate))

            if refilled >= tokens:
                remaining = refilled - tokens
                self._local_buckets[user_id] = (remaining, effective_now)
                reset_after = max(0.0, (snapshot.capacity - remaining) / snapshot.refill_rate)
                return RateLimitResult(
                    allowed=True,
                    limit=snapshot.capacity,
                    remaining=remaining,
                    reset_after=reset_after,
                    retry_after=None
                )
            else:
                self._local_buckets[user_id] = (refilled, effective_now)
                reset_after = max(0.0, (snapshot.capacity - refilled) / snapshot.refill_rate)
                retry_after = max(1, math.ceil((tokens - refilled) / snapshot.refill_rate))
                return RateLimitResult(
                    allowed=False,
                    limit=snapshot.capacity,
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
