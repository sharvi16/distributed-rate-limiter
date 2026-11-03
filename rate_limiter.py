import time
import threading
from typing import Optional, Dict, Tuple
import redis

class RateLimiter:
    """
    Token Bucket Rate Limiter with Distributed Redis support and
    automatic local in-memory fallback for high availability.
    """
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        capacity: int = 10,
        refill_rate: float = 10.0 / 60.0,
        enable_fallback: bool = True
    ):
        """
        Initialize the RateLimiter.

        :param redis_url: URL for the Redis connection.
        :param capacity: Maximum number of tokens in the bucket.
        :param refill_rate: Number of tokens added per second.
        :param enable_fallback: When True, falls back to in-memory Token Bucket if Redis is down.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.enable_fallback = enable_fallback
        self.redis_url = redis_url
        
        # In-memory storage fallback: user_id -> (tokens, last_updated)
        self._local_buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        
        # Redis connection
        self.redis: Optional[redis.Redis] = None
        self.check_limit_script = None
        self._init_redis()

    def _init_redis(self):
        try:
            self.redis = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5
            )
            # Lua script for atomic token bucket operations in Redis
            lua_script_content = """
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local requested = tonumber(ARGV[4])

            -- Get current state
            local state = redis.call('HMGET', key, 'tokens', 'last_updated')
            local tokens = tonumber(state[1])
            local last_updated = tonumber(state[2])

            -- Initialize if not exists
            if not tokens then
                tokens = capacity
                last_updated = now
            end

            -- Calculate refill
            local delta = math.max(0, now - last_updated)
            local filled_tokens = math.min(capacity, tokens + (delta * refill_rate))

            local allowed = 0
            
            if filled_tokens >= requested then
                filled_tokens = filled_tokens - requested
                allowed = 1
                -- Update state
                redis.call('HMSET', key, 'tokens', filled_tokens, 'last_updated', now)
                -- Set expiry to clean up inactive keys (1 hour)
                redis.call('EXPIRE', key, 3600)
            end

            return allowed
            """
            self.check_limit_script = self.redis.register_script(lua_script_content)
        except Exception as e:
            print(f"Notice: Redis initialization failed ({e}). Fallback active.")

    def is_allowed(self, user_id: str, tokens: int = 1) -> bool:
        """
        Check if the request is allowed for the given user_id.

        :param user_id: The unique identifier for the user.
        :param tokens: Number of tokens required for the request.
        :return: True if allowed, False otherwise.
        """
        now = time.time()
        
        # Attempt Redis check first
        if self.redis and self.check_limit_script:
            key = f"rate_limit:{user_id}"
            try:
                result = self.check_limit_script(
                    keys=[key],
                    args=[self.capacity, self.refill_rate, now, tokens]
                )
                return bool(result)
            except redis.RedisError as e:
                if not self.enable_fallback:
                    raise e
                # Fallback gracefully to in-memory Token Bucket
                pass

        # In-memory Token Bucket algorithm
        with self._lock:
            current_tokens, last_updated = self._local_buckets.get(user_id, (self.capacity, now))
            
            # Refill tokens based on elapsed time
            delta = max(0.0, now - last_updated)
            refilled = min(float(self.capacity), current_tokens + (delta * self.refill_rate))
            
            if refilled >= tokens:
                self._local_buckets[user_id] = (refilled - tokens, now)
                return True
            else:
                self._local_buckets[user_id] = (refilled, now)
                return False

    def is_redis_active(self) -> bool:
        """Helper to check if Redis is currently reachable."""
        if not self.redis:
            return False
        try:
            return bool(self.redis.ping())
        except Exception:
            return False
