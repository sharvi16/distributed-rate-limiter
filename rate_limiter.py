import time
import redis
from typing import Optional

class RateLimiter:
    def __init__(self, redis_url: str = "redis://localhost:6379", capacity: int = 10, refill_rate: float = 10.0 / 60.0):
        """
        Initialize the RateLimiter.

        :param redis_url: URL for the Redis connection.
        :param capacity: Maximum number of tokens in the bucket.
        :param refill_rate: Number of tokens added per second.
        """
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.capacity = capacity
        self.refill_rate = refill_rate
        
        # Lua script for atomic token bucket operations
        # Keys: [rate_limit_key]
        # Args: [capacity, refill_rate, current_timestamp, requested_tokens]
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
            -- Set expiry to clean up inactive keys (e.g., 1 hour)
            redis.call('EXPIRE', key, 3600)
        end

        return allowed
        """
        self.check_limit_script = self.redis.register_script(lua_script_content)

    def is_allowed(self, user_id: str, tokens: int = 1) -> bool:
        """
        Check if the request is allowed for the given user_id.

        :param user_id: The unique identifier for the user.
        :param tokens: Number of tokens required for the request.
        :return: True if allowed, False otherwise.
        """
        key = f"rate_limit:{user_id}"
        now = time.time()
        
        try:
            # Execute the Lua script atomically
            # The registered script handles SHA caching and loading
            result = self.check_limit_script(
                keys=[key],
                args=[self.capacity, self.refill_rate, now, tokens]
            )
            return bool(result)
        except redis.RedisError as e:
            # Fallback or error handling if Redis is unavailable
            print(f"Redis error: {e}")
            # Raise an exception to let the caller handle the infrastructure failure
            raise e
