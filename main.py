from fastapi import FastAPI, Header, HTTPException, status
from rate_limiter import RateLimiter
import os
import redis

app = FastAPI()

# Initialize Rate Limiter
# Using default values: 10 requests per minute
# Capacity = 10, Refill Rate = 10/60 tokens/sec
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
limiter = RateLimiter(redis_url=redis_url, capacity=10, refill_rate=10.0/60.0)

@app.get("/limited-resource")
async def limited_resource(user_id: str = Header(...)):
    """
    Endpoint that is rate limited.
    Requires 'user_id' in headers.
    """
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id header is required")

    try:
        is_allowed = limiter.is_allowed(user_id)
    except redis.RedisError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter service unavailable (Redis down)"
        )

    if is_allowed:
        return {"message": "Request allowed", "user_id": user_id}
    else:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later."
        )

@app.get("/")
async def root():
    return {"message": "Rate Limiter API is running. Use /limited-resource with 'user_id' header."}
