# Distributed Rate Limiter

A distributed rate limiter implementation using **FastAPI** and **Redis**, utilizing the **Token Bucket algorithm**.

## Features

- Per-user rate limiting (default: 10 requests/minute)
- Token Bucket algorithm (supports burst traffic)
- Redis-backed shared state (works across multiple servers)
- Atomic operations using Redis Lua scripting
- Proper HTTP responses (200, 429, 503)

## How It Works
- Each user has a token bucket
- Each request consumes 1 token
- Tokens refill gradually over time
- Requests are blocked when tokens run out
- Redis stores token state to support distributed systems

**Responses:**

- `200 OK`: Request allowed.
- `429 Too Many Requests`: Rate limit exceeded (10 requests per minute).
- `503 Service Unavailable`: Redis is down.

## Project Structure

- `main.py`: FastAPI application and endpoint definition.
- `rate_limiter.py`: Core logic for the Token Bucket algorithm using Redis Lua scripts.
- `requirements.txt`: Python dependencies.
