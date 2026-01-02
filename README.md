# Distributed Rate Limiter

A distributed rate limiter implementation using **FastAPI** and **Redis**, utilizing the **Token Bucket algorithm**.

## Features

- **Token Bucket Algorithm**: Smooth rate limiting allowing for bursts.
- **Distributed State**: Uses Redis to store token buckets, making it suitable for distributed systems.
- **Atomic Operations**: Uses Redis Lua scripts to ensure concurrency safety.
- **FastAPI Integration**: Easy-to-use API endpoint.
- **Error Handling**: Gracefully handles Redis connection failures.

## Prerequisites

- **Python 3.8+**
- **Redis Server** (Must be running locally or accessible via URL)

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/sharvi16/distributed-rate-limiter.git
    cd distributed-rate-limiter
    ```

2.  Create a virtual environment:
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Mac/Linux
    source .venv/bin/activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

The application expects a Redis server. By default, it connects to `redis://localhost:6379`.
You can configure this by setting the `REDIS_URL` environment variable.

## Running the Application

1.  Ensure your Redis server is running.
2.  Start the FastAPI server:
    ```bash
    uvicorn main:app --reload
    ```
    The server will start at `http://127.0.0.1:8000`.

## Usage

### Rate Limited Endpoint

**GET** `/limited-resource`

**Headers:**
- `user_id`: A unique identifier for the user (string).

**Example Request:**

```bash
curl -H "user_id: test_user" http://127.0.0.1:8000/limited-resource
```

**Responses:**

- `200 OK`: Request allowed.
- `429 Too Many Requests`: Rate limit exceeded (10 requests per minute).
- `503 Service Unavailable`: Redis is down.

## Project Structure

- `main.py`: FastAPI application and endpoint definition.
- `rate_limiter.py`: Core logic for the Token Bucket algorithm using Redis Lua scripts.
- `requirements.txt`: Python dependencies.
