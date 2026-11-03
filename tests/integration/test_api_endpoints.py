"""
Integration tests for FastAPI endpoints (Phase 6).

Verifies:
  - Standard RFC rate limit response headers (X-RateLimit-*, Retry-After).
  - Admin key protection on /model-stats.
  - Rate limiting for verified humans vs unverified burst traffic.
"""

import os
import uuid
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, detector



@pytest.fixture(autouse=True)
def clean_testclient_ip():
    if detector.redis:
        detector.redis.delete("ip_identities:testclient")
        detector.redis.delete("penalty_box:ip:testclient")
        detector.redis.delete("rate_limit:ip:testclient")
        detector.redis.delete("rate_limit:ip:127.0.0.1")
    with detector._lock:
        if hasattr(detector, "_local_ip_identities"):
            detector._local_ip_identities.pop("testclient", None)
            detector._local_ip_identities.pop("127.0.0.1", None)
        if hasattr(detector, "_local_penalties"):
            detector._local_penalties.pop("ip:testclient", None)
            detector._local_penalties.pop("ip:127.0.0.1", None)

@pytest.fixture
def client():
    return TestClient(app)


def test_standard_rate_limit_headers_on_success(client):
    uid = uuid.uuid4().hex[:8]
    user_id = f"test_user_ok_{uid}"
    ua = f"TestAgent/1.0 ({uid})"
    limiter.reset(user_id)
    main.ip_limiter.reset("ip:testclient")

    response = client.get(
        "/limited-resource",
        headers={"user-id": user_id, "user-agent": ua}
    )
    assert response.status_code == 200
    headers = response.headers
    assert "x-ratelimit-limit" in headers
    assert "x-ratelimit-remaining" in headers
    assert "x-ratelimit-reset" in headers
    assert headers["x-ratelimit-limit"] == "10"
    remaining = int(headers["x-ratelimit-remaining"])
    assert 0 <= remaining <= 10


def test_standard_rate_limit_headers_on_token_bucket_exhaustion(client):
    uid = uuid.uuid4().hex[:8]
    user_id = f"test_user_exhaust_{uid}"
    ua = f"TestAgent/1.0 ({uid})"
    limiter.reset(user_id)
    main.ip_limiter.reset("ip:testclient")
    
    # Grant verified human pass so behavioral classifier doesn't jail user before bucket exhausts
    detector.set_verified_human(user_id, duration_seconds=300)

    # Consume all 10 tokens
    for _ in range(10):
        res = client.get("/limited-resource", headers={"user-id": user_id, "user-agent": ua})
        assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.json()}"

    # 11th request must return 429 with Retry-After and X-RateLimit-* headers
    response = client.get(
        "/limited-resource",
        headers={"user-id": user_id, "user-agent": ua}
    )
    assert response.status_code == 429
    headers = response.headers
    assert "retry-after" in headers
    assert int(headers["retry-after"]) >= 1
    assert headers["x-ratelimit-remaining"] == "0"
    assert headers["x-ratelimit-limit"] == "10"


def test_penalty_box_returns_retry_after(client):
    uid = uuid.uuid4().hex[:8]
    user_id = f"test_jailed_{uid}"
    ua = f"TestAgent/1.0 ({uid})"
    # Ensure fresh strike record
    if detector.redis:
        detector.redis.delete(f"strikes:{user_id}")
    detector.jail_user(user_id, duration_seconds=45)

    response = client.get(
        "/limited-resource",
        headers={"user-id": user_id, "user-agent": ua}
    )
    assert response.status_code == 429
    assert "retry-after" in response.headers
    retry_sec = int(response.headers["retry-after"])
    assert 40 <= retry_sec <= 45


def test_admin_api_key_protection_on_model_stats(client, monkeypatch):
    # Test open access when ADMIN_API_KEY is unset
    monkeypatch.setattr(main, "ADMIN_API_KEY", "")
    res_open = client.get("/model-stats")
    assert res_open.status_code == 200

    # Test protected access when ADMIN_API_KEY is configured
    monkeypatch.setattr(main, "ADMIN_API_KEY", "super-secret-admin-key")

    # Missing header -> 401
    res_no_key = client.get("/model-stats")
    assert res_no_key.status_code == 401

    # Wrong key -> 401
    res_wrong_key = client.get("/model-stats", headers={"x-admin-key": "bad-key"})
    assert res_wrong_key.status_code == 401

    # Correct key -> 200
    res_auth = client.get("/model-stats", headers={"x-admin-key": "super-secret-admin-key"})
    assert res_auth.status_code == 200
    data = res_auth.json()
    assert "model_centroids" in data
    assert "metrics" in data


def test_prometheus_metrics_scraping(client):
    # Make request to populate counters
    uid = uuid.uuid4().hex[:8]
    client.get("/limited-resource", headers={"user-id": f"test_metric_{uid}"})

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "# HELP ratelimit_requests_total" in body
    assert "# TYPE ratelimit_requests_total counter" in body
    assert "ratelimit_requests_total{status=" in body
    assert "ratelimit_redis_connected" in body
    assert "ratelimit_model_version" in body
