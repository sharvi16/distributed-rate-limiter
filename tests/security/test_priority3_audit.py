"""
Priority 3 Audit Regression Tests: Operations, Multi-Worker Metrics & Deployment Security.

Covers:
  1. Metrics Endpoint Access Control (Priority 3, Item 9):
     - Unauthenticated access allowed in development/test when unprotected.
     - Access strictly protected in production (fail-closed).
     - Protected when PROTECT_METRICS=true in any environment.
     - Authorization via x-admin-key, x-metrics-key, or Bearer token using constant-time comparison.
     - Authorization via network CIDR allowlist (METRICS_ALLOWED_CIDRS).
     - Constant-time UTF-8 byte handling for non-ASCII headers.
  2. Multi-Worker Prometheus Metrics (Priority 3, Item 10):
     - Unified cluster-wide aggregation across multiple worker processes via Redis.
     - Process-local metrics tagged with worker PID to observe per-process distribution.
     - Graceful degradation with explicit scope="process" when Redis is unavailable
       (never falsely claiming cluster-wide figures when counters are process-local).
     - Cluster-wide aggregation of abuse engine metrics (jailed, challenges, Sybil, VPN hopping).
  3. Docker & Deployment Configuration Hardening (Priority 3, Item 11):
     - Production startup validation rejects PROTECT_METRICS=false.
     - Production startup validates METRICS_API_KEY length and entropy.
     - Genuine multi-stage Dockerfile structure (builder and runtime separation, non-root user).
     - Docker Compose does not expose Redis port 6379 publicly by default.
     - Docker Compose restricts TRUSTED_PROXIES strictly to actual proxies (no blanket RFC1918 CIDRs).
"""

import os
import re
import uuid
import tempfile
import urllib.parse
from typing import Any, Optional
import multiprocessing as mp
import pytest
import redis
from fastapi.testclient import TestClient

import main
from main import app, limiter, detector
from metrics import MetricsCollector
from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError, mask_redis_url
from auth import (
    validate_auth_configuration,
    validate_redis_configuration,
    get_redis_auth_mode,
    is_redis_auth_required
)


def _mp_metrics_worker_task(redis_url: str, redis_password: Optional[str], status_label: str, count: int, result_queue: Any):
    """
    Top-level helper function for multiprocessing tests (Windows spawn-compatible).
    Simulates a separate OS worker process initializing its own Redis-backed MetricsCollector
    and incrementing request counters.
    """
    client = None
    if redis_url:
        client = redis.from_url(redis_url, password=redis_password, decode_responses=True)
    collector = MetricsCollector(redis_client=client)
    for _ in range(count):
        collector.inc_request(status_label)
    scrape = collector.generate_prometheus_output()
    result_queue.put({
        "pid": os.getpid(),
        "status_label": status_label,
        "count": count,
        "scrape": scrape
    })


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. Metrics Endpoint Access Control (Priority 3, Item 9)
# =============================================================================

class TestMetricsEndpointProtection:
    """Verifies security policy and access controls for the /metrics exposition endpoint."""

    def test_metrics_accessible_without_auth_in_dev_test_when_unprotected(self, client, monkeypatch):
        """In development/test with default configuration, /metrics is accessible for local scraping."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "false")

        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        assert "ratelimit_requests_total" in response.text

    def test_metrics_denies_unauthenticated_request_when_protected_in_dev(self, client, monkeypatch):
        """When PROTECT_METRICS=true is explicitly set in dev/test, unauthenticated access is denied (401)."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret-at-least-32-chars-long-12345")

        response = client.get("/metrics")
        assert response.status_code == 401
        assert "Unauthorized: invalid or missing metrics credentials" in response.json()["detail"]

    def test_metrics_strictly_protected_in_production(self, client, monkeypatch):
        """In production (ENVIRONMENT=production), /metrics must ALWAYS be protected (fail-closed)."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")

        # Unauthenticated scrape denied
        response = client.get("/metrics")
        assert response.status_code == 401
        assert "Unauthorized" in response.json()["detail"]

    def test_metrics_authorized_via_admin_key(self, client, monkeypatch):
        """When protected, a valid x-admin-key header successfully authorizes /metrics scraping."""
        admin_key = "prod-admin-secret-at-least-32-chars-long-12345"
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("ADMIN_API_KEY", admin_key)

        response = client.get("/metrics", headers={"x-admin-key": admin_key})
        assert response.status_code == 200
        assert "ratelimit_requests_total" in response.text

    def test_metrics_authorized_via_metrics_key(self, client, monkeypatch):
        """When protected, a dedicated x-metrics-key header authorizes /metrics scraping."""
        metrics_key = "dedicated-metrics-secret-key-32-chars-long-abc"
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", metrics_key)

        response = client.get("/metrics", headers={"x-metrics-key": metrics_key})
        assert response.status_code == 200
        assert "ratelimit_requests_total" in response.text

    def test_metrics_authorized_via_bearer_token(self, client, monkeypatch):
        """When protected, Authorization: Bearer <key> authorizes /metrics scraping."""
        metrics_key = "dedicated-metrics-secret-key-32-chars-long-abc"
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", metrics_key)

        response = client.get("/metrics", headers={"authorization": f"Bearer {metrics_key}"})
        assert response.status_code == 200
        assert "ratelimit_requests_total" in response.text

    def test_metrics_rejects_incorrect_key(self, client, monkeypatch):
        """When protected, an incorrect key is rejected with HTTP 401."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", "dedicated-metrics-secret-key-32-chars-long-abc")

        response = client.get("/metrics", headers={"x-metrics-key": "wrong-key-value"})
        assert response.status_code == 401
        assert "Unauthorized: invalid or missing metrics credentials" in response.json()["detail"]

    def test_metrics_authorized_via_network_cidr_allowlist(self, monkeypatch):
        """When METRICS_ALLOWED_CIDRS matches the client IP, scraping is authorized without credentials."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", "dedicated-metrics-secret-key-32-chars-long-abc")
        # Allow loopback IP (127.0.0.1) via CIDR subnet
        monkeypatch.setenv("METRICS_ALLOWED_CIDRS", "127.0.0.0/8,10.200.0.0/16")

        c = TestClient(app, client=("127.0.0.1", 50000))
        response = c.get("/metrics")
        assert response.status_code == 200
        assert "ratelimit_requests_total" in response.text

    def test_metrics_denied_when_client_ip_outside_allowed_cidrs(self, monkeypatch):
        """When client IP is outside METRICS_ALLOWED_CIDRS and no key is provided, access is denied (401)."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", "dedicated-metrics-secret-key-32-chars-long-abc")
        # Subnet that does not include 192.168.1.50
        monkeypatch.setenv("METRICS_ALLOWED_CIDRS", "10.0.0.0/24")

        c = TestClient(app, client=("192.168.1.50", 50000))
        response = c.get("/metrics")
        assert response.status_code == 401

    def test_metrics_constant_time_non_ascii_header_safety(self, client, monkeypatch):
        """Non-ASCII unicode characters in metrics authorization headers do not raise unexpected 500 errors."""
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("METRICS_API_KEY", "dedicated-metrics-secret-key-32-chars-long-abc")

        non_ascii_headers = [
            "🔑_unicode_emoji_attack_12345",
            "ñ_accent_unicode_char_£_€",
            "日本語_metrics_token_test",
            "invalid\x00null_byte_sequence"
        ]

        for h in non_ascii_headers:
            response = client.get("/metrics", headers={"x-metrics-key": h.encode("utf-8")})
            assert response.status_code == 401
            assert "Unauthorized" in response.json()["detail"]


# =============================================================================
# 2. Multi-Worker Prometheus Metrics (Priority 3, Item 10)
# =============================================================================

class TestMultiWorkerPrometheusMetrics:
    """Tests Prometheus telemetry under multi-worker and multi-instance concurrency."""

    def test_redis_backed_cluster_wide_counters_aggregate_across_workers(self):
        """
        Simulates two independent worker processes sharing a Redis client.
        Verifies that increments from both workers update the unified cluster-wide total
        and scrapes from both workers return identical cluster-wide metrics.
        """
        if not limiter.redis:
            pytest.skip("Redis not available")

        # Clean test keys
        limiter.redis.delete("metrics:requests_total")
        limiter.redis.delete("metrics:jailed_total")

        # Worker process 1
        worker_1 = MetricsCollector(redis_client=limiter.redis)
        worker_1._pid = 1001

        # Worker process 2
        worker_2 = MetricsCollector(redis_client=limiter.redis)
        worker_2._pid = 1002

        # Worker 1 evaluates 5 allowed requests
        for _ in range(5):
            worker_1.inc_request("allowed")

        # Worker 2 evaluates 7 allowed requests
        for _ in range(7):
            worker_2.inc_request("allowed")

        # Scrape worker 1: cluster-wide metric reflects combined total (5 + 7 = 12)
        out_1 = worker_1.generate_prometheus_output()
        assert 'ratelimit_requests_total{status="allowed",scope="cluster"} 12' in out_1
        # Worker 1 process-local metric shows its individual contribution (5)
        assert 'ratelimit_process_requests_total{status="allowed",pid="1001"} 5' in out_1

        # Scrape worker 2: cluster-wide metric also reflects combined total (12)
        out_2 = worker_2.generate_prometheus_output()
        assert 'ratelimit_requests_total{status="allowed",scope="cluster"} 12' in out_2
        # Worker 2 process-local metric shows its individual contribution (7)
        assert 'ratelimit_process_requests_total{status="allowed",pid="1002"} 7' in out_2

        # Clean up
        limiter.redis.delete("metrics:requests_total")
        limiter.redis.delete("metrics:jailed_total")

    def test_redis_unavailable_fallback_labels_process_scope(self):
        """
        When Redis is disconnected, metrics exposition falls back to process-local counters,
        explicitly labeling scope="process" to avoid misleading claims of cluster-wide totals.
        """
        collector = MetricsCollector(redis_client=None)
        collector._pid = 9999

        collector.inc_request("allowed")
        collector.inc_request("allowed")
        collector.inc_request("rate_limited")

        output = collector.generate_prometheus_output()
        # Explicit process-local labeling
        assert 'scope="process"' in output
        assert 'ratelimit_requests_total{status="allowed",scope="process",pid="9999"} 2' in output
        assert 'ratelimit_requests_total{status="rate_limited",scope="process",pid="9999"} 1' in output
        # Verified documentation in help text
        assert "process-local fallback: Redis unavailable" in output
        # Does not claim cluster-wide scope
        assert 'scope="cluster"' not in output

    def test_all_abuse_metrics_increment_cluster_counters_in_redis(self):
        """Verifies that all abuse detection metrics update cluster counters in Redis."""
        if not limiter.redis:
            pytest.skip("Redis not available")

        keys = [
            "metrics:jailed_total",
            "metrics:challenges_issued_total",
            "metrics:challenges_verified_total",
            "metrics:challenges_exhausted_total",
            "metrics:sybil_detected_total",
            "metrics:vpn_hopping_detected_total"
        ]
        limiter.redis.delete(*keys)

        collector = MetricsCollector(redis_client=limiter.redis)

        collector.inc_jailed()
        collector.inc_challenge_issued()
        collector.inc_challenge_verified()
        collector.inc_challenge_exhausted()
        collector.inc_sybil()
        collector.inc_vpn_hopping()

        output = collector.generate_prometheus_output()
        assert 'ratelimit_jailed_total{scope="cluster"} 1' in output
        assert 'ratelimit_challenges_issued_total{scope="cluster"} 1' in output
        assert 'ratelimit_challenges_verified_total{scope="cluster"} 1' in output
        assert 'ratelimit_challenges_exhausted_total{scope="cluster"} 1' in output
        assert 'ratelimit_sybil_attacks_detected_total{scope="cluster"} 1' in output
        assert 'ratelimit_vpn_hopping_detected_total{scope="cluster"} 1' in output

        limiter.redis.delete(*keys)


# =============================================================================
# 3. Docker & Deployment Configuration Hardening (Priority 3, Item 11)
# =============================================================================

class TestDeploymentAndConfigurationHardening:
    """Verifies operational security, Docker multi-stage build, and deployment configurations."""

    def test_production_startup_fails_if_protect_metrics_is_false(self, monkeypatch):
        """In production, attempting to disable metrics protection (PROTECT_METRICS=false) fails startup."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("PROTECT_METRICS", "false")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")

        with pytest.raises(ValueError, match="PROTECT_METRICS cannot be set to false in a production environment"):
            validate_auth_configuration()

    def test_production_startup_validates_metrics_api_key_length_and_entropy(self, monkeypatch):
        """In production, weak or low-entropy METRICS_API_KEY fails application startup."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")

        # 1. Short key (< 32 chars)
        monkeypatch.setenv("METRICS_API_KEY", "too-short-metrics-key")
        with pytest.raises(ValueError, match="METRICS_API_KEY has insufficient length"):
            validate_auth_configuration()

        # 2. Low entropy key (e.g. repeated chars)
        monkeypatch.setenv("METRICS_API_KEY", "m" * 32)
        with pytest.raises(ValueError, match="METRICS_API_KEY has insufficient cryptographic entropy"):
            validate_auth_configuration()

        # 3. Known placeholder key
        monkeypatch.setenv("METRICS_API_KEY", "change-me-in-production-secret-key-min-32-chars")
        with pytest.raises(ValueError, match="METRICS_API_KEY is configured with a known insecure placeholder"):
            validate_auth_configuration()

    def test_dockerfile_is_genuine_multi_stage(self):
        """Verifies that Dockerfile implements a genuine multi-stage build with non-root security."""
        dockerfile_path = os.path.join(os.path.dirname(__file__), "..", "..", "Dockerfile")
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check multi-stage build instructions
        stages = re.findall(r"FROM\s+[^\s]+\s+AS\s+([^\s\n]+)", content, re.IGNORECASE)
        assert len(stages) >= 2, f"Expected at least 2 build stages in Dockerfile, found: {stages}"
        assert any("builder" in s.lower() for s in stages), "Expected a builder stage in Dockerfile"
        assert any("runtime" in s.lower() for s in stages), "Expected a runtime stage in Dockerfile"

        # Check artifact transfer between stages
        assert "--from=builder" in content, "Expected artifacts to be copied from builder stage"

        # Check non-root security
        assert "USER appuser" in content, "Expected Dockerfile to run as non-root user 'appuser'"
        assert "addgroup" in content and "adduser" in content, "Expected non-root system user/group creation"

    def test_docker_compose_redis_not_publicly_exposed(self):
        """Verifies that docker-compose.yml does NOT publish Redis port 6379 to 0.0.0.0 by default."""
        compose_path = os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Ensure "6379:6379" is not an active (uncommented) port mapping under redis
        lines = content.splitlines()
        redis_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("redis:"):
                redis_section = True
            elif stripped.startswith("api:"):
                redis_section = False

            if redis_section and not stripped.startswith("#"):
                assert "6379:6379" not in stripped, (
                    "Redis port 6379 must not be published publicly by default in docker-compose.yml"
                )

        # Ensure Redis password authentication is configured
        assert "requirepass" in content, "Expected Redis authentication (--requirepass) in docker-compose.yml"

    def test_docker_compose_trusted_proxies_restricted(self):
        """Verifies that docker-compose.yml restricts TRUSTED_PROXIES to actual proxies without blanket RFC1918 CIDRs."""
        compose_path = os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Blanket private ranges must not be present in TRUSTED_PROXIES
        assert "10.0.0.0/8" not in content, "Blanket CIDR 10.0.0.0/8 must not be in TRUSTED_PROXIES"
        assert "172.16.0.0/12" not in content, "Blanket CIDR 172.16.0.0/12 must not be in TRUSTED_PROXIES"
        assert "192.168.0.0/16" not in content, "Blanket CIDR 192.168.0.0/16 must not be in TRUSTED_PROXIES"


# =============================================================================
# 4. Redis Authentication & Password Handling Integration
# =============================================================================

@pytest.fixture
def live_protected_redis():
    """Sets up live local Redis with requirepass and guarantees clean reset in finally."""
    secret = "test_redis_prod_secret_token_12345"
    r = redis.Redis(host="localhost", port=6379, socket_timeout=1.0)
    try:
        r.ping()
    except Exception:
        pytest.skip("Local Redis server not available on localhost:6379 for live auth test")

    r.config_set("requirepass", secret)
    try:
        yield secret
    finally:
        try:
            r_authed = redis.Redis(host="localhost", port=6379, password=secret, socket_timeout=1.0)
            r_authed.config_set("requirepass", "")
        except Exception:
            pass


class TestRedisAuthenticationIntegration:
    """
    Real Redis integration tests using live CONFIG SET requirepass.
    Verifies that password-authenticated Redis connections work seamlessly,
    missing or incorrect credentials fail closed, embedded credentials are preserved,
    and secrets never leak in logs, string representations, or exceptions.
    """

    def test_authenticated_redis_connection_accepted(self, live_protected_redis):
        """RateLimiter connects and executes Lua script successfully with correct password."""
        secret = live_protected_redis
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=secret,
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        assert limiter.is_redis_active() is True
        res = limiter.check_limit(f"test_auth_user_{uuid.uuid4().hex[:8]}")
        assert res.allowed is True
        assert res.limit == 10.0

    def test_missing_redis_password_fails_closed(self, live_protected_redis):
        """RateLimiter with missing password fails closed with RedisUnavailableError (no secret leaked)."""
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=None,
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.check_limit(f"test_user_no_pwd_{uuid.uuid4().hex[:8]}")

        err_msg = str(exc_info.value)
        assert "Authentication" in err_msg or "NOAUTH" in err_msg or "unavailable" in err_msg
        assert live_protected_redis not in err_msg

    def test_incorrect_redis_password_fails_closed(self, live_protected_redis):
        """RateLimiter with wrong password fails closed with RedisUnavailableError without leaking wrong secret."""
        wrong_pwd = "wrong_password_attempt_9999"
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=wrong_pwd,
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.check_limit(f"test_user_wrong_pwd_{uuid.uuid4().hex[:8]}")

        err_msg = str(exc_info.value)
        assert "unavailable" in err_msg or "WRONGPASS" in err_msg or "Authentication" in err_msg
        assert wrong_pwd not in err_msg
        assert live_protected_redis not in err_msg

    def test_both_user_and_ip_limiters_authenticate(self, live_protected_redis, monkeypatch):
        """Both user limiter and IP limiter authenticate and function properly."""
        secret = live_protected_redis
        monkeypatch.setenv("REDIS_PASSWORD", secret)
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")

        user_limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=secret,
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        ip_limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=secret,
            capacity=30,
            refill_rate=2.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )

        assert user_limiter.is_redis_active() is True
        assert ip_limiter.is_redis_active() is True

        user_res = user_limiter.check_limit(f"user_{uuid.uuid4().hex[:8]}")
        ip_res = ip_limiter.check_limit(f"198.51.100.{uuid.uuid4().int % 250}")
        assert user_res.allowed is True
        assert ip_res.allowed is True

    def test_embedded_url_credentials_accepted_and_not_overwritten(self, live_protected_redis):
        """Credentials embedded in REDIS_URL are accepted, not overwritten, and masked in diagnostics."""
        secret = live_protected_redis
        url_with_auth = f"redis://:{secret}@localhost:6379/0"

        limiter = RateLimiter(
            redis_url=url_with_auth,
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        assert limiter.is_redis_active() is True
        res = limiter.check_limit(f"test_url_auth_{uuid.uuid4().hex[:8]}")
        assert res.allowed is True

        # Diagnostic masking
        assert limiter.masked_redis_url == "redis://:***@localhost:6379/0"
        assert secret not in str(limiter)
        assert secret not in repr(limiter)
        assert secret not in limiter.masked_redis_url

    def test_contradictory_credentials_rejected_immediately(self):
        """Contradictory password in REDIS_URL vs REDIS_PASSWORD raises ValueError failing fast."""
        with pytest.raises(ValueError, match="Contradictory Redis credentials"):
            RateLimiter(
                redis_url="redis://:url_password@localhost:6379/0",
                redis_password="different_password_in_env",
                failure_mode=FailureMode.FAIL_CLOSED
            )

    def test_configure_updates_redis_password_transactionally(self, live_protected_redis):
        """RateLimiter.configure() safely updates Redis password and re-connects."""
        secret = live_protected_redis
        # Start with wrong password
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password="incorrect_initial_pwd",
            capacity=10,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        assert limiter.is_redis_active() is False

        # Reconfigure with correct password
        limiter.configure(redis_password=secret)
        assert limiter.is_redis_active() is True
        assert limiter.check_limit(f"reconfigured_user_{uuid.uuid4().hex[:8]}").allowed is True

    def test_percent_encoded_url_credentials_with_special_characters(self):
        """
        Verifies that percent-encoded credentials containing special characters
        (@, :, /, ?, #, %, +) in REDIS_URL are properly normalized and accepted without
        contradiction, and that credentials are NEVER exposed in diagnostics.
        """
        secret = "p@ss:w/ord?#%+ "
        r = redis.Redis(host="localhost", port=6379, socket_timeout=1.0)
        try:
            r.ping()
        except Exception:
            pytest.skip("Local Redis server not available on localhost:6379 for live special characters test")

        r.config_set("requirepass", secret)
        try:
            encoded_secret = urllib.parse.quote(secret, safe="")
            url_with_encoded_auth = f"redis://default:{encoded_secret}@localhost:6379/0"

            # 1. Matches env password without false contradiction error
            limiter = RateLimiter(
                redis_url=url_with_encoded_auth,
                redis_password=secret,
                capacity=10,
                refill_rate=1.0,
                failure_mode=FailureMode.FAIL_CLOSED
            )
            assert limiter.is_redis_active() is True
            res = limiter.check_limit(f"user_special_{uuid.uuid4().hex[:8]}")
            assert res.allowed is True

            # 2. Diagnostics mask all special characters cleanly
            masked = limiter.masked_redis_url
            assert masked == "redis://default:***@localhost:6379/0"
            assert secret not in masked
            assert encoded_secret not in masked
            assert secret not in str(limiter)
            assert secret not in repr(limiter)
        finally:
            try:
                r_reset = redis.Redis(host="localhost", port=6379, password=secret, socket_timeout=1.0)
                r_reset.config_set("requirepass", "")
            except Exception:
                pass

    def test_preserve_redis_password_leading_trailing_whitespace_initialization(self, monkeypatch):
        """
        Verifies that passwords containing leading and trailing spaces or special characters
        are preserved intact without destructive .strip() across RateLimiter, main.py,
        and sync_rate_limiter_configuration(), and only an empty string is treated as unset.
        """
        secret_with_spaces = "   secret_with_surrounding_spaces_123   "

        # 1. RateLimiter direct initialization preserves whitespace
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=secret_with_spaces,
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        assert limiter.redis_password == secret_with_spaces
        assert limiter.redis_password.startswith("   ")
        assert limiter.redis_password.endswith("   ")

        # 2. URL-embedded and environment credentials with whitespace match without false contradiction
        encoded_pwd = urllib.parse.quote(secret_with_spaces, safe="")
        url_with_spaces = f"redis://:{encoded_pwd}@localhost:6379/0"
        limiter_url = RateLimiter(
            redis_url=url_with_spaces,
            redis_password=secret_with_spaces,
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        assert limiter_url.redis_password == secret_with_spaces

        # 3. Application initialization and lifespan sync in main.py preserves whitespace
        monkeypatch.setenv("REDIS_PASSWORD", secret_with_spaces)
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
        main.sync_rate_limiter_configuration()
        assert main.limiter.redis_password == secret_with_spaces
        assert main.ip_limiter.redis_password == secret_with_spaces

        # 4. Empty string is treated as unset password (None)
        limiter_empty = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password="",
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        assert limiter_empty.redis_password is None


# =============================================================================
# 5. Redis Startup Validation
# =============================================================================

class TestRedisStartupValidation:
    """Validates startup-time configuration enforcement for Redis authentication."""

    def test_production_default_requires_redis_auth(self, monkeypatch):
        """Production requires Redis authentication by default even if REDIS_AUTH_REQUIRED is unset."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.delenv("REDIS_AUTH_REQUIRED", raising=False)
        monkeypatch.delenv("REQUIRE_REDIS_AUTH", raising=False)
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")

        with pytest.raises(RuntimeError, match="Redis authentication is mandatory in production by default"):
            validate_auth_configuration()

    def test_production_rejects_redis_auth_required_false(self, monkeypatch):
        """Production strictly prohibits setting REDIS_AUTH_REQUIRED=false without an attested alternative."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_AUTH_REQUIRED", "false")

        with pytest.raises(ValueError, match="REDIS_AUTH_REQUIRED cannot be set to false in a production environment"):
            validate_auth_configuration()

    def test_production_fails_when_redis_password_is_placeholder(self, monkeypatch):
        """Production startup fails if Redis password is a known insecure placeholder."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_PASSWORD", "password")

        with pytest.raises(ValueError, match="known insecure placeholder"):
            validate_auth_configuration()

    def test_production_fails_when_redis_password_too_short(self, monkeypatch):
        """Production startup fails if Redis password is too short (< 16 chars)."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_PASSWORD", "short_pwd")

        with pytest.raises(ValueError, match="insufficient length"):
            validate_auth_configuration()

    def test_development_permits_passwordless_redis(self, monkeypatch):
        """Development explicitly permits passwordless Redis and REDIS_AUTH_REQUIRED=false."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("REQUIRE_AUTH", "false")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
        monkeypatch.setenv("REDIS_AUTH_REQUIRED", "false")
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
        validate_auth_configuration()  # Must not raise

    def test_development_permits_redis_auth_mode_none(self, monkeypatch):
        """Development explicitly permits REDIS_AUTH_MODE=none."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("REQUIRE_AUTH", "false")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
        monkeypatch.setenv("REDIS_AUTH_MODE", "none")
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)
        validate_auth_configuration()  # Must not raise

    def test_production_rejects_redis_auth_mode_none(self, monkeypatch):
        """Production strictly prohibits REDIS_AUTH_MODE=none."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_AUTH_MODE", "none")

        with pytest.raises(ValueError, match="REDIS_AUTH_MODE=none .* is strictly prohibited in production"):
            validate_auth_configuration()

    def test_iam_mode_strictly_rejected(self, monkeypatch):
        """REDIS_AUTH_MODE=iam is rejected with NotImplementedError because no IAM provider is implemented."""
        monkeypatch.setenv("REDIS_AUTH_MODE", "iam")
        with pytest.raises(NotImplementedError, match="Redis authentication mode 'iam' is not implemented"):
            validate_auth_configuration()

    def test_unknown_redis_auth_mode_rejected(self, monkeypatch):
        """Unrecognized REDIS_AUTH_MODE values are rejected with ValueError."""
        monkeypatch.setenv("REDIS_AUTH_MODE", "unsupported_protocol_xyz")
        with pytest.raises(ValueError, match="Unknown or unsupported REDIS_AUTH_MODE"):
            validate_auth_configuration()

    def test_mtls_missing_tls_scheme_rejected(self, monkeypatch):
        """REDIS_AUTH_MODE=mtls requires a TLS connection (rediss:// or REDIS_SSL=true)."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_AUTH_MODE", "mtls")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")  # Plain redis://

        with pytest.raises(ValueError, match="REDIS_AUTH_MODE=mtls requires a TLS-enabled Redis connection"):
            validate_auth_configuration()

    def test_mtls_missing_cert_file_rejected(self, monkeypatch):
        """REDIS_AUTH_MODE=mtls requires real certificate files on disk."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_AUTH_MODE", "mtls")
        monkeypatch.setenv("REDIS_URL", "rediss://redis.internal:6379/0")
        monkeypatch.setenv("REDIS_SSL_CERTFILE", "/non/existent/cert.crt")

        with pytest.raises(ValueError, match="REDIS_SSL_CERTFILE is missing or file does not exist"):
            validate_auth_configuration()

    def test_mtls_valid_certificates_accepted(self, monkeypatch):
        """REDIS_AUTH_MODE=mtls succeeds when TLS scheme and valid cert files exist."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key, tempfile.NamedTemporaryFile() as ca:
            monkeypatch.setenv("ENVIRONMENT", "production")
            monkeypatch.setenv("REQUIRE_AUTH", "true")
            monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
            monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
            monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
            monkeypatch.setenv("PROTECT_METRICS", "true")
            monkeypatch.setenv("REDIS_AUTH_MODE", "mtls")
            monkeypatch.setenv("REDIS_URL", "rediss://redis.internal:6379/0")
            monkeypatch.setenv("REDIS_SSL_CERTFILE", cert.name)
            monkeypatch.setenv("REDIS_SSL_KEYFILE", key.name)
            monkeypatch.setenv("REDIS_SSL_CA_CERTS", ca.name)

            validate_auth_configuration()  # Must succeed!

    def test_network_isolated_requires_explicit_operator_attestation(self, monkeypatch):
        """REDIS_AUTH_MODE=network_isolated requires explicit operator attestation in production."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e")
        monkeypatch.setenv("ADMIN_API_KEY", "prod-admin-secret-at-least-32-chars-long-12345")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "false")
        monkeypatch.setenv("PROTECT_METRICS", "true")
        monkeypatch.setenv("REDIS_AUTH_MODE", "network_isolated")
        monkeypatch.delenv("ATTEST_NETWORK_ISOLATED_REDIS", raising=False)
        monkeypatch.delenv("ALLOW_NETWORK_ISOLATED_REDIS", raising=False)

        # 1. Unattested: strictly rejected
        with pytest.raises(ValueError, match="operator-attested network security boundary"):
            validate_auth_configuration()

        # 2. Operator attested: accepted
        monkeypatch.setenv("ATTEST_NETWORK_ISOLATED_REDIS", "true")
        validate_auth_configuration()


# =============================================================================
# 6. Redis Client mTLS & SSL Runtime Configuration
# =============================================================================

class TestRedisClientMTLSConfiguration:
    """Verifies that redis-py client is genuinely configured with SSLConnection and mTLS certificates."""

    def test_redis_client_configured_with_genuine_ssl_connection_and_certificates(self):
        """RateLimiter creates SSLConnection with exact client cert, private key, and CA bundle."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key, tempfile.NamedTemporaryFile() as ca:
            limiter = RateLimiter(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile=cert.name,
                ssl_keyfile=key.name,
                ssl_ca_certs=ca.name,
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            assert limiter.redis is not None
            assert limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection
            conn_kwargs = limiter.redis.connection_pool.connection_kwargs
            assert conn_kwargs["ssl_certfile"] == cert.name
            assert conn_kwargs["ssl_keyfile"] == key.name
            assert conn_kwargs["ssl_ca_certs"] == ca.name
            assert conn_kwargs["ssl_cert_reqs"] == "required"
            assert conn_kwargs["ssl_check_hostname"] is True

    def test_redis_client_configure_transactionally_updates_ssl_parameters(self):
        """RateLimiter.configure() updates client SSL certificate settings transactionally."""
        with tempfile.NamedTemporaryFile() as cert1, tempfile.NamedTemporaryFile() as key1, tempfile.NamedTemporaryFile() as ca1, \
             tempfile.NamedTemporaryFile() as cert2, tempfile.NamedTemporaryFile() as key2, tempfile.NamedTemporaryFile() as ca2:
            limiter = RateLimiter(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile=cert1.name,
                ssl_keyfile=key1.name,
                ssl_ca_certs=ca1.name,
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            assert limiter.redis.connection_pool.connection_kwargs["ssl_certfile"] == cert1.name

            # Transactionally reconfigure with second certificate set
            limiter.configure(
                ssl_certfile=cert2.name,
                ssl_keyfile=key2.name,
                ssl_ca_certs=ca2.name
            )
            assert limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection
            conn_kwargs = limiter.redis.connection_pool.connection_kwargs
            assert conn_kwargs["ssl_certfile"] == cert2.name
            assert conn_kwargs["ssl_keyfile"] == key2.name
            assert conn_kwargs["ssl_ca_certs"] == ca2.name

    def test_plain_redis_url_rejects_ssl_parameters_in_client(self):
        """RateLimiter strictly rejects using SSL/mTLS parameters with plain redis:// scheme."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key:
            with pytest.raises(ValueError, match="plain 'redis://' connection scheme cannot claim TLS"):
                RateLimiter(
                    redis_url="redis://localhost:6379/0",
                    ssl_certfile=cert.name,
                    ssl_keyfile=key.name,
                    failure_mode=FailureMode.LOCAL_FALLBACK
                )

    def test_redis_ssl_true_cannot_claim_tls_with_plain_scheme(self, monkeypatch):
        """REDIS_SSL=true cannot claim TLS while using a plain redis:// connection."""
        monkeypatch.setenv("REDIS_SSL", "true")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

        # Startup validation rejects
        with pytest.raises(ValueError, match="REDIS_SSL=true cannot claim TLS while using a plain 'redis://' connection scheme"):
            validate_auth_configuration()

        # RateLimiter rejects
        with pytest.raises(ValueError, match="plain 'redis://' connection scheme cannot claim TLS"):
            RateLimiter(
                redis_url="redis://localhost:6379/0",
                failure_mode=FailureMode.LOCAL_FALLBACK
            )

    def test_mtls_requires_both_cert_and_key_in_client(self):
        """Configuring mTLS on rediss:// without private key fails fast."""
        with tempfile.NamedTemporaryFile() as cert:
            with pytest.raises(ValueError, match="mTLS configuration requires both ssl_certfile and ssl_keyfile"):
                RateLimiter(
                    redis_url="rediss://localhost:6379/0",
                    ssl_certfile=cert.name,
                    ssl_keyfile=None,
                    failure_mode=FailureMode.LOCAL_FALLBACK
                )

    def test_application_lifespan_syncs_mtls_configuration_to_client(self, monkeypatch):
        """FastAPI lifespan configuration sync propagates mTLS certificates to application limiters."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key, tempfile.NamedTemporaryFile() as ca:
            monkeypatch.setenv("REDIS_URL", "rediss://localhost:6379/0")
            monkeypatch.setenv("REDIS_SSL_CERTFILE", cert.name)
            monkeypatch.setenv("REDIS_SSL_KEYFILE", key.name)
            monkeypatch.setenv("REDIS_SSL_CA_CERTS", ca.name)

            main.sync_rate_limiter_configuration()

            assert main.limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection
            conn_kwargs = main.limiter.redis.connection_pool.connection_kwargs
            assert conn_kwargs["ssl_certfile"] == cert.name
            assert conn_kwargs["ssl_keyfile"] == key.name
            assert conn_kwargs["ssl_ca_certs"] == ca.name
            assert main.ip_limiter.redis.connection_pool.connection_kwargs["ssl_certfile"] == cert.name

    def test_configure_explicitly_clears_ssl_parameters_transactionally(self):
        """RateLimiter.configure() explicitly clears SSL settings when caller supplies None."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key, tempfile.NamedTemporaryFile() as ca:
            limiter = RateLimiter(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile=cert.name,
                ssl_keyfile=key.name,
                ssl_ca_certs=ca.name,
                ssl_cert_reqs="required",
                ssl_check_hostname=True,
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            assert limiter.ssl_certfile == cert.name
            assert limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection

            # Explicitly clear SSL settings and switch to plain redis://
            limiter.configure(
                redis_url="redis://localhost:6379/0",
                ssl_certfile=None,
                ssl_keyfile=None,
                ssl_ca_certs=None,
                ssl_cert_reqs=None,
                ssl_check_hostname=None
            )

            assert limiter.redis_url == "redis://localhost:6379/0"
            assert limiter.ssl_certfile is None
            assert limiter.ssl_keyfile is None
            assert limiter.ssl_ca_certs is None
            assert limiter.ssl_cert_reqs is None
            assert limiter.ssl_check_hostname is None
            assert limiter.redis.connection_pool.connection_class is redis.connection.Connection
            assert "ssl_certfile" not in limiter.redis.connection_pool.connection_kwargs

    def test_configure_omitted_ssl_parameters_retain_existing_values(self):
        """RateLimiter.configure() does not mutate or clear omitted SSL settings."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key:
            limiter = RateLimiter(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile=cert.name,
                ssl_keyfile=key.name,
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            # Update only capacity and refill rate
            limiter.configure(capacity=50.0, refill_rate=2.0)

            assert limiter.capacity == 50.0
            assert limiter.refill_rate == 2.0
            assert limiter.ssl_certfile == cert.name
            assert limiter.ssl_keyfile == key.name
            assert limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection
            assert limiter.redis.connection_pool.connection_kwargs["ssl_certfile"] == cert.name

    def test_configure_switching_to_plain_redis_without_clearing_ssl_fails_transactionally(self):
        """Switching to plain redis:// without clearing active SSL settings fails with state unchanged."""
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key:
            limiter = RateLimiter(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile=cert.name,
                ssl_keyfile=key.name,
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            # Attempt to switch to plain redis:// without clearing ssl_certfile/keyfile
            with pytest.raises(ValueError, match="plain 'redis://' connection scheme cannot claim TLS"):
                limiter.configure(redis_url="redis://localhost:6379/0")

            # State must remain unmutated
            assert limiter.redis_url == "rediss://localhost:6379/0"
            assert limiter.ssl_certfile == cert.name
            assert limiter.ssl_keyfile == key.name
            assert limiter.redis.connection_pool.connection_class is redis.connection.SSLConnection

    def test_configure_invalid_ssl_file_fails_transactionally(self):
        """Passing nonexistent SSL certificate paths fails fast before mutating state."""
        limiter = RateLimiter(
            redis_url="redis://localhost:6379/0",
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        with pytest.raises(ValueError, match="client certificate file does not exist"):
            limiter.configure(
                redis_url="rediss://localhost:6379/0",
                ssl_certfile="/nonexistent/cert.pem",
                ssl_keyfile="/nonexistent/key.pem"
            )

        assert limiter.redis_url == "redis://localhost:6379/0"
        assert limiter.ssl_certfile is None
        assert limiter.redis.connection_pool.connection_class is redis.connection.Connection


# =============================================================================
# 7. Redis Startup Connectivity & PING Verification
# =============================================================================

class TestRedisStartupConnectivityCheck:
    """Verifies bounded-time Redis connectivity & auth PING during startup."""

    def test_startup_ping_succeeds_with_correct_credentials(self, live_protected_redis):
        """Startup PING succeeds when correct Redis credentials are provided."""
        secret = live_protected_redis
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=secret,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        assert limiter.verify_connection(timeout=1.0) is True

    def test_startup_ping_fails_closed_on_missing_password(self, live_protected_redis):
        """Startup PING fails closed with RedisUnavailableError when password is required but missing."""
        secret = live_protected_redis
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=None,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.verify_connection(timeout=1.0)
        err = str(exc_info.value)
        assert "startup connectivity check failed" in err
        assert secret not in err

    def test_startup_ping_fails_closed_on_incorrect_password(self, live_protected_redis):
        """Startup PING fails closed with RedisUnavailableError when password is incorrect."""
        secret = live_protected_redis
        wrong_pwd = "wrong_test_pass_12345"
        limiter = RateLimiter(
            redis_url="redis://localhost:6379",
            redis_password=wrong_pwd,
            failure_mode=FailureMode.FAIL_CLOSED
        )
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.verify_connection(timeout=1.0)
        err = str(exc_info.value)
        assert "startup connectivity check failed" in err
        assert wrong_pwd not in err
        assert secret not in err

    def test_startup_ping_fails_closed_on_unavailable_redis(self):
        """Startup PING fails closed with RedisUnavailableError when Redis is completely down/unreachable."""
        limiter = RateLimiter(
            redis_url="redis://localhost:6399",  # unreachable port
            redis_password="some_password_12345",
            failure_mode=FailureMode.FAIL_CLOSED
        )
        with pytest.raises(RedisUnavailableError) as exc_info:
            limiter.verify_connection(timeout=0.5)
        err = str(exc_info.value)
        assert "startup connectivity check failed" in err

    def test_startup_ping_graceful_under_fail_open_and_local_fallback(self):
        """Startup PING returns False without raising when failure mode is FAIL_OPEN or LOCAL_FALLBACK."""
        limiter_open = RateLimiter(
            redis_url="redis://localhost:6399",
            redis_password="some_password_12345",
            failure_mode=FailureMode.FAIL_OPEN
        )
        assert limiter_open.verify_connection(timeout=0.5) is False

        limiter_fallback = RateLimiter(
            redis_url="redis://localhost:6399",
            redis_password="some_password_12345",
            failure_mode=FailureMode.LOCAL_FALLBACK
        )
        assert limiter_fallback.verify_connection(timeout=0.5) is False

    def test_verify_connection_respects_custom_timeout_and_fails_closed(self):
        """verify_connection(timeout) enforces socket timeout and raises RedisUnavailableError when connect/read times out."""
        import socket
        import threading
        import time

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                client, _ = server.accept()
                time.sleep(1.0)
                client.close()
            except Exception:
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        try:
            limiter = RateLimiter(
                redis_url=f"redis://127.0.0.1:{port}",
                failure_mode=FailureMode.FAIL_CLOSED
            )
            with pytest.raises(RedisUnavailableError) as exc_info:
                limiter.verify_connection(timeout=0.05)

            err = str(exc_info.value)
            assert "timed out after 0.05s" in err
        finally:
            server.close()

    def test_verify_connection_timeout_returns_false_under_fail_open_and_fallback(self):
        """verify_connection(timeout) returns False without raising when socket times out in fail_open/fallback."""
        import socket
        import threading
        import time

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        port = server.getsockname()[1]

        def serve():
            while True:
                try:
                    client, _ = server.accept()
                    time.sleep(1.0)
                    client.close()
                except Exception:
                    break

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        try:
            limiter_open = RateLimiter(
                redis_url=f"redis://127.0.0.1:{port}",
                failure_mode=FailureMode.FAIL_OPEN
            )
            assert limiter_open.verify_connection(timeout=0.05) is False

            limiter_fallback = RateLimiter(
                redis_url=f"redis://127.0.0.1:{port}",
                failure_mode=FailureMode.LOCAL_FALLBACK
            )
            assert limiter_fallback.verify_connection(timeout=0.05) is False
        finally:
            server.close()

    def test_verify_connection_repeated_timeouts_do_not_accumulate_threads(self):
        """Repeated timed-out verify_connection calls do not leak background worker threads."""
        import socket
        import threading
        import time

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(15)
        port = server.getsockname()[1]

        def serve():
            while True:
                try:
                    client, _ = server.accept()
                    time.sleep(1.0)
                    client.close()
                except Exception:
                    break

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        try:
            limiter = RateLimiter(
                redis_url=f"redis://127.0.0.1:{port}",
                failure_mode=FailureMode.FAIL_CLOSED
            )
            initial_threads = threading.active_count()

            for _ in range(10):
                try:
                    limiter.verify_connection(timeout=0.03)
                except RedisUnavailableError:
                    pass

            # No worker threads should be left behind
            assert threading.active_count() <= initial_threads
        finally:
            server.close()

    def test_verify_connection_rejects_invalid_timeout(self):
        """verify_connection() strictly validates timeout argument."""
        limiter = RateLimiter(redis_url="redis://localhost:6379", failure_mode=FailureMode.LOCAL_FALLBACK)
        with pytest.raises(ValueError, match="timeout must be a positive number"):
            limiter.verify_connection(timeout=-1.0)
        with pytest.raises(ValueError, match="timeout must be a positive number"):
            limiter.verify_connection(timeout=0)
        with pytest.raises(ValueError, match="timeout cannot be a boolean"):
            limiter.verify_connection(timeout=True)
        with pytest.raises(ValueError, match="timeout cannot be NaN"):
            limiter.verify_connection(timeout=float("nan"))
        with pytest.raises(ValueError, match="timeout must be a number"):
            limiter.verify_connection(timeout="0.5")


# =============================================================================
# 6. Multi-Worker Real Multiprocessing Metrics Integration
# =============================================================================

class TestMultiprocessingMetricsIntegration:
    """Verifies multi-worker metrics aggregation using distinct OS processes via multiprocessing."""

    def test_distinct_os_processes_aggregate_cluster_wide_counters(self):
        """Spawns 2 real OS worker processes and verifies cluster-wide totals and PID attribution."""
        r = redis.Redis(host="localhost", port=6379, socket_timeout=1.0)
        try:
            r.ping()
        except Exception:
            pytest.skip("Local Redis server not available on localhost:6379 for multiprocessing test")

        # Reset Redis test metrics keys
        r.delete("metrics:requests_total")

        result_queue = mp.Queue()
        redis_url = "redis://localhost:6379"

        # Worker 1: generates 12 'allowed' requests
        p1 = mp.Process(
            target=_mp_metrics_worker_task,
            args=(redis_url, None, "allowed", 12, result_queue)
        )
        # Worker 2: generates 7 'rate_limited' requests
        p2 = mp.Process(
            target=_mp_metrics_worker_task,
            args=(redis_url, None, "rate_limited", 7, result_queue)
        )

        p1.start()
        p2.start()

        p1.join(timeout=10.0)
        p2.join(timeout=10.0)

        assert p1.exitcode == 0, f"Worker process 1 failed with exit code {p1.exitcode}"
        assert p2.exitcode == 0, f"Worker process 2 failed with exit code {p2.exitcode}"

        # Collect worker results
        results = [result_queue.get(timeout=2.0), result_queue.get(timeout=2.0)]
        pids = {res["pid"] for res in results}

        # Verify two distinct OS PIDs executed
        assert len(pids) == 2, f"Expected 2 distinct OS worker PIDs, got {pids}"
        assert p1.pid in pids
        assert p2.pid in pids

        # Scrape metrics from parent process
        parent_collector = MetricsCollector(redis_client=r)
        parent_scrape = parent_collector.generate_prometheus_output()

        # Cluster-wide totals must equal sum of worker contributions
        assert 'ratelimit_requests_total{status="allowed",scope="cluster"} 12' in parent_scrape
        assert 'ratelimit_requests_total{status="rate_limited",scope="cluster"} 7' in parent_scrape

        # Each worker's individual scrape attributed to its own PID
        for res in results:
            w_pid = res["pid"]
            w_scrape = res["scrape"]
            assert f'pid="{w_pid}"' in w_scrape
            assert "ratelimit_process_requests_total" in w_scrape
