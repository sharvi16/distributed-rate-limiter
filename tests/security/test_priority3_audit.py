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
import pytest
from fastapi.testclient import TestClient

import main
from main import app, limiter, detector
from metrics import MetricsCollector
from auth import validate_auth_configuration


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
