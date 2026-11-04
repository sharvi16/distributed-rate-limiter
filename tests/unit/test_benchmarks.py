"""
Unit tests for the performance benchmarking suite.
Validates statistical aggregations, percentile calculations, result models,
data exporters, chart generators, and configuration models.
"""

import json
import csv
import math
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from benchmarks.config import BenchmarkConfig, EnvironmentMetadata
from benchmarks.aggregator import (
    calculate_percentile,
    LatencyStats,
    BenchmarkResult,
    ResultAggregator
)
from benchmarks.chart_generator import SVGChartGenerator
from benchmarks.core_benchmarks import FaultInjectableRedisClient, _run_engine_load
from benchmarks.http_benchmarks import run_http_load_test


# =============================================================================
# 1. Statistical Percentile Calculations
# =============================================================================

class TestPercentileCalculations:
    """Tests calculate_percentile for correctness under edge cases and distributions."""

    def test_empty_list(self):
        assert calculate_percentile([], 50.0) == 0.0
        assert calculate_percentile([], 99.0) == 0.0

    def test_single_element(self):
        val = 42.5
        assert calculate_percentile([val], 0.0) == val
        assert calculate_percentile([val], 50.0) == val
        assert calculate_percentile([val], 99.0) == val
        assert calculate_percentile([val], 100.0) == val

    def test_boundary_percentiles(self):
        sorted_vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        assert calculate_percentile(sorted_vals, -5.0) == 10.0
        assert calculate_percentile(sorted_vals, 0.0) == 10.0
        assert calculate_percentile(sorted_vals, 100.0) == 50.0
        assert calculate_percentile(sorted_vals, 105.0) == 50.0

    def test_uniform_list(self):
        uniform = [15.0] * 10
        assert calculate_percentile(uniform, 25.0) == 15.0
        assert calculate_percentile(uniform, 50.0) == 15.0
        assert calculate_percentile(uniform, 95.0) == 15.0

    def test_known_ranks_odd_elements(self):
        # 5 elements: n=5, ranks = (p/100) * 4
        # p=0 -> rank=0 -> 10
        # p=25 -> rank=1 -> 20
        # p=50 -> rank=2 -> 30
        # p=75 -> rank=3 -> 40
        # p=100 -> rank=4 -> 50
        sorted_vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        assert calculate_percentile(sorted_vals, 0.0) == 10.0
        assert calculate_percentile(sorted_vals, 25.0) == 20.0
        assert calculate_percentile(sorted_vals, 50.0) == 30.0
        assert calculate_percentile(sorted_vals, 75.0) == 40.0
        assert calculate_percentile(sorted_vals, 100.0) == 50.0

    def test_linear_interpolation_even_elements(self):
        # 4 elements: [10, 20, 30, 40], n=4, max rank=3
        # p=50 -> rank = 0.5 * 3 = 1.5 -> weight = 0.5 -> 20*0.5 + 30*0.5 = 25.0
        sorted_vals = [10.0, 20.0, 30.0, 40.0]
        assert calculate_percentile(sorted_vals, 50.0) == 25.0
        # p=25 -> rank = 0.25 * 3 = 0.75 -> weight = 0.75 -> 10*0.25 + 20*0.75 = 17.5
        assert calculate_percentile(sorted_vals, 25.0) == 17.5


# =============================================================================
# 2. LatencyStats
# =============================================================================

class TestLatencyStats:
    """Tests LatencyStats extraction from raw latency observations."""

    def test_empty_latencies(self):
        stats = LatencyStats.from_latencies([])
        assert stats.count == 0
        assert stats.mean_ms == 0.0
        assert stats.std_dev_ms == 0.0
        assert stats.min_ms == 0.0
        assert stats.p50_ms == 0.0
        assert stats.p90_ms == 0.0
        assert stats.p95_ms == 0.0
        assert stats.p99_ms == 0.0
        assert stats.max_ms == 0.0

    def test_single_latency(self):
        stats = LatencyStats.from_latencies([5.5])
        assert stats.count == 1
        assert stats.mean_ms == 5.5
        assert stats.std_dev_ms == 0.0
        assert stats.min_ms == 5.5
        assert stats.p50_ms == 5.5
        assert stats.max_ms == 5.5

    def test_multi_latencies(self):
        lats = [10.0, 20.0, 30.0, 40.0, 50.0]
        stats = LatencyStats.from_latencies(lats)
        assert stats.count == 5
        assert stats.mean_ms == 30.0
        assert stats.min_ms == 10.0
        assert stats.max_ms == 50.0
        assert stats.p50_ms == 30.0
        assert stats.std_dev_ms == pytest.approx(14.142, abs=0.01)

    def test_to_dict(self):
        stats = LatencyStats.from_latencies([1.0, 2.0, 3.0])
        d = stats.to_dict()
        assert isinstance(d, dict)
        assert d["count"] == 3
        assert "mean_ms" in d
        assert "p99_ms" in d


# =============================================================================
# 3. BenchmarkResult
# =============================================================================

class TestBenchmarkResult:
    """Tests creation, rate calculation, and serialization of BenchmarkResult."""

    def test_result_creation_and_metrics(self):
        latencies = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        status_codes = {200: 8, 429: 2}
        result = BenchmarkResult.create(
            scenario_name="test_scenario",
            concurrency=10,
            workers=2,
            duration_seconds=2.0,
            latencies_ms=latencies,
            status_codes=status_codes,
            error_count=0
        )
        assert result.scenario_name == "test_scenario"
        assert result.concurrency == 10
        assert result.workers == 2
        assert result.total_requests == 10
        assert result.successful_requests == 8
        assert result.rate_limited_requests == 2
        assert result.error_requests == 0
        assert result.requests_per_second == 5.0  # 10 reqs / 2.0s
        assert result.error_rate_percent == 0.0
        assert result.latency.count == 10
        assert result.latency.min_ms == 1.0
        assert result.latency.max_ms == 10.0

    def test_result_with_server_errors(self):
        status_codes = {200: 5, 500: 3, 503: 2}
        result = BenchmarkResult.create(
            scenario_name="error_scenario",
            concurrency=5,
            workers=1,
            duration_seconds=1.0,
            latencies_ms=[10.0] * 11,
            status_codes=status_codes,
            error_count=1
        )
        # Total = 5 (200) + 3 (500) + 2 (503) + 1 (transport error) = 11
        assert result.total_requests == 11
        # Server errors = 3 + 2 + 1 = 6
        assert result.error_requests == 6
        assert result.error_rate_percent == pytest.approx(54.55, abs=0.01)

    def test_serialization(self):
        result = BenchmarkResult.create(
            scenario_name="serial_test",
            concurrency=1,
            workers=1,
            duration_seconds=1.0,
            latencies_ms=[2.5],
            status_codes={200: 1}
        )
        d = result.to_dict()
        assert d["scenario_name"] == "serial_test"
        assert d["requests_per_second"] == 1.0
        # Ensure json serializable
        encoded = json.dumps(d)
        assert "serial_test" in encoded


# =============================================================================
# 4. ResultAggregator
# =============================================================================

class TestResultAggregator:
    """Tests aggregation and JSON/CSV file exports."""

    def test_export_json_and_csv(self, tmp_path):
        aggregator = ResultAggregator(output_dir=tmp_path)

        r1 = BenchmarkResult.create(
            scenario_name="scenario_a",
            concurrency=10,
            workers=1,
            duration_seconds=5.0,
            latencies_ms=[1.0, 2.0, 3.0],
            status_codes={200: 3}
        )
        r2 = BenchmarkResult.create(
            scenario_name="scenario_b",
            concurrency=50,
            workers=2,
            duration_seconds=5.0,
            latencies_ms=[4.0, 5.0, 6.0],
            status_codes={200: 3}
        )
        aggregator.add_result(r1)
        aggregator.add_result(r2)

        data = {
            "environment": {"redis_version": "7.0.0", "redis_mode": "distributed"},
            "benchmarks": [r1.to_dict(), r2.to_dict()]
        }

        json_path = aggregator.save_json("results.json", data)
        csv_path = aggregator.save_csv("results.csv", [r1, r2])

        assert json_path.exists()
        assert csv_path.exists()

        # Check JSON structure
        with open(json_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            assert "environment" in loaded
            assert loaded["environment"]["redis_version"] == "7.0.0"
            assert "benchmarks" in loaded
            assert len(loaded["benchmarks"]) == 2
            assert loaded["benchmarks"][0]["scenario_name"] == "scenario_a"

        # Check CSV structure
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["scenario_name"] == "scenario_a"
            assert float(rows[0]["concurrency"]) == 10
            assert rows[1]["scenario_name"] == "scenario_b"


# =============================================================================
# 5. SVGChartGenerator
# =============================================================================

class TestSVGChartGenerator:
    """Tests vector SVG chart generation with valid XML/SVG output."""

    def test_svg_escape(self):
        escaped = SVGChartGenerator._svg_escape("<test> & 'quotes' \"here\"")
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "&amp;" in escaped
        assert "&#39;" in escaped
        assert "&quot;" in escaped

    def test_generate_line_chart(self, tmp_path):
        out_svg = tmp_path / "line_chart.svg"
        x_vals = [1, 10, 50, 100]
        series = {
            "1 Worker": [150.0, 450.0, 850.0, 920.0],
            "2 Workers": [160.0, 500.0, 1100.0, 1300.0]
        }
        res_path = SVGChartGenerator.generate_line_chart(
            title="Throughput vs Concurrency",
            x_label="Concurrent Clients",
            y_label="Requests / Second",
            x_values=x_vals,
            series=series,
            output_path=out_svg
        )
        assert res_path.exists()
        content = res_path.read_text(encoding="utf-8")
        assert content.startswith("<svg")
        assert content.endswith("</svg>")
        assert "Throughput vs Concurrency" in content
        assert "Concurrent Clients" in content
        assert "Requests / Second" in content
        assert "1 Worker" in content
        assert "2 Workers" in content
        assert "<polyline" in content

    def test_generate_bar_chart(self, tmp_path):
        out_svg = tmp_path / "bar_chart.svg"
        categories = ["Baseline", "FAIL_CLOSED", "FAIL_OPEN", "LOCAL_FALLBACK"]
        series = {
            "Throughput (RPS)": [1200.0, 0.0, 800.0, 1400.0]
        }
        res_path = SVGChartGenerator.generate_bar_chart(
            title="Redis Outage Failure Modes",
            x_label="Strategy",
            y_label="Requests / Second",
            categories=categories,
            series=series,
            output_path=out_svg
        )
        assert res_path.exists()
        content = res_path.read_text(encoding="utf-8")
        assert content.startswith("<svg")
        assert content.endswith("</svg>")
        assert "Redis Outage Failure Modes" in content
        assert "<rect" in content
        assert "LOCAL_FALLBACK" in content

    def test_empty_series_handling(self, tmp_path):
        out_svg = tmp_path / "empty.svg"
        res_path = SVGChartGenerator.generate_line_chart(
            title="Empty Test",
            x_label="X",
            y_label="Y",
            x_values=[1, 2],
            series={"Empty": [0.0, 0.0]},
            output_path=out_svg
        )
        assert res_path.exists()
        content = res_path.read_text(encoding="utf-8")
        assert "<svg" in content


# =============================================================================
# 6. BenchmarkConfig and EnvironmentMetadata
# =============================================================================

class TestBenchmarkConfig:
    """Tests configuration defaults, overrides, and environment capture."""

    def test_default_config(self):
        cfg = BenchmarkConfig()
        assert cfg.concurrency_levels == [1, 10, 50, 100, 250, 500]
        assert cfg.worker_counts == [1, 2, 4]
        assert cfg.base_url == "http://127.0.0.1:8000"
        assert not cfg.quick_mode

    def test_quick_mode_overrides(self):
        cfg = BenchmarkConfig(quick_mode=True)
        assert cfg.concurrency_levels == [1, 10, 50]
        assert cfg.worker_counts == [1, 2]
        assert cfg.duration_seconds == 2.0
        assert cfg.warmup_requests == 20

    def test_custom_output_dir_conversion(self, tmp_path):
        cfg = BenchmarkConfig(output_dir=str(tmp_path / "custom"))
        assert isinstance(cfg.output_dir, Path)
        assert cfg.output_dir == tmp_path / "custom"

    def test_environment_metadata_collection(self):
        env = EnvironmentMetadata()
        assert env.os_name != ""
        assert env.cpu_cores > 0
        assert env.python_version != ""
        assert env.timestamp_utc.endswith("Z")
        d = env.to_dict()
        assert "os_name" in d
        assert "cpu_cores" in d


# =============================================================================
# 7. Aggregator Strict Validation & Error Handling
# =============================================================================

class TestAggregatorValidation:
    """Tests strict validation of durations, request consistency, and sample counts."""

    @pytest.mark.parametrize("invalid_dur", [0.0, -1.0, -0.001, float("nan"), float("inf"), "invalid"])
    def test_non_positive_or_non_finite_duration_raises(self, invalid_dur):
        with pytest.raises(ValueError, match="duration_seconds must be a positive finite number"):
            BenchmarkResult.create(
                scenario_name="test_dur",
                concurrency=1,
                workers=1,
                duration_seconds=invalid_dur,
                latencies_ms=[1.0],
                status_codes={200: 1}
            )

    def test_negative_error_count_raises(self):
        with pytest.raises(ValueError, match="error_count cannot be negative"):
            BenchmarkResult.create(
                scenario_name="test_err_cnt",
                concurrency=1,
                workers=1,
                duration_seconds=1.0,
                latencies_ms=[],
                status_codes={200: 1},
                error_count=-1
            )

    def test_negative_status_code_count_raises(self):
        with pytest.raises(ValueError, match="status code count cannot be negative"):
            BenchmarkResult.create(
                scenario_name="test_neg_status",
                concurrency=1,
                workers=1,
                duration_seconds=1.0,
                latencies_ms=[],
                status_codes={200: -5}
            )

    def test_latency_sample_count_mismatch_raises(self):
        # 10 requests total (8 200s + 2 429s), but only 9 latency samples
        with pytest.raises(ValueError, match="Latency sample count mismatch"):
            BenchmarkResult.create(
                scenario_name="test_mismatch",
                concurrency=2,
                workers=1,
                duration_seconds=1.0,
                latencies_ms=[5.0] * 9,
                status_codes={200: 8, 429: 2}
            )

    def test_safe_zero_request_handling(self):
        res = BenchmarkResult.create(
            scenario_name="test_zero_reqs",
            concurrency=1,
            workers=1,
            duration_seconds=1.0,
            latencies_ms=[],
            status_codes={},
            error_count=0
        )
        assert res.total_requests == 0
        assert res.successful_requests == 0
        assert res.rate_limited_requests == 0
        assert res.challenge_requests == 0
        assert res.error_requests == 0
        assert res.requests_per_second == 0.0
        assert res.error_rate_percent == 0.0
        assert res.latency.count == 0

    def test_zero_requests_with_non_empty_latencies_raises(self):
        with pytest.raises(ValueError, match="latencies_ms must be empty when total_requests is 0"):
            BenchmarkResult.create(
                scenario_name="test_zero_with_samples",
                concurrency=1,
                workers=1,
                duration_seconds=1.0,
                latencies_ms=[10.0],
                status_codes={},
                error_count=0
            )

    def test_strict_request_consistency_invariant(self):
        # Mixed status codes including 200, 429, 403, 500, 503, 404 and transport errors
        status_codes = {200: 10, 429: 5, 403: 3, 500: 2, 503: 4, 404: 1}
        transport_errors = 3
        # Total = 10 + 5 + 3 + 2 + 4 + 1 + 3 = 28
        total_expected = 28
        latencies = [1.5] * total_expected

        res = BenchmarkResult.create(
            scenario_name="test_consistency",
            concurrency=5,
            workers=1,
            duration_seconds=2.0,
            latencies_ms=latencies,
            status_codes=status_codes,
            error_count=transport_errors
        )
        assert res.total_requests == total_expected
        assert res.successful_requests == 10
        assert res.rate_limited_requests == 5
        assert res.challenge_requests == 3
        # Error requests = 2 (500) + 4 (503) + 1 (404) + 3 (transport) = 10
        assert res.error_requests == 10
        assert (
            res.total_requests
            == res.successful_requests + res.rate_limited_requests + res.challenge_requests + res.error_requests
        )
        assert res.requests_per_second == 14.0  # 28 / 2.0s


# =============================================================================
# 8. Engine Timing, Wall-Clock Measurement & Remainder Accounting
# =============================================================================

class TestEngineWallClockAndDistribution:
    """Tests wall-clock execution timing and remainder request accounting in core engine."""

    def test_engine_remainder_request_distribution(self):
        # 23 requests across 7 concurrency workers: 23 % 7 = 2 remainder
        # Workers should get: [4, 4, 3, 3, 3, 3, 3] = 23 exactly
        limiter = RateLimiter(redis_client=None, capacity=100.0, refill_rate=10.0, failure_mode=FailureMode.LOCAL_FALLBACK)
        latencies, status_codes, error_count, elapsed = _run_engine_load(
            limiter=limiter,
            concurrency=7,
            total_requests=23,
            user_prefix="remainder_user"
        )
        assert len(latencies) == 23
        assert sum(status_codes.values()) + error_count == 23
        assert status_codes.get(200, 0) == 23
        assert elapsed > 0.0
        assert math.isfinite(elapsed)

        res = BenchmarkResult.create(
            scenario_name="remainder_test",
            concurrency=7,
            workers=1,
            duration_seconds=elapsed,
            latencies_ms=latencies,
            status_codes=status_codes,
            error_count=error_count
        )
        assert res.total_requests == 23
        assert res.requests_per_second == pytest.approx(23.0 / elapsed, abs=0.05)


# =============================================================================
# 9. Fault Injection & Same-Instance Outage Recovery Lifecycle
# =============================================================================

class MockRedisTarget:
    """Mock Redis client providing Lua script execution and ping."""

    def __init__(self):
        self.call_count = 0

    def register_script(self, script_str: str):
        def _script_caller(keys=(), args=(), client=None):
            self.call_count += 1
            return [1, 9.0]
        return _script_caller

    def ping(self, timeout=None):
        return True

    def verify_connection(self, timeout=1.0):
        return True


class TestFaultInjectionAndOutageLifecycle:
    """Tests FaultInjectableRedisClient and complete same-instance 5-phase lifecycle."""

    def test_fault_injectable_redis_client_toggling(self):
        target = MockRedisTarget()
        fault_client = FaultInjectableRedisClient(target)

        assert not fault_client.is_fault
        assert fault_client.ping() is True
        script = fault_client.register_script("test_script")
        assert script() == [1, 9.0]

        # Inject fault
        fault_client.set_fault(True)
        assert fault_client.is_fault
        with pytest.raises(redis.ConnectionError, match="simulated outage"):
            fault_client.ping()
        with pytest.raises(redis.ConnectionError, match="simulated outage"):
            script()

        # Clear fault
        fault_client.set_fault(False)
        assert not fault_client.is_fault
        assert fault_client.ping() is True
        assert script() == [1, 9.0]

    def test_same_instance_outage_recovery_lifecycle(self):
        """
        Validates the 5-phase lifecycle on the EXACT SAME RateLimiter instance:
          1. Baseline Online (FAIL_CLOSED) -> Allowed via Redis mock
          2. Outage under FAIL_CLOSED -> Raises RedisUnavailableError
          3. Outage under FAIL_OPEN -> Allowed gracefully (200)
          4. Outage under LOCAL_FALLBACK -> Allowed via in-memory local bucket
          5. Restored & Recovery -> Reconfigured to FAIL_CLOSED, Redis restored -> Probe succeeds
        """
        target = MockRedisTarget()
        fault_client = FaultInjectableRedisClient(target)

        limiter = RateLimiter(
            redis_client=fault_client,
            capacity=10.0,
            refill_rate=1.0,
            failure_mode=FailureMode.FAIL_CLOSED
        )

        # 1. Baseline Online
        fault_client.set_fault(False)
        res_baseline = limiter.check_limit("lifecycle_user", tokens=1.0)
        assert res_baseline.allowed is True
        assert res_baseline.remaining == 9.0

        # 2. Outage under FAIL_CLOSED
        fault_client.set_fault(True)
        with pytest.raises(RedisUnavailableError):
            limiter.check_limit("lifecycle_user", tokens=1.0)

        # 3. Outage under FAIL_OPEN (on the SAME instance)
        limiter.configure(failure_mode=FailureMode.FAIL_OPEN)
        res_fo = limiter.check_limit("lifecycle_user", tokens=1.0)
        assert res_fo.allowed is True
        assert res_fo.remaining == 10.0

        # 4. Outage under LOCAL_FALLBACK (on the SAME instance)
        limiter.configure(failure_mode=FailureMode.LOCAL_FALLBACK)
        res_fb1 = limiter.check_limit("fallback_user", tokens=2.0)
        assert res_fb1.allowed is True
        assert res_fb1.remaining == pytest.approx(8.0, abs=0.05)
        res_fb2 = limiter.check_limit("fallback_user", tokens=3.0)
        assert res_fb2.allowed is True
        assert res_fb2.remaining == pytest.approx(5.0, abs=0.05)

        # 5. Restored & Recovery (on the SAME instance)
        fault_client.set_fault(False)
        limiter.configure(failure_mode=FailureMode.FAIL_CLOSED)

        # Immediate recovery probe check
        probe_res = limiter.check_limit("probe_user", tokens=1.0)
        assert probe_res.allowed is True
        assert probe_res.remaining == 9.0


# =============================================================================
# 10. HTTP Benchmark Timing & Warm-up Isolation
# =============================================================================

class TestHttpWarmupIsolation:
    """Tests that run_http_load_test strictly isolates warm-up from measured metrics."""

    @pytest.mark.asyncio
    async def test_warmup_requests_excluded_from_metrics(self):
        import httpx

        total_server_requests = 0

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal total_server_requests
            total_server_requests += 1
            return httpx.Response(200, json={"allowed": True, "remaining": 9.0})

        mock_transport = httpx.MockTransport(mock_handler)

        warmup_reqs = 6
        measured_reqs = 14
        concurrency = 3

        # Patch httpx.AsyncClient to instantiate client with mock_transport
        orig_async_client = httpx.AsyncClient
        with patch("httpx.AsyncClient", side_effect=lambda **kwargs: orig_async_client(transport=mock_transport, **kwargs)):
            latencies, status_codes, error_count, duration = await run_http_load_test(
                base_url="http://test",
                concurrency=concurrency,
                total_requests=measured_reqs,
                auth_secret_key="c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e",
                warmup_requests=warmup_reqs,
                scenario_name="warmup_test"
            )

        # Total server hits = warmup (min(6, max(3, 10)) = 6) + measured (14) = 20
        assert total_server_requests == warmup_reqs + measured_reqs

        # Metrics must reflect ONLY the measured requests: exactly 14 samples and 14 status codes!
        assert len(latencies) == measured_reqs
        assert sum(status_codes.values()) + error_count == measured_reqs
        assert status_codes.get(200, 0) == measured_reqs
        assert error_count == 0
        assert duration > 0.0

