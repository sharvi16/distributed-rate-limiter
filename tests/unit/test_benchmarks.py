"""
Unit tests for the performance benchmarking suite.
Validates statistical aggregations, percentile calculations, result models,
data exporters, chart generators, and configuration models.
"""

import json
import csv
import math
from pathlib import Path
import pytest

from benchmarks.config import BenchmarkConfig, EnvironmentMetadata
from benchmarks.aggregator import (
    calculate_percentile,
    LatencyStats,
    BenchmarkResult,
    ResultAggregator
)
from benchmarks.chart_generator import SVGChartGenerator


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
            latencies_ms=[10.0] * 10,
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
