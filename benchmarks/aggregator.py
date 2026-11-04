"""
Result Aggregator, Statistical Analysis, and Machine-Readable Metrics Exporter.
"""

from dataclasses import dataclass, field, asdict
import csv
import json
import math
from pathlib import Path
from typing import List, Dict, Any, Optional


def calculate_percentile(sorted_values: List[float], percentile: float) -> float:
    """
    Calculates a percentile using linear interpolation between nearest ranks.
    percentile must be in the range [0.0, 100.0].
    """
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    if percentile <= 0.0:
        return float(sorted_values[0])
    if percentile >= 100.0:
        return float(sorted_values[-1])

    n = len(sorted_values)
    rank = (percentile / 100.0) * (n - 1)
    low_idx = int(math.floor(rank))
    high_idx = int(math.ceil(rank))

    if low_idx == high_idx:
        return float(sorted_values[low_idx])

    weight = rank - low_idx
    return float(sorted_values[low_idx] * (1.0 - weight) + sorted_values[high_idx] * weight)


@dataclass
class LatencyStats:
    """Statistical summary of request latencies in milliseconds."""
    count: int = 0
    mean_ms: float = 0.0
    std_dev_ms: float = 0.0
    min_ms: float = 0.0
    p50_ms: float = 0.0
    p90_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    max_ms: float = 0.0

    @classmethod
    def from_latencies(cls, latencies_ms: List[float]) -> "LatencyStats":
        if not latencies_ms:
            return cls()

        sorted_lats = sorted(latencies_ms)
        n = len(sorted_lats)
        mean_val = sum(sorted_lats) / n

        variance = sum((x - mean_val) ** 2 for x in sorted_lats) / n if n > 1 else 0.0
        std_dev = math.sqrt(variance)

        return cls(
            count=n,
            mean_ms=round(mean_val, 3),
            std_dev_ms=round(std_dev, 3),
            min_ms=round(sorted_lats[0], 3),
            p50_ms=round(calculate_percentile(sorted_lats, 50.0), 3),
            p90_ms=round(calculate_percentile(sorted_lats, 90.0), 3),
            p95_ms=round(calculate_percentile(sorted_lats, 95.0), 3),
            p99_ms=round(calculate_percentile(sorted_lats, 99.0), 3),
            max_ms=round(sorted_lats[-1], 3)
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkResult:
    """Structured result of a single benchmark execution scenario."""
    scenario_name: str
    concurrency: int
    workers: int
    duration_seconds: float
    total_requests: int
    successful_requests: int
    rate_limited_requests: int
    challenge_requests: int
    error_requests: int
    requests_per_second: float
    error_rate_percent: float
    latency: LatencyStats
    status_codes: Dict[int, int] = field(default_factory=dict)
    redis_operation_latency: Optional[LatencyStats] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        scenario_name: str,
        concurrency: int,
        workers: int,
        duration_seconds: float,
        latencies_ms: List[float],
        status_codes: Dict[int, int],
        error_count: int = 0,
        redis_latencies_ms: Optional[List[float]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "BenchmarkResult":
        total_reqs = sum(status_codes.values()) + error_count
        dur = max(duration_seconds, 0.0001)
        rps = total_reqs / dur

        success = status_codes.get(200, 0)
        rate_limited = status_codes.get(429, 0)
        challenge = status_codes.get(403, 0)
        errs = error_count + sum(count for code, count in status_codes.items() if code >= 500)

        err_rate = (errs / total_reqs * 100.0) if total_reqs > 0 else 0.0

        lat_stats = LatencyStats.from_latencies(latencies_ms)
        redis_stats = LatencyStats.from_latencies(redis_latencies_ms) if redis_latencies_ms else None

        return cls(
            scenario_name=scenario_name,
            concurrency=concurrency,
            workers=workers,
            duration_seconds=round(dur, 3),
            total_requests=total_reqs,
            successful_requests=success,
            rate_limited_requests=rate_limited,
            challenge_requests=challenge,
            error_requests=errs,
            requests_per_second=round(rps, 2),
            error_rate_percent=round(err_rate, 2),
            latency=lat_stats,
            status_codes=status_codes,
            redis_operation_latency=redis_stats,
            metadata=metadata or {}
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


class ResultAggregator:
    """Collects, consolidates, and exports benchmark results to JSON and CSV."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[BenchmarkResult] = []

    def add_result(self, result: BenchmarkResult) -> None:
        self.results.append(result)

    def save_json(self, filename: str, data: Any) -> Path:
        target = self.output_dir / filename
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return target

    def save_csv(self, filename: str, results: List[BenchmarkResult]) -> Path:
        target = self.output_dir / filename
        fieldnames = [
            "scenario_name", "concurrency", "workers", "duration_seconds",
            "total_requests", "successful_requests", "rate_limited_requests",
            "challenge_requests", "error_requests", "requests_per_second",
            "error_rate_percent", "mean_latency_ms", "p50_latency_ms",
            "p90_latency_ms", "p95_latency_ms", "p99_latency_ms", "max_latency_ms"
        ]

        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "scenario_name": r.scenario_name,
                    "concurrency": r.concurrency,
                    "workers": r.workers,
                    "duration_seconds": r.duration_seconds,
                    "total_requests": r.total_requests,
                    "successful_requests": r.successful_requests,
                    "rate_limited_requests": r.rate_limited_requests,
                    "challenge_requests": r.challenge_requests,
                    "error_requests": r.error_requests,
                    "requests_per_second": r.requests_per_second,
                    "error_rate_percent": r.error_rate_percent,
                    "mean_latency_ms": r.latency.mean_ms,
                    "p50_latency_ms": r.latency.p50_ms,
                    "p90_latency_ms": r.latency.p90_ms,
                    "p95_latency_ms": r.latency.p95_ms,
                    "p99_latency_ms": r.latency.p99_ms,
                    "max_latency_ms": r.latency.max_ms
                })
        return target
