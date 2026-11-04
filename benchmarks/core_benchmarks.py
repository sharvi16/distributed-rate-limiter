"""
Core Rate Limiter Engine Benchmarks (Scenario C, Scenario D, Scenario E).
Evaluates Redis Lua atomicity, local fallback, failure modes, contention, and capacity configurations.
"""

import concurrent.futures
import time
from typing import List, Dict, Tuple, Optional, Any
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from benchmarks.config import BenchmarkConfig
from benchmarks.aggregator import BenchmarkResult


def benchmark_rate_limiter_behavior(
    config: BenchmarkConfig,
    redis_client: redis.Redis
) -> List[BenchmarkResult]:
    """
    Scenario C: Evaluates rate limiter behavior under different operational states:
      1. Within limit (tokens available)
      2. Exceeding limit (bucket exhausted / 429 fast-path)
      3. Multiple users sharing Redis (50 distinct keys)
      4. Different token bucket configs (high burst vs sustained refill)
      5. Concurrent requests against the same user (single key contention)
    """
    results: List[BenchmarkResult] = []
    concurrency = min(config.default_concurrency, 50)
    total_reqs = max(config.requests_per_test, 1000)

    print("\n" + "=" * 70)
    print(" SCENARIO C: Rate Limiter Engine Behavior & Contention")
    print("=" * 70)

    # 1. Within Limit (Capacity = 100,000)
    lim_within = RateLimiter(redis_client=redis_client, capacity=100000.0, refill_rate=1000.0)
    latencies_within, status_within = _run_engine_load(
        lim_within, concurrency=concurrency, total_requests=total_reqs, user_prefix="user_within", distinct=True
    )
    r1 = BenchmarkResult.create(
        scenario_name="behavior_within_limit",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_within) / 1000.0 / concurrency,
        latencies_ms=latencies_within,
        status_codes=status_within,
        metadata={"description": "Requests within configured burst capacity (allowed=True)"}
    )
    results.append(r1)
    print(f" -> Within Limit:         RPS: {r1.requests_per_second:8.1f} | p50: {r1.latency.p50_ms:6.2f}ms | p95: {r1.latency.p95_ms:6.2f}ms | Allowed: {r1.successful_requests}")

    # 2. Exceeding Limit (Capacity = 1, Refill = 0.001)
    lim_exceed = RateLimiter(redis_client=redis_client, capacity=1.0, refill_rate=0.001)
    # Prime bucket to empty
    lim_exceed.check_limit("user_exhausted", tokens=1.0)
    latencies_exceed, status_exceed = _run_engine_load(
        lim_exceed, concurrency=concurrency, total_requests=total_reqs, user_prefix="user_exhausted", distinct=False
    )
    r2 = BenchmarkResult.create(
        scenario_name="behavior_exceeding_limit",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_exceed) / 1000.0 / concurrency,
        latencies_ms=latencies_exceed,
        status_codes=status_exceed,
        metadata={"description": "Requests exceeding bucket capacity (allowed=False fast-path)"}
    )
    results.append(r2)
    print(f" -> Exceeding Limit:      RPS: {r2.requests_per_second:8.1f} | p50: {r2.latency.p50_ms:6.2f}ms | p95: {r2.latency.p95_ms:6.2f}ms | Rejected: {r2.rate_limited_requests}")

    # 3. Multiple Users Sharing Redis (50 distinct keys)
    lim_multi = RateLimiter(redis_client=redis_client, capacity=10000.0, refill_rate=100.0)
    latencies_multi, status_multi = _run_engine_load(
        lim_multi, concurrency=concurrency, total_requests=total_reqs, user_prefix="multi_user", distinct=True
    )
    r3 = BenchmarkResult.create(
        scenario_name="behavior_multiple_users",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_multi) / 1000.0 / concurrency,
        latencies_ms=latencies_multi,
        status_codes=status_multi,
        metadata={"description": "50 distinct user keys concurrently evaluating limits in Redis"}
    )
    results.append(r3)
    print(f" -> Multi-User (50 keys): RPS: {r3.requests_per_second:8.1f} | p50: {r3.latency.p50_ms:6.2f}ms | p95: {r3.latency.p95_ms:6.2f}ms")

    # 4. Token Bucket Configurations: High Burst vs Sustained Refill
    lim_high_burst = RateLimiter(redis_client=redis_client, capacity=1000.0, refill_rate=1.0)
    latencies_hb, status_hb = _run_engine_load(
        lim_high_burst, concurrency=concurrency, total_requests=total_reqs, user_prefix="high_burst", distinct=True
    )
    r4 = BenchmarkResult.create(
        scenario_name="behavior_config_high_burst",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_hb) / 1000.0 / concurrency,
        latencies_ms=latencies_hb,
        status_codes=status_hb,
        metadata={"description": "High burst (capacity=1000, refill=1/s)"}
    )
    results.append(r4)

    lim_sustained = RateLimiter(redis_client=redis_client, capacity=10.0, refill_rate=100.0)
    latencies_sust, status_sust = _run_engine_load(
        lim_sustained, concurrency=concurrency, total_requests=total_reqs, user_prefix="sustained", distinct=True
    )
    r5 = BenchmarkResult.create(
        scenario_name="behavior_config_sustained_refill",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_sust) / 1000.0 / concurrency,
        latencies_ms=latencies_sust,
        status_codes=status_sust,
        metadata={"description": "Sustained refill (capacity=10, refill=100/s)"}
    )
    results.append(r5)
    print(f" -> High Burst Config:    RPS: {r4.requests_per_second:8.1f} | p50: {r4.latency.p50_ms:6.2f}ms")
    print(f" -> Sustained Refill:     RPS: {r5.requests_per_second:8.1f} | p50: {r5.latency.p50_ms:6.2f}ms")

    # 5. Concurrent Requests Against Same User (Single Key Contention)
    lim_contend = RateLimiter(redis_client=redis_client, capacity=100000.0, refill_rate=10000.0)
    latencies_contend, status_contend = _run_engine_load(
        lim_contend, concurrency=concurrency, total_requests=total_reqs, user_prefix="single_hotspot_key", distinct=False
    )
    r6 = BenchmarkResult.create(
        scenario_name="behavior_same_user_contention",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(latencies_contend) / 1000.0 / concurrency,
        latencies_ms=latencies_contend,
        status_codes=status_contend,
        metadata={"description": "High contention against single hot key in Redis"}
    )
    results.append(r6)
    print(f" -> Single Key Contend:   RPS: {r6.requests_per_second:8.1f} | p50: {r6.latency.p50_ms:6.2f}ms | p95: {r6.latency.p95_ms:6.2f}ms")

    return results


def benchmark_redis_failure_scenarios(
    config: BenchmarkConfig,
    redis_client: redis.Redis
) -> List[BenchmarkResult]:
    """
    Scenario D: Evaluates rate limiter behavior under Redis availability, outage, and recovery:
      1. Baseline: Redis Available
      2. Outage under FAIL_CLOSED: Rejects requests immediately (503 / RedisUnavailableError)
      3. Outage under FAIL_OPEN: Allows requests (200 pass-through)
      4. Outage under LOCAL_FALLBACK: Falls back to in-memory Token Bucket
      5. Recovery: Redis connectivity restored, measuring recovery latency
    """
    results: List[BenchmarkResult] = []
    total_reqs = max(config.requests_per_test // 2, 500)
    concurrency = min(config.default_concurrency, 20)

    print("\n" + "=" * 70)
    print(" SCENARIO D: Redis Failure, Fallback & Recovery Scenarios")
    print("=" * 70)

    # 1. Baseline: Redis Available
    lim_online = RateLimiter(redis_client=redis_client, capacity=10000.0, refill_rate=100.0, failure_mode=FailureMode.FAIL_CLOSED)
    lat_online, st_online = _run_engine_load(lim_online, concurrency, total_reqs, "redis_online")
    r1 = BenchmarkResult.create(
        scenario_name="failure_mode_redis_available",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_online) / 1000.0 / concurrency,
        latencies_ms=lat_online,
        status_codes=st_online,
        metadata={"description": "Normal operation with Redis online"}
    )
    results.append(r1)
    print(f" -> Baseline (Online):    RPS: {r1.requests_per_second:8.1f} | p50: {r1.latency.p50_ms:6.2f}ms | Status: {st_online}")

    # Simulated Offline Redis client
    class OfflineRedisMock:
        def register_script(self, script):
            raise redis.ConnectionError("Redis connection refused (simulated outage)")
        def ping(self, timeout=None):
            raise redis.ConnectionError("Redis connection refused")

    offline_mock = OfflineRedisMock()

    # 2. FAIL_CLOSED Outage
    lim_fc = RateLimiter(redis_client=offline_mock, capacity=10000.0, refill_rate=100.0, failure_mode=FailureMode.FAIL_CLOSED)
    lat_fc, st_fc = _run_engine_load(lim_fc, concurrency, total_reqs, "redis_down_fc")
    r2 = BenchmarkResult.create(
        scenario_name="failure_mode_fail_closed",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_fc) / 1000.0 / concurrency,
        latencies_ms=lat_fc,
        status_codes=st_fc,
        metadata={"description": "Redis down under FAIL_CLOSED (fast-path rejection)"}
    )
    results.append(r2)
    print(f" -> Outage FAIL_CLOSED:   RPS: {r2.requests_per_second:8.1f} | p50: {r2.latency.p50_ms:6.2f}ms | 503 Errors: {st_fc.get(503, 0)}")

    # 3. FAIL_OPEN Outage
    lim_fo = RateLimiter(redis_client=offline_mock, capacity=10000.0, refill_rate=100.0, failure_mode=FailureMode.FAIL_OPEN)
    lat_fo, st_fo = _run_engine_load(lim_fo, concurrency, total_reqs, "redis_down_fo")
    r3 = BenchmarkResult.create(
        scenario_name="failure_mode_fail_open",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_fo) / 1000.0 / concurrency,
        latencies_ms=lat_fo,
        status_codes=st_fo,
        metadata={"description": "Redis down under FAIL_OPEN (graceful allow)"}
    )
    results.append(r3)
    print(f" -> Outage FAIL_OPEN:     RPS: {r3.requests_per_second:8.1f} | p50: {r3.latency.p50_ms:6.2f}ms | Allowed: {st_fo.get(200, 0)}")

    # 4. LOCAL_FALLBACK Outage
    lim_fb = RateLimiter(redis_client=offline_mock, capacity=10000.0, refill_rate=100.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    lat_fb, st_fb = _run_engine_load(lim_fb, concurrency, total_reqs, "redis_down_fb")
    r4 = BenchmarkResult.create(
        scenario_name="failure_mode_local_fallback",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_fb) / 1000.0 / concurrency,
        latencies_ms=lat_fb,
        status_codes=st_fb,
        metadata={"description": "Redis down under LOCAL_FALLBACK (in-memory token bucket)"}
    )
    results.append(r4)
    print(f" -> Outage LOCAL_FALLBACK:RPS: {r4.requests_per_second:8.1f} | p50: {r4.latency.p50_ms:6.2f}ms | Allowed: {st_fb.get(200, 0)}")

    # 5. Recovery Phase: Reconnect back to online Redis
    lim_recovered = RateLimiter(redis_client=redis_client, capacity=10000.0, refill_rate=100.0, failure_mode=FailureMode.FAIL_CLOSED)
    lat_rec, st_rec = _run_engine_load(lim_recovered, concurrency, total_reqs, "redis_recovered")
    r5 = BenchmarkResult.create(
        scenario_name="failure_mode_redis_recovery",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_rec) / 1000.0 / concurrency,
        latencies_ms=lat_rec,
        status_codes=st_rec,
        metadata={"description": "Redis reconnected and restored to normal operation"}
    )
    results.append(r5)
    print(f" -> Restored / Recovery:  RPS: {r5.requests_per_second:8.1f} | p50: {r5.latency.p50_ms:6.2f}ms | Allowed: {st_rec.get(200, 0)}")

    return results


def benchmark_local_vs_distributed(
    config: BenchmarkConfig,
    redis_client: redis.Redis
) -> List[BenchmarkResult]:
    """
    Scenario E: Direct comparison between local in-memory rate limiting and Redis-backed distributed limiting.
    Evaluates throughput, latency distribution, and documents trade-offs.
    """
    results: List[BenchmarkResult] = []
    concurrency = min(config.default_concurrency, 50)
    total_reqs = max(config.requests_per_test * 2, 2000)

    print("\n" + "=" * 70)
    print(" SCENARIO E: Local In-Memory vs Redis Distributed Performance")
    print("=" * 70)

    # 1. Local In-Memory Limiting
    lim_local = RateLimiter(redis_client=None, capacity=100000.0, refill_rate=10000.0, failure_mode=FailureMode.LOCAL_FALLBACK)
    lim_local.redis = None
    lim_local.check_limit_script = None
    lat_local, st_local = _run_engine_load(lim_local, concurrency, total_reqs, "pure_local", distinct=True)
    r_local = BenchmarkResult.create(
        scenario_name="comparison_local_in_memory",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_local) / 1000.0 / concurrency,
        latencies_ms=lat_local,
        status_codes=st_local,
        metadata={
            "mode": "local_in_memory",
            "consistency": "process_local",
            "sharing": "none (isolated per process)",
            "description": "Pure in-memory mutex-guarded Token Bucket"
        }
    )
    results.append(r_local)
    print(f" -> Local In-Memory:      RPS: {r_local.requests_per_second:8.1f} | p50: {r_local.latency.p50_ms:6.3f}ms | p99: {r_local.latency.p99_ms:6.3f}ms")

    # 2. Redis-Backed Distributed Limiting
    lim_dist = RateLimiter(redis_client=redis_client, capacity=100000.0, refill_rate=10000.0, failure_mode=FailureMode.FAIL_CLOSED)
    lat_dist, st_dist = _run_engine_load(lim_dist, concurrency, total_reqs, "redis_dist", distinct=True)
    r_dist = BenchmarkResult.create(
        scenario_name="comparison_redis_distributed",
        concurrency=concurrency,
        workers=1,
        duration_seconds=sum(lat_dist) / 1000.0 / concurrency,
        latencies_ms=lat_dist,
        status_codes=st_dist,
        redis_latencies_ms=lat_dist,  # Direct Redis Lua execution time
        metadata={
            "mode": "redis_distributed",
            "consistency": "cluster_wide_atomic",
            "sharing": "synchronized across all nodes & workers",
            "description": "Distributed Redis Token Bucket with server-side Lua atomicity"
        }
    )
    results.append(r_dist)
    print(f" -> Redis Distributed:    RPS: {r_dist.requests_per_second:8.1f} | p50: {r_dist.latency.p50_ms:6.3f}ms | p99: {r_dist.latency.p99_ms:6.3f}ms")

    # Summary Comparison
    speedup = r_local.requests_per_second / max(r_dist.requests_per_second, 0.001)
    latency_ratio = r_dist.latency.p50_ms / max(r_local.latency.p50_ms, 0.0001)
    print(f"\n    [TRADE-OFF ANALYSIS]:")
    print(f"    - Local in-memory throughput is {speedup:.1f}x higher than Redis distributed mode.")
    print(f"    - Redis distributed mode p50 latency is {latency_ratio:.1f}x of local in-memory due to network/socket round-trip.")
    print(f"    - Consistency Guarantee: Redis provides strict cluster-wide quota synchronization; Local mode is isolated per-process.")

    return results


def _run_engine_load(
    limiter: RateLimiter,
    concurrency: int,
    total_requests: int,
    user_prefix: str,
    distinct: bool = True
) -> Tuple[List[float], Dict[int, int]]:
    """
    Executes multi-threaded load directly against a RateLimiter instance
    measuring pure rate limiter check_limit() execution latency.
    """
    latencies_ms: List[float] = []
    status_codes: Dict[int, int] = {}
    user_count = concurrency if distinct else 1
    users = [f"{user_prefix}_{i}" for i in range(user_count)]
    reqs_per_worker = total_requests // concurrency

    def worker_fn(worker_idx: int) -> Tuple[List[float], Dict[int, int]]:
        w_lats = []
        w_stats = {}
        u = users[worker_idx % len(users)]

        for _ in range(reqs_per_worker):
            t0 = time.perf_counter()
            try:
                res = limiter.check_limit(u, tokens=1.0)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                w_lats.append(elapsed_ms)
                code = 200 if res.allowed else 429
                w_stats[code] = w_stats.get(code, 0) + 1
            except (redis.RedisError, RedisUnavailableError):
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                w_lats.append(elapsed_ms)
                w_stats[503] = w_stats.get(503, 0) + 1
            except Exception:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                w_lats.append(elapsed_ms)
                w_stats[500] = w_stats.get(500, 0) + 1

        return w_lats, w_stats

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker_fn, i) for i in range(concurrency)]
        for f in concurrent.futures.as_completed(futures):
            lats, stats = f.result()
            latencies_ms.extend(lats)
            for code, cnt in stats.items():
                status_codes[code] = status_codes.get(code, 0) + cnt

    return latencies_ms, status_codes
