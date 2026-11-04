"""
Core Rate Limiter Engine Benchmarks (Scenario C, Scenario D, Scenario E).
Evaluates Redis Lua atomicity, local fallback, failure modes, contention, and capacity configurations.
"""

import concurrent.futures
import threading
import time
from typing import List, Dict, Tuple, Optional, Any
import redis

from rate_limiter import RateLimiter, FailureMode, RedisUnavailableError
from benchmarks.config import BenchmarkConfig
from benchmarks.aggregator import BenchmarkResult


class FaultInjectableRedisClient:
    """
    Thread-safe Redis client wrapper capable of dynamically injecting network outages
    and connection drops on an active RateLimiter instance without replacing the instance.
    """

    def __init__(self, target_client: redis.Redis):
        self._target = target_client
        self._fault = False
        self._lock = threading.Lock()

    def set_fault(self, fault: bool) -> None:
        with self._lock:
            self._fault = fault

    @property
    def is_fault(self) -> bool:
        with self._lock:
            return self._fault

    def register_script(self, script_str: str):
        real_script = self._target.register_script(script_str)

        def _script_caller(*args, **kwargs):
            with self._lock:
                if self._fault:
                    raise redis.ConnectionError("Connection refused: host unreachable (simulated outage)")
            return real_script(*args, **kwargs)

        return _script_caller

    def ping(self, *args, **kwargs):
        with self._lock:
            if self._fault:
                raise redis.ConnectionError("Connection refused: host unreachable (simulated outage)")
        return self._target.ping(*args, **kwargs)

    def verify_connection(self, timeout: float = 1.0) -> bool:
        with self._lock:
            if self._fault:
                raise redis.ConnectionError("Connection refused: host unreachable (simulated outage)")
        if hasattr(self._target, "verify_connection"):
            return self._target.verify_connection(timeout=timeout)
        return bool(self._target.ping())

    def __getattr__(self, name: str) -> Any:
        with self._lock:
            if self._fault:
                raise redis.ConnectionError("Connection refused: host unreachable (simulated outage)")
        return getattr(self._target, name)


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
    lat_within, st_within, err_within, dur_within = _run_engine_load(
        lim_within, concurrency=concurrency, total_requests=total_reqs, user_prefix="user_within", distinct=True
    )
    r1 = BenchmarkResult.create(
        scenario_name="behavior_within_limit",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_within,
        latencies_ms=lat_within,
        status_codes=st_within,
        error_count=err_within,
        metadata={"description": "Requests within configured burst capacity (allowed=True)"}
    )
    results.append(r1)
    print(f" -> Within Limit:         RPS: {r1.requests_per_second:8.1f} | p50: {r1.latency.p50_ms:6.2f}ms | p95: {r1.latency.p95_ms:6.2f}ms | Allowed: {r1.successful_requests}")

    # 2. Exceeding Limit (Capacity = 1, Refill = 0.001)
    lim_exceed = RateLimiter(redis_client=redis_client, capacity=1.0, refill_rate=0.001)
    # Prime bucket to empty
    lim_exceed.check_limit("user_exhausted", tokens=1.0)
    lat_exceed, st_exceed, err_exceed, dur_exceed = _run_engine_load(
        lim_exceed, concurrency=concurrency, total_requests=total_reqs, user_prefix="user_exhausted", distinct=False
    )
    r2 = BenchmarkResult.create(
        scenario_name="behavior_exceeding_limit",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_exceed,
        latencies_ms=lat_exceed,
        status_codes=st_exceed,
        error_count=err_exceed,
        metadata={"description": "Requests exceeding bucket capacity (allowed=False fast-path)"}
    )
    results.append(r2)
    print(f" -> Exceeding Limit:      RPS: {r2.requests_per_second:8.1f} | p50: {r2.latency.p50_ms:6.2f}ms | p95: {r2.latency.p95_ms:6.2f}ms | Rejected: {r2.rate_limited_requests}")

    # 3. Multiple Users Sharing Redis (50 distinct keys)
    lim_multi = RateLimiter(redis_client=redis_client, capacity=10000.0, refill_rate=100.0)
    lat_multi, st_multi, err_multi, dur_multi = _run_engine_load(
        lim_multi, concurrency=concurrency, total_requests=total_reqs, user_prefix="multi_user", distinct=True
    )
    r3 = BenchmarkResult.create(
        scenario_name="behavior_multiple_users",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_multi,
        latencies_ms=lat_multi,
        status_codes=st_multi,
        error_count=err_multi,
        metadata={"description": "50 distinct user keys concurrently evaluating limits in Redis"}
    )
    results.append(r3)
    print(f" -> Multi-User (50 keys): RPS: {r3.requests_per_second:8.1f} | p50: {r3.latency.p50_ms:6.2f}ms | p95: {r3.latency.p95_ms:6.2f}ms")

    # 4. Token Bucket Configurations: High Burst vs Sustained Refill
    lim_high_burst = RateLimiter(redis_client=redis_client, capacity=1000.0, refill_rate=1.0)
    lat_hb, st_hb, err_hb, dur_hb = _run_engine_load(
        lim_high_burst, concurrency=concurrency, total_requests=total_reqs, user_prefix="high_burst", distinct=True
    )
    r4 = BenchmarkResult.create(
        scenario_name="behavior_config_high_burst",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_hb,
        latencies_ms=lat_hb,
        status_codes=st_hb,
        error_count=err_hb,
        metadata={"description": "High burst (capacity=1000, refill=1/s)"}
    )
    results.append(r4)

    lim_sustained = RateLimiter(redis_client=redis_client, capacity=10.0, refill_rate=100.0)
    lat_sust, st_sust, err_sust, dur_sust = _run_engine_load(
        lim_sustained, concurrency=concurrency, total_requests=total_reqs, user_prefix="sustained", distinct=True
    )
    r5 = BenchmarkResult.create(
        scenario_name="behavior_config_sustained_refill",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_sust,
        latencies_ms=lat_sust,
        status_codes=st_sust,
        error_count=err_sust,
        metadata={"description": "Sustained refill (capacity=10, refill=100/s)"}
    )
    results.append(r5)
    print(f" -> High Burst Config:    RPS: {r4.requests_per_second:8.1f} | p50: {r4.latency.p50_ms:6.2f}ms")
    print(f" -> Sustained Refill:     RPS: {r5.requests_per_second:8.1f} | p50: {r5.latency.p50_ms:6.2f}ms")

    # 5. Concurrent Requests Against Same User (Single Key Contention)
    lim_contend = RateLimiter(redis_client=redis_client, capacity=100000.0, refill_rate=10000.0)
    lat_contend, st_contend, err_contend, dur_contend = _run_engine_load(
        lim_contend, concurrency=concurrency, total_requests=total_reqs, user_prefix="single_hotspot_key", distinct=False
    )
    r6 = BenchmarkResult.create(
        scenario_name="behavior_same_user_contention",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_contend,
        latencies_ms=lat_contend,
        status_codes=st_contend,
        error_count=err_contend,
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
    Scenario D: Evaluates rate limiter behavior under Redis availability, outage, and recovery
    using the EXACT SAME RateLimiter instance throughout all phases:
      1. Baseline: Redis Available (FAIL_CLOSED)
      2. Outage under FAIL_CLOSED: Rejects requests immediately (503 / RedisUnavailableError)
      3. Outage under FAIL_OPEN: Allows requests (200 pass-through)
      4. Outage under LOCAL_FALLBACK: Falls back to in-memory Token Bucket
      5. Recovery: Redis connectivity restored on the same instance, measuring recovery latency
    """
    results: List[BenchmarkResult] = []
    total_reqs = max(config.requests_per_test // 2, 500)
    concurrency = min(config.default_concurrency, 20)

    print("\n" + "=" * 70)
    print(" SCENARIO D: Redis Failure, Fallback & Same-Instance Recovery")
    print("=" * 70)

    fault_client = FaultInjectableRedisClient(redis_client)
    limiter = RateLimiter(
        redis_client=fault_client,
        capacity=10000.0,
        refill_rate=100.0,
        failure_mode=FailureMode.FAIL_CLOSED
    )

    # 1. Baseline: Redis Available
    fault_client.set_fault(False)
    lat_online, st_online, err_online, dur_online = _run_engine_load(
        limiter, concurrency, total_reqs, "redis_online"
    )
    r1 = BenchmarkResult.create(
        scenario_name="failure_mode_redis_available",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_online,
        latencies_ms=lat_online,
        status_codes=st_online,
        error_count=err_online,
        metadata={"description": "Normal operation with Redis online"}
    )
    results.append(r1)
    print(f" -> Baseline (Online):    RPS: {r1.requests_per_second:8.1f} | p50: {r1.latency.p50_ms:6.2f}ms | Status: {st_online}")

    # 2. FAIL_CLOSED Outage
    fault_client.set_fault(True)
    lat_fc, st_fc, err_fc, dur_fc = _run_engine_load(
        limiter, concurrency, total_reqs, "redis_down_fc"
    )
    r2 = BenchmarkResult.create(
        scenario_name="failure_mode_fail_closed",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_fc,
        latencies_ms=lat_fc,
        status_codes=st_fc,
        error_count=err_fc,
        metadata={"description": "Redis down under FAIL_CLOSED (fast-path rejection via 503)"}
    )
    results.append(r2)
    print(f" -> Outage FAIL_CLOSED:   RPS: {r2.requests_per_second:8.1f} | p50: {r2.latency.p50_ms:6.2f}ms | 503 Errors: {st_fc.get(503, 0)}")

    # 3. FAIL_OPEN Outage (on the same limiter instance)
    limiter.configure(failure_mode=FailureMode.FAIL_OPEN)
    lat_fo, st_fo, err_fo, dur_fo = _run_engine_load(
        limiter, concurrency, total_reqs, "redis_down_fo"
    )
    r3 = BenchmarkResult.create(
        scenario_name="failure_mode_fail_open",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_fo,
        latencies_ms=lat_fo,
        status_codes=st_fo,
        error_count=err_fo,
        metadata={"description": "Redis down under FAIL_OPEN (graceful allow via 200)"}
    )
    results.append(r3)
    print(f" -> Outage FAIL_OPEN:     RPS: {r3.requests_per_second:8.1f} | p50: {r3.latency.p50_ms:6.2f}ms | Allowed: {st_fo.get(200, 0)}")

    # 4. LOCAL_FALLBACK Outage (on the same limiter instance)
    limiter.configure(failure_mode=FailureMode.LOCAL_FALLBACK)
    lat_fb, st_fb, err_fb, dur_fb = _run_engine_load(
        limiter, concurrency, total_reqs, "redis_down_fb"
    )
    r4 = BenchmarkResult.create(
        scenario_name="failure_mode_local_fallback",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_fb,
        latencies_ms=lat_fb,
        status_codes=st_fb,
        error_count=err_fb,
        metadata={"description": "Redis down under LOCAL_FALLBACK (in-memory token bucket)"}
    )
    results.append(r4)
    print(f" -> Outage LOCAL_FALLBACK:RPS: {r4.requests_per_second:8.1f} | p50: {r4.latency.p50_ms:6.2f}ms | Allowed: {st_fb.get(200, 0)}")

    # 5. Recovery Phase: Restore Redis connectivity on the same instance
    fault_client.set_fault(False)
    limiter.configure(failure_mode=FailureMode.FAIL_CLOSED)

    # Measure time to first successful request (recovery probe latency)
    t_probe = time.perf_counter()
    first_res = limiter.check_limit("recovery_probe_user", tokens=1.0)
    probe_latency_ms = (time.perf_counter() - t_probe) * 1000.0

    lat_rec, st_rec, err_rec, dur_rec = _run_engine_load(
        limiter, concurrency, total_reqs, "redis_recovered"
    )
    r5 = BenchmarkResult.create(
        scenario_name="failure_mode_redis_recovery",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_rec,
        latencies_ms=lat_rec,
        status_codes=st_rec,
        error_count=err_rec,
        metadata={
            "description": "Redis reconnected and restored to normal operation on the same instance",
            "first_request_allowed": first_res.allowed,
            "recovery_probe_latency_ms": round(probe_latency_ms, 3)
        }
    )
    results.append(r5)
    print(f" -> Restored / Recovery:  RPS: {r5.requests_per_second:8.1f} | p50: {r5.latency.p50_ms:6.2f}ms | Allowed: {st_rec.get(200, 0)} | Probe: {probe_latency_ms:.2f}ms")

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
    lat_local, st_local, err_local, dur_local = _run_engine_load(
        lim_local, concurrency, total_reqs, "pure_local", distinct=True
    )
    r_local = BenchmarkResult.create(
        scenario_name="comparison_local_in_memory",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_local,
        latencies_ms=lat_local,
        status_codes=st_local,
        error_count=err_local,
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
    lat_dist, st_dist, err_dist, dur_dist = _run_engine_load(
        lim_dist, concurrency, total_reqs, "redis_dist", distinct=True
    )
    r_dist = BenchmarkResult.create(
        scenario_name="comparison_redis_distributed",
        concurrency=concurrency,
        workers=1,
        duration_seconds=dur_dist,
        latencies_ms=lat_dist,
        status_codes=st_dist,
        error_count=err_dist,
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
) -> Tuple[List[float], Dict[int, int], int, float]:
    """
    Executes multi-threaded load directly against a RateLimiter instance,
    measuring pure rate limiter check_limit() execution latency and true wall-clock time.
    Returns: (latencies_ms, status_codes, error_count, elapsed_seconds)
    """
    latencies_ms: List[float] = []
    status_codes: Dict[int, int] = {}
    error_count: int = 0
    user_count = concurrency if distinct else 1
    users = [f"{user_prefix}_{i}" for i in range(user_count)]

    # Exact request distribution across workers to prevent remainder truncation
    base_reqs = total_requests // concurrency
    remainder = total_requests % concurrency
    reqs_per_worker = [base_reqs + (1 if i < remainder else 0) for i in range(concurrency)]

    def worker_fn(worker_idx: int, num_reqs: int) -> Tuple[List[float], Dict[int, int], int]:
        w_lats = []
        w_stats = {}
        w_errs = 0
        u = users[worker_idx % len(users)]

        for _ in range(num_reqs):
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

        return w_lats, w_stats, w_errs

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker_fn, i, reqs_per_worker[i]) for i in range(concurrency)]
        for f in concurrent.futures.as_completed(futures):
            lats, stats, errs = f.result()
            latencies_ms.extend(lats)
            for code, cnt in stats.items():
                status_codes[code] = status_codes.get(code, 0) + cnt
            error_count += errs
    elapsed_seconds = max(time.perf_counter() - t_start, 0.0001)

    return latencies_ms, status_codes, error_count, elapsed_seconds
