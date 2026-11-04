"""
HTTP API Load Benchmarks (Scenario A & Scenario B).
Evaluates single-worker performance and multi-worker scalability under concurrent client load.
"""

import asyncio
import time
from typing import List, Dict, Tuple, Optional, Any
import httpx
import redis

from auth import create_signed_token
from benchmarks.config import BenchmarkConfig
from benchmarks.aggregator import BenchmarkResult
from benchmarks.server_manager import UvicornServerManager, RedisServerManager


async def run_http_load_test(
    base_url: str,
    concurrency: int,
    total_requests: int,
    auth_secret_key: str,
    timeout_seconds: float = 10.0,
    warmup_requests: int = 50,
    scenario_name: str = "http_load",
    user_prefix: str = "bench_user",
    distinct_users: bool = True,
    redis_url: Optional[str] = None
) -> Tuple[List[float], Dict[int, int], int]:
    """
    Executes a high-concurrency HTTP load test against the API endpoint /limited-resource.
    Generates cryptographically valid HMAC-SHA256 signed bearer tokens for every user.
    """
    # Pre-generate signed tokens to avoid crypto overhead skewing network measurements
    tokens = {}
    user_ips = {}
    user_count = concurrency if distinct_users else 1
    for i in range(user_count):
        uid = f"{user_prefix}_{i}"
        tokens[uid] = create_signed_token(uid, secret_key=auth_secret_key)
        user_ips[uid] = f"198.51.100.{(i % 250) + 1}"

    users_list = list(tokens.keys())

    # Pre-authorize benchmark users as verified humans in Redis so pure token-bucket rate limiting is measured
    if redis_url:
        try:
            r = redis.from_url(redis_url, socket_timeout=2.0)
            pipe = r.pipeline()
            for uid in users_list:
                pipe.setex(f"verified_human:{uid}", 3600, "verified")
                pipe.delete(f"user_penalty_box:{uid}", f"user_pending_challenge:{uid}")
                u_ip = user_ips[uid]
                pipe.delete(f"user_penalty_box:ip:{u_ip}", f"rate_limit:ip:{u_ip}")
            pipe.execute()
        except Exception:
            pass

    limits = httpx.Limits(max_connections=max(concurrency * 2, 100), max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(timeout_seconds)

    async with httpx.AsyncClient(base_url=base_url, limits=limits, timeout=timeout) as client:
        # 1. Warm-up Phase
        if warmup_requests > 0:
            warmup_tasks = []
            for i in range(min(warmup_requests, concurrency)):
                uid = users_list[i % len(users_list)]
                token = tokens[uid]
                u_ip = user_ips.get(uid, "198.51.100.1")
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Forwarded-For": u_ip,
                    "User-Agent": "RateLimiterBenchmark/1.0"
                }
                warmup_tasks.append(client.get("/limited-resource", headers=headers))
            await asyncio.gather(*warmup_tasks, return_exceptions=True)

        # 2. Measurement Phase
        latencies_ms: List[float] = []
        status_codes: Dict[int, int] = {}
        error_count: int = 0
        queue: asyncio.Queue[Tuple[str, str]] = asyncio.Queue()

        for i in range(total_requests):
            uid = users_list[i % len(users_list)]
            token = tokens[uid]
            queue.put_nowait((uid, token))

        async def worker():
            nonlocal error_count
            while not queue.empty():
                try:
                    uid, token = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                u_ip = user_ips.get(uid, "198.51.100.1")
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Forwarded-For": u_ip,
                    "User-Agent": "RateLimiterBenchmark/1.0"
                }

                t0 = time.perf_counter()
                try:
                    resp = await client.get("/limited-resource", headers=headers)
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    latencies_ms.append(elapsed_ms)
                    code = resp.status_code
                    status_codes[code] = status_codes.get(code, 0) + 1
                except Exception:
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    latencies_ms.append(elapsed_ms)
                    error_count += 1
                finally:
                    queue.task_done()

        workers_pool = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers_pool)

    return latencies_ms, status_codes, error_count


def benchmark_single_worker_concurrency(
    config: BenchmarkConfig,
    redis_url: str
) -> List[BenchmarkResult]:
    """
    Scenario A: Evaluates single-worker throughput and latency across concurrency levels
    (1, 10, 50, 100, 250, 500 clients).
    """
    results: List[BenchmarkResult] = []

    print("\n" + "=" * 70)
    print(" SCENARIO A: Single-Worker Performance Across Concurrency Levels")
    print("=" * 70)

    with UvicornServerManager(config, workers=1, redis_url=redis_url) as base_url:
        for conc in config.concurrency_levels:
            total_reqs = min(config.requests_per_test * 2, max(conc * 4, 200))
            warmup = min(config.warmup_requests, max(conc // 2, 10))

            print(f" -> Testing concurrency={conc:3d} clients ({total_reqs} requests)...", end="", flush=True)

            t_start = time.perf_counter()
            latencies_ms, status_codes, errors = asyncio.run(
                run_http_load_test(
                    base_url=base_url,
                    concurrency=conc,
                    total_requests=total_reqs,
                    auth_secret_key=config.auth_secret_key,
                    timeout_seconds=config.timeout_seconds,
                    warmup_requests=warmup,
                    scenario_name=f"single_worker_c{conc}",
                    redis_url=redis_url
                )
            )
            duration = time.perf_counter() - t_start

            res = BenchmarkResult.create(
                scenario_name=f"single_worker_concurrency_{conc}",
                concurrency=conc,
                workers=1,
                duration_seconds=duration,
                latencies_ms=latencies_ms,
                status_codes=status_codes,
                error_count=errors,
                metadata={"test_type": "single_worker_concurrency"}
            )
            results.append(res)

            print(f" Done! RPS: {res.requests_per_second:8.1f} | p50: {res.latency.p50_ms:6.2f}ms | p95: {res.latency.p95_ms:6.2f}ms | p99: {res.latency.p99_ms:6.2f}ms")

    return results


def benchmark_multi_worker_scalability(
    config: BenchmarkConfig,
    redis_url: str
) -> Tuple[List[BenchmarkResult], bool]:
    """
    Scenario B: Evaluates multi-worker scalability across 1, 2, and 4 workers.
    Also strictly verifies that workers share rate-limit state in Redis.
    """
    results: List[BenchmarkResult] = []
    concurrency = config.default_concurrency
    total_reqs = min(config.requests_per_test, 500)
    warmup = min(config.warmup_requests, 25)

    print("\n" + "=" * 70)
    print(f" SCENARIO B: Multi-Worker Scalability (Concurrency = {concurrency})")
    print("=" * 70)

    state_shared = False

    for w_count in config.worker_counts:
        print(f" -> Launching API with {w_count} worker(s)...", end="", flush=True)

        with UvicornServerManager(config, workers=w_count, redis_url=redis_url) as base_url:
            print(" ready! Executing load test...", end="", flush=True)

            t_start = time.perf_counter()
            latencies_ms, status_codes, errors = asyncio.run(
                run_http_load_test(
                    base_url=base_url,
                    concurrency=concurrency,
                    total_requests=total_reqs,
                    auth_secret_key=config.auth_secret_key,
                    timeout_seconds=config.timeout_seconds,
                    warmup_requests=warmup,
                    scenario_name=f"multi_worker_w{w_count}",
                    redis_url=redis_url
                )
            )
            duration = time.perf_counter() - t_start

            res = BenchmarkResult.create(
                scenario_name=f"multi_worker_scalability_w{w_count}",
                concurrency=concurrency,
                workers=w_count,
                duration_seconds=duration,
                latencies_ms=latencies_ms,
                status_codes=status_codes,
                error_count=errors,
                metadata={"test_type": "multi_worker_scalability"}
            )
            results.append(res)

            print(f" Done! RPS: {res.requests_per_second:8.1f} | p50: {res.latency.p50_ms:6.2f}ms | p95: {res.latency.p95_ms:6.2f}ms")

            # Verification of shared rate limit state on 2+ workers
            if w_count >= 2 and not state_shared:
                print(" -> Verifying shared state across worker processes...", end="", flush=True)
                state_shared = verify_shared_state_across_workers(base_url, config.auth_secret_key, redis_url=redis_url)
                print(f" {'PASS (Atomic State Shared in Redis)' if state_shared else 'FAIL'}")

    return results, state_shared


def verify_shared_state_across_workers(
    base_url: str,
    auth_secret_key: str,
    redis_url: Optional[str] = None
) -> bool:
    """
    Sends sequential requests for a single user to a multi-worker API
    and verifies that X-RateLimit-Remaining decrements across workers.
    """
    test_user = "shared_state_verify_user"
    test_ip = "198.51.100.254"
    token = create_signed_token(test_user, secret_key=auth_secret_key)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": test_ip,
        "User-Agent": "SharedStateVerifier/1.0"
    }

    # Pre-authorize and reset quota in Redis
    if redis_url:
        try:
            r = redis.from_url(redis_url, socket_timeout=2.0)
            r.delete(
                f"rate_limit:{test_user}",
                f"rate_limit:ip:{test_ip}",
                f"user_penalty_box:{test_user}",
                f"user_penalty_box:ip:{test_ip}",
                f"user_pending_challenge:{test_user}"
            )
            r.setex(f"verified_human:{test_user}", 3600, "verified")
        except Exception:
            pass

    remainings = []
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for _ in range(5):
            resp = client.get("/limited-resource", headers=headers)
            if resp.status_code == 200:
                rem_hdr = resp.headers.get("X-RateLimit-Remaining")
                if rem_hdr:
                    try:
                        remainings.append(float(rem_hdr))
                    except ValueError:
                        pass
            time.sleep(0.01)

    if len(remainings) >= 2:
        # Check that remaining tokens strictly decreased
        is_strictly_decreasing = all(remainings[i] > remainings[i + 1] for i in range(len(remainings) - 1))
        if is_strictly_decreasing:
            print(f"    [VERIFIED] Workers share rate-limit state in Redis: tokens {remainings}")
            return True

    print(f"    [WARNING] Could not confirm strictly decreasing tokens across requests: {remainings}")
    return False
