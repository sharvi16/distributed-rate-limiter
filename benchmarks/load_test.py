import sys
sys.path.insert(0, '.')
"""
High-Concurrency Performance & Load Benchmark (Phase 8).

Measures:
  - Throughput (Requests Per Second)
  - Latency percentiles: P50, P90, P99, Max (milliseconds)
  - Rate limit enforcement accuracy under multi-threaded contention
  - Status code breakdown (200 OK, 429 Rate Limited, 403 Challenge)
"""

import time
import math
import concurrent.futures
from typing import List, Dict
from fastapi.testclient import TestClient

import main
from main import app, limiter


def run_benchmark(num_clients: int = 10, requests_per_client: int = 50) -> Dict:
    total_requests = num_clients * requests_per_client
    latencies: List[float] = []
    status_counts: Dict[int, int] = {}

    client = TestClient(app)

    print(f"\n=======================================================")
    print(f" BENCHMARK: {num_clients} concurrent workers | {total_requests} total requests")
    print(f"=======================================================")

    start_time = time.perf_counter()

    def worker_task(worker_id: int):
        worker_latencies = []
        worker_statuses = {}
        user_id = f"bench_user_{worker_id}"
        limiter.reset(user_id)

        for _ in range(requests_per_client):
            t0 = time.perf_counter()
            resp = client.get(
                "/limited-resource",
                headers={"user-id": user_id, "user-agent": "BenchmarkClient/1.0"}
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            worker_latencies.append(elapsed_ms)
            worker_statuses[resp.status_code] = worker_statuses.get(resp.status_code, 0) + 1

        return worker_latencies, worker_statuses

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
        futures = [executor.submit(worker_task, i) for i in range(num_clients)]
        for f in concurrent.futures.as_completed(futures):
            w_lat, w_stat = f.result()
            latencies.extend(w_lat)
            for sc, count in w_stat.items():
                status_counts[sc] = status_counts.get(sc, 0) + count

    total_duration = time.perf_counter() - start_time
    rps = total_requests / total_duration if total_duration > 0 else 0.0

    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p90 = latencies[int(len(latencies) * 0.90)]
    p99 = latencies[int(len(latencies) * 0.99)]
    max_lat = latencies[-1]
    avg_lat = sum(latencies) / len(latencies)

    print(f"\nResults Summary:")
    print(f"  Duration:          {total_duration:.3f} s")
    print(f"  Throughput:        {rps:.1f} req/s")
    print(f"  Average Latency:   {avg_lat:.2f} ms")
    print(f"  P50 Latency:       {p50:.2f} ms")
    print(f"  P90 Latency:       {p90:.2f} ms")
    print(f"  P99 Latency:       {p99:.2f} ms")
    print(f"  Max Latency:       {max_lat:.2f} ms")
    print(f"  Status Codes:      {status_counts}")
    print(f"=======================================================\n")

    return {
        "total_requests": total_requests,
        "duration_sec": total_duration,
        "rps": rps,
        "p50_ms": p50,
        "p90_ms": p90,
        "p99_ms": p99,
        "status_counts": status_counts
    }


if __name__ == "__main__":
    run_benchmark(num_clients=8, requests_per_client=25)
