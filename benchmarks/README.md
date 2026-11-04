# Performance Benchmarking & Scalability Evaluation Suite

This directory contains the reproducible performance benchmarking and scalability evaluation framework for the **Distributed Rate Limiter** project.

The suite measures throughput, latency distributions (p50, p90, p95, p99, max), multi-worker scaling efficiency, contention patterns, failure mode behaviors, and local vs. distributed tradeoffs under real-world traffic profiles.

---

## Architecture Overview

```
benchmarks/
├── config.py              # Configuration models & runtime environment metadata capture
├── aggregator.py          # Linear interpolation percentiles, LatencyStats & JSON/CSV exporters
├── chart_generator.py     # Pure-Python standalone SVG vector chart generator (zero dependencies)
├── server_manager.py      # Lifecycle manager for TCP Redis (native/embedded) and Uvicorn workers
├── http_benchmarks.py     # Scenarios A & B: HTTP load test engine and multi-worker scalability
├── core_benchmarks.py     # Scenarios C, D & E: Core engine behavior, outages, local vs Redis
├── locustfile.py          # Dedicated Locust load-testing script with HMAC-SHA256 authenticated users
├── runner.py              # Master CLI runner, orchestrator, and Markdown report builder
├── README.md              # Documentation and execution instructions
└── results/               # Generated reports, JSON, CSV, and SVG vector charts
```

---

## Prerequisites & Installation

The benchmark suite runs on Python 3.10+ and requires the standard repository virtual environment:

```bash
# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install application dependencies
pip install -r requirements.txt

# (Optional) For Locust distributed testing
pip install locust
```

> **Redis Availability**: The benchmarking suite automatically connects to any live Redis instance specified via `REDIS_URL` (e.g. `redis://localhost:6379`). If an external Redis instance is not reachable, the runner automatically instantiates an embedded TCP-based server with full Redis Lua script execution support (`fakeredis` + `lupa`), ensuring all benchmarks run seamlessly without external infrastructure.

---

## Running Benchmarks

### 1. Run the Full Benchmark Suite (All Scenarios A through E)

To run the complete benchmark suite:

```bash
python -m benchmarks.runner
```

### 2. Quick Mode (Rapid Sanity Run)

Runs all scenarios with reduced concurrency and duration (~30 seconds total) for fast verification:

```bash
python -m benchmarks.runner --quick
```

### 3. Run Specific Scenarios

Run individual scenarios by name:

```bash
# Run only Single-Worker Concurrency (Scenario A) and Multi-Worker Scalability (Scenario B)
python -m benchmarks.runner --scenarios A,B

# Run only Core Rate-Limiter Behavior (Scenario C)
python -m benchmarks.runner --scenarios C

# Run Redis Outage Failure Modes (Scenario D) and Local vs. Distributed Comparison (Scenario E)
python -m benchmarks.runner --scenarios D,E
```

### 4. Custom Output Directory

Specify a custom directory for output files, charts, and reports:

```bash
python -m benchmarks.runner --output-dir my_benchmarks/run_01
```

---

## Scenario Descriptions

### Scenario A: Single-Worker Performance
- **Target**: Single Uvicorn HTTP worker backed by Redis.
- **Concurrency Levels**: 1, 10, 50, 100, 250, and 500 concurrent HTTP clients.
- **Authentication**: HMAC-SHA256 signed Bearer tokens pre-generated via `create_signed_token`.
- **Metrics Collected**: Throughput (requests/second), Mean, Min, p50, p90, p95, p99, and Max latency.
- **Analysis**: Identifies event loop saturation, socket backlog pressure, and latency inflection points as concurrency scales.

### Scenario B: Multi-Worker Scalability & Contention
- **Target**: Multi-process Uvicorn cluster (1, 2, and 4 worker processes).
- **Workload**: Fixed concurrency (50 concurrent clients) executing authenticated rate-limited requests.
- **Verification**: Verifies atomic distributed state synchronization across worker processes via Redis Lua token bucket scripts.
- **Metrics Collected**: Scaling factor, throughput progression, latency distribution, and multi-core CPU utilization.

### Scenario C: Rate-Limiter Behavior & Fast-Path Rejection
- **Workload Scenarios**:
  - *Within Limit*: Token bucket has sufficient capacity; returns HTTP 200 with standard RFC headers (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`).
  - *Exceeding Limit*: Quota exhausted; returns HTTP 429 Too Many Requests.
  - *Multi-User Isolation*: 10 distinct users operating independently with partitioned quotas.
  - *Single-Key Contention*: 50 concurrent threads hammering a single user token bucket simultaneously.
  - *Token Bucket Parameters*: Compares default vs. burst (100 tokens) vs. tight (5 tokens) capacity.
- **Analysis**: Demonstrates the low-latency fast-path execution of 429 rejections compared to downstream endpoint handling.

### Scenario D: Redis Outage Failure Modes
Evaluates system resilience and throughput under all three configured failure modes during a complete Redis outage:
- **`FAIL_CLOSED`**: Strictly rejects all requests during outages (0 RPS passed, 100% fail-closed protection).
- **`FAIL_OPEN`**: Permits all traffic during outages (maximum availability, zero rate limiting).
- **`LOCAL_FALLBACK`**: Gracefully degrades to an in-memory thread-safe sliding token bucket per process (balanced resilience with localized rate limiting).
- **Recovery Behavior**: Measures system self-healing when Redis returns to service.

### Scenario E: Local In-Memory vs. Distributed Redis Comparison
- **Direct Engine Comparison**: Micro-benchmarks the core rate limiter engine directly (in-memory sliding bucket vs. distributed Redis Lua execution).
- **Metrics**: Raw throughput, operation latency distribution, lock overhead, and consistency guarantees.
- **Tradeoff Analysis**: Documents the throughput advantage of local in-memory limiting vs. the global consistency of Redis distributed state.

---

## Running Locust Load Tests

For continuous traffic simulation and interactive browser dashboards:

```bash
# Headless run: 50 concurrent users, spawn rate of 10 users/sec, run for 30s
locust -f benchmarks/locustfile.py --headless -u 50 -r 10 --run-time 30s --host http://127.0.0.1:8000

# Interactive Web UI (opens on http://localhost:8089):
locust -f benchmarks/locustfile.py --host http://127.0.0.1:8000
```

---

## Output Artifacts

Every benchmark run produces structured, machine-readable data and visual charts in the designated output directory (default: `benchmarks/results/`):

| File | Description |
|------|-------------|
| `benchmarks/REPORT.md` | Comprehensive Markdown report with executive summary, tables, and analysis |
| `single_worker_concurrency.json` | Detailed latency distributions across concurrency levels 1-500 |
| `multi_worker_scalability.json` | Scaling efficiency and throughput data across 1, 2, 4 Uvicorn workers |
| `rate_limiter_behavior.json` | Within-limit vs 429 fast-path latency and multi-user isolation results |
| `redis_failure_scenarios.json` | Throughput and error rates across FAIL_CLOSED, FAIL_OPEN, and LOCAL_FALLBACK |
| `local_vs_distributed.json` | In-memory token bucket vs Redis distributed token bucket micro-benchmarks |
| `summary_results.json` | Consolidated results with hardware and environment metadata |
| `benchmark_summary.csv` | Flat CSV table of all executed scenarios for spreadsheet ingestion |
| `charts/throughput_vs_concurrency.svg` | Vector line chart: RPS across concurrency levels |
| `charts/p95_latency_vs_concurrency.svg` | Vector line chart: Tail p95 latency vs concurrency |
| `charts/throughput_vs_workers.svg` | Vector bar chart: Multi-worker scaling comparison |
| `charts/local_vs_redis.svg` | Vector bar chart: In-memory vs. Redis latency & throughput comparison |

---

## Automated CI/CD Benchmarking

A standalone GitHub Actions workflow is provided at `.github/workflows/benchmarks.yml`. It runs on `workflow_dispatch` (on demand) against a dedicated `redis:7-alpine` container, publishes execution artifacts, and renders the executive summary directly into the GitHub Actions Job Summary.
