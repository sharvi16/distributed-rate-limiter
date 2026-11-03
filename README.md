# Distributed Rate Limiter & Multi-Tier Abuse Defense System

A production-ready distributed rate limiting and defense-in-depth abuse mitigation system built with **FastAPI**, **Redis**, the **Token Bucket algorithm**, and an **Online Self-Learning Gaussian Anomaly Detection Engine**.

---

## 🌟 Security Architecture & Execution Flow

Incoming requests pass through a strictly prioritized, multi-tier evaluation pipeline before accessing protected resources:

```mermaid
flowchart TD
    Req[Incoming HTTP Request] --> AuthCheck{Authentication & Principal Resolution<br/>Bearer Token or API Key}
    AuthCheck -->|Invalid / Missing| Reject401[HTTP 401: Unauthorized]
    AuthCheck -->|Verified Principal| ResolveIP[Resolve Client IP via Trusted Proxy Chain]
    ResolveIP --> PenaltyCheck{Tier 0: Penalty Box Check<br/>User, IP, or Device Jailed?}
    
    PenaltyCheck -->|Jailed| BlockJail[HTTP 429: Penalty Box Active<br/>Returns Retry-After Header]
    PenaltyCheck -->|Clean| VPNHopping{Tier 1: VPN Hopping Check<br/>>2 distinct IPs for single device in 60s?}
    
    VPNHopping -->|Yes: VPN Churn| JailDevice[HTTP 429: Device Jailed for 120s<br/>dev:... stored in Redis]
    VPNHopping -->|Clean| SybilCheck{Tier 1: Sybil Attack Check<br/>>3 distinct user IDs from single IP in 60s?}
    
    SybilCheck -->|Yes: ID Cycling| JailIP[HTTP 429: IP Jailed for 120s<br/>ip:... stored in Redis]
    SybilCheck -->|Clean| OuterIPLimit{Tier 2: Outer IP Guardrail<br/>>30 req/min for physical IP?}
    
    OuterIPLimit -->|Exceeded| BlockIP[HTTP 429: IP Rate Limit Exceeded]
    OuterIPLimit -->|Clean| UserQuota{Tier 3: User Token Bucket<br/>Atomic Lua Evaluation<br/>Capacity: 10, Refill: 10/min}
    
    UserQuota -->|No Tokens Left| BlockUser[HTTP 429: Quota Exhausted<br/>Returns X-RateLimit-* & Retry-After]
    UserQuota -->|Tokens Available| VerifiedCheck{Tier 3: Verified Human Pass<br/>Active Pass in Redis / Memory?}
    
    VerifiedCheck -->|Active Pass| AllowVerified[HTTP 200 OK: Allowed<br/>Verified Human Session Pass]
    VerifiedCheck -->|Unverified| MLBehavior[Tier 4: Behavioral ML Classification<br/>Timing Jitter & Burst Frequency Analysis]
    
    MLBehavior -->|Bot Machine Speed| JailBot[HTTP 429: Jailed for 60s<br/>Model Trained on Bot Pattern]
    MLBehavior -->|Suspicious Burst| IssueChallenge[HTTP 403: Single-Use Challenge Issued<br/>State Stored in Redis with 120s TTL]
    MLBehavior -->|Natural Human Jitter| AllowHuman[HTTP 200 OK: Request Allowed<br/>Returns X-RateLimit-* Headers]

    IssueChallenge -->|Valid Verification| GrantPass[Unlocks 5-Min Verified Pass & Updates Centroids]
```

---

## 🛡️ Multi-Tier Defenses & Threat Model

| Defense Layer | Mechanism | Protection Provided | Limitations & Threat Boundaries |
| :--- | :--- | :--- | :--- |
| **Authentication & Principal Resolution** | HMAC-SHA256 token verification with constant-time comparison, expiry (3600s), and clock skew limits | Binds user quotas to verified cryptographic identities. Rejects forged, unsigned (`usr_*`, `token_*`), expired, or low-entropy credentials. | Requires secure distribution of `AUTH_SECRET_KEY` (minimum 32 bytes / 256 bits of random material). |
| **Token Bucket Quota** | Atomic Redis Lua script using Redis server clock (`TIME`) | Strict ceiling on request throughput per authenticated `user_id` (10 req/min). | Application-layer only. Large-scale volumetric L3/L4 DDoS attacks require upstream scrubbing (Cloudflare, AWS Shield). |
| **Physical IP Guardrail** | Outer Token Bucket tracking IP addresses (30 req/min) | Prevents runaway consumption from a single physical connection or network. | Shared public NATs (universities, corporate offices) share quota. Configurable via subnets. |
| **Trusted Proxy Resolution** | Reverse proxy chain traversal (RFC 7239 compliant) | Rejects spoofed `X-Forwarded-For` headers from untrusted direct peers. | Requires operator to correctly configure `TRUSTED_PROXIES` CIDRs in production. |
| **Sybil Attack Defense** | Atomic sliding window in Redis tracking `user_id` velocity per IP | Jails IP for 120s if $>3$ distinct user accounts are rotated within a 60-second window. | High-density NAT environments should tune `max_allowed_ids` or rely on user authentication tokens. |
| **VPN Hopping Defense** | Sliding window tracking IP velocity per Device Fingerprint | Jails Device Fingerprint for 120s if a single client rotates across $>2$ IPs in 60 seconds. | Header-based device fingerprinting is heuristic; sophisticated attackers can spoof browser attributes. |
| **Self-Learning Gaussian Anomaly Detector** | Bivariate Gaussian mixture tracking request interval jitter ($\sigma$) and burst sizes | Automatically flags zero-jitter robotic traffic and challenges suspicious micro-bursts. | Cold-start sensitivity is bounded by pre-seeded baseline centroids; model adapts online via verified feedback. |
| **Challenge-Based Verification** | Single-use challenges with cryptographic IDs, Redis TTL (120s), and attempt caps (3 max) | Allows false-positive human traffic to prove legitimacy and calibrate Gaussian parameters online. Binds verification strictly to authenticated principal. | Arithmetic challenges serve as automated script friction and model calibration signals, NOT bulletproof proof-of-human CAPTCHAs. |
| **Penalty Box Escalation** | Multi-target penalty lookup (`user_id`, `client_ip`, `device_id`) | Rapidly isolates abusive actors with geometric strike escalation (1x, 2x, 3x duration). | Stored with finite TTLs in Redis to prevent permanent lockout of reclaimed dynamic IPs. |

---

## 🔑 Authentication & Identity Security

Production deployments strictly require cryptographic authentication (`REQUIRE_AUTH=true` by default):

1. **HMAC-SHA256 Bearer Tokens**:
   - Format: `<user_id>:<timestamp>:<signature>`
   - Generated with `create_signed_token(user_id)`.
   - Verified via `verify_signed_token(token)` using `hmac.compare_digest` (timing-attack resistant).
2. **Token Lifetime & Skew Enforcement**:
   - Default lifetime: 3600 seconds (1 hour). Expired tokens return `401 Unauthorized`.
   - Future timestamps exceeding 60 seconds clock skew are rejected.
3. **No Unsigned Tokens**:
   - Unsigned shorthand patterns like `token_<user_id>` or `usr_<user_id>` are strictly rejected.
4. **Anti-Spoofing & Unified Endpoints**:
   - Both `/limited-resource` and `/verify-challenge` share the exact same `get_authenticated_principal` dependency.
   - When an authenticated token is present, any client-supplied `user-id` header or body payload is ignored. The rate-limiting and challenge-verification identity is derived exclusively from the verified principal.
5. **Strict Production Environment Isolation**:
   - In production (`ENVIRONMENT=production` or default), client-provided `user-id` headers are **ALWAYS prohibited**, regardless of other flags.
   - `ALLOW_UNAUTHENTICATED_DEV_HEADERS=true` is strictly rejected at startup in production.
   - Development-only client headers require explicit non-production configuration (`ENVIRONMENT=development` and `REQUIRE_AUTH=false` and `ALLOW_UNAUTHENTICATED_DEV_HEADERS=true`).
6. **Entropy Validation (Length is Not Entropy)**:
   - `AUTH_SECRET_KEY` must have a minimum length of 32 characters (256 bits).
   - In production, keys must contain securely generated random material: minimum 10 unique symbols and Shannon entropy $\ge 3.0$ bits/symbol. Trivial keys (such as `"x" * 32` or `"01" * 16`) and known documentation placeholders are rejected.
   - Generate a secure key with:
     ```bash
     python -c "import secrets; print(secrets.token_hex(32))"
     ```
7. **Strict Boolean Configuration Parsing**:
   - Configuration options like `REQUIRE_AUTH` and `ALLOW_UNAUTHENTICATED_DEV_HEADERS` strictly accept recognized boolean tokens (`true`, `false`, `1`, `0`, `yes`, `no`). Typos (e.g. `REQUIRE_AUTH=treu`) immediately fail startup rather than silently defaulting to insecure states.
8. **Startup-Time Lifespan Validation**:
   - Validation occurs eagerly during FastAPI application initialization (`lifespan`), halting process launch immediately on configuration errors or contradictory settings before traffic can be received. Secrets are never logged.

---

## ⚙️ Configurable Failure Modes

When Redis becomes unreachable, the rate limiter adheres to an explicitly configured failure mode policy:

1. **`fail_closed` (Default & Recommended)**:
   - Rejects unthrottled requests with `503 Service Unavailable`.
   - Applied consistently across both user and physical IP rate limiters.
   - Recommended for high-security, paid API, or compute-intensive endpoints where uncontrolled traffic could crash backend dependencies.
2. **`fail_open`**:
   - Allows requests to proceed unthrottled during an outage.
   - Suitable for mission-critical read endpoints prioritizing 100% availability over strict rate enforcement.
3. **`local_fallback`**:
   - Degrades to a thread-safe, memory-bounded (LRU/TTL) in-memory Token Bucket on each application worker.
   - **Operational Note**: Local fallback does NOT provide globally consistent distributed enforcement. Multiple instances maintain independent quotas. When Redis recovers, local consumption is not reconciled with Redis state.

---

## 📊 Standard RFC & IETF Rate-Limit Headers

All responses set standard RFC and IETF rate-limiting headers:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-RateLimit-Limit` / `RateLimit-Limit` | Maximum token burst capacity for the user/IP | `10` |
| `X-RateLimit-Remaining` / `RateLimit-Remaining` | Remaining tokens available in the bucket immediately following evaluation | `7` |
| `X-RateLimit-Reset` / `RateLimit-Reset` | Integer ceiling seconds until the bucket completely replenishes to full capacity: `ceil((capacity - remaining) / refill_rate)` | `18` |
| `Retry-After` | Integer seconds the client must wait before retrying to have sufficient tokens: `max(1, ceil((tokens - remaining) / refill_rate))` (present on all `429 Too Many Requests` responses) | `6` |

### Redis Server Wall-Clock Time Semantics & Monotonic Recovery

The rate limiter evaluates continuous refills inside an atomic Lua script using Redis server time (`redis.call('TIME')`):
- **Server Wall-Clock Time (gettimeofday)**: Redis `TIME` returns host operating system wall-clock time (`CLOCK_REALTIME`), not a guaranteed hardware monotonic clock (`CLOCK_MONOTONIC`).
- **Monotonic Clock Recovery**: To protect against backward time steps (NTP stepping, VM migration, leap seconds), both Redis Lua and local fallback compute `effective_now = math.max(now, last_updated)`. Elapsed time is strictly computed as `effective_now - last_updated`, and `effective_now` is persisted back to storage. This guarantees that `last_updated` is monotonically non-decreasing, preventing excess artificial token refills when the clock later catches up to normal time.
- **Server-Controlled Request Costs**: Ordinary requests consume strictly 1.0 token (server-controlled). Public client-specified `tokens` query parameters are removed to prevent malicious clients from multiplying quotas using fractional amounts (e.g., `?tokens=0.01`).
- **Oversized Token Requests**: A request demanding more tokens than bucket capacity is treated as invalid input (`ValueError` in `check_limit` and HTTP 400 Bad Request at the API layer), never HTTP 429 with a misleading `Retry-After`.
- **Burst Capacity vs Sustained Refill Rate**: API telemetry and error messages explicitly distinguish instantaneous burst capacity (e.g., 10 tokens) from continuous sustained refill rates (e.g., 10.0 requests/minute).
- **NTP Synchronization Requirements**: Production Redis hosts must run NTP in slew mode (e.g. `chrony` with slewing or `ntpd -x`) rather than abrupt step adjustments.
- **Failover & Replication Assumptions**: In distributed Redis Sentinel or Cluster environments, primary and replica hosts must maintain clock synchronization (skew $< 10\,\text{ms}$). A promoted replica with clock skew will either temporarily pause refills until elapsed time catches up or refill up to total bucket capacity without overflow.

---

## 📈 Prometheus Metrics & Observability

The application exposes real-time telemetry at `GET /metrics` adhering to Prometheus text exposition format (version 0.0.4):

- **Cluster-Wide Multi-Worker Aggregation (Priority 3, Item 10)**:
  - When Redis is connected, request and abuse counters are atomically updated and aggregated across all Uvicorn worker processes and application instances via Redis.
  - Cluster-wide metrics are explicitly tagged with `scope="cluster"` (e.g. `ratelimit_requests_total{status="allowed",scope="cluster"}`).
  - Each worker process also exposes process-local telemetry tagged with its worker PID (`ratelimit_process_requests_total{status="allowed",pid="<PID>"}`) to observe load distribution.
  - When Redis is disconnected, metrics gracefully fall back to process-local counters labeled with `scope="process"` (`(process-local fallback: Redis unavailable)`), preventing misleading claims of cluster-wide figures when counters are worker-local.
- **Metrics Access Protection (Priority 3, Item 9)**:
  - In production (`ENVIRONMENT=production` or default), `/metrics` is strictly protected (fail-closed, HTTP 401 Unauthorized for unauthenticated requests).
  - Can be authorized using `x-admin-key: <ADMIN_API_KEY>`, `x-metrics-key: <METRICS_API_KEY>`, or `Authorization: Bearer <METRICS_API_KEY>` via constant-time UTF-8 byte comparison.
  - Alternatively, supports network-level scraper allowlisting via `METRICS_ALLOWED_CIDRS` (e.g., internal Prometheus pod subnet).
  - In development/test, unauthenticated access can be permitted by setting `PROTECT_METRICS=false`.

### Metrics Exposed:
- `ratelimit_requests_total{status="allowed|rate_limited|jailed|challenge_required|error",scope="cluster|process"}`
- `ratelimit_process_requests_total{status="...",pid="..."}`
- `ratelimit_redis_connected` (gauge: 1 = healthy, 0 = disconnected)
- `ratelimit_jailed_total{scope="cluster|process"}` (counter of penalty box jailing events)
- `ratelimit_challenges_issued_total{scope="cluster|process"}`
- `ratelimit_challenges_verified_total{scope="cluster|process"}`
- `ratelimit_challenges_exhausted_total{scope="cluster|process"}`
- `ratelimit_sybil_attacks_detected_total{scope="cluster|process"}`
- `ratelimit_vpn_hopping_detected_total{scope="cluster|process"}`
- `ratelimit_model_version` (gauge tracking online learning iterations)

---

## 🔒 Administrative Endpoint Security

The diagnostic endpoint `GET /model-stats` exposes active model centroids, evaluation counters, and jailed users.
- **Fail-Closed Protection**: Access is strictly denied (HTTP 401 Unauthorized) if `ADMIN_API_KEY` is missing, empty, or incorrect. Unauthenticated public access is NEVER permitted in any environment.
- **Constant-Time Comparison**: Credentials submitted via `x-admin-key: <ADMIN_API_KEY>` are verified using `hmac.compare_digest` to prevent side-channel timing attacks.
- **Production Startup Enforcement**: In production (`ENVIRONMENT=production` or default), `ADMIN_API_KEY` is mandatory (minimum 32 characters, Shannon entropy $\ge 3.0$ bits/symbol, minimum 10 unique symbols). Missing or weak keys immediately halt process launch.
- **Error Neutrality**: Response error messages (`Unauthorized: invalid or missing admin credentials.`) do not leak whether the key is missing from server configuration or mismatched.
- Generate a cryptographically secure key with:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```

---

## 🚀 Quick Start & Deployment

### Local Development Setup

1. **Clone repository & set up virtual environment**:
   ```bash
   git clone https://github.com/sharvi16/distributed-rate-limiter.git
   cd distributed-rate-limiter
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env
   # Generate your secret key:
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Start local Redis**:
   ```bash
   redis-server
   ```

4. **Run FastAPI with Uvicorn**:
   ```bash
   uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```

---

### Docker & Docker Compose Deployment (Priority 3, Item 11)

Run the production multi-worker FastAPI application cluster and secured Redis service:

```bash
docker compose up --build
```

#### Production Deployment Hardening:
- **Genuine Multi-Stage Build**: `Dockerfile` separates the dependency compiler (`builder` stage) from the minimal runtime image (`runtime` stage), running under a non-root system user (`appuser:appgroup`).
- **Internal Redis Network**: Redis port 6379 is NOT published publicly to `0.0.0.0` by default. It is accessible exclusively by the `api` container over the internal Docker bridge network (`rate_limiter_net`).
- **Redis Authentication**: Supports password protection via `REDIS_PASSWORD` and `--requirepass` with authenticated healthchecks.
- **Restricted Trusted Proxies**: Defaults to loopback (`127.0.0.1,::1`). Operators must only specify their actual ingress reverse proxies/load balancers; blanket-trusting RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) is strictly avoided.
- **Metrics Endpoint Security**: `PROTECT_METRICS=true` by default, protecting `/metrics` via `x-admin-key`, `x-metrics-key`, `Authorization: Bearer`, or `METRICS_ALLOWED_CIDRS`.

---

## 🧪 Comprehensive Automated Test Suite

The test suite contains **162 exhaustive unit, integration, distributed, and security tests** executed via Pytest:

```bash
pytest tests/ -v
```

### Test Categories:
- **`tests/security/test_priority3_audit.py`** (18 tests): Prometheus `/metrics` access protection (fail-closed in production, `x-admin-key`, `x-metrics-key`, Bearer token, and `METRICS_ALLOWED_CIDRS` allowlisting, constant-time UTF-8 byte comparison), multi-worker metrics aggregation via Redis atomic counters, process-local telemetry attribution tagged with worker PID, graceful fallback labeling (`scope="process"`) when Redis is unavailable, genuine multi-stage Dockerfile build structure, unexposed internal Redis port in `docker-compose.yml`, and restricted `TRUSTED_PROXIES` configuration.
- **`tests/security/test_priority2_audit.py`** (35 tests): Consistent configuration snapshots in `check_limit()` and fallback paths under `self._lock` (eliminating torn reads), transactional integrity and thread safety of `RateLimiter.configure()` (rejecting partial mutations and verifying Redis arguments/telemetry parity), concurrent `max_local_keys` cache cleanup, server-controlled request costs (elimination of public `tokens` query parameters, ensuring strictly 1.0 token consumed per request and preventing fractional quota evasion), oversized token request handling (raising `ValueError` / returning HTTP 400 Bad Request on `tokens > capacity`, never HTTP 429), complete backward-clock and recovery sequence testing across Redis Lua and local fallback (preventing artificial refills via monotonic `effective_now`), dynamic startup configuration synchronization via `sync_rate_limiter_configuration()`, telemetry precision (`RateLimitResult.limit` float preservation), and clear distinction between burst capacity and sustained refill rate in API responses and headers.
- **`tests/security/test_admin_protection.py`** (15 tests): Admin key enforcement (fail-closed, missing/empty key denial, invalid key denial, valid key acceptance, UTF-8 byte constant-time comparison to prevent timing attacks and avoid 500 errors on non-ASCII input, single environment variable authoritative source with no stale global fallback, error message neutrality, production startup validation for existence/length/entropy/placeholders).
- **`tests/security/test_priority1_audit.py`** (43 tests): Redis failure modes at API level, challenge session binding, cryptographic token verification (HMAC-SHA256, expiry, future skew, unsigned token rejection), secret key entropy (Shannon entropy & diversity vs length), known placeholder blocklist, strict boolean configuration parsing, startup configuration validation through FastAPI lifespan, production vs development environment isolation, prohibition of unauthenticated headers in production, and identity anti-spoofing.
- **`tests/unit/test_token_bucket.py`** (11 tests): Capacity, refill math, oversized requests, atomic concurrency, failure modes (`fail_closed`, `fail_open`, `local_fallback`), and RFC headers.
- **`tests/unit/test_challenge.py`** (8 tests): Cryptographic ID generation, single-use enforcement, attempt exhaustion, user-session binding, and answer leak prevention.
- **`tests/integration/test_model_sync.py`** (4 tests): Gaussian centroid persistence across restarts, cross-instance synchronization, and atomic EMA Lua updates.
- **`tests/integration/test_identity_tracking.py`** (5 tests): Atomic sliding window Lua scripts, VPN hopping detection, Sybil attack velocity, and strike-based penalty escalation.
- **`tests/integration/test_api_endpoints.py`** (5 tests): Rate limit headers, 429 retry-after behavior, admin key protection, and Prometheus `/metrics` scraping.
- **`tests/security/test_header_spoofing.py`** (10 tests): Trusted proxy chain traversal, untrusted `X-Forwarded-For` rejection, CIDR subnet matching, and device fingerprint entropy.
- **`tests/distributed/test_multiple_instances.py`** (4 tests): Multi-worker shared quota enforcement, cluster-wide penalty propagation, and distributed model synchronization.
- **`tests/distributed/test_redis_failure.py`** (4 tests): Network partition simulation and graceful fallback behavior.

---

## ⚡ Performance Benchmarking

A reproducible load testing tool is included to benchmark throughput and latency percentiles under high concurrency:

```bash
python benchmarks/load_test.py
```

Outputs duration, throughput (req/s), P50, P90, P99, Max latencies, and HTTP status code distribution.
