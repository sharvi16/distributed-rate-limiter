"""
Lightweight Prometheus Metrics Exposition (Phase 8 / Priority 3).

Generates real-time Prometheus / OpenMetrics metrics adhering to RFC / Prometheus text
exposition format (version 0.0.4) without heavy external dependencies.

Supports:
  - Cluster-wide aggregation via Redis atomic counters across multiple worker processes.
  - Process-local metrics attribution (labeled by worker PID) to avoid misleading claims
    when operating without Redis or across multiple worker processes.
  - Graceful fallback to process-local counters when Redis is unreachable.
"""

import os
import threading
from typing import Dict, Optional, Any
import redis


class MetricsCollector:
    """
    Thread-safe Prometheus metrics collector for distributed rate limiter and abuse engine.
    Supports atomic cluster-wide counters via Redis, as well as process-local telemetry.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self._lock = threading.Lock()
        self.redis: Optional[redis.Redis] = redis_client
        self._pid = os.getpid()
        self.request_counters: Dict[str, int] = {
            "allowed": 0,
            "rate_limited": 0,
            "jailed": 0,
            "challenge_required": 0,
            "error": 0
        }
        self.jailed_total = 0
        self.challenges_issued_total = 0
        self.challenges_verified_total = 0
        self.challenges_exhausted_total = 0
        self.sybil_detected_total = 0
        self.vpn_hopping_detected_total = 0

    def set_redis(self, redis_client: Optional[redis.Redis]):
        """Sets or updates the Redis client used for cluster-wide metrics synchronization."""
        with self._lock:
            self.redis = redis_client

    def inc_request(self, status_label: str):
        with self._lock:
            if status_label in self.request_counters:
                self.request_counters[status_label] += 1
            else:
                self.request_counters[status_label] = 1

        if self.redis:
            try:
                self.redis.hincrby("metrics:requests_total", status_label, 1)
            except Exception:
                pass

    def inc_jailed(self):
        with self._lock:
            self.jailed_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:jailed_total")
            except Exception:
                pass

    def inc_challenge_issued(self):
        with self._lock:
            self.challenges_issued_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:challenges_issued_total")
            except Exception:
                pass

    def inc_challenge_verified(self):
        with self._lock:
            self.challenges_verified_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:challenges_verified_total")
            except Exception:
                pass

    inc_challenges_verified = inc_challenge_verified

    def inc_challenge_exhausted(self):
        with self._lock:
            self.challenges_exhausted_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:challenges_exhausted_total")
            except Exception:
                pass

    def inc_sybil(self):
        with self._lock:
            self.sybil_detected_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:sybil_detected_total")
            except Exception:
                pass

    def inc_vpn_hopping(self):
        with self._lock:
            self.vpn_hopping_detected_total += 1
        if self.redis:
            try:
                self.redis.incr("metrics:vpn_hopping_detected_total")
            except Exception:
                pass

    def reset_local(self):
        """Resets process-local counters (primarily for testing)."""
        with self._lock:
            for k in self.request_counters:
                self.request_counters[k] = 0
            self.jailed_total = 0
            self.challenges_issued_total = 0
            self.challenges_verified_total = 0
            self.challenges_exhausted_total = 0
            self.sybil_detected_total = 0
            self.vpn_hopping_detected_total = 0

    def generate_prometheus_output(self, limiter=None, detector=None) -> str:
        """
        Serializes current telemetry to Prometheus text format.

        Multi-Worker & Cluster Metrics Rules (Priority 3):
          - If Redis is connected, reads authoritative cluster-wide totals aggregated
            across all worker processes and application instances.
          - Exposes process-local counters tagged with worker PID so operators
            can observe traffic distribution across individual worker processes.
          - If Redis is disconnected, explicitly labels metrics with scope="process" to avoid
            misleadingly claiming cluster-wide figures when counters are only process-local.
        """
        cluster_data: Optional[Dict[str, Any]] = None
        if self.redis:
            try:
                pipe = self.redis.pipeline()
                pipe.hgetall("metrics:requests_total")
                pipe.mget([
                    "metrics:jailed_total",
                    "metrics:challenges_issued_total",
                    "metrics:challenges_verified_total",
                    "metrics:challenges_exhausted_total",
                    "metrics:sybil_detected_total",
                    "metrics:vpn_hopping_detected_total"
                ])
                h_reqs, m_totals = pipe.execute()
                cluster_reqs = {
                    (k.decode("utf-8") if isinstance(k, bytes) else str(k)): int(v)
                    for k, v in (h_reqs or {}).items()
                }
                for st in ("allowed", "rate_limited", "jailed", "challenge_required", "error"):
                    if st not in cluster_reqs:
                        cluster_reqs[st] = 0

                cluster_data = {
                    "requests": cluster_reqs,
                    "jailed": int(m_totals[0] or 0),
                    "challenges_issued": int(m_totals[1] or 0),
                    "challenges_verified": int(m_totals[2] or 0),
                    "challenges_exhausted": int(m_totals[3] or 0),
                    "sybil": int(m_totals[4] or 0),
                    "vpn_hopping": int(m_totals[5] or 0),
                }
            except Exception:
                cluster_data = None

        with self._lock:
            local_reqs = dict(self.request_counters)
            local_jailed = self.jailed_total
            local_ci = self.challenges_issued_total
            local_cv = self.challenges_verified_total
            local_ce = self.challenges_exhausted_total
            local_sybil = self.sybil_detected_total
            local_vpn = self.vpn_hopping_detected_total

        lines = []

        if cluster_data is not None:
            # Cluster-wide aggregated metrics
            lines.extend([
                "# HELP ratelimit_requests_total Total number of evaluated requests by outcome status across the cluster",
                "# TYPE ratelimit_requests_total counter",
            ])
            for status, count in sorted(cluster_data["requests"].items()):
                lines.append(f'ratelimit_requests_total{{status="{status}",scope="cluster"}} {count}')

            lines.extend([
                "",
                "# HELP ratelimit_jailed_total Total entities placed into the penalty box across the cluster",
                "# TYPE ratelimit_jailed_total counter",
                f'ratelimit_jailed_total{{scope="cluster"}} {cluster_data["jailed"]}',
                "",
                "# HELP ratelimit_challenges_issued_total Total verification challenges issued across the cluster",
                "# TYPE ratelimit_challenges_issued_total counter",
                f'ratelimit_challenges_issued_total{{scope="cluster"}} {cluster_data["challenges_issued"]}',
                "",
                "# HELP ratelimit_challenges_verified_total Total verification challenges solved across the cluster",
                "# TYPE ratelimit_challenges_verified_total counter",
                f'ratelimit_challenges_verified_total{{scope="cluster"}} {cluster_data["challenges_verified"]}',
                "",
                "# HELP ratelimit_challenges_exhausted_total Total challenges exhausted across the cluster",
                "# TYPE ratelimit_challenges_exhausted_total counter",
                f'ratelimit_challenges_exhausted_total{{scope="cluster"}} {cluster_data["challenges_exhausted"]}',
                "",
                "# HELP ratelimit_sybil_attacks_detected_total Total Sybil identity cycling events detected across the cluster",
                "# TYPE ratelimit_sybil_attacks_detected_total counter",
                f'ratelimit_sybil_attacks_detected_total{{scope="cluster"}} {cluster_data["sybil"]}',
                "",
                "# HELP ratelimit_vpn_hopping_detected_total Total VPN IP churning events detected across the cluster",
                "# TYPE ratelimit_vpn_hopping_detected_total counter",
                f'ratelimit_vpn_hopping_detected_total{{scope="cluster"}} {cluster_data["vpn_hopping"]}',
            ])

            # Process-local telemetry tagged with worker PID
            lines.extend([
                "",
                "# HELP ratelimit_process_requests_total Process-local evaluated requests by this worker process",
                "# TYPE ratelimit_process_requests_total counter",
            ])
            for status, count in sorted(local_reqs.items()):
                lines.append(f'ratelimit_process_requests_total{{status="{status}",pid="{self._pid}"}} {count}')

        else:
            # Process-local fallback when Redis is unreachable
            lines.extend([
                "# HELP ratelimit_requests_total Total number of evaluated requests by outcome status (process-local fallback: Redis unavailable)",
                "# TYPE ratelimit_requests_total counter",
            ])
            for status, count in sorted(local_reqs.items()):
                lines.append(f'ratelimit_requests_total{{status="{status}",scope="process",pid="{self._pid}"}} {count}')

            lines.extend([
                "",
                "# HELP ratelimit_jailed_total Total entities placed into the penalty box (process-local)",
                "# TYPE ratelimit_jailed_total counter",
                f'ratelimit_jailed_total{{scope="process",pid="{self._pid}"}} {local_jailed}',
                "",
                "# HELP ratelimit_challenges_issued_total Total verification challenges issued (process-local)",
                "# TYPE ratelimit_challenges_issued_total counter",
                f'ratelimit_challenges_issued_total{{scope="process",pid="{self._pid}"}} {local_ci}',
                "",
                "# HELP ratelimit_challenges_verified_total Total verification challenges solved (process-local)",
                "# TYPE ratelimit_challenges_verified_total counter",
                f'ratelimit_challenges_verified_total{{scope="process",pid="{self._pid}"}} {local_cv}',
                "",
                "# HELP ratelimit_challenges_exhausted_total Total challenges exhausted (process-local)",
                "# TYPE ratelimit_challenges_exhausted_total counter",
                f'ratelimit_challenges_exhausted_total{{scope="process",pid="{self._pid}"}} {local_ce}',
                "",
                "# HELP ratelimit_sybil_attacks_detected_total Total Sybil identity cycling events detected (process-local)",
                "# TYPE ratelimit_sybil_attacks_detected_total counter",
                f'ratelimit_sybil_attacks_detected_total{{scope="process",pid="{self._pid}"}} {local_sybil}',
                "",
                "# HELP ratelimit_vpn_hopping_detected_total Total VPN IP churning events detected (process-local)",
                "# TYPE ratelimit_vpn_hopping_detected_total counter",
                f'ratelimit_vpn_hopping_detected_total{{scope="process",pid="{self._pid}"}} {local_vpn}',
            ])

        if limiter:
            redis_status = 1 if limiter.is_redis_active() else 0
            lines.extend([
                "",
                "# HELP ratelimit_redis_connected Redis connection status (1 = connected, 0 = disconnected)",
                "# TYPE ratelimit_redis_connected gauge",
                f"ratelimit_redis_connected {redis_status}",
            ])

        if detector:
            model_ver = getattr(detector, "model_version", 1)
            lines.extend([
                "",
                "# HELP ratelimit_model_version Current version of learned Gaussian centroids",
                "# TYPE ratelimit_model_version gauge",
                f"ratelimit_model_version {model_ver}",
            ])

        return "\n".join(lines) + "\n"


# Global singleton metrics collector
metrics_collector = MetricsCollector()
