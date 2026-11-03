"""
Lightweight Prometheus Metrics Exposition (Phase 8).

Generates real-time Prometheus / OpenMetrics metrics adhering to RFC / Prometheus text
exposition format (version 0.0.4) without heavy external dependencies.
"""

import threading
from typing import Dict, Optional


class MetricsCollector:
    """Thread-safe Prometheus metrics collector for distributed rate limiter and abuse engine."""

    def __init__(self):
        self._lock = threading.Lock()
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

    def inc_request(self, status_label: str):
        with self._lock:
            if status_label in self.request_counters:
                self.request_counters[status_label] += 1
            else:
                self.request_counters[status_label] = 1

    def inc_jailed(self):
        with self._lock:
            self.jailed_total += 1

    def inc_challenge_issued(self):
        with self._lock:
            self.challenges_issued_total += 1

    def inc_challenge_verified(self):
        with self._lock:
            self.challenges_verified_total += 1

    def inc_challenge_exhausted(self):
        with self._lock:
            self.challenges_exhausted_total += 1

    def inc_sybil(self):
        with self._lock:
            self.sybil_detected_total += 1

    def inc_vpn_hopping(self):
        with self._lock:
            self.vpn_hopping_detected_total += 1

    def generate_prometheus_output(self, limiter=None, detector=None) -> str:
        """Serializes current telemetry to Prometheus text format."""
        with self._lock:
            lines = [
                "# HELP ratelimit_requests_total Total number of evaluated requests by outcome status",
                "# TYPE ratelimit_requests_total counter",
            ]
            for status, count in sorted(self.request_counters.items()):
                lines.append(f'ratelimit_requests_total{{status="{status}"}} {count}')

            lines.extend([
                "",
                "# HELP ratelimit_jailed_total Total entities placed into the penalty box",
                "# TYPE ratelimit_jailed_total counter",
                f"ratelimit_jailed_total {self.jailed_total}",
                "",
                "# HELP ratelimit_challenges_issued_total Total verification challenges issued to suspicious clients",
                "# TYPE ratelimit_challenges_issued_total counter",
                f"ratelimit_challenges_issued_total {self.challenges_issued_total}",
                "",
                "# HELP ratelimit_challenges_verified_total Total verification challenges successfully solved",
                "# TYPE ratelimit_challenges_verified_total counter",
                f"ratelimit_challenges_verified_total {self.challenges_verified_total}",
                "",
                "# HELP ratelimit_challenges_exhausted_total Total challenges where attempts were exhausted or failed",
                "# TYPE ratelimit_challenges_exhausted_total counter",
                f"ratelimit_challenges_exhausted_total {self.challenges_exhausted_total}",
                "",
                "# HELP ratelimit_sybil_attacks_detected_total Total Sybil identity cycling events detected",
                "# TYPE ratelimit_sybil_attacks_detected_total counter",
                f"ratelimit_sybil_attacks_detected_total {self.sybil_detected_total}",
                "",
                "# HELP ratelimit_vpn_hopping_detected_total Total VPN IP churning events detected",
                "# TYPE ratelimit_vpn_hopping_detected_total counter",
                f"ratelimit_vpn_hopping_detected_total {self.vpn_hopping_detected_total}",
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
