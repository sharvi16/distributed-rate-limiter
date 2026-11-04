"""
Locust Load-Testing Definition for Distributed Rate Limiter.
Provides realistic user profiles with HMAC-SHA256 signed authentication.

Usage:
    locust -f benchmarks/locustfile.py --host http://127.0.0.1:8000
    locust -f benchmarks/locustfile.py --headless -u 100 -r 20 -t 30s --host http://127.0.0.1:8000
"""

import os
import uuid
import random
from locust import HttpUser, task, between, events

from auth import create_signed_token

AUTH_SECRET_KEY = os.getenv(
    "AUTH_SECRET_KEY",
    "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e"
)


class StandardRateLimitedUser(HttpUser):
    """
    Simulates a standard authenticated user making regular requests within normal quota.
    """
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.user_id = f"locust_std_{uuid.uuid4().hex[:8]}"
        self.token = create_signed_token(self.user_id, secret_key=AUTH_SECRET_KEY)
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "Locust/StandardUser"
        }

    @task(5)
    def access_limited_resource(self):
        with self.client.get(
            "/limited-resource",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code in (200, 429):
                response.success()
            else:
                response.failure(f"Unexpected status code: {response.status_code}")

    @task(1)
    def check_health(self):
        self.client.get("/")


class BurstSpammerUser(HttpUser):
    """
    Simulates an aggressive client sending rapid bursts to intentionally test rate limiting (429)
    and behavioral anomaly detection.
    """
    wait_time = between(0.01, 0.05)

    def on_start(self):
        self.user_id = f"locust_burst_{uuid.uuid4().hex[:8]}"
        self.token = create_signed_token(self.user_id, secret_key=AUTH_SECRET_KEY)
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "Locust/BurstSpammer"
        }

    @task
    def aggressive_burst(self):
        with self.client.get(
            "/limited-resource",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code in (200, 403, 429):
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
