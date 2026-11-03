"""
Global pytest configuration and environment setup.
"""

import os
import secrets
import pytest

# Ensure testing environment has a cryptographically strong secret key and explicit test flags
TEST_SECRET_KEY = "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e"
os.environ.setdefault("AUTH_SECRET_KEY", TEST_SECRET_KEY)
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
os.environ.setdefault("ENVIRONMENT", "test")


@pytest.fixture(autouse=True)
def reset_global_rate_limiters():
    """Guarantees global singletons in main are clean before and after each test."""
    yield
    try:
        import main
        main.limiter.configure(
            redis_url="redis://localhost:6379",
            redis_password=None,
            ssl_certfile=None,
            ssl_keyfile=None,
            ssl_ca_certs=None,
            ssl_cert_reqs=None,
            ssl_check_hostname=None
        )
        main.ip_limiter.configure(
            redis_url="redis://localhost:6379",
            redis_password=None,
            ssl_certfile=None,
            ssl_keyfile=None,
            ssl_ca_certs=None,
            ssl_cert_reqs=None,
            ssl_check_hostname=None
        )
    except Exception:
        pass
