"""
Global pytest configuration and environment setup.
"""

import os
import secrets

# Ensure testing environment has a cryptographically strong secret key and explicit test flags
TEST_SECRET_KEY = "c47a98b0f81d2f195e26b17c80523f46da9a738c642e051783e4bb9057d2913e"
os.environ.setdefault("AUTH_SECRET_KEY", TEST_SECRET_KEY)
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
os.environ.setdefault("ENVIRONMENT", "test")
