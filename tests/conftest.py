"""
Global pytest configuration and environment setup.
"""

import os
import pytest

# Ensure testing environment has a valid strong secret key and explicit test flags
TEST_SECRET_KEY = "test-secret-key-with-sufficient-length-32-characters"
os.environ.setdefault("AUTH_SECRET_KEY", TEST_SECRET_KEY)
os.environ.setdefault("REQUIRE_AUTH", "false")
os.environ.setdefault("ALLOW_UNAUTHENTICATED_DEV_HEADERS", "true")
os.environ.setdefault("ENVIRONMENT", "test")
