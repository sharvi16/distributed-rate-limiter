"""
Admin API Key Security & Diagnostics Protection Regression Tests.

Covers:
  1. Missing admin key -> access denied (401).
  2. Empty admin key -> access denied (401).
  3. Missing request header -> access denied (401).
  4. Incorrect admin key -> access denied (401).
  5. Correct admin key -> access granted (200).
  6. Production startup with missing admin key -> startup fails (RuntimeError).
  7. Production startup with weak admin key -> startup fails (ValueError).
  8. Production startup with valid admin key -> startup succeeds.
  9. Constant-time key comparison (timing attack resistance).
 10. Information leak prevention (neutral error message across all failures).
 11. No stale global fallback (environment variable is single authoritative source).
 12. Safe handling of non-ASCII headers via UTF-8 byte comparison (no unexpected 500 errors).
"""

import hmac
import secrets
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from main import app, verify_admin_key
from auth import validate_auth_configuration, validate_admin_configuration


@pytest.fixture
def client():
    return TestClient(app)


class TestAdminEndpointProtection:
    def test_missing_admin_key_denies_access(self, client, monkeypatch):
        """When ADMIN_API_KEY is not configured, /model-stats must deny access (401 fail-closed)."""
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)

        # Even with a non-empty header, access is denied
        response = client.get("/model-stats", headers={"x-admin-key": "attempted_key"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

    def test_empty_admin_key_denies_access(self, client, monkeypatch):
        """When ADMIN_API_KEY is empty or whitespace, /model-stats must deny access (401)."""
        monkeypatch.setenv("ADMIN_API_KEY", "   ")

        response = client.get("/model-stats", headers={"x-admin-key": "attempted_key"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

    def test_missing_request_header_denies_access(self, client, monkeypatch):
        """When x-admin-key header is omitted, /model-stats must return 401 Unauthorized."""
        valid_key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", valid_key)

        response = client.get("/model-stats")
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

    def test_incorrect_admin_key_denies_access(self, client, monkeypatch):
        """When x-admin-key header is incorrect, /model-stats must return 401 Unauthorized."""
        valid_key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", valid_key)

        response = client.get("/model-stats", headers={"x-admin-key": "wrong-admin-key-value"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

    def test_correct_admin_key_grants_access(self, client, monkeypatch):
        """When x-admin-key header matches configured ADMIN_API_KEY, access is granted (200)."""
        valid_key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", valid_key)

        response = client.get("/model-stats", headers={"x-admin-key": valid_key})
        assert response.status_code == 200
        data = response.json()
        assert "model_centroids" in data
        assert "storage_mode" in data

    def test_neutral_error_message_prevents_information_leak(self, client, monkeypatch):
        """Missing key, empty key, missing header, and wrong key must all return identical generic error."""
        expected_detail = "Unauthorized: invalid or missing admin credentials."

        # Case 1: Key missing on server
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        r1 = client.get("/model-stats", headers={"x-admin-key": "any"})
        assert r1.status_code == 401
        assert r1.json()["detail"] == expected_detail

        # Case 2: Header missing on client
        key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", key)
        r2 = client.get("/model-stats")
        assert r2.status_code == 401
        assert r2.json()["detail"] == expected_detail

        # Case 3: Wrong key provided
        r3 = client.get("/model-stats", headers={"x-admin-key": "wrong"})
        assert r3.status_code == 401
        assert r3.json()["detail"] == expected_detail

    def test_constant_time_comparison_used(self, monkeypatch):
        """verify_admin_key must perform constant-time comparison via hmac.compare_digest."""
        called_compare = False
        original_compare = hmac.compare_digest

        def mock_compare(a, b):
            nonlocal called_compare
            called_compare = True
            return original_compare(a, b)

        monkeypatch.setattr(hmac, "compare_digest", mock_compare)
        key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", key)

        verify_admin_key(x_admin_key=key)
        assert called_compare is True

    def test_no_stale_global_fallback_fails_closed(self, client, monkeypatch):
        """
        If the environment variable becomes empty or deleted after module load,
        the endpoint must immediately fail closed and NEVER fall back to a stale global variable.
        """
        # Set an old key in main module namespace if any
        if hasattr(main, "ADMIN_API_KEY"):
            monkeypatch.setattr(main, "ADMIN_API_KEY", "stale_old_module_global_key")

        # But environment variable is deleted / empty
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)

        # Attacking with stale old key must be rejected (401)
        response = client.get("/model-stats", headers={"x-admin-key": "stale_old_module_global_key"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

    def test_non_ascii_header_handled_safely_without_500(self, client, monkeypatch):
        """
        Sending non-ASCII or multi-byte unicode characters in x-admin-key must be
        handled safely via UTF-8 bytes comparison without causing an unexpected 500 error.
        """
        key = secrets.token_hex(32)
        monkeypatch.setenv("ADMIN_API_KEY", key)

        non_ascii_attack_headers = [
            "🔑_unicode_emoji_attack_12345",
            "ñ_accent_unicode_char_£_€",
            "日本語_admin_token_test",
            "räksmörgås_special_chars_12345",
            "invalid\x00null_byte_sequence"
        ]

        for header_val in non_ascii_attack_headers:
            # Test via client with encoded byte header (as transmitted over HTTP)
            response = client.get("/model-stats", headers={"x-admin-key": header_val.encode("utf-8")})
            assert response.status_code == 401, f"Expected 401 for header {header_val!r}, got {response.status_code}"
            assert response.json()["detail"] == "Unauthorized: invalid or missing admin credentials."

            # Test direct verify_admin_key with unicode string (would crash with TypeError in hmac without byte conversion)
            with pytest.raises(HTTPException) as exc_info:
                verify_admin_key(x_admin_key=header_val)
            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Unauthorized: invalid or missing admin credentials."

    def test_matching_non_ascii_admin_key_authorizes_correctly(self, monkeypatch):
        """
        UTF-8 byte comparison correctly matches and authorizes when both the configured
        key and client header contain valid matching multi-byte UTF-8 characters.
        """
        utf8_key = "🔑_valid_unicode_key_ñ_€_12345678901234567890"
        monkeypatch.setenv("ADMIN_API_KEY", utf8_key)

        assert verify_admin_key(x_admin_key=utf8_key) is True


class TestAdminStartupValidation:
    def test_production_startup_fails_with_missing_admin_key(self, monkeypatch):
        """In production, missing ADMIN_API_KEY must raise RuntimeError at startup."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)

        with pytest.raises(RuntimeError) as exc_info:
            validate_admin_configuration()
        assert "ADMIN_API_KEY" in str(exc_info.value)
        assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)

        # Full startup validation also fails
        with pytest.raises(RuntimeError):
            validate_auth_configuration()

        # FastAPI lifespan aborts launch
        with pytest.raises(RuntimeError):
            with TestClient(app):
                pass

    def test_production_startup_fails_with_weak_admin_key_length(self, monkeypatch):
        """In production, an ADMIN_API_KEY shorter than 32 characters must raise ValueError."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.setenv("ADMIN_API_KEY", "short-admin-key")
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)

        with pytest.raises(ValueError) as exc_info:
            validate_admin_configuration()
        assert "insufficient length" in str(exc_info.value)
        assert "Minimum required length is 32 characters" in str(exc_info.value)

    def test_production_startup_fails_with_low_entropy_admin_key(self, monkeypatch):
        """In production, a low-entropy ADMIN_API_KEY like 'x' * 32 must raise ValueError."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)

        # Repeating character
        monkeypatch.setenv("ADMIN_API_KEY", "x" * 32)
        with pytest.raises(ValueError) as exc_info:
            validate_admin_configuration()
        assert "insufficient cryptographic entropy" in str(exc_info.value)

        # Alternating characters
        monkeypatch.setenv("ADMIN_API_KEY", "01" * 16)
        with pytest.raises(ValueError) as exc_info:
            validate_admin_configuration()
        assert "insufficient cryptographic entropy" in str(exc_info.value)

    def test_production_startup_fails_with_placeholder_admin_key(self, monkeypatch):
        """In production, an ADMIN_API_KEY matching known documentation placeholders must raise ValueError."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)

        placeholder = "replace-with-a-secure-random-secret-key-at-least-32-chars-long"
        monkeypatch.setenv("ADMIN_API_KEY", placeholder)
        with pytest.raises(ValueError) as exc_info:
            validate_admin_configuration()
        assert "known insecure placeholder" in str(exc_info.value)

    def test_production_startup_succeeds_with_valid_admin_key(self, monkeypatch):
        """In production, a cryptographically secure random ADMIN_API_KEY succeeds startup."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        monkeypatch.setenv("AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.setenv("ADMIN_API_KEY", secrets.token_hex(32))
        monkeypatch.delenv("ALLOW_UNAUTHENTICATED_DEV_HEADERS", raising=False)

        # Validation must complete without raising
        validate_admin_configuration()
        validate_auth_configuration()

        with TestClient(app) as test_client:
            res = test_client.get("/")
            assert res.status_code == 200
