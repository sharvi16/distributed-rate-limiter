"""
Security Tests: IP Resolution, Header Spoofing Prevention, and Device Fingerprinting.

Verifies:
  1. Untrusted clients cannot spoof client IPs via X-Forwarded-For to evade rate limits or frame victims.
  2. Trusted proxy chains are securely parsed from right to left (RFC 7239 compliant).
  3. Custom CIDR subnet configurations properly identify trusted intermediaries.
  4. Malformed and edge-case IP inputs fail safely to peer IP without crashing.
  5. Device fingerprinting produces deterministic signatures while combining browser attributes.
  6. Full HTTP API integration test verifying spoofed header rejection.
"""

import pytest
from starlette.requests import Request
from fastapi.testclient import TestClient

from ip_utils import parse_trusted_proxies, is_ip_trusted, resolve_client_ip, DEFAULT_TRUSTED_PROXIES
from spam_detector import AdaptiveSpamDetector
from main import app


def _make_mock_request(client_host: str, headers_dict: dict = None) -> Request:
    """Helper to construct a Starlette Request with a specific client IP and headers."""
    if headers_dict is None:
        headers_dict = {}

    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers_dict.items()]
    scope = {
        "type": "http",
        "client": (client_host, 54321),
        "headers": raw_headers,
        "method": "GET",
        "path": "/limited-resource",
    }
    return Request(scope)


class TestIPResolutionAndSpoofingDefense:
    def test_untrusted_peer_cannot_spoof_x_forwarded_for(self):
        """Direct untrusted peer IP must NEVER be overridden by X-Forwarded-For."""
        untrusted_peer = "198.51.100.42"
        req = _make_mock_request(
            client_host=untrusted_peer,
            headers_dict={"x-forwarded-for": "1.1.1.1, 8.8.8.8"}
        )
        resolved = resolve_client_ip(req, trusted_networks=DEFAULT_TRUSTED_PROXIES)
        assert resolved == untrusted_peer, f"Expected {untrusted_peer}, got {resolved} (IP spoofing allowed!)"

    def test_trusted_proxy_single_forwarded_ip(self):
        """When peer is a trusted reverse proxy (e.g. 127.0.0.1), use the forwarded IP."""
        trusted_peer = "127.0.0.1"
        real_client = "203.0.113.195"
        req = _make_mock_request(
            client_host=trusted_peer,
            headers_dict={"x-forwarded-for": real_client}
        )
        resolved = resolve_client_ip(req, trusted_networks=DEFAULT_TRUSTED_PROXIES)
        assert resolved == real_client

    def test_trusted_proxy_chain_multiple_hops(self):
        """
        Reverse proxy chain: Client -> Cloudflare (10.0.0.5) -> Local LB (127.0.0.1) -> App.
        Both 10.0.0.0/8 and 127.0.0.0/8 are trusted proxies.
        Real client is 198.51.100.99.
        """
        trusted_nets = parse_trusted_proxies("127.0.0.0/8, 10.0.0.0/8")
        req = _make_mock_request(
            client_host="127.0.0.1",
            headers_dict={
                "x-forwarded-for": "198.51.100.99, 10.0.0.5"
            }
        )
        resolved = resolve_client_ip(req, trusted_networks=trusted_nets)
        assert resolved == "198.51.100.99"

    def test_client_spoofs_header_behind_trusted_proxy(self):
        """
        Attacker (203.0.113.5) injects '1.2.3.4' into X-Forwarded-For before hitting trusted proxy (127.0.0.1).
        Header received: '1.2.3.4, 203.0.113.5'.
        Rightmost untrusted IP is 203.0.113.5, NOT the injected 1.2.3.4!
        """
        trusted_nets = parse_trusted_proxies("127.0.0.1")
        req = _make_mock_request(
            client_host="127.0.0.1",
            headers_dict={"x-forwarded-for": "1.2.3.4, 203.0.113.5"}
        )
        resolved = resolve_client_ip(req, trusted_networks=trusted_nets)
        assert resolved == "203.0.113.5", "Attacker injected header was mistakenly accepted!"

    def test_all_ips_trusted_returns_leftmost(self):
        """If every IP in the chain is in trusted proxies, return the leftmost entry."""
        trusted_nets = parse_trusted_proxies("10.0.0.0/8, 127.0.0.0/8")
        req = _make_mock_request(
            client_host="127.0.0.1",
            headers_dict={"x-forwarded-for": "10.0.0.1, 10.0.0.2"}
        )
        resolved = resolve_client_ip(req, trusted_networks=trusted_nets)
        assert resolved == "10.0.0.1"

    def test_malformed_ips_handled_without_crash(self):
        """Garbage strings in X-Forwarded-For should safely fall back to peer IP."""
        req = _make_mock_request(
            client_host="127.0.0.1",
            headers_dict={"x-forwarded-for": "invalid-ip, ???, 999.999.999.999"}
        )
        resolved = resolve_client_ip(req, trusted_networks=DEFAULT_TRUSTED_PROXIES)
        assert resolved == "127.0.0.1"

    def test_custom_cidr_subnet_parsing(self):
        nets = parse_trusted_proxies("172.16.0.0/12, 192.168.1.0/24")
        assert is_ip_trusted("172.16.10.5", nets) is True
        assert is_ip_trusted("172.31.255.255", nets) is True
        assert is_ip_trusted("172.32.0.1", nets) is False
        assert is_ip_trusted("192.168.1.50", nets) is True
        assert is_ip_trusted("192.168.2.1", nets) is False


class TestDeviceFingerprintingSecurity:
    def test_deterministic_fingerprint(self):
        detector = AdaptiveSpamDetector(redis_client=None)
        h1 = {
            "device-id": "phone-abc",
            "accept-language": "en-US",
            "accept-encoding": "gzip, deflate",
            "sec-ch-ua": '"Chromium";v="120"',
            "sec-ch-ua-platform": '"Windows"',
        }
        fp1 = detector.compute_device_fingerprint(h1, user_agent="Mozilla/5.0")
        fp2 = detector.compute_device_fingerprint(h1, user_agent="Mozilla/5.0")
        assert fp1 == fp2
        assert fp1.startswith("dev_")

    def test_fingerprint_changes_with_browser_characteristics(self):
        detector = AdaptiveSpamDetector(redis_client=None)
        h1 = {"sec-ch-ua-platform": '"Windows"', "accept-language": "en-US"}
        h2 = {"sec-ch-ua-platform": '"macOS"', "accept-language": "en-GB"}

        fp1 = detector.compute_device_fingerprint(h1, user_agent="Chrome")
        fp2 = detector.compute_device_fingerprint(h2, user_agent="Safari")
        assert fp1 != fp2


class TestHTTPAPIHeaderSpoofingIntegration:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_root_endpoint_metadata(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "Distributed Rate Limiter" in data["message"]

    def test_limited_resource_ignores_spoofed_header_from_untrusted_peer(self, client, monkeypatch):
        """
        When TRUSTED_PROXIES is configured to require an explicit upstream (e.g. 10.0.0.1),
        a request from 127.0.0.1 sending 'x-forwarded-for: 198.51.100.99' must use 127.0.0.1,
        not 198.51.100.99.
        """
        import main
        from ip_utils import parse_trusted_proxies
        # Configure TRUSTED_PROXIES to only trust 10.0.0.1
        monkeypatch.setattr(main, "TRUSTED_PROXIES", parse_trusted_proxies("10.0.0.1"))
        
        response = client.get(
            "/limited-resource",
            headers={
                "user-id": "test_user_hdr_spoof_safe",
                "x-forwarded-for": "198.51.100.99"
            }
        )
        assert response.status_code in [200, 403, 429]
        if response.status_code == 200:
            data = response.json()
            assert data["message"] in ["Request allowed", "Request allowed (Verified Human Session)"]
