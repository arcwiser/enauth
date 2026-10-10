import os
import unittest

from utils.request_security import csrf_origin_allowed, resolve_client_ip


class RequestSecurityTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("TRUST_PROXY_HEADERS", None)
        os.environ.pop("TRUSTED_PROXY_CIDRS", None)

    def test_forwarded_header_from_untrusted_peer_is_ignored(self):
        os.environ["TRUST_PROXY_HEADERS"] = "true"
        os.environ["TRUSTED_PROXY_CIDRS"] = "172.22.1.0/24"
        self.assertEqual(resolve_client_ip("198.51.100.20", "1.2.3.4"), "198.51.100.20")

    def test_rightmost_untrusted_hop_defeats_prepended_spoof(self):
        os.environ["TRUST_PROXY_HEADERS"] = "true"
        os.environ["TRUSTED_PROXY_CIDRS"] = "172.22.1.0/24"
        self.assertEqual(resolve_client_ip("172.22.1.5", "1.2.3.4, 203.0.113.9"), "203.0.113.9")

    def test_malformed_forwarding_chain_fails_closed_to_socket_peer(self):
        os.environ["TRUST_PROXY_HEADERS"] = "true"
        os.environ["TRUSTED_PROXY_CIDRS"] = "172.22.1.0/24"
        self.assertEqual(
            resolve_client_ip("172.22.1.5", "198.51.100.12, definitely-not-an-ip"),
            "172.22.1.5",
        )
        self.assertEqual(resolve_client_ip("172.22.1.5", "198.51.100.12,"), "172.22.1.5")

    def test_csrf_requires_exact_configured_origin(self):
        allowed = "https://auth.olsoftwares.com,https://admin.olsoftwares.com"
        self.assertTrue(csrf_origin_allowed("https://auth.olsoftwares.com", allowed))
        self.assertFalse(csrf_origin_allowed("https://evil.example", allowed))
        self.assertFalse(csrf_origin_allowed(None, allowed))
        self.assertFalse(csrf_origin_allowed("https://auth.olsoftwares.com.evil.example", allowed))

    def test_actual_admin_middleware_rejects_cross_origin_cookie_mutation(self):
        import json
        import main
        from starlette.requests import Request

        probe_path = "/api/admin/_csrf-integration-probe"

        previous = os.environ.get("CSRF_TRUSTED_ORIGINS")
        os.environ["CSRF_TRUSTED_ORIGINS"] = "https://auth.olsoftwares.com"
        try:
            scope = {
                "type": "http", "asgi": {"version": "3.0"},
                "http_version": "1.1", "method": "POST",
                "scheme": "https", "path": probe_path, "raw_path": probe_path.encode(),
                "query_string": b"", "server": ("testserver", 443),
                "client": ("127.0.0.1", 12345),
                "headers": [
                    (b"host", b"testserver"),
                    (b"origin", b"https://auth.olsoftwares.com.attacker.test"),
                    (b"cookie", b"enauth_admin_session=test-session"),
                ],
            }

            async def unreachable_handler(_request):
                raise AssertionError("Rejected CSRF requests must not reach the route")

            # A rejected request returns before the middleware's first await,
            # so advancing once proves the real middleware short-circuits the route.
            coroutine = main.security_middleware(Request(scope), unreachable_handler)
            with self.assertRaises(StopIteration) as stopped:
                coroutine.send(None)
            response = stopped.exception.value
            rejected_status, rejected_body = response.status_code, json.loads(response.body)
        finally:
            if previous is None:
                os.environ.pop("CSRF_TRUSTED_ORIGINS", None)
            else:
                os.environ["CSRF_TRUSTED_ORIGINS"] = previous

        self.assertEqual(rejected_status, 403)
        self.assertEqual(rejected_body, {"detail": "CSRF_ORIGIN_REJECTED"})


if __name__ == "__main__":
    unittest.main()
