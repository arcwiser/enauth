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

    def test_csrf_requires_exact_configured_origin(self):
        allowed = "https://auth.olsoftwares.com,https://admin.olsoftwares.com"
        self.assertTrue(csrf_origin_allowed("https://auth.olsoftwares.com", allowed))
        self.assertFalse(csrf_origin_allowed("https://evil.example", allowed))
        self.assertFalse(csrf_origin_allowed(None, allowed))
        self.assertFalse(csrf_origin_allowed("https://auth.olsoftwares.com.evil.example", allowed))


if __name__ == "__main__":
    unittest.main()
