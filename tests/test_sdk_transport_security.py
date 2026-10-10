from pathlib import Path
import unittest


SDK_SOURCE = Path(__file__).resolve().parents[1] / "sdk" / "enauth.cpp"


class SdkTransportSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SDK_SOURCE.read_text(encoding="utf-8")

    def test_certificate_errors_are_never_ignored(self):
        forbidden = (
            "SECURITY_FLAG_IGNORE_CERT_CN_INVALID",
            "SECURITY_FLAG_IGNORE_CERT_DATE_INVALID",
            "SECURITY_FLAG_IGNORE_UNKNOWN_CA",
            "SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE",
            "WINHTTP_OPTION_SECURITY_FLAGS",
        )
        for flag in forbidden:
            with self.subTest(flag=flag):
                self.assertNotIn(flag, self.source)

    def test_modern_tls_and_bounded_timeouts_are_enforced(self):
        self.assertIn("WINHTTP_OPTION_SECURE_PROTOCOLS", self.source)
        self.assertIn("WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2", self.source)
        self.assertIn("WinHttpSetTimeouts", self.source)
        self.assertIn("if (!WinHttpSetTimeouts", self.source)
        self.assertIn("WINHTTP_ENABLE_SSL_REVOCATION", self.source)
        self.assertIn("WINHTTP_OPTION_REDIRECT_POLICY_NEVER", self.source)
        self.assertIn("WINHTTP_QUERY_CONTENT_LENGTH", self.source)
        self.assertIn("if (!WinHttpQueryDataAvailable", self.source)


if __name__ == "__main__":
    unittest.main()
