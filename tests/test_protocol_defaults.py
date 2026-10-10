import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProtocolDefaultTests(unittest.TestCase):
    def _read_client_setting(self, value: str | None) -> str:
        env = os.environ.copy()
        if value is None:
            env.pop("ALLOW_LEGACY_PROTOCOL", None)
        else:
            env["ALLOW_LEGACY_PROTOCOL"] = value
        result = subprocess.run(
            [sys.executable, "-c", "from routes.client import ALLOW_LEGACY_PROTOCOL; print(ALLOW_LEGACY_PROTOCOL)"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=20,
            check=True,
        )
        return result.stdout.strip()

    def test_legacy_protocol_is_disabled_when_setting_is_absent(self):
        self.assertEqual(self._read_client_setting(None), "False")

    def test_legacy_protocol_requires_explicit_opt_in(self):
        self.assertEqual(self._read_client_setting("true"), "True")

    def test_deployment_templates_default_to_protocol_two(self):
        env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("ALLOW_LEGACY_PROTOCOL=false", env_example)
        self.assertIn("ALLOW_LEGACY_PROTOCOL=${ALLOW_LEGACY_PROTOCOL:-false}", compose)


if __name__ == "__main__":
    unittest.main()
