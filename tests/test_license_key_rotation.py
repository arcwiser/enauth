import base64
import hashlib
import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.crypto import (
    decrypt_license_key,
    encrypt_license_key,
    license_lookup_hashes,
)


class LicenseKeyRotationTests(unittest.TestCase):
    ENV_NAMES = (
        "LICENSE_KEY_PEPPER",
        "LICENSE_LOOKUP_KEY_ID",
        "LICENSE_LOOKUP_KEY",
        "LICENSE_LOOKUP_PREVIOUS_KEYS",
        "LICENSE_ENCRYPTION_KEY_ID",
        "LICENSE_ENCRYPTION_KEY",
        "LICENSE_ENCRYPTION_PREVIOUS_KEYS",
    )

    def setUp(self):
        self.original = {name: os.environ.get(name) for name in self.ENV_NAMES}
        for name in self.ENV_NAMES:
            os.environ.pop(name, None)

    def tearDown(self):
        for name, value in self.original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_lookup_rotation_accepts_previous_but_writes_current(self):
        os.environ["LICENSE_LOOKUP_KEY_ID"] = "lookup-v2"
        os.environ["LICENSE_LOOKUP_KEY"] = "L" * 32
        os.environ["LICENSE_LOOKUP_PREVIOUS_KEYS"] = json.dumps({"lookup-v1": "O" * 32})
        hashes = license_lookup_hashes("abc-123")
        self.assertEqual([item[0] for item in hashes], ["lookup-v2", "lookup-v1"])
        self.assertNotEqual(hashes[0][1], hashes[1][1])

    def test_encryption_rotation_decrypts_previous_version(self):
        os.environ["LICENSE_ENCRYPTION_KEY_ID"] = "enc-v2"
        os.environ["LICENSE_ENCRYPTION_KEY"] = "E" * 32
        encrypted = encrypt_license_key("ABCDEF-123456")
        self.assertTrue(encrypted.startswith("v2.enc-v2."))

        os.environ["LICENSE_ENCRYPTION_KEY_ID"] = "enc-v3"
        os.environ["LICENSE_ENCRYPTION_KEY"] = "N" * 32
        os.environ["LICENSE_ENCRYPTION_PREVIOUS_KEYS"] = json.dumps({"enc-v2": "E" * 32})
        self.assertEqual(decrypt_license_key(encrypted), "ABCDEF-123456")

    def test_legacy_ciphertext_remains_decryptable_during_transition(self):
        legacy_secret = "P" * 32
        os.environ["LICENSE_KEY_PEPPER"] = legacy_secret
        os.environ["LICENSE_ENCRYPTION_KEY_ID"] = "enc-v2"
        os.environ["LICENSE_ENCRYPTION_KEY"] = "E" * 32
        nonce = b"0" * 12
        old_key = hashlib.sha256(b"enauth-license-storage-v1\0" + legacy_secret.encode()).digest()
        ciphertext = AESGCM(old_key).encrypt(nonce, b"LEGACY-KEY", b"enauth-license-key-v1")
        stored = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        self.assertEqual(decrypt_license_key(stored), "LEGACY-KEY")

    def test_lookup_and_encryption_secrets_are_independent(self):
        os.environ["LICENSE_LOOKUP_KEY_ID"] = "lookup-v1"
        os.environ["LICENSE_LOOKUP_KEY"] = "L" * 32
        os.environ["LICENSE_ENCRYPTION_KEY_ID"] = "enc-v1"
        os.environ["LICENSE_ENCRYPTION_KEY"] = "E" * 32
        first_hash = license_lookup_hashes("ABC-123")[0][1]
        encrypted = encrypt_license_key("ABC-123")
        os.environ["LICENSE_ENCRYPTION_KEY"] = "F" * 32
        self.assertEqual(license_lookup_hashes("ABC-123")[0][1], first_hash)
        with self.assertRaises(Exception):
            decrypt_license_key(encrypted)


if __name__ == "__main__":
    unittest.main()
