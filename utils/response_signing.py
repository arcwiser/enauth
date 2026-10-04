"""Server-only ECDSA response signing.

The private key never belongs in the SDK. Clients embed only the public X/Y
coordinates and verify every encrypted response before decrypting it.
"""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

KEY_PATH = Path(os.getenv("RESPONSE_SIGNING_KEY_PATH", "response-signing-key.pem")).resolve()


def ensure_response_signing_key() -> None:
    if KEY_PATH.exists():
        _load_private_key()
        return
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    encoded = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(KEY_PATH, flags, 0o600)
    except FileExistsError:
        _load_private_key()
        return
    try:
        os.write(fd, encoded)
    finally:
        os.close(fd)


def _load_private_key():
    if not KEY_PATH.exists():
        ensure_response_signing_key()
    key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise RuntimeError("Response signing key must be ECDSA P-256")
    return key


def response_public_key_hex() -> str:
    numbers = _load_private_key().public_key().public_numbers()
    return numbers.x.to_bytes(32, "big").hex() + numbers.y.to_bytes(32, "big").hex()


def sign_response(message: str) -> str:
    der = _load_private_key().sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")
